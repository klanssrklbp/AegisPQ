//! File encryption and decryption protocol.
//!
//! Implements the AegisPQ encrypted file format (DESIGN.md §9.5–9.6, §10.6).
//!
//! ## Encryption flow
//!
//! 1. Generate random file ID (16 bytes) and file encryption key (FEK, 32 bytes).
//! 2. For each recipient: hybrid KEM → derive KEK → wrap FEK under KEK.
//! 3. Pad entire plaintext, split into chunks, encrypt each chunk with AEAD.
//! 4. Sign the complete pre-signature payload with the sender's hybrid signing key.
//!
//! ## Decryption flow
//!
//! 1. Parse envelope header, verify format and version.
//! 2. Parse payload structure (slots, chunks, signature).
//! 3. Verify sender signature — reject before any decryption if invalid.
//! 4. Find matching recipient slot, decapsulate KEM, derive KEK, unwrap FEK.
//! 5. Decrypt chunks in order, verifying each AEAD tag (reject on first failure).
//! 6. Reassemble and unpad to recover original plaintext.
//!
//! ## Security properties
//!
//! - **Confidentiality:** Hybrid KEM (X25519 + ML-KEM-768) protects the FEK.
//! - **Integrity:** Per-chunk AEAD tags detect any modification.
//! - **Authentication:** Hybrid signature (Ed25519 + ML-DSA-65) over the ciphertext.
//! - **Anti-reordering:** Chunk index and is-final flag in AAD prevent reordering/truncation.
//! - **Multi-recipient:** Each recipient gets an independent KEM slot; compromising
//!   one recipient's key does not help attack another's slot.

use aegispq_core::{aead, hash, kdf, kem, nonce, sig};
use zeroize::Zeroize;

use crate::envelope::{self, Header, HEADER_SIZE};
use crate::error::ProtocolError;
use crate::identity::{IdentityId, IDENTITY_ID_LEN};
use crate::padding::{self, PaddingScheme};
use crate::{FormatType, Suite};

// ---------------------------------------------------------------------------
// Domain separation constants
// ---------------------------------------------------------------------------

/// HKDF salt for deriving file-specific KEK from the KEM shared secret.
const FILE_KEK_DOMAIN: &[u8] = b"AegisPQ-v1-file-kek";

/// Domain string prepended to FEK-wrapping AAD.
const FILE_WRAP_DOMAIN: &[u8] = b"AegisPQ-v1-file-wrap";

/// Domain string prepended to per-chunk AEAD AAD.
const FILE_AEAD_DOMAIN: &[u8] = b"AegisPQ-v1-file-aead";

/// Domain separator for the sender's hybrid signature over the ciphertext.
const FILE_SIGN_DOMAIN: &[u8] = b"AegisPQ-v1-file-sign";

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Default chunk size: 1 MiB.
pub const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;

/// Maximum number of recipient slots per encrypted file.
pub const MAX_RECIPIENTS: usize = 1000;

/// Maximum number of encrypted chunks per file (~4 TiB at 1 MiB chunks).
pub const MAX_CHUNKS: u32 = 4_194_304;

/// File ID length in bytes.
pub const FILE_ID_LEN: usize = 16;

/// A 16-byte random file identifier.
pub type FileId = [u8; FILE_ID_LEN];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information about a recipient needed to encrypt for them.
pub struct RecipientInfo {
    /// The recipient's identity ID.
    pub identity_id: IdentityId,
    /// The recipient's hybrid KEM public key.
    pub kem_public_key: kem::HybridPublicKey,
}

/// A recipient slot inside the encrypted file payload.
struct RecipientSlot {
    recipient_identity_id: IdentityId,
    ephemeral_x25519_pk: [u8; 32],
    pq_ciphertext: Vec<u8>,
    /// Full `seal()` output: `nonce || encrypted_fek || tag`.
    wrapped_fek: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt a file for one or more recipients.
///
/// Returns the complete binary-encoded encrypted file (envelope header + payload).
///
/// - `plaintext`: The file contents to encrypt.
/// - `sender_signing_key`: The sender's hybrid signing key (for authentication).
/// - `sender_identity_id`: The sender's 16-byte identity ID.
/// - `recipients`: One or more recipients (identity + KEM public key).
/// - `suite`: Which algorithm suite to use for chunk encryption.
/// - `padding_scheme`: How to pad the plaintext before chunking.
/// - `chunk_size`: Chunk size in bytes (0 = use default 1 MiB).
pub fn encrypt(
    plaintext: &[u8],
    sender_signing_key: &sig::HybridSigningKey,
    sender_identity_id: &IdentityId,
    recipients: &[RecipientInfo],
    suite: Suite,
    padding_scheme: PaddingScheme,
    chunk_size: u32,
) -> Result<Vec<u8>, ProtocolError> {
    // --- Validation ---
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(ProtocolError::TooManyRecipients {
            count: recipients.len(),
            max: MAX_RECIPIENTS,
        });
    }
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };

    // --- Generate file ID and FEK ---
    let file_id: FileId = nonce::random_bytes()?;
    let mut fek_bytes: [u8; 32] = nonce::random_bytes()?;
    let fek = aead::AeadKey::from_bytes(fek_bytes);

    // --- Build recipient slots ---
    let mut slots = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        slots.push(build_recipient_slot(
            &fek_bytes,
            &file_id,
            sender_identity_id,
            recipient,
        )?);
    }

    // Zeroize the raw FEK bytes now that the key object and all wrappings are done.
    fek_bytes.zeroize();

    // --- Pad and chunk ---
    let padded = padding::pad(plaintext, padding_scheme, 0);

    let max_padded = chunk_size as u64 * MAX_CHUNKS as u64;
    if padded.len() as u64 > max_padded {
        return Err(ProtocolError::PayloadTooLarge {
            size: plaintext.len() as u64,
            max: max_padded,
        });
    }

    let algorithm = suite.symmetric_algorithm();
    let mut nonce_gen = match algorithm {
        aead::Algorithm::Aes256Gcm => Some(nonce::GcmNonceGenerator::new()?),
        aead::Algorithm::XChaCha20Poly1305 => None,
    };

    let total_chunks = (padded.len() + chunk_size as usize - 1) / chunk_size as usize;
    let mut encrypted_chunks: Vec<Vec<u8>> = Vec::with_capacity(total_chunks);

    for (i, chunk_data) in padded.chunks(chunk_size as usize).enumerate() {
        let is_final = i == total_chunks - 1;
        let aad = chunk_aad(&file_id, i as u32, is_final);
        let ct = aead::seal(algorithm, &fek, &aad, chunk_data, nonce_gen.as_mut())?;
        encrypted_chunks.push(ct);
    }

    // --- Serialize the pre-signature payload ---
    let mut payload = Vec::new();

    // File metadata.
    payload.extend_from_slice(&file_id);
    payload.extend_from_slice(sender_identity_id);

    // Recipient slots.
    payload.extend_from_slice(&(slots.len() as u16).to_be_bytes());
    for slot in &slots {
        serialize_slot(&mut payload, slot);
    }

    // Chunk metadata.
    payload.extend_from_slice(&chunk_size.to_be_bytes());
    payload.push(padding_scheme as u8);

    // Encrypted chunks.
    payload.extend_from_slice(&(encrypted_chunks.len() as u32).to_be_bytes());
    for ct in &encrypted_chunks {
        payload.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        payload.extend_from_slice(ct);
    }

    // --- Sign the payload ---
    let signed_portion_len = payload.len();
    let payload_hash = hash::blake3_hash(&payload);
    let signature = sig::sign(sender_signing_key, FILE_SIGN_DOMAIN, &payload_hash)?;
    let sig_bytes = signature.to_bytes();

    // Append signature.
    payload.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&sig_bytes);

    // --- Check payload fits in envelope u32 ---
    if payload.len() > envelope::MAX_PAYLOAD_SIZE as usize {
        return Err(ProtocolError::PayloadTooLarge {
            size: payload.len() as u64,
            max: envelope::MAX_PAYLOAD_SIZE as u64,
        });
    }

    // --- Build envelope ---
    let header = Header {
        format_type: FormatType::EncryptedFile,
        version: crate::version::CURRENT,
        suite,
        payload_length: payload.len() as u32,
    };

    let mut output = Vec::with_capacity(HEADER_SIZE + payload.len());
    output.extend_from_slice(&header.to_bytes());
    output.extend_from_slice(&payload);

    // Suppress unused-variable warning; signed_portion_len is used only
    // conceptually to delimit what is hashed for the signature.
    let _ = signed_portion_len;

    Ok(output)
}

/// Decrypt a file encrypted with [`encrypt`].
///
/// Returns the original plaintext if authentication and decryption succeed.
///
/// - `ciphertext`: The complete binary-encoded encrypted file.
/// - `recipient_kem_keypair`: The recipient's hybrid KEM key pair.
/// - `recipient_identity_id`: The recipient's 16-byte identity ID.
/// - `sender_verifying_key`: The sender's hybrid verifying key (for signature check).
pub fn decrypt(
    ciphertext: &[u8],
    recipient_kem_keypair: &kem::HybridKeyPair,
    recipient_identity_id: &IdentityId,
    sender_verifying_key: &sig::HybridVerifyingKey,
) -> Result<Vec<u8>, ProtocolError> {
    // --- Parse envelope header ---
    let header = Header::from_bytes(ciphertext)?;

    if header.format_type != FormatType::EncryptedFile {
        return Err(ProtocolError::UnknownFormat {
            found: header.format_type as u8,
        });
    }

    let expected_end = HEADER_SIZE
        .checked_add(header.payload_length as usize)
        .ok_or(ProtocolError::Truncated {
            expected: usize::MAX,
            actual: ciphertext.len(),
        })?;
    if ciphertext.len() < expected_end {
        return Err(ProtocolError::Truncated {
            expected: expected_end,
            actual: ciphertext.len(),
        });
    }
    if ciphertext.len() > expected_end {
        return Err(ProtocolError::TrailingData {
            expected: expected_end,
            actual: ciphertext.len(),
        });
    }
    let payload = &ciphertext[HEADER_SIZE..expected_end];
    let algorithm = header.suite.symmetric_algorithm();

    // --- Parse payload structure ---
    let mut pos: usize = 0;

    // File ID.
    let file_id = read_fixed::<FILE_ID_LEN>(payload, &mut pos)?;

    // Sender identity ID.
    let sender_identity_id = read_fixed::<IDENTITY_ID_LEN>(payload, &mut pos)?;

    // Recipient slots.
    let num_recipients = read_u16(payload, &mut pos)? as usize;
    if num_recipients > MAX_RECIPIENTS {
        return Err(ProtocolError::TooManyRecipients {
            count: num_recipients,
            max: MAX_RECIPIENTS,
        });
    }
    let mut slots = Vec::with_capacity(num_recipients);
    for _ in 0..num_recipients {
        slots.push(parse_slot(payload, &mut pos)?);
    }

    // Chunk metadata.
    let chunk_size = read_u32(payload, &mut pos)?;
    let padding_scheme_byte = read_byte(payload, &mut pos)?;
    let _padding_scheme = PaddingScheme::from_byte(padding_scheme_byte).ok_or(
        ProtocolError::UnknownFormat {
            found: padding_scheme_byte,
        },
    )?;

    // Encrypted chunks.
    let num_chunks = read_u32(payload, &mut pos)?;
    if num_chunks > MAX_CHUNKS {
        return Err(ProtocolError::PayloadTooLarge {
            size: num_chunks as u64 * chunk_size as u64,
            max: MAX_CHUNKS as u64 * chunk_size as u64,
        });
    }
    let mut encrypted_chunks: Vec<&[u8]> = Vec::with_capacity(num_chunks as usize);
    for _ in 0..num_chunks {
        let chunk_len = read_u32(payload, &mut pos)? as usize;
        if pos + chunk_len > payload.len() {
            return Err(ProtocolError::Truncated {
                expected: pos + chunk_len,
                actual: payload.len(),
            });
        }
        encrypted_chunks.push(&payload[pos..pos + chunk_len]);
        pos += chunk_len;
    }

    // The signed portion is everything parsed so far.
    let signed_data = &payload[..pos];

    // Signature.
    let sig_len = read_u16(payload, &mut pos)? as usize;
    if pos + sig_len > payload.len() {
        return Err(ProtocolError::Truncated {
            expected: pos + sig_len,
            actual: payload.len(),
        });
    }
    let sig_bytes = &payload[pos..pos + sig_len];
    pos += sig_len;

    // Reject trailing bytes beyond the signature.
    if pos != payload.len() {
        return Err(ProtocolError::TrailingData {
            expected: pos,
            actual: payload.len(),
        });
    }

    let signature = sig::HybridSignature::from_bytes(sig_bytes)?;

    // --- Verify signature BEFORE any decryption ---
    let payload_hash = hash::blake3_hash(signed_data);
    sig::verify(sender_verifying_key, FILE_SIGN_DOMAIN, &payload_hash, &signature)
        .map_err(|_| ProtocolError::AuthenticationFailed)?;

    // --- Find matching recipient slot ---
    let slot = slots
        .iter()
        .find(|s| s.recipient_identity_id == *recipient_identity_id)
        .ok_or(ProtocolError::NotARecipient)?;

    // --- Unwrap FEK ---
    let fek = unwrap_fek(
        slot,
        &file_id,
        &sender_identity_id,
        recipient_kem_keypair,
        recipient_identity_id,
    )?;

    // --- Decrypt chunks ---
    let mut reassembled = Vec::new();
    for (i, encrypted_chunk) in encrypted_chunks.iter().enumerate() {
        let is_final = i == encrypted_chunks.len() - 1;
        let aad = chunk_aad(&file_id, i as u32, is_final);
        let chunk_plaintext = aead::open(algorithm, &fek, &aad, encrypted_chunk)
            .map_err(|_| ProtocolError::IntegrityError {
                chunk_index: i as u32,
            })?;
        reassembled.extend_from_slice(&chunk_plaintext);
    }

    // --- Unpad ---
    padding::unpad(&reassembled).ok_or(ProtocolError::Truncated {
        expected: 4, // minimum: 4-byte length prefix
        actual: reassembled.len(),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers — KEM and key wrapping
// ---------------------------------------------------------------------------

/// Build a recipient slot by performing hybrid KEM and wrapping the FEK.
fn build_recipient_slot(
    fek_bytes: &[u8; 32],
    file_id: &FileId,
    sender_identity_id: &IdentityId,
    recipient: &RecipientInfo,
) -> Result<RecipientSlot, ProtocolError> {
    // KEM context binds the exchange to this file and recipient.
    let kem_context = concat_slices(&[file_id.as_ref(), recipient.identity_id.as_ref()]);

    // Hybrid encapsulation (X25519 + ML-KEM-768).
    let encap = kem::encapsulate(&recipient.kem_public_key, &kem_context)?;

    // Derive file-specific KEK from the KEM shared secret.
    let kek_info = concat_slices(&[
        recipient.identity_id.as_ref(),
        encap.classical_ephemeral_pk.as_ref(),
    ]);
    let kek_derived = kdf::hkdf_sha512(FILE_KEK_DOMAIN, encap.shared_secret.as_bytes(), &kek_info, 32)?;
    let kek = aead::AeadKey::from_slice(kek_derived.as_bytes())?;

    // Wrap FEK under KEK with AES-256-GCM (always, regardless of suite).
    let wrap_aad = build_wrap_aad(file_id, sender_identity_id, &recipient.identity_id);
    let wrapped_fek = aead::seal(aead::Algorithm::Aes256Gcm, &kek, &wrap_aad, fek_bytes, None)?;

    Ok(RecipientSlot {
        recipient_identity_id: recipient.identity_id,
        ephemeral_x25519_pk: encap.classical_ephemeral_pk,
        pq_ciphertext: encap.pq_ciphertext.as_bytes().to_vec(),
        wrapped_fek,
    })
}

/// Unwrap the FEK from a recipient slot.
fn unwrap_fek(
    slot: &RecipientSlot,
    file_id: &FileId,
    sender_identity_id: &IdentityId,
    recipient_kp: &kem::HybridKeyPair,
    recipient_identity_id: &IdentityId,
) -> Result<aead::AeadKey, ProtocolError> {
    // Reconstruct the same KEM context used during encryption.
    let kem_context = concat_slices(&[file_id.as_ref(), recipient_identity_id.as_ref()]);

    // Hybrid decapsulation.
    let shared_secret = kem::decapsulate(
        recipient_kp,
        &slot.ephemeral_x25519_pk,
        &slot.pq_ciphertext,
        &kem_context,
    )?;

    // Derive the same KEK.
    let kek_info = concat_slices(&[
        recipient_identity_id.as_ref(),
        slot.ephemeral_x25519_pk.as_ref(),
    ]);
    let kek_derived = kdf::hkdf_sha512(FILE_KEK_DOMAIN, shared_secret.as_bytes(), &kek_info, 32)?;
    let kek = aead::AeadKey::from_slice(kek_derived.as_bytes())?;

    // Unwrap FEK.
    let wrap_aad = build_wrap_aad(file_id, sender_identity_id, recipient_identity_id);
    let fek_bytes = aead::open(aead::Algorithm::Aes256Gcm, &kek, &wrap_aad, &slot.wrapped_fek)?;

    Ok(aead::AeadKey::from_slice(&fek_bytes)?)
}

// ---------------------------------------------------------------------------
// Internal helpers — AAD construction
// ---------------------------------------------------------------------------

/// Build the per-chunk AAD: `domain || file_id || chunk_index(u32 BE) || is_final(u8)`.
fn chunk_aad(file_id: &FileId, chunk_index: u32, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_AEAD_DOMAIN.len() + FILE_ID_LEN + 5);
    aad.extend_from_slice(FILE_AEAD_DOMAIN);
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

/// Build the FEK-wrapping AAD: `domain || file_id || sender_id || recipient_id`.
fn build_wrap_aad(file_id: &FileId, sender_id: &IdentityId, recipient_id: &IdentityId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_WRAP_DOMAIN.len() + FILE_ID_LEN + 2 * IDENTITY_ID_LEN);
    aad.extend_from_slice(FILE_WRAP_DOMAIN);
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(sender_id);
    aad.extend_from_slice(recipient_id);
    aad
}

// ---------------------------------------------------------------------------
// Internal helpers — binary serialization
// ---------------------------------------------------------------------------

/// Serialize a recipient slot into the output buffer.
fn serialize_slot(buf: &mut Vec<u8>, slot: &RecipientSlot) {
    buf.extend_from_slice(&slot.recipient_identity_id);
    buf.extend_from_slice(&slot.ephemeral_x25519_pk);
    // Length-prefixed PQ ciphertext.
    buf.extend_from_slice(&(slot.pq_ciphertext.len() as u16).to_be_bytes());
    buf.extend_from_slice(&slot.pq_ciphertext);
    // Length-prefixed wrapped FEK (nonce || encrypted_fek || tag).
    buf.extend_from_slice(&(slot.wrapped_fek.len() as u16).to_be_bytes());
    buf.extend_from_slice(&slot.wrapped_fek);
}

/// Parse a recipient slot from the payload at the current position.
fn parse_slot(payload: &[u8], pos: &mut usize) -> Result<RecipientSlot, ProtocolError> {
    let recipient_identity_id = read_fixed::<IDENTITY_ID_LEN>(payload, pos)?;
    let ephemeral_x25519_pk = read_fixed::<32>(payload, pos)?;
    let pq_ciphertext = read_length_prefixed(payload, pos)?;
    let wrapped_fek = read_length_prefixed(payload, pos)?;

    Ok(RecipientSlot {
        recipient_identity_id,
        ephemeral_x25519_pk,
        pq_ciphertext,
        wrapped_fek,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers — binary parsing primitives
// ---------------------------------------------------------------------------

fn read_byte(data: &[u8], pos: &mut usize) -> Result<u8, ProtocolError> {
    if *pos >= data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + 1,
            actual: data.len(),
        });
    }
    let val = data[*pos];
    *pos += 1;
    Ok(val)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, ProtocolError> {
    if *pos + 2 > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + 2,
            actual: data.len(),
        });
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, ProtocolError> {
    if *pos + 4 > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + 4,
            actual: data.len(),
        });
    }
    let val = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N], ProtocolError> {
    if *pos + N > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + N,
            actual: data.len(),
        });
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    Ok(arr)
}

fn read_length_prefixed(
    data: &[u8],
    pos: &mut usize,
) -> Result<Vec<u8>, ProtocolError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + len,
            actual: data.len(),
        });
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

/// Concatenate multiple byte slices into a single Vec.
fn concat_slices(slices: &[&[u8]]) -> Vec<u8> {
    let total: usize = slices.iter().map(|s| s.len()).sum();
    let mut out = Vec::with_capacity(total);
    for s in slices {
        out.extend_from_slice(s);
    }
    out
}

// ---------------------------------------------------------------------------
// Streaming API
// ---------------------------------------------------------------------------

/// Encrypt a file using streaming I/O.
///
/// Reads plaintext from `input` in chunks and writes the encrypted file to `output`.
/// The `input_size` must be known upfront to compute the padded size and header.
///
/// Memory usage is O(chunk_size) rather than O(file_size).
pub fn encrypt_stream<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    input_size: u64,
    sender_signing_key: &sig::HybridSigningKey,
    sender_identity_id: &IdentityId,
    recipients: &[RecipientInfo],
    suite: Suite,
    padding_scheme: PaddingScheme,
    chunk_size: u32,
) -> Result<(), ProtocolError> {
    use std::io::Read;

    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(ProtocolError::TooManyRecipients {
            count: recipients.len(),
            max: MAX_RECIPIENTS,
        });
    }
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };

    // --- Compute padded size ---
    let content_len = 4 + input_size as usize; // 4-byte length prefix + plaintext
    let padded_len = padding::padded_size(content_len, padding_scheme, 0);

    let max_padded = chunk_size as u64 * MAX_CHUNKS as u64;
    if padded_len as u64 > max_padded {
        return Err(ProtocolError::PayloadTooLarge {
            size: input_size,
            max: max_padded,
        });
    }

    // --- Generate file ID and FEK ---
    let file_id: FileId = nonce::random_bytes()?;
    let mut fek_bytes: [u8; 32] = nonce::random_bytes()?;
    let fek = aead::AeadKey::from_bytes(fek_bytes);

    // --- Build recipient slots ---
    let mut slots = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        slots.push(build_recipient_slot(
            &fek_bytes,
            &file_id,
            sender_identity_id,
            recipient,
        )?);
    }
    fek_bytes.zeroize();

    // --- Build pre-chunk metadata ---
    let algorithm = suite.symmetric_algorithm();
    let mut nonce_gen = match algorithm {
        aead::Algorithm::Aes256Gcm => Some(nonce::GcmNonceGenerator::new()?),
        aead::Algorithm::XChaCha20Poly1305 => None,
    };

    let total_chunks = (padded_len + chunk_size as usize - 1) / chunk_size as usize;

    // Pre-compute chunk sizes to determine total payload length.
    let aead_overhead = algorithm.overhead();
    let mut chunk_sizes: Vec<u32> = Vec::with_capacity(total_chunks);
    let mut remaining_padded = padded_len;
    for _ in 0..total_chunks {
        let this_chunk = remaining_padded.min(chunk_size as usize);
        chunk_sizes.push((this_chunk + aead_overhead) as u32);
        remaining_padded -= this_chunk;
    }

    // Serialize metadata into a buffer (small — a few KB).
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&file_id);
    metadata.extend_from_slice(sender_identity_id);
    metadata.extend_from_slice(&(slots.len() as u16).to_be_bytes());
    for slot in &slots {
        serialize_slot(&mut metadata, slot);
    }
    metadata.extend_from_slice(&chunk_size.to_be_bytes());
    metadata.push(padding_scheme as u8);
    metadata.extend_from_slice(&(total_chunks as u32).to_be_bytes());

    // We'll estimate the signature size (hybrid sig is ~2+32+64+2+4627 ≈ variable,
    // but we need the exact size). Sign a dummy to find out.
    // Actually, we need the real signature over the real data. So we'll compute
    // payload_length after we know the signature size.
    // Strategy: accumulate hash as we go, sign at end, then we know sig size.
    // But header needs payload_length upfront...
    //
    // Solution: compute expected signature length from the algorithm.
    // Ed25519 signature: 64 bytes. ML-DSA-65 signature: 3309 bytes.
    // HybridSignature: 2 (ed_len) + 64 (ed) + 2 (pq_len) + 3309 (pq) = 3377 bytes.
    // Plus the 2-byte length prefix in the payload = 3379 bytes total.
    let sig_overhead = 2 + sig::HYBRID_SIGNATURE_SIZE; // u16 len + signature bytes

    let chunks_payload: usize = chunk_sizes
        .iter()
        .map(|&s| 4 + s as usize) // u32 len prefix + encrypted chunk
        .sum();

    let payload_len = metadata.len() + chunks_payload + sig_overhead;

    if payload_len > envelope::MAX_PAYLOAD_SIZE as usize {
        return Err(ProtocolError::PayloadTooLarge {
            size: payload_len as u64,
            max: envelope::MAX_PAYLOAD_SIZE as u64,
        });
    }

    // --- Write envelope header ---
    let header = Header {
        format_type: FormatType::EncryptedFile,
        version: crate::version::CURRENT,
        suite,
        payload_length: payload_len as u32,
    };
    output.write_all(&header.to_bytes()).map_err(io_to_proto)?;

    // --- Write metadata and start hashing ---
    let mut hasher = hash::Blake3Hasher::new();
    write_and_hash(output, &mut hasher, &metadata)?;

    // --- Stream chunks ---
    // Build a "padded reader" that produces the padded plaintext stream:
    //   [4-byte BE length][plaintext bytes][zero padding]
    let length_prefix = (input_size as u32).to_be_bytes();
    let mut padded_reader = PaddedReader::new(input, &length_prefix, input_size, padded_len);
    let mut chunk_buf = vec![0u8; chunk_size as usize];

    for i in 0..total_chunks {
        let this_chunk_size = if i == total_chunks - 1 {
            padded_len - (chunk_size as usize * (total_chunks - 1))
        } else {
            chunk_size as usize
        };
        padded_reader
            .read_exact(&mut chunk_buf[..this_chunk_size])
            .map_err(io_to_proto)?;

        let is_final = i == total_chunks - 1;
        let aad = chunk_aad(&file_id, i as u32, is_final);
        let ct = aead::seal(algorithm, &fek, &aad, &chunk_buf[..this_chunk_size], nonce_gen.as_mut())?;

        let ct_len = ct.len() as u32;
        write_and_hash(output, &mut hasher, &ct_len.to_be_bytes())?;
        write_and_hash(output, &mut hasher, &ct)?;
    }

    // --- Sign and append ---
    let payload_hash = hasher.finalize();
    let signature = sig::sign(sender_signing_key, FILE_SIGN_DOMAIN, &payload_hash)?;
    let sig_bytes = signature.to_bytes();

    output
        .write_all(&(sig_bytes.len() as u16).to_be_bytes())
        .map_err(io_to_proto)?;
    output.write_all(&sig_bytes).map_err(io_to_proto)?;

    Ok(())
}

/// Decrypt a file using streaming I/O.
///
/// Reads the encrypted file from `input` and writes the recovered plaintext to `output`.
/// Per-chunk AEAD tags are verified during streaming. The sender's signature is verified
/// after all chunks have been processed.
///
/// Memory usage is O(chunk_size) rather than O(file_size).
///
/// **Security note:** Individual chunks are AEAD-authenticated during streaming, but
/// the sender signature is verified at the end. If signature verification fails, the
/// caller should discard any output written so far.
pub fn decrypt_stream<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    recipient_kem_keypair: &kem::HybridKeyPair,
    recipient_identity_id: &IdentityId,
    sender_verifying_key: &sig::HybridVerifyingKey,
) -> Result<u64, ProtocolError> {
    // --- Read envelope header ---
    let mut header_buf = [0u8; HEADER_SIZE];
    input
        .read_exact(&mut header_buf)
        .map_err(io_to_proto)?;
    let header = Header::from_bytes(&header_buf)?;

    if header.format_type != FormatType::EncryptedFile {
        return Err(ProtocolError::UnknownFormat {
            found: header.format_type as u8,
        });
    }

    let algorithm = header.suite.symmetric_algorithm();
    let mut hasher = hash::Blake3Hasher::new();

    // --- Read and hash metadata ---
    // File ID.
    let file_id = read_and_hash_fixed::<FILE_ID_LEN>(input, &mut hasher)?;

    // Sender identity ID.
    let _sender_identity_id = read_and_hash_fixed::<IDENTITY_ID_LEN>(input, &mut hasher)?;

    // Recipient count.
    let num_recipients_bytes = read_and_hash_fixed::<2>(input, &mut hasher)?;
    let num_recipients = u16::from_be_bytes(num_recipients_bytes) as usize;
    if num_recipients > MAX_RECIPIENTS {
        return Err(ProtocolError::TooManyRecipients {
            count: num_recipients,
            max: MAX_RECIPIENTS,
        });
    }

    // Parse recipient slots.
    let mut slots = Vec::with_capacity(num_recipients);
    for _ in 0..num_recipients {
        slots.push(parse_slot_streaming(input, &mut hasher)?);
    }

    // Chunk metadata.
    let chunk_size_bytes = read_and_hash_fixed::<4>(input, &mut hasher)?;
    let _chunk_size = u32::from_be_bytes(chunk_size_bytes);

    let mut padding_byte = [0u8; 1];
    read_and_hash_exact(input, &mut hasher, &mut padding_byte)?;

    // Number of chunks.
    let num_chunks_bytes = read_and_hash_fixed::<4>(input, &mut hasher)?;
    let num_chunks = u32::from_be_bytes(num_chunks_bytes);
    if num_chunks > MAX_CHUNKS {
        return Err(ProtocolError::PayloadTooLarge {
            size: num_chunks as u64,
            max: MAX_CHUNKS as u64,
        });
    }

    // --- Find matching recipient slot and unwrap FEK ---
    let slot = slots
        .iter()
        .find(|s| s.recipient_identity_id == *recipient_identity_id)
        .ok_or(ProtocolError::NotARecipient)?;

    let fek = unwrap_fek(
        slot,
        &file_id,
        &_sender_identity_id,
        recipient_kem_keypair,
        recipient_identity_id,
    )?;

    // --- Stream-decrypt chunks ---
    let mut total_plaintext_bytes: u64 = 0;
    let mut first_chunk_header = true;
    let mut original_plaintext_len: Option<u32> = None;

    for i in 0..num_chunks {
        // Read chunk length.
        let chunk_len_bytes = read_and_hash_fixed::<4>(input, &mut hasher)?;
        let chunk_len = u32::from_be_bytes(chunk_len_bytes) as usize;

        // Read encrypted chunk.
        let mut chunk_ct = vec![0u8; chunk_len];
        read_and_hash_exact(input, &mut hasher, &mut chunk_ct)?;

        // Decrypt.
        let is_final = i == num_chunks - 1;
        let aad = chunk_aad(&file_id, i, is_final);
        let chunk_pt = aead::open(algorithm, &fek, &aad, &chunk_ct)
            .map_err(|_| ProtocolError::IntegrityError { chunk_index: i })?;

        // Handle the 4-byte length prefix in the first chunk (part of padding format).
        if first_chunk_header {
            if chunk_pt.len() < 4 {
                return Err(ProtocolError::Truncated {
                    expected: 4,
                    actual: chunk_pt.len(),
                });
            }
            let orig_len =
                u32::from_be_bytes([chunk_pt[0], chunk_pt[1], chunk_pt[2], chunk_pt[3]]);
            original_plaintext_len = Some(orig_len);

            // Write the actual plaintext portion (skip 4-byte prefix, truncate padding).
            let data_start = 4;
            let available = chunk_pt.len() - data_start;
            let to_write = available.min(orig_len as usize);
            output
                .write_all(&chunk_pt[data_start..data_start + to_write])
                .map_err(io_to_proto)?;
            total_plaintext_bytes += to_write as u64;
            first_chunk_header = false;
        } else {
            // Subsequent chunks: write only up to the remaining plaintext length.
            let remaining = original_plaintext_len.unwrap() as u64 - total_plaintext_bytes;
            let to_write = (chunk_pt.len() as u64).min(remaining) as usize;
            output
                .write_all(&chunk_pt[..to_write])
                .map_err(io_to_proto)?;
            total_plaintext_bytes += to_write as u64;
        }
    }

    // --- Read and verify signature ---
    let mut sig_len_bytes = [0u8; 2];
    input
        .read_exact(&mut sig_len_bytes)
        .map_err(io_to_proto)?;
    let sig_len = u16::from_be_bytes(sig_len_bytes) as usize;

    let mut sig_bytes = vec![0u8; sig_len];
    input.read_exact(&mut sig_bytes).map_err(io_to_proto)?;

    let payload_hash = hasher.finalize();
    let signature = sig::HybridSignature::from_bytes(&sig_bytes)?;
    sig::verify(sender_verifying_key, FILE_SIGN_DOMAIN, &payload_hash, &signature)
        .map_err(|_| ProtocolError::AuthenticationFailed)?;

    // Reject trailing bytes beyond the signature (parity with in-memory path).
    let mut trailing = [0u8; 1];
    match input.read(&mut trailing) {
        Ok(0) => {} // EOF — correct
        Ok(_) => {
            return Err(ProtocolError::TrailingData {
                expected: 0,
                actual: 1,
            });
        }
        Err(_) => {} // Read error at EOF is fine (e.g. pipes)
    }

    Ok(total_plaintext_bytes)
}

// ---------------------------------------------------------------------------
// Streaming helpers
// ---------------------------------------------------------------------------

/// A reader that produces the padded plaintext stream:
/// `[length_prefix][plaintext from inner reader][zero padding]`
///
/// - `prefix`: the 4-byte BE length prefix
/// - `plaintext_len`: number of bytes to read from the inner reader
/// - `padding_len`: number of zero bytes appended after the plaintext
struct PaddedReader<'a, R> {
    inner: &'a mut R,
    prefix: &'a [u8],
    prefix_pos: usize,
    plaintext_remaining: u64,
    padding_remaining: usize,
}

impl<'a, R: std::io::Read> PaddedReader<'a, R> {
    fn new(inner: &'a mut R, prefix: &'a [u8], plaintext_len: u64, total_padded_len: usize) -> Self {
        let padding_len = total_padded_len - prefix.len() - plaintext_len as usize;
        Self {
            inner,
            prefix,
            prefix_pos: 0,
            plaintext_remaining: plaintext_len,
            padding_remaining: padding_len,
        }
    }
}

impl<R: std::io::Read> std::io::Read for PaddedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0;

        // Phase 1: emit prefix bytes.
        while written < buf.len() && self.prefix_pos < self.prefix.len() {
            buf[written] = self.prefix[self.prefix_pos];
            self.prefix_pos += 1;
            written += 1;
        }

        // Phase 2: read from inner reader.
        while written < buf.len() && self.plaintext_remaining > 0 {
            let to_read =
                (buf.len() - written).min(self.plaintext_remaining as usize);
            match self.inner.read(&mut buf[written..written + to_read])? {
                0 => {
                    // Inner reader short — treat remaining as padding.
                    self.padding_remaining += self.plaintext_remaining as usize;
                    self.plaintext_remaining = 0;
                    break;
                }
                n => {
                    written += n;
                    self.plaintext_remaining -= n as u64;
                }
            }
        }

        // Phase 3: emit zero padding.
        while written < buf.len() && self.padding_remaining > 0 {
            buf[written] = 0;
            written += 1;
            self.padding_remaining -= 1;
        }

        Ok(written)
    }
}

fn io_to_proto(e: std::io::Error) -> ProtocolError {
    ProtocolError::IoError {
        kind: format!("{:?}", e.kind()),
        message: e.to_string(),
    }
}

fn write_and_hash<W: std::io::Write>(
    output: &mut W,
    hasher: &mut hash::Blake3Hasher,
    data: &[u8],
) -> Result<(), ProtocolError> {
    output.write_all(data).map_err(io_to_proto)?;
    hasher.update(data);
    Ok(())
}

fn read_and_hash_fixed<const N: usize>(
    input: &mut impl std::io::Read,
    hasher: &mut hash::Blake3Hasher,
) -> Result<[u8; N], ProtocolError> {
    let mut buf = [0u8; N];
    input.read_exact(&mut buf).map_err(io_to_proto)?;
    hasher.update(&buf);
    Ok(buf)
}

fn read_and_hash_exact(
    input: &mut impl std::io::Read,
    hasher: &mut hash::Blake3Hasher,
    buf: &mut [u8],
) -> Result<(), ProtocolError> {
    input.read_exact(buf).map_err(io_to_proto)?;
    hasher.update(buf);
    Ok(())
}

/// Parse a recipient slot from a streaming reader.
fn parse_slot_streaming(
    input: &mut impl std::io::Read,
    hasher: &mut hash::Blake3Hasher,
) -> Result<RecipientSlot, ProtocolError> {
    let recipient_identity_id = read_and_hash_fixed::<IDENTITY_ID_LEN>(input, hasher)?;
    let ephemeral_x25519_pk = read_and_hash_fixed::<32>(input, hasher)?;

    // PQ ciphertext (u16 length-prefixed).
    let len_bytes = read_and_hash_fixed::<2>(input, hasher)?;
    let pq_len = u16::from_be_bytes(len_bytes) as usize;
    let mut pq_ciphertext = vec![0u8; pq_len];
    read_and_hash_exact(input, hasher, &mut pq_ciphertext)?;

    // Wrapped FEK (u16 length-prefixed).
    let len_bytes = read_and_hash_fixed::<2>(input, hasher)?;
    let fek_len = u16::from_be_bytes(len_bytes) as usize;
    let mut wrapped_fek = vec![0u8; fek_len];
    read_and_hash_exact(input, hasher, &mut wrapped_fek)?;

    Ok(RecipientSlot {
        recipient_identity_id,
        ephemeral_x25519_pk,
        pq_ciphertext,
        wrapped_fek,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegispq_core::{kem as core_kem, sig as core_sig};

    /// Create a test identity: signing keypair + KEM keypair + identity ID.
    struct TestIdentity {
        identity_id: IdentityId,
        signing_key: core_sig::HybridSigningKey,
        verifying_key: core_sig::HybridVerifyingKey,
        kem_keypair: core_kem::HybridKeyPair,
        kem_public: core_kem::HybridPublicKey,
    }

    fn make_identity() -> TestIdentity {
        let identity_id: IdentityId = nonce::random_bytes().unwrap();
        let (signing_key, verifying_key) = core_sig::generate_keypair().unwrap();
        let kem_keypair = core_kem::generate_keypair().unwrap();
        let kem_public = core_kem::public_key(&kem_keypair);
        TestIdentity {
            identity_id,
            signing_key,
            verifying_key,
            kem_keypair,
            kem_public,
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"Hello, post-quantum world!";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_xchacha_suite() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"XChaCha20-Poly1305 roundtrip test";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1XChaCha,
            PaddingScheme::FixedBlock,
            0,
        )
        .unwrap();

        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn multi_recipient() {
        let sender = make_identity();
        let bob = make_identity();
        let carol = make_identity();

        let plaintext = b"Secret for both Bob and Carol";
        let recipients = [
            RecipientInfo {
                identity_id: bob.identity_id,
                kem_public_key: bob.kem_public,
            },
            RecipientInfo {
                identity_id: carol.identity_id,
                kem_public_key: carol.kem_public,
            },
        ];

        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Bob can decrypt.
        let bob_pt = decrypt(
            &encrypted,
            &bob.kem_keypair,
            &bob.identity_id,
            &sender.verifying_key,
        )
        .unwrap();
        assert_eq!(&bob_pt, plaintext);

        // Carol can decrypt.
        let carol_pt = decrypt(
            &encrypted,
            &carol.kem_keypair,
            &carol.identity_id,
            &sender.verifying_key,
        )
        .unwrap();
        assert_eq!(&carol_pt, plaintext);
    }

    #[test]
    fn wrong_recipient_fails() {
        let sender = make_identity();
        let recipient = make_identity();
        let intruder = make_identity();

        let plaintext = b"not for you";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::None,
            0,
        )
        .unwrap();

        // Intruder's identity ID doesn't match any slot.
        let result = decrypt(
            &encrypted,
            &intruder.kem_keypair,
            &intruder.identity_id,
            &sender.verifying_key,
        );
        assert!(matches!(result, Err(ProtocolError::NotARecipient)));
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"tamper with me";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let mut encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::None,
            0,
        )
        .unwrap();

        // Flip a byte near the end (in the chunk data region).
        let flip_pos = encrypted.len() - 100;
        encrypted[flip_pos] ^= 0xFF;

        // Should fail authentication (signature won't match the tampered data).
        let result = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_sender_key_rejected() {
        let sender = make_identity();
        let fake_sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"who sent this?";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Verify with wrong sender key.
        let result = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &fake_sender.verifying_key,
        );
        assert!(matches!(result, Err(ProtocolError::AuthenticationFailed)));
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn multi_chunk_roundtrip() {
        let sender = make_identity();
        let recipient = make_identity();

        // 5000 bytes with a 1024-byte chunk size → multiple chunks.
        let plaintext = vec![0xABu8; 5000];
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            &plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            1024,
        )
        .unwrap();

        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn no_recipients_rejected() {
        let sender = make_identity();

        let result = encrypt(
            b"test",
            &sender.signing_key,
            &sender.identity_id,
            &[],
            Suite::HybridV1,
            PaddingScheme::None,
            0,
        );
        assert!(matches!(
            result,
            Err(ProtocolError::TooManyRecipients { count: 0, .. })
        ));
    }

    #[test]
    fn envelope_header_correct() {
        let sender = make_identity();
        let recipient = make_identity();

        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            b"check header",
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1XChaCha,
            PaddingScheme::None,
            0,
        )
        .unwrap();

        let header = Header::from_bytes(&encrypted).unwrap();
        assert_eq!(header.format_type, FormatType::EncryptedFile);
        assert_eq!(header.version, crate::version::CURRENT);
        assert_eq!(header.suite, Suite::HybridV1XChaCha);
    }

    // -----------------------------------------------------------------------
    // Streaming tests
    // -----------------------------------------------------------------------

    #[test]
    fn stream_encrypt_decrypt_roundtrip() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"Hello, streaming post-quantum world!";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        let bytes_written = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(bytes_written, plaintext.len() as u64);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn stream_encrypt_matches_in_memory_decrypt() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"Cross-compatibility test between streaming and in-memory";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        // Encrypt with streaming API.
        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Decrypt with in-memory API.
        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn in_memory_encrypt_stream_decrypt() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"In-memory encrypt, streaming decrypt";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        // Encrypt with in-memory API.
        let encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Decrypt with streaming API.
        let mut decrypted = Vec::new();
        let bytes_written = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(bytes_written, plaintext.len() as u64);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn stream_xchacha_roundtrip() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"XChaCha streaming test";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1XChaCha,
            PaddingScheme::FixedBlock,
            0,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn stream_multi_chunk() {
        let sender = make_identity();
        let recipient = make_identity();

        // Use a small chunk size to force multiple chunks.
        let plaintext = vec![0xABu8; 10_000];
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            1024, // 1 KiB chunks → many chunks for 10 KB + padding
        )
        .unwrap();

        let mut decrypted = Vec::new();
        let bytes_written = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(bytes_written, plaintext.len() as u64);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn stream_empty_plaintext() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            0,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        let bytes_written = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        assert_eq!(bytes_written, 0);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn stream_multi_recipient() {
        let sender = make_identity();
        let bob = make_identity();
        let carol = make_identity();

        let plaintext = b"Streaming multi-recipient";
        let recipients = [
            RecipientInfo {
                identity_id: bob.identity_id,
                kem_public_key: bob.kem_public.clone(),
            },
            RecipientInfo {
                identity_id: carol.identity_id,
                kem_public_key: carol.kem_public.clone(),
            },
        ];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Bob decrypts.
        let mut bob_decrypted = Vec::new();
        decrypt_stream(
            &mut &encrypted[..],
            &mut bob_decrypted,
            &bob.kem_keypair,
            &bob.identity_id,
            &sender.verifying_key,
        )
        .unwrap();
        assert_eq!(&bob_decrypted, plaintext);

        // Carol decrypts.
        let mut carol_decrypted = Vec::new();
        decrypt_stream(
            &mut &encrypted[..],
            &mut carol_decrypted,
            &carol.kem_keypair,
            &carol.identity_id,
            &sender.verifying_key,
        )
        .unwrap();
        assert_eq!(&carol_decrypted, plaintext);
    }

    // -------------------------------------------------------------------
    // Adversarial / hardening tests
    // -------------------------------------------------------------------

    #[test]
    fn stream_trailing_data_rejected() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"trailing garbage test";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Append trailing garbage.
        encrypted.extend_from_slice(b"\xDE\xAD\xBE\xEF");

        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );
        assert!(
            matches!(result, Err(ProtocolError::TrailingData { .. })),
            "expected TrailingData, got {result:?}"
        );
    }

    #[test]
    fn stream_wrong_sender_key_rejected() {
        let sender = make_identity();
        let fake_sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"wrong sender streaming test";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &fake_sender.verifying_key,
        );
        assert!(
            matches!(result, Err(ProtocolError::AuthenticationFailed)),
            "expected AuthenticationFailed, got {result:?}"
        );
    }

    #[test]
    fn stream_truncated_input_rejected() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"truncation test with some data here";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Truncate halfway through the ciphertext.
        let truncated = &encrypted[..encrypted.len() / 2];
        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            &mut &truncated[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );
        assert!(result.is_err(), "expected error on truncated input");
    }

    #[test]
    fn stream_tampered_chunk_detected() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"tamper with streaming chunks";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Flip a byte in the middle of the ciphertext payload.
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xFF;

        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            &mut &encrypted[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );
        assert!(result.is_err(), "expected error on tampered chunk data");
    }

    #[test]
    fn stream_signature_stripped_detected() {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"strip signature test";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public.clone(),
        }];

        let mut encrypted = Vec::new();
        encrypt_stream(
            &mut &plaintext[..],
            &mut encrypted,
            plaintext.len() as u64,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Remove the last 100 bytes (signature region).
        let chopped = &encrypted[..encrypted.len().saturating_sub(100)];
        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            &mut &chopped[..],
            &mut decrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );
        assert!(result.is_err(), "expected error when signature is stripped");
    }
}
