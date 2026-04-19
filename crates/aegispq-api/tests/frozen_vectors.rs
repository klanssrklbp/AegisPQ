//! Frozen test vectors for encrypted files and detached signatures.
//!
//! These tests verify that AegisPQ can still decrypt/verify data produced by
//! earlier versions of the code. Unlike the protocol-layer frozen vectors
//! (which test deterministic serialization), these exercise the full
//! cryptographic pipeline including KEM, AEAD, and hybrid signatures.
//!
//! ## Workflow
//!
//! 1. Run `cargo test -p aegispq-api --test frozen_vectors -- --ignored`
//!    to (re)generate the `.bin` fixtures.
//! 2. Run the normal test suite — each conformance test loads frozen bytes
//!    and verifies that current code can still decrypt/verify them.
//!
//! ## File layout
//!
//! ```text
//! tests/vectors/v1/
//!   encrypted_file/
//!     ciphertext.bin   — frozen encrypted file (envelope + payload + sig)
//!     plaintext.bin    — expected plaintext after decryption
//!     keys.bin         — serialized key material for sender + recipient
//!   detached_signature/
//!     message.bin      — the signed message
//!     signature.bin    — the hybrid signature bytes
//!     keys.bin         — serialized signer verifying key
//! ```
//!
//! If a legitimate crypto or protocol change breaks these vectors, create a
//! `v2/` directory and regenerate. Do **not** silently overwrite `v1/`.

use std::path::PathBuf;

use aegispq_api::encrypt;
use aegispq_api::identity;
use aegispq_api::sign;
use aegispq_api::types::{EncryptOptions, Identity, PublicIdentity};
use aegispq_core::{kdf, kem, sig};
use aegispq_protocol::file;
use aegispq_protocol::identity::IdentityId;
use aegispq_store::fs::FileStore;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("v1")
}

fn encrypted_file_dir() -> PathBuf {
    vectors_dir().join("encrypted_file")
}

fn signature_dir() -> PathBuf {
    vectors_dir().join("detached_signature")
}

// ---------------------------------------------------------------------------
// Key material serialization
// ---------------------------------------------------------------------------

/// Serialize all key material needed to decrypt a frozen encrypted file.
///
/// Format (all lengths big-endian):
/// ```text
/// [sender_identity_id: 16]
/// [sender_ed25519_pk: 32]
/// [sender_ml_dsa_pk_len: u16][sender_ml_dsa_pk]
/// [recipient_identity_id: 16]
/// [recipient_x25519_sk: 32]
/// [recipient_x25519_pk: 32]
/// [recipient_ml_kem_dk_len: u16][recipient_ml_kem_dk]
/// [recipient_ml_kem_pk_len: u16][recipient_ml_kem_pk]
/// ```
fn serialize_decrypt_keys(sender: &Identity, recipient: &Identity) -> Vec<u8> {
    let mut buf = Vec::new();

    // Sender verifying key material
    buf.extend_from_slice(&sender.identity_id);
    buf.extend_from_slice(&sender.verifying_key.classical.to_bytes());
    let ml_dsa_pk = sender.verifying_key.pq.to_bytes();
    buf.extend_from_slice(&(ml_dsa_pk.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ml_dsa_pk);

    // Recipient KEM key material
    buf.extend_from_slice(&recipient.identity_id);
    buf.extend_from_slice(&recipient.kem_keypair.classical_secret.to_bytes());
    buf.extend_from_slice(&recipient.kem_keypair.classical_public.to_bytes());
    let ml_kem_dk = recipient.kem_keypair.pq_secret.to_bytes();
    buf.extend_from_slice(&(ml_kem_dk.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ml_kem_dk);
    let ml_kem_pk = recipient.kem_keypair.pq_public.to_bytes();
    buf.extend_from_slice(&(ml_kem_pk.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ml_kem_pk);

    buf
}

/// Deserialize key material for decryption.
///
/// Returns (sender_verifying_key, recipient_identity_id, recipient_kem_keypair).
fn deserialize_decrypt_keys(
    data: &[u8],
) -> (sig::HybridVerifyingKey, IdentityId, kem::HybridKeyPair) {
    let mut pos = 0;

    // Sender identity_id (skipped for decryption, but present for documentation)
    let _sender_id: [u8; 16] = read_fixed(data, &mut pos);

    // Sender ed25519 verifying key
    let ed_pk: [u8; 32] = read_fixed(data, &mut pos);
    let classical_vk = sig::ClassicalVerifyingKey::from_bytes(&ed_pk).unwrap();

    // Sender ml_dsa verifying key
    let ml_dsa_pk = read_var(data, &mut pos);
    let pq_vk = sig::PqVerifyingKey::from_bytes(&ml_dsa_pk).unwrap();

    let sender_vk = sig::HybridVerifyingKey {
        classical: classical_vk,
        pq: pq_vk,
    };

    // Recipient identity_id
    let recipient_id: [u8; 16] = read_fixed(data, &mut pos);

    // Recipient x25519 secret key
    let x_sk: [u8; 32] = read_fixed(data, &mut pos);
    let classical_secret = kem::ClassicalSecretKey::from_bytes(x_sk);

    // Recipient x25519 public key
    let x_pk: [u8; 32] = read_fixed(data, &mut pos);
    let classical_public = kem::ClassicalPublicKey::from_bytes(x_pk);

    // Recipient ml_kem decapsulation key
    let ml_kem_dk = read_var(data, &mut pos);
    let pq_secret = kem::PqSecretKey::from_bytes(&ml_kem_dk).unwrap();

    // Recipient ml_kem encapsulation key
    let ml_kem_pk = read_var(data, &mut pos);
    let pq_public = kem::PqPublicKey::from_bytes(&ml_kem_pk).unwrap();

    assert_eq!(pos, data.len(), "trailing bytes in keys.bin");

    let kem_kp = kem::HybridKeyPair {
        classical_secret,
        classical_public,
        pq_secret,
        pq_public,
    };

    (sender_vk, recipient_id, kem_kp)
}

/// Serialize verifying key material for a frozen signature.
///
/// Format:
/// ```text
/// [ed25519_pk: 32]
/// [ml_dsa_pk_len: u16][ml_dsa_pk]
/// ```
fn serialize_verify_keys(signer: &Identity) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&signer.verifying_key.classical.to_bytes());
    let ml_dsa_pk = signer.verifying_key.pq.to_bytes();
    buf.extend_from_slice(&(ml_dsa_pk.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ml_dsa_pk);
    buf
}

/// Deserialize verifying key material for signature verification.
fn deserialize_verify_keys(data: &[u8]) -> sig::HybridVerifyingKey {
    let mut pos = 0;

    let ed_pk: [u8; 32] = read_fixed(data, &mut pos);
    let classical_vk = sig::ClassicalVerifyingKey::from_bytes(&ed_pk).unwrap();

    let ml_dsa_pk = read_var(data, &mut pos);
    let pq_vk = sig::PqVerifyingKey::from_bytes(&ml_dsa_pk).unwrap();

    assert_eq!(pos, data.len(), "trailing bytes in keys.bin");

    sig::HybridVerifyingKey {
        classical: classical_vk,
        pq: pq_vk,
    }
}

// ---------------------------------------------------------------------------
// Binary helpers
// ---------------------------------------------------------------------------

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    arr
}

fn read_var(data: &[u8], pos: &mut usize) -> Vec<u8> {
    let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    result
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

fn temp_store() -> (TempDir, FileStore) {
    let dir = TempDir::new().unwrap();
    let store = FileStore::open(dir.path()).unwrap();
    (dir, store)
}

fn fast_create(name: &str, passphrase: &[u8], store: &FileStore) -> Identity {
    identity::create_identity_with_params(name, passphrase, store, kdf::Argon2Params::testing())
        .unwrap()
}

fn to_public(ident: &Identity) -> PublicIdentity {
    PublicIdentity {
        identity_id: ident.identity_id,
        display_name: ident.display_name.clone(),
        status: ident.status,
        verifying_key: ident.verifying_key.clone(),
        kem_public: ident.kem_public.clone(),
    }
}

// =========================================================================
// Generator tests — run with `--ignored` to create/refresh fixtures
// =========================================================================

/// Generate a frozen encrypted file vector.
///
/// Creates real identities, encrypts a known plaintext with the default suite
/// (AES-256-GCM), and saves the ciphertext + key material to disk.
#[test]
#[ignore]
fn generate_encrypted_file_vector() {
    let dir = encrypted_file_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let (_tmp, store) = temp_store();
    let sender = fast_create("VectorSender", b"pass", &store);
    let recipient = fast_create("VectorRecipient", b"pass", &store);
    let recipient_public = to_public(&recipient);

    let plaintext = b"AegisPQ frozen vector: encrypted file v1";
    let options = EncryptOptions::default();

    let ciphertext =
        encrypt::encrypt_file(plaintext, &sender, &[&recipient_public], &options).unwrap();

    std::fs::write(dir.join("ciphertext.bin"), &ciphertext).unwrap();
    std::fs::write(dir.join("plaintext.bin"), plaintext).unwrap();
    std::fs::write(
        dir.join("keys.bin"),
        serialize_decrypt_keys(&sender, &recipient),
    )
    .unwrap();

    eprintln!(
        "wrote encrypted_file vector ({} bytes ciphertext) to {}",
        ciphertext.len(),
        dir.display()
    );
}

/// Generate a frozen XChaCha20-Poly1305 encrypted file vector.
#[test]
#[ignore]
fn generate_encrypted_file_xchacha_vector() {
    let dir = vectors_dir().join("encrypted_file_xchacha");
    std::fs::create_dir_all(&dir).unwrap();

    let (_tmp, store) = temp_store();
    let sender = fast_create("VectorSender", b"pass", &store);
    let recipient = fast_create("VectorRecipient", b"pass", &store);
    let recipient_public = to_public(&recipient);

    let plaintext = b"AegisPQ frozen vector: encrypted file v1 XChaCha";
    let options = EncryptOptions {
        suite: aegispq_protocol::Suite::HybridV1XChaCha,
        ..EncryptOptions::default()
    };

    let ciphertext =
        encrypt::encrypt_file(plaintext, &sender, &[&recipient_public], &options).unwrap();

    std::fs::write(dir.join("ciphertext.bin"), &ciphertext).unwrap();
    std::fs::write(dir.join("plaintext.bin"), plaintext).unwrap();
    std::fs::write(
        dir.join("keys.bin"),
        serialize_decrypt_keys(&sender, &recipient),
    )
    .unwrap();

    eprintln!(
        "wrote encrypted_file_xchacha vector ({} bytes ciphertext) to {}",
        ciphertext.len(),
        dir.display()
    );
}

/// Generate a frozen detached signature vector.
///
/// Signs a known message with real keys and saves the signature + verifying
/// key material to disk.
#[test]
#[ignore]
fn generate_detached_signature_vector() {
    let dir = signature_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let (_tmp, store) = temp_store();
    let signer = fast_create("VectorSigner", b"pass", &store);

    let message = b"AegisPQ frozen vector: detached signature v1";
    let signature = sign::sign(&signer, message).unwrap();

    std::fs::write(dir.join("message.bin"), message).unwrap();
    std::fs::write(dir.join("signature.bin"), &signature).unwrap();
    std::fs::write(dir.join("keys.bin"), serialize_verify_keys(&signer)).unwrap();

    eprintln!(
        "wrote detached_signature vector ({} bytes sig) to {}",
        signature.len(),
        dir.display()
    );
}

// =========================================================================
// Conformance tests — run normally to verify frozen vectors still work
// =========================================================================

/// Load a frozen encrypted file and verify the current code can decrypt it.
#[test]
fn encrypted_file_vector_decrypts() {
    let dir = encrypted_file_dir();
    let ciphertext = load_vector_file(&dir, "ciphertext.bin");
    let expected_plaintext = load_vector_file(&dir, "plaintext.bin");
    let keys_data = load_vector_file(&dir, "keys.bin");

    let (sender_vk, recipient_id, recipient_kp) = deserialize_decrypt_keys(&keys_data);

    let plaintext = file::decrypt(&ciphertext, &recipient_kp, &recipient_id, &sender_vk)
        .expect("frozen encrypted file must decrypt with current code");

    assert_eq!(
        plaintext, expected_plaintext,
        "decrypted plaintext does not match frozen plaintext"
    );
}

/// Load a frozen XChaCha encrypted file and verify decryption.
#[test]
fn encrypted_file_xchacha_vector_decrypts() {
    let dir = vectors_dir().join("encrypted_file_xchacha");
    let ciphertext = load_vector_file(&dir, "ciphertext.bin");
    let expected_plaintext = load_vector_file(&dir, "plaintext.bin");
    let keys_data = load_vector_file(&dir, "keys.bin");

    let (sender_vk, recipient_id, recipient_kp) = deserialize_decrypt_keys(&keys_data);

    let plaintext = file::decrypt(&ciphertext, &recipient_kp, &recipient_id, &sender_vk)
        .expect("frozen XChaCha encrypted file must decrypt with current code");

    assert_eq!(
        plaintext, expected_plaintext,
        "decrypted plaintext does not match frozen plaintext (XChaCha)"
    );
}

/// Load a frozen detached signature and verify it with current code.
#[test]
fn detached_signature_vector_verifies() {
    let dir = signature_dir();
    let message = load_vector_file(&dir, "message.bin");
    let signature = load_vector_file(&dir, "signature.bin");
    let keys_data = load_vector_file(&dir, "keys.bin");

    let verifying_key = deserialize_verify_keys(&keys_data);

    // Use core-level verify with the standalone sign domain separator.
    let sig_parsed = sig::HybridSignature::from_bytes(&signature)
        .expect("frozen signature must parse");

    sig::verify(&verifying_key, b"AegisPQ-v1-sign", &message, &sig_parsed)
        .expect("frozen signature must verify with current code");
}

/// Verify the frozen signature fails against wrong data.
#[test]
fn detached_signature_vector_rejects_wrong_message() {
    let dir = signature_dir();
    let signature = load_vector_file(&dir, "signature.bin");
    let keys_data = load_vector_file(&dir, "keys.bin");

    let verifying_key = deserialize_verify_keys(&keys_data);
    let sig_parsed = sig::HybridSignature::from_bytes(&signature).unwrap();

    let result = sig::verify(&verifying_key, b"AegisPQ-v1-sign", b"wrong message", &sig_parsed);
    assert!(
        result.is_err(),
        "frozen signature must not verify against wrong message"
    );
}

/// Verify the frozen encrypted file's envelope header is well-formed.
#[test]
fn encrypted_file_vector_header_valid() {
    let dir = encrypted_file_dir();
    let ciphertext = load_vector_file(&dir, "ciphertext.bin");

    // Must have the correct magic and format type.
    assert_eq!(&ciphertext[0..4], b"APQ\x01", "envelope magic must be APQ\\x01");
    assert_eq!(
        ciphertext[4],
        aegispq_protocol::FormatType::EncryptedFile as u8,
        "format type must be EncryptedFile"
    );

    // extract_sender_id must succeed.
    let sender_id = encrypt::extract_sender_id(&ciphertext).unwrap();
    assert_ne!(sender_id, [0u8; 16], "sender ID must not be all zeros");
}

/// Verify the frozen signature has the expected hybrid structure.
#[test]
fn detached_signature_vector_size_pinned() {
    let dir = signature_dir();
    let signature = load_vector_file(&dir, "signature.bin");

    // Hybrid signature: 2 + 64 + 2 + 3309 = 3377 bytes
    assert_eq!(
        signature.len(),
        sig::HYBRID_SIGNATURE_SIZE,
        "detached signature must be exactly {} bytes",
        sig::HYBRID_SIGNATURE_SIZE
    );
}

/// Tamper with each byte of the frozen ciphertext and ensure decryption fails
/// or produces different output.
#[test]
fn encrypted_file_vector_tamper_detected() {
    let dir = encrypted_file_dir();
    let ciphertext = load_vector_file(&dir, "ciphertext.bin");
    let expected_plaintext = load_vector_file(&dir, "plaintext.bin");
    let keys_data = load_vector_file(&dir, "keys.bin");
    let (sender_vk, recipient_id, recipient_kp) = deserialize_decrypt_keys(&keys_data);

    // Tamper each byte in the payload (past the 12-byte header) and verify
    // that decryption either fails or produces different plaintext.
    // Test a sample of bytes to keep runtime reasonable.
    let header_size = 12;
    let step = std::cmp::max(1, (ciphertext.len() - header_size) / 200);
    for i in (header_size..ciphertext.len()).step_by(step) {
        let mut tampered = ciphertext.clone();
        tampered[i] ^= 0xFF;

        match file::decrypt(&tampered, &recipient_kp, &recipient_id, &sender_vk) {
            Err(_) => {} // expected
            Ok(pt) => {
                assert_ne!(
                    pt, expected_plaintext,
                    "tamper at byte {i} was not detected"
                );
            }
        }
    }
}

// =========================================================================
// Generic conformance runner — verifies all vectors from disk
// =========================================================================

/// Scan the vectors directory and verify every frozen vector.
///
/// This test acts as a conformance runner: it discovers vector directories
/// on disk and applies the appropriate verification logic. New vector types
/// can be added by creating a directory with the right files and extending
/// the match arm below.
#[test]
fn conformance_runner_all_vectors() {
    let base = vectors_dir();
    if !base.exists() {
        panic!(
            "vectors directory not found at {}. Run with --ignored to generate.",
            base.display()
        );
    }

    let mut tested = 0;

    for entry in std::fs::read_dir(&base).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = path.file_name().unwrap().to_str().unwrap();

        if name.starts_with("encrypted_file") {
            verify_encrypted_file_vector(&path);
            tested += 1;
        } else if name.starts_with("detached_signature") {
            verify_signature_vector(&path);
            tested += 1;
        }
        // Future: add more vector types here.
    }

    assert!(tested > 0, "no vectors found to test");
    eprintln!("conformance runner: {tested} vector(s) verified");
}

/// Verify a single encrypted file vector directory.
fn verify_encrypted_file_vector(dir: &std::path::Path) {
    let ciphertext = std::fs::read(dir.join("ciphertext.bin"))
        .unwrap_or_else(|_| panic!("missing ciphertext.bin in {}", dir.display()));
    let expected = std::fs::read(dir.join("plaintext.bin"))
        .unwrap_or_else(|_| panic!("missing plaintext.bin in {}", dir.display()));
    let keys_data = std::fs::read(dir.join("keys.bin"))
        .unwrap_or_else(|_| panic!("missing keys.bin in {}", dir.display()));

    let (sender_vk, recipient_id, recipient_kp) = deserialize_decrypt_keys(&keys_data);

    let plaintext = file::decrypt(&ciphertext, &recipient_kp, &recipient_id, &sender_vk)
        .unwrap_or_else(|e| {
            panic!(
                "failed to decrypt vector in {}: {e}",
                dir.display()
            )
        });

    assert_eq!(
        plaintext, expected,
        "plaintext mismatch in vector {}",
        dir.display()
    );
}

/// Verify a single detached signature vector directory.
fn verify_signature_vector(dir: &std::path::Path) {
    let message = std::fs::read(dir.join("message.bin"))
        .unwrap_or_else(|_| panic!("missing message.bin in {}", dir.display()));
    let signature_bytes = std::fs::read(dir.join("signature.bin"))
        .unwrap_or_else(|_| panic!("missing signature.bin in {}", dir.display()));
    let keys_data = std::fs::read(dir.join("keys.bin"))
        .unwrap_or_else(|_| panic!("missing keys.bin in {}", dir.display()));

    let verifying_key = deserialize_verify_keys(&keys_data);
    let sig_parsed = sig::HybridSignature::from_bytes(&signature_bytes)
        .unwrap_or_else(|e| {
            panic!(
                "failed to parse signature in {}: {e}",
                dir.display()
            )
        });

    sig::verify(&verifying_key, b"AegisPQ-v1-sign", &message, &sig_parsed)
        .unwrap_or_else(|e| {
            panic!(
                "signature verification failed in {}: {e}",
                dir.display()
            )
        });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_vector_file(dir: &std::path::Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    std::fs::read(&path).unwrap_or_else(|_| {
        panic!(
            "frozen vector not found at {}. Run with --ignored to generate.",
            path.display()
        )
    })
}
