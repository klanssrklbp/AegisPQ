//! File encryption and decryption.
//!
//! Wraps the protocol-layer file encryption with the API's type-safe
//! `Identity` / `PublicIdentity` types, and provides a store-integrated
//! decryption path that automatically resolves the sender.

use aegispq_protocol::envelope::{Header, HEADER_SIZE};
use aegispq_protocol::file::{self, RecipientInfo, FILE_ID_LEN};
use aegispq_protocol::identity::{IdentityId, IDENTITY_ID_LEN};
use aegispq_store::fs::FileStore;
use aegispq_store::record::IdentityStatus;

use crate::error::Error;
use crate::types::{DecryptedFile, EncryptOptions, Identity, PublicIdentity};

/// Encrypt a file for one or more recipients.
///
/// Returns the complete binary-encoded encrypted file (envelope header + payload).
///
/// The sender's hybrid signing key is used to authenticate the ciphertext.
/// Each recipient gets an independent KEM slot; compromising one recipient's
/// key does not help attack another's.
pub fn encrypt_file(
    plaintext: &[u8],
    sender: &Identity,
    recipients: &[&PublicIdentity],
    options: &EncryptOptions,
) -> Result<Vec<u8>, Error> {
    // Enforce lifecycle: only Active identities may encrypt.
    if sender.status != IdentityStatus::Active {
        return Err(crate::identity::revoked_error(&sender.identity_id));
    }
    for r in recipients {
        if r.status != IdentityStatus::Active {
            return Err(crate::identity::revoked_error(&r.identity_id));
        }
    }

    let recipient_infos: Vec<RecipientInfo> = recipients
        .iter()
        .map(|r| RecipientInfo {
            identity_id: r.identity_id,
            kem_public_key: r.kem_public.clone(),
        })
        .collect();

    let ciphertext = file::encrypt(
        plaintext,
        &sender.signing_key,
        &sender.identity_id,
        &recipient_infos,
        options.suite,
        options.padding,
        options.chunk_size,
    )?;

    Ok(ciphertext)
}

/// Decrypt a file, looking up the sender's public key from the contact store.
///
/// 1. Extracts the sender's identity ID from the ciphertext header.
/// 2. Loads the sender's public identity from the store.
/// 3. Verifies the sender's signature **before** any decryption.
/// 4. Decrypts and returns the plaintext along with the sender identity ID.
pub fn decrypt_file(
    ciphertext: &[u8],
    recipient: &Identity,
    store: &FileStore,
) -> Result<DecryptedFile, Error> {
    let sender_id = extract_sender_id(ciphertext)?;
    let sender = crate::identity::load_contact(&sender_id, store)?;

    let plaintext = file::decrypt(
        ciphertext,
        &recipient.kem_keypair,
        &recipient.identity_id,
        &sender.verifying_key,
    )?;

    Ok(DecryptedFile {
        plaintext,
        sender_identity_id: sender_id,
    })
}

/// Decrypt a file when the sender's public identity is already known.
///
/// Use this when the caller has already resolved the sender (e.g., from a
/// previous call to [`extract_sender_id`] + manual lookup), or when the
/// sender is not in the local contact store.
pub fn decrypt_file_with_sender(
    ciphertext: &[u8],
    recipient: &Identity,
    sender: &PublicIdentity,
) -> Result<DecryptedFile, Error> {
    let plaintext = file::decrypt(
        ciphertext,
        &recipient.kem_keypair,
        &recipient.identity_id,
        &sender.verifying_key,
    )?;

    Ok(DecryptedFile {
        plaintext,
        sender_identity_id: sender.identity_id,
    })
}

// ---------------------------------------------------------------------------
// Streaming API
// ---------------------------------------------------------------------------

/// Encrypt a file using streaming I/O.
///
/// Reads plaintext from `input` and writes the encrypted file to `output`.
/// `input_size` must be the exact number of plaintext bytes that will be read.
///
/// Memory usage is O(chunk_size) rather than O(file_size).
pub fn encrypt_file_stream<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    input_size: u64,
    sender: &Identity,
    recipients: &[&PublicIdentity],
    options: &EncryptOptions,
) -> Result<(), Error> {
    if sender.status != IdentityStatus::Active {
        return Err(crate::identity::revoked_error(&sender.identity_id));
    }
    for r in recipients {
        if r.status != IdentityStatus::Active {
            return Err(crate::identity::revoked_error(&r.identity_id));
        }
    }

    let recipient_infos: Vec<RecipientInfo> = recipients
        .iter()
        .map(|r| RecipientInfo {
            identity_id: r.identity_id,
            kem_public_key: r.kem_public.clone(),
        })
        .collect();

    file::encrypt_stream(
        input,
        output,
        input_size,
        &sender.signing_key,
        &sender.identity_id,
        &recipient_infos,
        options.suite,
        options.padding,
        options.chunk_size,
    )?;

    Ok(())
}

/// Decrypt a file using streaming I/O with a known sender.
///
/// Reads the encrypted file from `input` and writes recovered plaintext to `output`.
/// Returns the number of plaintext bytes written.
///
/// **Security note:** Per-chunk AEAD tags are verified during streaming, but the
/// sender signature is verified at the end. If signature verification fails, the
/// caller should discard any output written so far.
pub fn decrypt_file_stream<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    recipient: &Identity,
    sender: &PublicIdentity,
) -> Result<u64, Error> {
    let bytes = file::decrypt_stream(
        input,
        output,
        &recipient.kem_keypair,
        &recipient.identity_id,
        &sender.verifying_key,
    )?;
    Ok(bytes)
}

/// Decrypt a file using streaming I/O with signature-before-output guarantee.
///
/// Unlike [`decrypt_file_stream`], this function buffers all decrypted output
/// in memory and only returns it after the sender signature has been verified.
/// No plaintext is exposed to the caller on authentication failure.
///
/// Use this when you cannot tolerate unauthenticated plaintext being written
/// to disk (e.g., CLI tools, automated pipelines).
pub fn decrypt_file_stream_verified<R: std::io::Read>(
    input: &mut R,
    recipient: &Identity,
    sender: &PublicIdentity,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    file::decrypt_stream(
        input,
        &mut buf,
        &recipient.kem_keypair,
        &recipient.identity_id,
        &sender.verifying_key,
    )?;
    // If we reach here, signature verification passed.
    Ok(buf)
}

/// Decrypt a file using streaming I/O, looking up the sender from the store.
///
/// Extracts the sender ID from the first bytes of the stream, loads the sender's
/// public key from the store, then streams decryption. Because the sender ID must
/// be read before decryption begins, this function buffers the envelope header
/// internally (a few bytes) but streams the payload.
pub fn decrypt_file_stream_with_store<W: std::io::Write>(
    ciphertext: &[u8],
    output: &mut W,
    recipient: &Identity,
    store: &FileStore,
) -> Result<(u64, IdentityId), Error> {
    let sender_id = extract_sender_id(ciphertext)?;
    let sender = crate::identity::load_contact(&sender_id, store)?;

    let mut reader = &ciphertext[..];
    let bytes = file::decrypt_stream(
        &mut reader,
        output,
        &recipient.kem_keypair,
        &recipient.identity_id,
        &sender.verifying_key,
    )?;
    Ok((bytes, sender_id))
}

// ---------------------------------------------------------------------------
// Path-based convenience APIs
// ---------------------------------------------------------------------------

/// Encrypt a file from one path to another using streaming I/O.
///
/// This is a thin wrapper around [`encrypt_file_stream`] that handles opening
/// the input and output files. Memory usage is O(chunk_size), not O(file_size),
/// so it is safe for files larger than RAM.
///
/// The output is written in place at `output_path`. If encryption fails
/// partway through, a partial output file may be left on disk; callers who
/// need stricter semantics should encrypt to a temp path and rename.
pub fn encrypt_file_to_path(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    sender: &Identity,
    recipients: &[&PublicIdentity],
    options: &EncryptOptions,
) -> Result<(), Error> {
    let input_size = std::fs::metadata(input_path)
        .map_err(|_| Error::IoError { context: "reading input file metadata" })?
        .len();
    let mut input = std::fs::File::open(input_path)
        .map_err(|_| Error::IoError { context: "opening input file" })?;
    let mut output = std::fs::File::create(output_path)
        .map_err(|_| Error::IoError { context: "creating output file" })?;

    encrypt_file_stream(&mut input, &mut output, input_size, sender, recipients, options)?;

    use std::io::Write;
    output.flush().map_err(|_| Error::IoError { context: "flushing output file" })?;
    Ok(())
}

/// Decrypt a file from one path to another with the safe temp-file pattern baked in.
///
/// This is the recommended high-level API for decrypting files on disk. It:
///
/// 1. Reads the ciphertext from `ciphertext_path`.
/// 2. Resolves the sender's public identity from `store` via the file header.
/// 3. Streams decryption to a sibling temp file (`<output>.aegispq-tmp-<pid>`).
/// 4. Verifies the sender signature.
/// 5. On success: atomically renames the temp file to `output_path`.
/// 6. On any failure: deletes the temp file, so no unauthenticated plaintext
///    is ever exposed at `output_path`.
///
/// Returns the sender's identity ID and the number of plaintext bytes written.
pub fn decrypt_file_to_path(
    ciphertext_path: &std::path::Path,
    output_path: &std::path::Path,
    recipient: &Identity,
    store: &FileStore,
) -> Result<(IdentityId, u64), Error> {
    let ciphertext = std::fs::read(ciphertext_path)
        .map_err(|_| Error::IoError { context: "reading ciphertext file" })?;

    let out_dir = output_path.parent().unwrap_or(std::path::Path::new("."));
    let temp_name = format!(".aegispq-dec-{}.tmp", std::process::id());
    let temp_path = out_dir.join(&temp_name);

    let result = {
        let mut temp_file = std::fs::File::create(&temp_path)
            .map_err(|_| Error::IoError { context: "creating temp file for decryption" })?;
        let r = decrypt_file_stream_with_store(&ciphertext, &mut temp_file, recipient, store);
        if r.is_ok() {
            use std::io::Write;
            let _ = temp_file.flush();
            let _ = temp_file.sync_all();
        }
        r
    };

    match result {
        Ok((bytes, sender_id)) => {
            std::fs::rename(&temp_path, output_path).map_err(|_| {
                let _ = std::fs::remove_file(&temp_path);
                Error::IoError { context: "renaming decrypted temp file to output" }
            })?;
            Ok((sender_id, bytes))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&temp_path);
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Extract the sender's identity ID from an encrypted file without decrypting.
///
/// Validates the envelope header but does not verify the signature or decrypt
/// any data. Useful for determining who sent a file before loading their
/// public key from the store.
pub fn extract_sender_id(ciphertext: &[u8]) -> Result<IdentityId, Error> {
    let _header = Header::from_bytes(ciphertext)?;

    let offset = HEADER_SIZE + FILE_ID_LEN;
    if ciphertext.len() < offset + IDENTITY_ID_LEN {
        return Err(Error::TruncatedInput);
    }

    let mut id = [0u8; IDENTITY_ID_LEN];
    id.copy_from_slice(&ciphertext[offset..offset + IDENTITY_ID_LEN]);
    Ok(id)
}
