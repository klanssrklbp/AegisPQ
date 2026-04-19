//! Error types for the cryptographic core.
//!
//! Errors never contain key material, plaintext, or sensitive context.
//! All error messages are safe to log.

use thiserror::Error;

/// Errors produced by cryptographic operations.
///
/// These errors are intentionally opaque about internal state to avoid
/// leaking information through error messages.
#[derive(Debug, Error)]
pub enum CoreError {
    /// AEAD encryption failed (internal error — should not occur with valid inputs).
    #[error("AEAD encryption failed")]
    AeadEncryptionFailed,

    /// AEAD decryption failed: ciphertext is corrupted or the key/nonce/AAD is wrong.
    #[error("AEAD decryption failed: authentication tag mismatch")]
    AeadDecryptionFailed,

    /// The provided key has an invalid length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length in bytes.
        actual: usize,
    },

    /// The provided nonce has an invalid length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length in bytes.
        actual: usize,
    },

    /// KEM encapsulation failed.
    #[error("KEM encapsulation failed")]
    KemEncapsulationFailed,

    /// KEM decapsulation failed.
    #[error("KEM decapsulation failed")]
    KemDecapsulationFailed,

    /// Signature creation failed.
    #[error("signature creation failed")]
    SignatureCreationFailed,

    /// Signature verification failed — the signature is invalid.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Key derivation failed.
    #[error("key derivation failed")]
    KdfError,

    /// The nonce counter has been exhausted for this key. The key must be rotated.
    #[error("nonce counter exhausted — key rotation required")]
    NonceExhausted,

    /// The system entropy source is unavailable.
    #[error("entropy source unavailable")]
    EntropyError,

    /// Input data exceeds the maximum allowed size.
    #[error("input too large: maximum {max_bytes} bytes")]
    InputTooLarge {
        /// Maximum allowed size in bytes.
        max_bytes: u64,
    },

    /// An invalid parameter was provided.
    #[error("invalid parameter: {reason}")]
    InvalidParameter {
        /// Static description of why the parameter is invalid.
        reason: &'static str,
    },
}
