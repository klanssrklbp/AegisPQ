//! Public API error types.
//!
//! These errors are safe to display to users and log. They never
//! contain key material, plaintext, or sensitive file paths.

use thiserror::Error;

/// Errors produced by AegisPQ public API operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The passphrase was incorrect.
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Ciphertext or signature authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Data integrity check failed.
    #[error("integrity error")]
    IntegrityError {
        /// Index of the corrupted chunk, if applicable.
        chunk_index: Option<u32>,
    },

    /// Protocol version not supported.
    #[error("unsupported version: found {found}, max supported {max_supported}")]
    UnsupportedVersion {
        /// The version found in the data.
        found: u16,
        /// The maximum version this build supports.
        max_supported: u16,
    },

    /// Algorithm suite not supported.
    #[error("unsupported suite: {found:#04x}")]
    UnsupportedSuite {
        /// The suite identifier found in the data.
        found: u8,
    },

    /// The local identity is not a recipient of this ciphertext.
    #[error("not a recipient of this ciphertext")]
    NotARecipient,

    /// The identity has been revoked and cannot be used for this operation.
    #[error("identity revoked: {identity_id}")]
    IdentityRevoked {
        /// Hex-encoded identity ID.
        identity_id: String,
    },

    /// The key has exceeded its usage limit and must be rotated.
    #[error("key exhausted — rotation required")]
    KeyExhausted,

    /// Storage I/O error.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Input exceeds maximum size.
    #[error("input too large: max {max_bytes} bytes")]
    InputTooLarge {
        /// Maximum allowed input size.
        max_bytes: u64,
    },

    /// File I/O error (used by path-based convenience APIs).
    #[error("I/O error: {context}")]
    IoError {
        /// What was being done when the error occurred.
        context: &'static str,
    },

    /// Key material is invalid or corrupted (wrong length, parse failure, etc.).
    #[error("invalid key material: {context}")]
    InvalidKeyMaterial {
        /// Which key or record failed to parse.
        context: &'static str,
    },

    /// Input data is truncated (too short for the expected structure).
    #[error("truncated input")]
    TruncatedInput,

    /// Invalid magic bytes — not an AegisPQ file.
    #[error("not an AegisPQ file (invalid magic bytes)")]
    InvalidFormat,

    /// Unknown format type in the envelope header.
    #[error("unknown format type: {found:#04x}")]
    UnknownFormat {
        /// Format type byte found in the data.
        found: u8,
    },

    /// Payload contains unexpected trailing bytes.
    #[error("trailing data after payload")]
    TrailingData,

    /// Too many recipients in the encrypted file.
    #[error("too many recipients: {count} (max {max})")]
    TooManyRecipients {
        /// Number of recipients specified.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Internal error (should not occur; indicates a bug).
    #[deprecated(note = "All uses have been replaced with specific variants. Will be removed in 0.2.")]
    #[error("internal error")]
    Internal,

    /// Cryptographic core error.
    #[error(transparent)]
    Core(#[from] aegispq_core::CoreError),
}

impl From<aegispq_protocol::error::ProtocolError> for Error {
    fn from(e: aegispq_protocol::error::ProtocolError) -> Self {
        use aegispq_protocol::error::ProtocolError;
        match e {
            ProtocolError::UnsupportedVersion {
                found,
                max_supported,
            } => Error::UnsupportedVersion {
                found,
                max_supported,
            },
            ProtocolError::UnsupportedSuite { found } => Error::UnsupportedSuite { found },
            ProtocolError::NotARecipient => Error::NotARecipient,
            ProtocolError::AuthenticationFailed => Error::AuthenticationFailed,
            ProtocolError::IntegrityError { chunk_index } => Error::IntegrityError {
                chunk_index: Some(chunk_index),
            },
            ProtocolError::PayloadTooLarge { max, .. } => Error::InputTooLarge { max_bytes: max },
            ProtocolError::Crypto(e) => Error::Core(e),
            ProtocolError::InvalidMagic => Error::InvalidFormat,
            ProtocolError::UnknownFormat { found } => Error::UnknownFormat { found },
            ProtocolError::Truncated { .. } => Error::TruncatedInput,
            ProtocolError::TrailingData { .. } => Error::TrailingData,
            ProtocolError::IoError { kind, message } => {
                Error::StorageError(format!("I/O error ({kind}): {message}"))
            }
            ProtocolError::TooManyRecipients { count, max } => {
                Error::TooManyRecipients { count, max }
            }
        }
    }
}
