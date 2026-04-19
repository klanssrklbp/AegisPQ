//! Storage-layer error types.

use thiserror::Error;

/// Errors from storage operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Identity not found in the store.
    #[error("identity not found: {identity_id}")]
    IdentityNotFound {
        /// Hex-encoded identity ID.
        identity_id: String,
    },

    /// Contact not found in the store.
    #[error("contact not found: {identity_id}")]
    ContactNotFound {
        /// Hex-encoded identity ID.
        identity_id: String,
    },

    /// The passphrase was incorrect (AEAD tag verification failed).
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// The stored record is corrupt or has an unrecognized format.
    #[error("corrupt record: {reason}")]
    CorruptRecord {
        /// Human-readable explanation (never contains secrets).
        reason: &'static str,
    },

    /// Filesystem I/O error. The message never contains file paths.
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] aegispq_core::CoreError),
}
