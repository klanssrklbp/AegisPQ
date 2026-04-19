//! Protocol-layer error types.

use thiserror::Error;

/// Errors from protocol operations.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Invalid magic bytes — not an AegisPQ file.
    #[error("invalid magic bytes: not an AegisPQ file")]
    InvalidMagic,

    /// Unsupported protocol version.
    #[error("unsupported protocol version: {found} (max supported: {max_supported})")]
    UnsupportedVersion {
        /// Version found in the data.
        found: u16,
        /// Maximum version this build supports.
        max_supported: u16,
    },

    /// Unsupported algorithm suite.
    #[error("unsupported suite: {found:#04x}")]
    UnsupportedSuite {
        /// Suite ID found in the data.
        found: u8,
    },

    /// Unknown format type.
    #[error("unknown format type: {found:#04x}")]
    UnknownFormat {
        /// Format type byte found in the data.
        found: u8,
    },

    /// Data is truncated or malformed.
    #[error("truncated data: expected at least {expected} bytes, got {actual}")]
    Truncated {
        /// Minimum expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },

    /// The local identity is not a recipient of this ciphertext.
    #[error("not a recipient of this ciphertext")]
    NotARecipient,

    /// Sender signature verification failed.
    #[error("sender authentication failed")]
    AuthenticationFailed,

    /// A chunk failed AEAD verification.
    #[error("integrity error at chunk {chunk_index}")]
    IntegrityError {
        /// Index of the corrupted chunk.
        chunk_index: u32,
    },

    /// Too many recipients.
    #[error("too many recipients: {count} (max {max})")]
    TooManyRecipients {
        /// Number of recipients specified.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Payload exceeds maximum size.
    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge {
        /// Actual size.
        size: u64,
        /// Maximum allowed.
        max: u64,
    },

    /// Payload contains trailing bytes beyond the expected end.
    #[error("trailing data: expected {expected} bytes, got {actual}")]
    TrailingData {
        /// Expected total length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// I/O error during streaming operation.
    #[error("I/O error ({kind}): {message}")]
    IoError {
        /// The [`std::io::ErrorKind`] as a string.
        kind: String,
        /// Human-readable description.
        message: String,
    },

    /// Underlying cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] aegispq_core::CoreError),
}
