//! # aegispq-protocol
//!
//! Protocol layer for the AegisPQ platform.
//!
//! Handles envelope construction/parsing, identity operations,
//! file encryption protocol, padding, and version negotiation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod envelope;
pub mod error;
pub mod file;
pub mod identity;
pub mod padding;
pub mod revocation;
pub mod rotation;

/// Protocol version constants.
pub mod version {
    /// Current protocol version.
    pub const CURRENT: u16 = 1;
    /// Minimum supported protocol version.
    pub const MIN_SUPPORTED: u16 = 1;
}

/// Magic bytes for AegisPQ data objects: `APQ\x01`.
pub const MAGIC: [u8; 4] = [0x41, 0x50, 0x51, 0x01];

/// Format type identifiers.
///
/// This enum is `#[non_exhaustive]` — new format types may be added in future
/// versions without a semver-breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum FormatType {
    /// Encrypted file.
    EncryptedFile = 0x01,
    /// Key package (public identity export).
    KeyPackage = 0x02,
    /// Session message (reserved — not yet implemented).
    SessionMessage = 0x03,
    /// Revocation certificate.
    RevocationCertificate = 0x04,
    /// Rotation certificate.
    RotationCertificate = 0x05,
    /// Recovery blob (reserved — not yet implemented).
    RecoveryBlob = 0x06,
    /// Signed document (reserved — not yet implemented).
    SignedDocument = 0x07,
}

impl FormatType {
    /// Parse from a byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::EncryptedFile),
            0x02 => Some(Self::KeyPackage),
            0x03 => Some(Self::SessionMessage),
            0x04 => Some(Self::RevocationCertificate),
            0x05 => Some(Self::RotationCertificate),
            0x06 => Some(Self::RecoveryBlob),
            0x07 => Some(Self::SignedDocument),
            _ => None,
        }
    }
}

/// Suite identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Suite {
    /// X25519+ML-KEM-768, Ed25519+ML-DSA-65, AES-256-GCM.
    HybridV1 = 0x01,
    /// Same as HybridV1 but with XChaCha20-Poly1305 for symmetric encryption.
    HybridV1XChaCha = 0x02,
}

impl Suite {
    /// Parse from a byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::HybridV1),
            0x02 => Some(Self::HybridV1XChaCha),
            _ => None,
        }
    }

    /// Get the symmetric algorithm for this suite.
    pub fn symmetric_algorithm(self) -> aegispq_core::aead::Algorithm {
        match self {
            Suite::HybridV1 => aegispq_core::aead::Algorithm::Aes256Gcm,
            Suite::HybridV1XChaCha => aegispq_core::aead::Algorithm::XChaCha20Poly1305,
        }
    }
}
