//! Core API types.

use aegispq_core::{kem, sig};
use aegispq_protocol::identity::{Fingerprint, IdentityId};
use aegispq_store::record::IdentityStatus;

/// A local identity with unlocked key material.
///
/// Created by [`crate::identity::create_identity`] or [`crate::identity::load_identity`].
pub struct Identity {
    /// 16-byte identity identifier.
    pub identity_id: IdentityId,
    /// Human-readable display name.
    pub display_name: String,
    /// Current status (Active, Rotated, or Revoked).
    pub status: IdentityStatus,
    /// Hybrid signing key (Ed25519 + ML-DSA-65).
    pub signing_key: sig::HybridSigningKey,
    /// Hybrid verifying key (Ed25519 + ML-DSA-65).
    pub verifying_key: sig::HybridVerifyingKey,
    /// Hybrid KEM key pair (X25519 + ML-KEM-768).
    pub kem_keypair: kem::HybridKeyPair,
    /// Hybrid KEM public key.
    pub kem_public: kem::HybridPublicKey,
}

impl Identity {
    /// Compute the fingerprint of this identity.
    pub fn fingerprint(&self) -> Fingerprint {
        aegispq_protocol::identity::compute_fingerprint(
            &self.verifying_key.classical.to_bytes(),
            &self.verifying_key.pq.to_bytes(),
            &self.kem_public.classical.to_bytes(),
            &self.kem_public.pq.to_bytes(),
        )
    }
}

/// A remote party's public identity (contact).
#[derive(Clone)]
pub struct PublicIdentity {
    /// 16-byte identity identifier.
    pub identity_id: IdentityId,
    /// Human-readable display name.
    pub display_name: String,
    /// Current status (Active, Rotated, or Revoked).
    pub status: IdentityStatus,
    /// Hybrid verifying key (Ed25519 + ML-DSA-65).
    pub verifying_key: sig::HybridVerifyingKey,
    /// Hybrid KEM public key (X25519 + ML-KEM-768).
    pub kem_public: kem::HybridPublicKey,
}

impl PublicIdentity {
    /// Compute the fingerprint of this identity.
    pub fn fingerprint(&self) -> Fingerprint {
        aegispq_protocol::identity::compute_fingerprint(
            &self.verifying_key.classical.to_bytes(),
            &self.verifying_key.pq.to_bytes(),
            &self.kem_public.classical.to_bytes(),
            &self.kem_public.pq.to_bytes(),
        )
    }
}

/// Options for file encryption.
pub struct EncryptOptions {
    /// Padding scheme. Default: PowerOfTwo.
    pub padding: aegispq_protocol::padding::PaddingScheme,
    /// Chunk size in bytes (0 = default 1 MiB).
    pub chunk_size: u32,
    /// Algorithm suite.
    pub suite: aegispq_protocol::Suite,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            padding: aegispq_protocol::padding::PaddingScheme::PowerOfTwo,
            chunk_size: 0,
            suite: aegispq_protocol::Suite::HybridV1,
        }
    }
}

/// Result of a file decryption.
pub struct DecryptedFile {
    /// The recovered plaintext.
    pub plaintext: Vec<u8>,
    /// The sender's identity ID from the file header.
    pub sender_identity_id: IdentityId,
}
