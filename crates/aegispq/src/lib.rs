//! # AegisPQ
//!
//! Post-quantum-ready hybrid encryption library for Rust.
//!
//! AegisPQ provides identity management, authenticated file encryption, and
//! hybrid digital signatures built on classical (X25519, Ed25519, AES-256-GCM)
//! and post-quantum (ML-KEM-768, ML-DSA-65) primitives.
//!
//! ## Quick start
//!
//! ```no_run
//! use aegispq::prelude::*;
//! use aegispq::store::FileStore;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open a store (creates the directory tree on first use).
//! let store = FileStore::open("/tmp/aegispq-demo")?;
//!
//! // Create an identity protected by a passphrase.
//! let alice = aegispq::identity::create_identity("Alice", b"strong-passphrase", &store)?;
//! println!("Created: {} ({})", alice.display_name, alice.fingerprint());
//!
//! // Export a key package for distribution.
//! let pkg = aegispq::identity::export_key_package(&alice)?;
//! std::fs::write("alice.pub.apq", &pkg)?;
//!
//! // Encrypt a file for one or more recipients.
//! let bob = aegispq::identity::import_key_package(&std::fs::read("bob.pub.apq")?, &store)?;
//! let options = EncryptOptions::default();
//! let ciphertext = aegispq::encrypt::encrypt_file(
//!     b"secret message",
//!     &alice,
//!     &[&bob],
//!     &options,
//! )?;
//!
//! // Sign arbitrary data.
//! let sig = aegispq::sign::sign(&alice, b"important document")?;
//! let valid = aegispq::sign::verify(&bob, b"important document", &sig)?;
//! assert!(valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Crate structure
//!
//! This crate re-exports the full public API from the internal workspace crates,
//! split into two tiers:
//!
//! ### Stable high-level API (recommended)
//!
//! These modules form the **stable public surface**. Breaking changes here
//! will follow semver and be called out in the changelog.
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`identity`] | Create, load, export, import, revoke, and rotate identities |
//! | [`encrypt`] | File encryption and decryption (in-memory, streaming, path-based) |
//! | [`sign`] | Standalone hybrid signing and verification |
//! | [`types`] | Core data types (`Identity`, `PublicIdentity`, `EncryptOptions`) |
//! | [`error`] | Error types |
//! | [`store`] | Filesystem-backed encrypted storage (`FileStore`) |
//!
//! For common workflows, prefer the path-based helpers in [`encrypt`]:
//! [`encrypt::encrypt_file_to_path`] and [`encrypt::decrypt_file_to_path`].
//! The latter bakes in a temp-file-then-rename pattern that guarantees no
//! unauthenticated plaintext ever appears at the destination path.
//!
//! ### Advanced / low-level API
//!
//! These modules expose protocol types and raw cryptographic primitives for
//! advanced use. They are **not part of the stable API** — their shape may
//! change without a major version bump if the protocol evolves. Prefer the
//! stable modules above unless you have a specific reason (custom storage,
//! embedded use, interop with another implementation).
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`protocol`] | Low-level protocol types (envelope, padding, certificates) |
//! | [`core`] | Raw cryptographic primitives (KEM, signatures, AEAD, KDF) |
//!
//! Most users only need [`prelude`] plus the stable modules.
//!
//! ## Security properties
//!
//! - **Hybrid construction:** Every asymmetric operation combines a classical and
//!   post-quantum algorithm. An attacker must break *both* to compromise security.
//! - **Authenticated encryption:** All ciphertext is AEAD-protected (AES-256-GCM or
//!   XChaCha20-Poly1305) with per-chunk integrity tags.
//! - **Sender authentication:** Encrypted files carry a hybrid signature (Ed25519 +
//!   ML-DSA-65) over the complete ciphertext.
//! - **Key lifecycle:** Identities support revocation and rotation with
//!   cryptographically signed certificates.
//! - **No unsafe code:** The entire crate tree is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Re-export the public API
// ---------------------------------------------------------------------------

/// Identity management: creation, loading, export/import, revocation, rotation.
pub use aegispq_api::identity;

/// File encryption and decryption (in-memory and streaming).
pub use aegispq_api::encrypt;

/// Standalone hybrid signing and verification.
pub use aegispq_api::sign;

/// Core API data types.
pub use aegispq_api::types;

/// Error types for public API operations.
pub use aegispq_api::error;

/// Filesystem-backed encrypted storage.
pub mod store {
    pub use aegispq_store::fs::FileStore;
    pub use aegispq_store::record::{ContactRecord, IdentityRecord, IdentityStatus};
    pub use aegispq_store::error::StoreError;
}

/// Low-level protocol types.
///
/// **Stability: unstable.** These types mirror the on-wire protocol and may
/// change if the protocol version is bumped. Prefer the stable high-level
/// API ([`identity`], [`encrypt`], [`sign`]) unless you are building custom
/// storage backends, interop tooling, or another protocol implementation.
pub mod protocol {
    pub use aegispq_protocol::FormatType;
    pub use aegispq_protocol::Suite;
    pub use aegispq_protocol::envelope::{Header, HEADER_SIZE};
    pub use aegispq_protocol::error::ProtocolError;
    pub use aegispq_protocol::file::{RecipientInfo, FILE_ID_LEN};
    pub use aegispq_protocol::identity::{
        Fingerprint, IdentityId, IDENTITY_ID_LEN, KeyPackage,
    };
    pub use aegispq_protocol::padding::PaddingScheme;
    pub use aegispq_protocol::revocation::{RevocationCertificate, RevocationReason};
    pub use aegispq_protocol::rotation::RotationCertificate;
    pub use aegispq_protocol::version;
}

/// Cryptographic primitives.
///
/// **Stability: unstable.** These modules expose raw KEM, signature, AEAD,
/// and KDF operations. Their APIs may change as upstream crates evolve
/// (e.g., algorithm parameter types, key representations).
///
/// Most users should prefer the higher-level [`encrypt`], [`sign`], and
/// [`identity`] modules. Use this module only if you need direct access to
/// the cryptographic building blocks (e.g., custom protocol construction,
/// benchmarking, or algorithm-level testing).
pub mod core {
    pub use aegispq_core::aead;
    pub use aegispq_core::hash;
    pub use aegispq_core::kdf;
    pub use aegispq_core::kem;
    pub use aegispq_core::nonce;
    pub use aegispq_core::sig;
    pub use aegispq_core::CoreError;
}

/// Convenience re-exports for common use.
///
/// ```
/// use aegispq::prelude::*;
/// ```
pub mod prelude {
    pub use crate::error::Error;
    pub use crate::types::{DecryptedFile, EncryptOptions, Identity, PublicIdentity};

    pub use aegispq_protocol::Suite;
    pub use aegispq_protocol::padding::PaddingScheme;
    pub use aegispq_protocol::revocation::RevocationReason;
    pub use aegispq_store::record::IdentityStatus;
}
