//! # aegispq-api
//!
//! Public, misuse-resistant API for the AegisPQ encryption platform.
//!
//! This crate exposes a small, type-safe surface for identity management,
//! encryption/decryption, signing/verification, and key lifecycle operations.
//! Internal crypto details are not exposed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod encrypt;
pub mod error;
pub mod identity;
pub mod sign;
pub mod types;

/// Re-export core types that appear in the public API.
pub use aegispq_core::aead::Algorithm as SymmetricAlgorithm;
pub use aegispq_protocol::padding::PaddingScheme;
pub use aegispq_protocol::revocation::RevocationReason;
pub use aegispq_protocol::Suite;
pub use aegispq_store::record::IdentityStatus;
