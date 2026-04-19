//! # aegispq-core
//!
//! Cryptographic core for the AegisPQ platform.
//!
//! This crate provides thin, misuse-resistant wrappers around audited
//! cryptographic primitives. It contains no business logic, no I/O,
//! and no unsafe code.
//!
//! ## Design constraints
//!
//! - All encryption is authenticated (AEAD). No unauthenticated ciphertext.
//! - All asymmetric operations use hybrid classical + post-quantum constructions.
//! - All nonces are generated internally. No user-supplied nonces.
//! - All secret material implements `Zeroize` and `ZeroizeOnDrop`.
//! - Domain separation strings are required for all KDF and signing operations.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod nonce;
pub mod sig;

pub use error::CoreError;
