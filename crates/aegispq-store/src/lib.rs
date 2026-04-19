//! # aegispq-store
//!
//! Encrypted storage for AegisPQ key material and contacts.
//!
//! This crate provides:
//! - **Record types** ([`record::IdentityRecord`], [`record::ContactRecord`]) with binary
//!   serialization for on-disk persistence.
//! - **Passphrase-based key wrapping** ([`keystore`]) using Argon2id + AES-256-GCM
//!   to encrypt private key material at rest.
//! - **Filesystem store** ([`fs::FileStore`]) for saving/loading records to a directory tree.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod fs;
pub mod keystore;
pub mod record;
