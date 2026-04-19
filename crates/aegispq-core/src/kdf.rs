//! Key derivation functions.
//!
//! - **HKDF-SHA-512**: For deriving session keys, sub-keys, and domain-separated
//!   keys from shared secrets. Used in the extract-and-expand pattern.
//! - **Argon2id**: For deriving encryption keys from user passphrases.
//!   Memory-hard, resistant to GPU/ASIC brute-force attacks.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;

/// A derived key with automatic zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    bytes: Vec<u8>,
}

impl DerivedKey {
    /// Access the derived key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the derived key into a fixed-size array.
    ///
    /// # Panics
    ///
    /// Panics if the derived key length does not match `N`.
    pub fn into_array<const N: usize>(self) -> [u8; N] {
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.bytes);
        // `self` is dropped here, zeroizing the Vec.
        arr
    }
}

/// Extract-and-expand key derivation using HKDF-SHA-512.
///
/// - `salt`: Domain separation salt (e.g., `b"AegisPQ-v1-session-key"`).
///   Must not be empty — use a domain-specific constant.
/// - `ikm`: Input key material (e.g., concatenated shared secrets).
/// - `info`: Context info (e.g., transcript hash, identity IDs).
/// - `out_len`: Desired output length in bytes (max 255 * 64 = 16,320).
pub fn hkdf_sha512(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<DerivedKey, CoreError> {
    if salt.is_empty() {
        return Err(CoreError::InvalidParameter {
            reason: "HKDF salt must not be empty — use a domain separation constant",
        });
    }
    if ikm.is_empty() {
        return Err(CoreError::InvalidParameter {
            reason: "HKDF input key material must not be empty",
        });
    }
    if out_len == 0 || out_len > 255 * 64 {
        return Err(CoreError::InvalidParameter {
            reason: "HKDF output length must be 1..=16320 bytes",
        });
    }

    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).map_err(|_| CoreError::KdfError)?;

    Ok(DerivedKey { bytes: okm })
}

/// Parameters for Argon2id key derivation.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB. Minimum: 65536 (64 MiB). Default: 262144 (256 MiB).
    pub memory_kib: u32,
    /// Number of iterations. Minimum: 2. Default: 3.
    pub iterations: u32,
    /// Degree of parallelism. Minimum: 1. Default: 4.
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 262_144, // 256 MiB
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl Argon2Params {
    /// Minimum-cost parameters suitable for testing.
    ///
    /// **Do not use in production.** These parameters provide the minimum
    /// allowed security margin and exist solely to keep test suites fast.
    pub fn testing() -> Self {
        Self {
            memory_kib: ARGON2_MIN_MEMORY_KIB, // 64 MiB
            iterations: ARGON2_MIN_ITERATIONS, // 2
            parallelism: 1,
        }
    }
}

/// Minimum allowed Argon2id parameters to prevent brute-force attacks.
const ARGON2_MIN_MEMORY_KIB: u32 = 65_536; // 64 MiB
const ARGON2_MIN_ITERATIONS: u32 = 2;

/// Salt length for Argon2id in bytes.
pub const ARGON2_SALT_LEN: usize = 16;

/// Derive a 32-byte key from a passphrase using Argon2id.
///
/// - `passphrase`: User-provided passphrase bytes.
/// - `salt`: 16-byte random salt (must be unique per identity, stored alongside the ciphertext).
/// - `params`: Argon2id cost parameters.
///
/// Returns a 32-byte derived key suitable for use as an AES-256-GCM key.
pub fn argon2id_derive(
    passphrase: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    params: &Argon2Params,
) -> Result<DerivedKey, CoreError> {
    if passphrase.is_empty() {
        return Err(CoreError::InvalidParameter {
            reason: "passphrase must not be empty",
        });
    }
    if params.memory_kib < ARGON2_MIN_MEMORY_KIB {
        return Err(CoreError::InvalidParameter {
            reason: "Argon2id memory cost below minimum (64 MiB)",
        });
    }
    if params.iterations < ARGON2_MIN_ITERATIONS {
        return Err(CoreError::InvalidParameter {
            reason: "Argon2id iterations below minimum (2)",
        });
    }
    if params.parallelism == 0 {
        return Err(CoreError::InvalidParameter {
            reason: "Argon2id parallelism must be at least 1",
        });
    }

    let argon2_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32), // output 32 bytes
    )
    .map_err(|_| CoreError::KdfError)?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|_| CoreError::KdfError)?;

    Ok(DerivedKey { bytes: output })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_deterministic() {
        let a = hkdf_sha512(b"test-salt", b"secret", b"info", 32).unwrap();
        let b = hkdf_sha512(b"test-salt", b"secret", b"info", 32).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn hkdf_different_salt_different_output() {
        let a = hkdf_sha512(b"salt-a", b"secret", b"info", 32).unwrap();
        let b = hkdf_sha512(b"salt-b", b"secret", b"info", 32).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn hkdf_different_info_different_output() {
        let a = hkdf_sha512(b"salt", b"secret", b"info-a", 32).unwrap();
        let b = hkdf_sha512(b"salt", b"secret", b"info-b", 32).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn hkdf_rejects_empty_salt() {
        let result = hkdf_sha512(b"", b"secret", b"info", 32);
        assert!(result.is_err());
    }

    #[test]
    fn hkdf_rejects_empty_ikm() {
        let result = hkdf_sha512(b"salt", b"", b"info", 32);
        assert!(result.is_err());
    }

    #[test]
    fn hkdf_rejects_zero_length() {
        let result = hkdf_sha512(b"salt", b"secret", b"info", 0);
        assert!(result.is_err());
    }

    #[test]
    fn argon2id_deterministic() {
        let salt = [0x42u8; ARGON2_SALT_LEN];
        let params = Argon2Params {
            memory_kib: ARGON2_MIN_MEMORY_KIB,
            iterations: ARGON2_MIN_ITERATIONS,
            parallelism: 1,
        };
        let a = argon2id_derive(b"password", &salt, &params).unwrap();
        let b = argon2id_derive(b"password", &salt, &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn argon2id_different_passwords() {
        let salt = [0x42u8; ARGON2_SALT_LEN];
        let params = Argon2Params {
            memory_kib: ARGON2_MIN_MEMORY_KIB,
            iterations: ARGON2_MIN_ITERATIONS,
            parallelism: 1,
        };
        let a = argon2id_derive(b"password1", &salt, &params).unwrap();
        let b = argon2id_derive(b"password2", &salt, &params).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn argon2id_rejects_low_memory() {
        let salt = [0u8; ARGON2_SALT_LEN];
        let params = Argon2Params {
            memory_kib: 1024, // Way below minimum
            iterations: 2,
            parallelism: 1,
        };
        assert!(argon2id_derive(b"pass", &salt, &params).is_err());
    }

    #[test]
    fn argon2id_rejects_empty_passphrase() {
        let salt = [0u8; ARGON2_SALT_LEN];
        let params = Argon2Params::default();
        assert!(argon2id_derive(b"", &salt, &params).is_err());
    }

    #[test]
    fn derived_key_into_array() {
        let dk = hkdf_sha512(b"salt", b"secret", b"info", 32).unwrap();
        let arr: [u8; 32] = dk.into_array();
        assert_eq!(arr.len(), 32);
    }
}
