//! Nonce generation and management.
//!
//! AegisPQ never accepts user-supplied nonces. All nonces are generated
//! internally using one of two strategies:
//!
//! - **Counter + random** for AES-256-GCM (96-bit nonce):
//!   `nonce = counter(32-bit BE) || random(64-bit)`
//!   The random component is generated once per key and stored with the key.
//!   The counter increments for each encryption. Maximum 2^32 encryptions per key.
//!
//! - **Random** for XChaCha20-Poly1305 (192-bit nonce):
//!   A fresh 192-bit random value for each encryption. The birthday bound at
//!   192 bits allows ~2^96 encryptions per key, making collision negligible.

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;

/// Nonce length for AES-256-GCM in bytes.
pub const GCM_NONCE_LEN: usize = 12;

/// Nonce length for XChaCha20-Poly1305 in bytes.
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Maximum number of encryptions allowed under a single AES-256-GCM key.
pub const GCM_MAX_COUNTER: u32 = u32::MAX;

/// A counter-based nonce generator for AES-256-GCM.
///
/// Each instance generates unique nonces by combining an incrementing
/// 32-bit counter with a 64-bit random value that is fixed for the
/// lifetime of the generator (and thus the key).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GcmNonceGenerator {
    /// Fixed random component (generated once per key).
    random_part: [u8; 8],
    /// Monotonically increasing counter.
    counter: u32,
}

impl GcmNonceGenerator {
    /// Create a new nonce generator with a fresh random component.
    pub fn new() -> Result<Self, CoreError> {
        let mut random_part = [0u8; 8];
        OsRng
            .try_fill_bytes(&mut random_part)
            .map_err(|_| CoreError::EntropyError)?;

        Ok(Self {
            random_part,
            counter: 0,
        })
    }

    /// Restore a nonce generator from persisted state.
    ///
    /// Used when loading a key from storage. The counter must be set to
    /// the last persisted value (or higher) to prevent nonce reuse.
    pub fn restore(random_part: [u8; 8], counter: u32) -> Self {
        Self {
            random_part,
            counter,
        }
    }

    /// Generate the next nonce.
    ///
    /// Returns an error if the counter has been exhausted (2^32 encryptions).
    /// When this happens, the key must be rotated.
    pub fn next(&mut self) -> Result<[u8; GCM_NONCE_LEN], CoreError> {
        if self.counter == GCM_MAX_COUNTER {
            return Err(CoreError::NonceExhausted);
        }

        let mut nonce = [0u8; GCM_NONCE_LEN];
        nonce[..4].copy_from_slice(&self.counter.to_be_bytes());
        nonce[4..].copy_from_slice(&self.random_part);

        self.counter = self.counter.checked_add(1).ok_or(CoreError::NonceExhausted)?;

        Ok(nonce)
    }

    /// Get the current counter value (for persistence).
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Get the random part (for persistence).
    pub fn random_part(&self) -> &[u8; 8] {
        &self.random_part
    }
}

/// Generate a random nonce for XChaCha20-Poly1305.
///
/// Each call produces a fresh 192-bit random value. The birthday bound
/// at 192 bits makes collision negligible even for ~2^96 encryptions.
pub fn xchacha_random_nonce() -> Result<[u8; XCHACHA_NONCE_LEN], CoreError> {
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CoreError::EntropyError)?;
    Ok(nonce)
}

/// Generate random bytes from the OS CSPRNG.
///
/// This is the only randomness source in the system.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut bytes = [0u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CoreError::EntropyError)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_nonces_are_unique() {
        let mut gen = GcmNonceGenerator::new().unwrap();
        let n1 = gen.next().unwrap();
        let n2 = gen.next().unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn gcm_counter_increments() {
        let mut gen = GcmNonceGenerator::new().unwrap();
        assert_eq!(gen.counter(), 0);
        let _ = gen.next().unwrap();
        assert_eq!(gen.counter(), 1);
        let _ = gen.next().unwrap();
        assert_eq!(gen.counter(), 2);
    }

    #[test]
    fn gcm_nonce_has_counter_prefix() {
        let mut gen = GcmNonceGenerator::new().unwrap();
        let n0 = gen.next().unwrap();
        assert_eq!(&n0[..4], &0u32.to_be_bytes());

        let n1 = gen.next().unwrap();
        assert_eq!(&n1[..4], &1u32.to_be_bytes());
    }

    #[test]
    fn gcm_nonce_random_part_is_stable() {
        let mut gen = GcmNonceGenerator::new().unwrap();
        let n0 = gen.next().unwrap();
        let n1 = gen.next().unwrap();
        // Random suffix is the same across nonces from the same generator.
        assert_eq!(&n0[4..], &n1[4..]);
    }

    #[test]
    fn gcm_restore_continues_counter() {
        let random_part = [0xAA; 8];
        let mut gen = GcmNonceGenerator::restore(random_part, 100);
        assert_eq!(gen.counter(), 100);
        let nonce = gen.next().unwrap();
        assert_eq!(&nonce[..4], &100u32.to_be_bytes());
        assert_eq!(gen.counter(), 101);
    }

    #[test]
    fn gcm_exhaustion() {
        let mut gen = GcmNonceGenerator::restore([0; 8], GCM_MAX_COUNTER);
        assert!(gen.next().is_err());
    }

    #[test]
    fn xchacha_nonces_are_random() {
        let n1 = xchacha_random_nonce().unwrap();
        let n2 = xchacha_random_nonce().unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn random_bytes_correct_length() {
        let bytes: [u8; 32] = random_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
