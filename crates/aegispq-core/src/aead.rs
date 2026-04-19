//! Authenticated Encryption with Associated Data (AEAD).
//!
//! Provides AES-256-GCM and XChaCha20-Poly1305 behind a unified interface.
//! All encryption is authenticated — there is no way to produce
//! unauthenticated ciphertext through this API.
//!
//! ## Nonce handling
//!
//! This module does **not** accept user-supplied nonces. Nonces are
//! generated internally via [`crate::nonce`]. The nonce is prepended
//! to the ciphertext output so that decryption is self-contained.
//!
//! ## Output format
//!
//! `seal` output: `nonce || ciphertext || tag`
//!
//! - AES-256-GCM: 12-byte nonce + ciphertext + 16-byte tag
//! - XChaCha20-Poly1305: 24-byte nonce + ciphertext + 16-byte tag

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;
use crate::nonce::{self, GcmNonceGenerator, GCM_NONCE_LEN, XCHACHA_NONCE_LEN};

/// AEAD key length in bytes (256-bit key for both algorithms).
pub const KEY_LEN: usize = 32;

/// AEAD tag length in bytes (128-bit tag for both algorithms).
pub const TAG_LEN: usize = 16;

/// The symmetric encryption algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// AES-256-GCM with 96-bit counter+random nonces.
    /// Preferred when AES-NI hardware acceleration is available.
    Aes256Gcm,
    /// XChaCha20-Poly1305 with 192-bit random nonces.
    /// Preferred when AES-NI is unavailable or when random nonces
    /// are desired (eliminates counter management).
    XChaCha20Poly1305,
}

impl Algorithm {
    /// Nonce length in bytes for this algorithm.
    pub fn nonce_len(self) -> usize {
        match self {
            Algorithm::Aes256Gcm => GCM_NONCE_LEN,
            Algorithm::XChaCha20Poly1305 => XCHACHA_NONCE_LEN,
        }
    }

    /// Overhead added to plaintext: nonce + tag.
    pub fn overhead(self) -> usize {
        self.nonce_len() + TAG_LEN
    }
}

/// A 256-bit AEAD key with automatic zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey {
    bytes: [u8; KEY_LEN],
}

impl AeadKey {
    /// Create a key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Create a key from a slice, validating length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.len() != KEY_LEN {
            return Err(CoreError::InvalidKeyLength {
                expected: KEY_LEN,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Generate a random key from the OS CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        let bytes: [u8; KEY_LEN] = nonce::random_bytes()?;
        Ok(Self { bytes })
    }

    /// Access the raw key bytes.
    ///
    /// This is intentionally not public — key material should not escape
    /// the core crate except through controlled export paths.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

/// Encrypt and authenticate plaintext using the specified algorithm.
///
/// - `algorithm`: Which AEAD to use.
/// - `key`: 256-bit encryption key.
/// - `aad`: Additional authenticated data (bound to ciphertext but not encrypted).
/// - `plaintext`: Data to encrypt.
/// - `nonce_gen`: Optional nonce generator for AES-256-GCM. If `None` and
///   algorithm is AES-256-GCM, a random nonce is used (safe for single-use keys).
///
/// Returns `nonce || ciphertext || tag`.
pub fn seal(
    algorithm: Algorithm,
    key: &AeadKey,
    aad: &[u8],
    plaintext: &[u8],
    nonce_gen: Option<&mut GcmNonceGenerator>,
) -> Result<Vec<u8>, CoreError> {
    match algorithm {
        Algorithm::Aes256Gcm => seal_aes256gcm(key, aad, plaintext, nonce_gen),
        Algorithm::XChaCha20Poly1305 => seal_xchacha20(key, aad, plaintext),
    }
}

/// Decrypt and verify ciphertext using the specified algorithm.
///
/// - `algorithm`: Which AEAD was used to encrypt.
/// - `key`: 256-bit decryption key.
/// - `aad`: Additional authenticated data (must match what was used during encryption).
/// - `ciphertext_with_nonce`: The output of `seal` (`nonce || ciphertext || tag`).
///
/// Returns the plaintext if authentication succeeds.
pub fn open(
    algorithm: Algorithm,
    key: &AeadKey,
    aad: &[u8],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CoreError> {
    match algorithm {
        Algorithm::Aes256Gcm => open_aes256gcm(key, aad, ciphertext_with_nonce),
        Algorithm::XChaCha20Poly1305 => open_xchacha20(key, aad, ciphertext_with_nonce),
    }
}

// --- AES-256-GCM implementation ---

fn seal_aes256gcm(
    key: &AeadKey,
    aad: &[u8],
    plaintext: &[u8],
    nonce_gen: Option<&mut GcmNonceGenerator>,
) -> Result<Vec<u8>, CoreError> {
    let nonce_bytes = match nonce_gen {
        Some(gen) => gen.next_nonce()?,
        None => {
            // Single-use key: use a random nonce.
            let mut n = [0u8; GCM_NONCE_LEN];
            n.copy_from_slice(&nonce::random_bytes::<GCM_NONCE_LEN>()?);
            n
        }
    };

    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CoreError::AeadEncryptionFailed)?;

    let nonce = GcmNonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CoreError::AeadEncryptionFailed)?;

    // Output: nonce || ciphertext (which includes the 16-byte tag appended by aes-gcm)
    let mut output = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn open_aes256gcm(
    key: &AeadKey,
    aad: &[u8],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if ciphertext_with_nonce.len() < GCM_NONCE_LEN + TAG_LEN {
        return Err(CoreError::AeadDecryptionFailed);
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(GCM_NONCE_LEN);

    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CoreError::AeadDecryptionFailed)?;

    let nonce = GcmNonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CoreError::AeadDecryptionFailed)
}

// --- XChaCha20-Poly1305 implementation ---

fn seal_xchacha20(key: &AeadKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let nonce_bytes = nonce::xchacha_random_nonce()?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CoreError::AeadEncryptionFailed)?;

    let nonce = XNonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CoreError::AeadEncryptionFailed)?;

    let mut output = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn open_xchacha20(
    key: &AeadKey,
    aad: &[u8],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if ciphertext_with_nonce.len() < XCHACHA_NONCE_LEN + TAG_LEN {
        return Err(CoreError::AeadDecryptionFailed);
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(XCHACHA_NONCE_LEN);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CoreError::AeadDecryptionFailed)?;

    let nonce = XNonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CoreError::AeadDecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(algo: Algorithm) {
        let key = AeadKey::generate().unwrap();
        let aad = b"AegisPQ-v1-test";
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        let ciphertext = seal(algo, &key, aad, plaintext, None).unwrap();

        // Ciphertext must be larger than plaintext by nonce + tag.
        assert_eq!(
            ciphertext.len(),
            algo.nonce_len() + plaintext.len() + TAG_LEN
        );

        let recovered = open(algo, &key, aad, &ciphertext).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn aes256gcm_roundtrip() {
        roundtrip(Algorithm::Aes256Gcm);
    }

    #[test]
    fn xchacha20_roundtrip() {
        roundtrip(Algorithm::XChaCha20Poly1305);
    }

    #[test]
    fn aes256gcm_with_nonce_generator() {
        let key = AeadKey::generate().unwrap();
        let mut gen = GcmNonceGenerator::new().unwrap();
        let aad = b"context";

        let ct1 = seal(Algorithm::Aes256Gcm, &key, aad, b"msg1", Some(&mut gen)).unwrap();
        let ct2 = seal(Algorithm::Aes256Gcm, &key, aad, b"msg2", Some(&mut gen)).unwrap();

        // Different nonces produce different ciphertexts.
        assert_ne!(ct1, ct2);

        // Both decrypt correctly.
        assert_eq!(
            open(Algorithm::Aes256Gcm, &key, aad, &ct1).unwrap(),
            b"msg1"
        );
        assert_eq!(
            open(Algorithm::Aes256Gcm, &key, aad, &ct2).unwrap(),
            b"msg2"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = AeadKey::generate().unwrap();
        let key2 = AeadKey::generate().unwrap();
        let aad = b"context";

        let ct = seal(Algorithm::Aes256Gcm, &key1, aad, b"secret", None).unwrap();
        assert!(open(Algorithm::Aes256Gcm, &key2, aad, &ct).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = AeadKey::generate().unwrap();

        let ct = seal(Algorithm::Aes256Gcm, &key, b"aad1", b"secret", None).unwrap();
        assert!(open(Algorithm::Aes256Gcm, &key, b"aad2", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = AeadKey::generate().unwrap();
        let aad = b"context";

        let mut ct = seal(Algorithm::XChaCha20Poly1305, &key, aad, b"secret", None).unwrap();

        // Flip a byte in the ciphertext (not the nonce).
        let mid = ct.len() / 2;
        ct[mid] ^= 0xFF;

        assert!(open(Algorithm::XChaCha20Poly1305, &key, aad, &ct).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = AeadKey::generate().unwrap();

        // Too short for nonce + tag.
        assert!(open(Algorithm::Aes256Gcm, &key, b"", &[0u8; 10]).is_err());
        assert!(open(Algorithm::XChaCha20Poly1305, &key, b"", &[0u8; 20]).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = AeadKey::generate().unwrap();
        let ct = seal(Algorithm::Aes256Gcm, &key, b"aad", b"", None).unwrap();
        let pt = open(Algorithm::Aes256Gcm, &key, b"aad", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn key_from_slice_valid() {
        let bytes = [0x42u8; KEY_LEN];
        let key = AeadKey::from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn key_from_slice_wrong_length() {
        assert!(AeadKey::from_slice(&[0u8; 16]).is_err());
        assert!(AeadKey::from_slice(&[0u8; 64]).is_err());
    }

    #[test]
    fn algorithm_overhead() {
        assert_eq!(Algorithm::Aes256Gcm.overhead(), 12 + 16);
        assert_eq!(Algorithm::XChaCha20Poly1305.overhead(), 24 + 16);
    }
}
