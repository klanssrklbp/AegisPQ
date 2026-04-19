//! Hybrid Key Encapsulation Mechanism (KEM).
//!
//! Combines X25519 (classical ECDH) with ML-KEM-768 (post-quantum lattice-based KEM)
//! so that the shared secret is secure if **either** algorithm remains unbroken.
//!
//! ## Hybrid construction
//!
//! The shared secret is derived by concatenating both component shared secrets
//! and feeding them into HKDF-SHA-512 with a domain separation salt:
//!
//! ```text
//! shared_secret = HKDF-SHA-512(
//!     salt = "AegisPQ-v1-hybrid-kex",
//!     ikm  = x25519_shared || ml_kem_shared,
//!     info = context
//! )
//! ```
//!
//! ## Key sizes
//!
//! | Component | Public Key | Secret Key | Ciphertext |
//! |-----------|-----------|-----------|------------|
//! | X25519 | 32 bytes | 32 bytes | 32 bytes (ephemeral public key) |
//! | ML-KEM-768 | 1,184 bytes | 2,400 bytes | 1,088 bytes |

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;
use crate::kdf;

/// Domain separation salt for hybrid KEM shared secret derivation.
const HYBRID_KEM_DOMAIN: &[u8] = b"AegisPQ-v1-hybrid-kex";

/// Length of the final derived shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

// --- X25519 key types ---

/// X25519 static secret key (32 bytes).
#[derive(ZeroizeOnDrop)]
pub struct ClassicalSecretKey {
    inner: X25519SecretKey,
}

impl ClassicalSecretKey {
    /// Serialize to 32 bytes. **For key storage only.**
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Deserialize from 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: X25519SecretKey::from(bytes),
        }
    }
}

/// X25519 public key (32 bytes).
#[derive(Clone)]
pub struct ClassicalPublicKey {
    inner: X25519PublicKey,
}

impl ClassicalPublicKey {
    /// Serialize to 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Deserialize from 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: X25519PublicKey::from(bytes),
        }
    }
}

// --- ML-KEM-768 key types ---

/// ML-KEM-768 decapsulation (secret) key.
pub struct PqSecretKey {
    inner: <MlKem768 as KemCore>::DecapsulationKey,
}

/// ML-KEM-768 decapsulation key size in bytes.
pub const PQ_SECRET_KEY_LEN: usize = 2400;

impl PqSecretKey {
    /// Serialize to bytes. **For key storage only.**
    pub fn to_bytes(&self) -> Vec<u8> {
        let encoded = EncodedSizeUser::as_bytes(&self.inner);
        let slice: &[u8] = &*encoded;
        slice.to_vec()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        type Dk = <MlKem768 as KemCore>::DecapsulationKey;
        let encoded: ml_kem::Encoded<Dk> = bytes.try_into().map_err(|_| {
            CoreError::InvalidKeyLength {
                expected: PQ_SECRET_KEY_LEN,
                actual: bytes.len(),
            }
        })?;
        Ok(Self {
            inner: Dk::from_bytes(&encoded),
        })
    }
}

impl Drop for PqSecretKey {
    fn drop(&mut self) {
        // ML-KEM keys are zeroized by the ml-kem crate on drop.
    }
}

/// ML-KEM-768 encapsulation (public) key.
#[derive(Clone)]
pub struct PqPublicKey {
    inner: <MlKem768 as KemCore>::EncapsulationKey,
}

/// ML-KEM-768 encapsulation key size in bytes.
pub const PQ_PUBLIC_KEY_LEN: usize = 1184;

impl PqPublicKey {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let encoded = EncodedSizeUser::as_bytes(&self.inner);
        let slice: &[u8] = &*encoded;
        slice.to_vec()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        type Ek = <MlKem768 as KemCore>::EncapsulationKey;
        let encoded: ml_kem::Encoded<Ek> = bytes.try_into().map_err(|_| {
            CoreError::InvalidKeyLength {
                expected: PQ_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            }
        })?;
        Ok(Self {
            inner: Ek::from_bytes(&encoded),
        })
    }
}

/// ML-KEM-768 ciphertext.
pub struct PqCiphertext {
    bytes: Vec<u8>,
}

impl PqCiphertext {
    /// Access the raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the expected ciphertext length for ML-KEM-768.
    pub fn expected_len() -> usize {
        1088
    }
}

// --- Hybrid key types ---

/// A hybrid KEM key pair combining X25519 and ML-KEM-768.
pub struct HybridKeyPair {
    /// Classical (X25519) secret key.
    pub classical_secret: ClassicalSecretKey,
    /// Classical (X25519) public key.
    pub classical_public: ClassicalPublicKey,
    /// Post-quantum (ML-KEM-768) secret key.
    pub pq_secret: PqSecretKey,
    /// Post-quantum (ML-KEM-768) public key.
    pub pq_public: PqPublicKey,
}

/// The public component of a hybrid KEM key pair.
#[derive(Clone)]
pub struct HybridPublicKey {
    /// Classical (X25519) public key.
    pub classical: ClassicalPublicKey,
    /// Post-quantum (ML-KEM-768) public key.
    pub pq: PqPublicKey,
}

/// The output of a hybrid encapsulation.
pub struct HybridEncapsulation {
    /// The X25519 ephemeral public key (sent to recipient).
    pub classical_ephemeral_pk: [u8; 32],
    /// The ML-KEM-768 ciphertext (sent to recipient).
    pub pq_ciphertext: PqCiphertext,
    /// The derived shared secret (kept by sender).
    pub shared_secret: SharedSecret,
}

/// A shared secret derived from the hybrid KEM, with automatic zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_LEN],
}

impl SharedSecret {
    /// Access the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.bytes
    }
}

// --- Key generation ---

/// Generate a new hybrid KEM key pair.
///
/// This produces both classical (X25519) and post-quantum (ML-KEM-768)
/// key pairs. Both are needed for hybrid key exchange.
pub fn generate_keypair() -> Result<HybridKeyPair, CoreError> {
    // Classical: X25519
    let classical_secret = X25519SecretKey::random_from_rng(OsRng);
    let classical_public = X25519PublicKey::from(&classical_secret);

    // Post-quantum: ML-KEM-768
    let (pq_secret, pq_public) = MlKem768::generate(&mut OsRng);

    Ok(HybridKeyPair {
        classical_secret: ClassicalSecretKey {
            inner: classical_secret,
        },
        classical_public: ClassicalPublicKey {
            inner: classical_public,
        },
        pq_secret: PqSecretKey { inner: pq_secret },
        pq_public: PqPublicKey { inner: pq_public },
    })
}

/// Extract the public key from a hybrid key pair.
pub fn public_key(keypair: &HybridKeyPair) -> HybridPublicKey {
    HybridPublicKey {
        classical: keypair.classical_public.clone(),
        pq: keypair.pq_public.clone(),
    }
}

// --- Encapsulation (sender side) ---

/// Encapsulate a shared secret against a recipient's hybrid public key.
///
/// The sender calls this function. It generates ephemeral keys, performs
/// both classical and post-quantum key exchange, and combines the results
/// via HKDF.
///
/// - `recipient_pk`: The recipient's hybrid public key.
/// - `context`: Additional context bound into the KDF (e.g., transcript hash).
///
/// Returns the encapsulation (to send to recipient) and the shared secret (to keep).
pub fn encapsulate(
    recipient_pk: &HybridPublicKey,
    context: &[u8],
) -> Result<HybridEncapsulation, CoreError> {
    // Classical: ephemeral X25519 DH
    let ephemeral_secret = X25519SecretKey::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let classical_shared = ephemeral_secret.diffie_hellman(&recipient_pk.classical.inner);

    // Post-quantum: ML-KEM-768 encapsulation
    let (pq_ciphertext, pq_shared) = recipient_pk
        .pq
        .inner
        .encapsulate(&mut OsRng)
        .map_err(|_| CoreError::KemEncapsulationFailed)?;

    // Combine shared secrets via HKDF
    let combined = combine_shared_secrets(
        classical_shared.as_bytes(),
        pq_shared.as_ref(),
        context,
    )?;

    Ok(HybridEncapsulation {
        classical_ephemeral_pk: ephemeral_public.to_bytes(),
        pq_ciphertext: PqCiphertext {
            bytes: {
                let ct_ref: &[u8] = pq_ciphertext.as_ref();
                ct_ref.to_vec()
            },
        },
        shared_secret: combined,
    })
}

/// Decapsulate a shared secret from a hybrid encapsulation.
///
/// The recipient calls this function with their secret key and the
/// encapsulation received from the sender.
///
/// - `secret_key`: The recipient's hybrid secret key pair.
/// - `classical_ephemeral_pk`: The sender's ephemeral X25519 public key.
/// - `pq_ciphertext`: The ML-KEM-768 ciphertext from the sender.
/// - `context`: Additional context (must match what the sender used).
pub fn decapsulate(
    secret_key: &HybridKeyPair,
    classical_ephemeral_pk: &[u8; 32],
    pq_ciphertext_bytes: &[u8],
    context: &[u8],
) -> Result<SharedSecret, CoreError> {
    // Classical: X25519 DH
    let sender_pk = X25519PublicKey::from(*classical_ephemeral_pk);
    let classical_shared = secret_key.classical_secret.inner.diffie_hellman(&sender_pk);

    // Post-quantum: ML-KEM-768 decapsulation
    let pq_ct_array: &[u8] = pq_ciphertext_bytes;
    let pq_ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(pq_ct_array)
        .map_err(|_| CoreError::KemDecapsulationFailed)?;

    let pq_shared = secret_key
        .pq_secret
        .inner
        .decapsulate(&pq_ciphertext)
        .map_err(|_| CoreError::KemDecapsulationFailed)?;

    // Combine shared secrets via HKDF
    combine_shared_secrets(classical_shared.as_bytes(), pq_shared.as_ref(), context)
}

/// Combine classical and PQ shared secrets via HKDF-SHA-512.
fn combine_shared_secrets(
    classical_ss: &[u8],
    pq_ss: &[u8],
    context: &[u8],
) -> Result<SharedSecret, CoreError> {
    // Concatenate both shared secrets as IKM.
    let mut ikm = Vec::with_capacity(classical_ss.len() + pq_ss.len());
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pq_ss);

    let derived = kdf::hkdf_sha512(HYBRID_KEM_DOMAIN, &ikm, context, SHARED_SECRET_LEN)?;

    // Zeroize the concatenated IKM.
    ikm.zeroize();

    let mut bytes = [0u8; SHARED_SECRET_LEN];
    bytes.copy_from_slice(derived.as_bytes());

    Ok(SharedSecret { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let kp = generate_keypair().unwrap();
        // Verify public key derivation is consistent.
        let pk = public_key(&kp);
        assert_eq!(pk.classical.to_bytes(), kp.classical_public.to_bytes());
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let recipient_kp = generate_keypair().unwrap();
        let recipient_pk = public_key(&recipient_kp);

        let context = b"test-context";
        let encap = encapsulate(&recipient_pk, context).unwrap();

        let decap_ss = decapsulate(
            &recipient_kp,
            &encap.classical_ephemeral_pk,
            encap.pq_ciphertext.as_bytes(),
            context,
        )
        .unwrap();

        // Both sides derive the same shared secret.
        assert_eq!(encap.shared_secret.as_bytes(), decap_ss.as_bytes());
    }

    #[test]
    fn different_contexts_produce_different_secrets() {
        let recipient_kp = generate_keypair().unwrap();
        let recipient_pk = public_key(&recipient_kp);

        let encap1 = encapsulate(&recipient_pk, b"context-1").unwrap();
        let encap2 = encapsulate(&recipient_pk, b"context-2").unwrap();

        // Different contexts (and different ephemeral keys) produce different secrets.
        assert_ne!(
            encap1.shared_secret.as_bytes(),
            encap2.shared_secret.as_bytes()
        );
    }

    #[test]
    fn wrong_secret_key_fails() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let pk1 = public_key(&kp1);

        let context = b"test";
        let encap = encapsulate(&pk1, context).unwrap();

        // Try to decapsulate with the wrong key pair.
        let result = decapsulate(
            &kp2,
            &encap.classical_ephemeral_pk,
            encap.pq_ciphertext.as_bytes(),
            context,
        );

        // The classical DH will produce a different shared secret, and
        // the ML-KEM decapsulation will produce an implicit reject value.
        // The combined result will differ from what the sender computed.
        match result {
            Ok(ss) => assert_ne!(ss.as_bytes(), encap.shared_secret.as_bytes()),
            Err(_) => {} // Also acceptable if decapsulation fails outright.
        }
    }

    #[test]
    fn encapsulation_produces_expected_sizes() {
        let kp = generate_keypair().unwrap();
        let pk = public_key(&kp);

        let encap = encapsulate(&pk, b"ctx").unwrap();

        assert_eq!(encap.classical_ephemeral_pk.len(), 32);
        assert_eq!(encap.pq_ciphertext.as_bytes().len(), PqCiphertext::expected_len());
        assert_eq!(encap.shared_secret.as_bytes().len(), SHARED_SECRET_LEN);
    }
}
