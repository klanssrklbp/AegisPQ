//! Hybrid digital signatures.
//!
//! Combines Ed25519 (classical) with ML-DSA-65 (post-quantum, FIPS 204)
//! so that signatures are unforgeable if **either** algorithm is secure.
//!
//! ## Verification policy
//!
//! **Both** signatures must verify. An attacker must forge both the classical
//! and post-quantum signature to succeed. This is the conservative choice.
//!
//! ## Signature sizes
//!
//! | Component | Signature Size | Public Key Size |
//! |-----------|---------------|----------------|
//! | Ed25519 | 64 bytes | 32 bytes |
//! | ML-DSA-65 | 3,309 bytes | 1,952 bytes |
//! | **Hybrid total** | **3,373 bytes** | **1,984 bytes** |
//!
//! ## Domain separation
//!
//! Every signing operation requires a domain separation string that is
//! prepended to the message before signing. This prevents cross-protocol
//! signature reuse attacks.

use core::convert::Infallible;

// Classical (Ed25519) — uses signature 2.x / rand_core 0.6
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use rand_core::OsRng;

// Post-quantum (ML-DSA-65) — uses signature 3.x / rand_core 0.10
use ml_dsa::signature::{
    Keypair as PqKeypair, SignatureEncoding as PqSigEncoding, Signer as PqSigner,
    Verifier as PqVerifier,
};
use ml_dsa::{KeyGen, MlDsa65};

use zeroize::ZeroizeOnDrop;

use crate::error::CoreError;

/// Bridge adapter: wraps rand_core 0.6 OsRng to implement rand_core 0.10 CryptoRng.
///
/// ml-dsa uses rand_core 0.10 (via signature 3.x) while the rest of the
/// ecosystem still uses rand_core 0.6. This adapter bridges the gap.
/// It will be removed once the ecosystem converges on rand_core 0.10.
struct PqOsRng;

impl rand_core_v10::TryRng for PqOsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        use rand_core::RngCore;
        Ok(OsRng.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        use rand_core::RngCore;
        Ok(OsRng.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        use rand_core::RngCore;
        OsRng.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core_v10::TryCryptoRng for PqOsRng {}

/// Ed25519 signature length in bytes.
pub const ED25519_SIG_LEN: usize = 64;
/// Ed25519 public key length in bytes.
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 secret key length in bytes.
pub const ED25519_SK_LEN: usize = 32;

// --- Classical (Ed25519) key types ---

/// Ed25519 signing (secret) key with zeroization on drop.
#[derive(ZeroizeOnDrop)]
pub struct ClassicalSigningKey {
    #[zeroize(skip)] // Ed25519SigningKey handles its own zeroization
    inner: Ed25519SigningKey,
}

impl ClassicalSigningKey {
    /// Serialize to 32 bytes. **For key storage only.**
    pub fn to_bytes(&self) -> [u8; ED25519_SK_LEN] {
        self.inner.to_bytes()
    }

    /// Deserialize from 32 bytes.
    pub fn from_bytes(bytes: &[u8; ED25519_SK_LEN]) -> Self {
        Self {
            inner: Ed25519SigningKey::from_bytes(bytes),
        }
    }
}

/// Ed25519 verifying (public) key.
#[derive(Clone)]
pub struct ClassicalVerifyingKey {
    inner: Ed25519VerifyingKey,
}

impl ClassicalVerifyingKey {
    /// Serialize to 32 bytes.
    pub fn to_bytes(&self) -> [u8; ED25519_PK_LEN] {
        self.inner.to_bytes()
    }

    /// Deserialize from 32 bytes.
    pub fn from_bytes(bytes: &[u8; ED25519_PK_LEN]) -> Result<Self, CoreError> {
        let inner =
            Ed25519VerifyingKey::from_bytes(bytes).map_err(|_| CoreError::InvalidParameter {
                reason: "invalid Ed25519 public key",
            })?;
        Ok(Self { inner })
    }
}

// --- Post-quantum (ML-DSA-65) key types ---

/// ML-DSA-65 signing (secret) key.
///
/// Boxed because the expanded ML-DSA-65 key is ~50 KB in memory
/// (pre-computed NTT polynomial matrices), which would overflow
/// the default 8 MB test thread stack when multiple identities
/// are created in a single call chain.
pub struct PqSigningKey {
    inner: Box<ml_dsa::SigningKey<MlDsa65>>,
}

/// ML-DSA-65 seed length in bytes.
pub const PQ_SEED_LEN: usize = 32;

impl PqSigningKey {
    /// Serialize to the 32-byte seed. **For key storage only.**
    ///
    /// The signing key can be deterministically regenerated from this seed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let seed = self.inner.to_seed();
        let slice: &[u8] = &seed;
        slice.to_vec()
    }

    /// Deserialize from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let seed: ml_dsa::Seed = bytes.try_into().map_err(|_| CoreError::InvalidKeyLength {
            expected: PQ_SEED_LEN,
            actual: bytes.len(),
        })?;
        let inner = Box::new(MlDsa65::from_seed(&seed));
        Ok(Self { inner })
    }
}

impl Drop for PqSigningKey {
    fn drop(&mut self) {
        // ML-DSA keys handle their own zeroization.
    }
}

/// ML-DSA-65 verifying (public) key.
#[derive(Clone)]
pub struct PqVerifyingKey {
    inner: ml_dsa::VerifyingKey<MlDsa65>,
}

/// ML-DSA-65 verifying key size in bytes.
pub const PQ_VK_LEN: usize = 1952;

impl PqVerifyingKey {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let encoded = self.inner.encode();
        let slice: &[u8] = &encoded;
        slice.to_vec()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let encoded: ml_dsa::EncodedVerifyingKey<MlDsa65> =
            bytes.try_into().map_err(|_| CoreError::InvalidKeyLength {
                expected: PQ_VK_LEN,
                actual: bytes.len(),
            })?;
        let inner = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);
        Ok(Self { inner })
    }
}

// --- Hybrid key types ---

/// A hybrid signing key pair combining Ed25519 and ML-DSA-65.
pub struct HybridSigningKey {
    /// Classical (Ed25519) signing key.
    pub classical: ClassicalSigningKey,
    /// Post-quantum (ML-DSA-65) signing key.
    pub pq: PqSigningKey,
}

/// A hybrid verifying key combining Ed25519 and ML-DSA-65 public keys.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    /// Classical (Ed25519) verifying key.
    pub classical: ClassicalVerifyingKey,
    /// Post-quantum (ML-DSA-65) verifying key.
    pub pq: PqVerifyingKey,
}

/// Serialized size of a `HybridSignature` in bytes.
///
/// `2 (ed25519_len) + 64 (ed25519_sig) + 2 (ml_dsa_len) + 3309 (ml_dsa_sig) = 3377`
pub const HYBRID_SIGNATURE_SIZE: usize = 2 + ED25519_SIG_LEN + 2 + 3309;

/// A hybrid signature containing both Ed25519 and ML-DSA-65 signatures.
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub classical: Vec<u8>,
    /// ML-DSA-65 signature (3,309 bytes).
    pub pq: Vec<u8>,
}

impl HybridSignature {
    /// Serialize the hybrid signature to bytes.
    ///
    /// Format: `[ed25519_len: u16 BE][ed25519_sig][ml_dsa_len: u16 BE][ml_dsa_sig]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.classical.len() + 2 + self.pq.len());
        out.extend_from_slice(&(self.classical.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&(self.pq.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.pq);
        out
    }

    /// Deserialize a hybrid signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidParameter {
                reason: "hybrid signature too short",
            });
        }

        let classical_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + classical_len + 2 {
            return Err(CoreError::InvalidParameter {
                reason: "hybrid signature truncated (classical component)",
            });
        }
        let classical = bytes[2..2 + classical_len].to_vec();

        let pq_offset = 2 + classical_len;
        let pq_len = u16::from_be_bytes([bytes[pq_offset], bytes[pq_offset + 1]]) as usize;
        if bytes.len() < pq_offset + 2 + pq_len {
            return Err(CoreError::InvalidParameter {
                reason: "hybrid signature truncated (PQ component)",
            });
        }
        let pq = bytes[pq_offset + 2..pq_offset + 2 + pq_len].to_vec();

        Ok(Self { classical, pq })
    }
}

// --- Key generation ---

/// Generate a new hybrid signing key pair.
pub fn generate_keypair() -> Result<(HybridSigningKey, HybridVerifyingKey), CoreError> {
    // Classical: Ed25519 (uses rand_core 0.6)
    let ed_signing = Ed25519SigningKey::generate(&mut OsRng);
    let ed_verifying = ed_signing.verifying_key();

    // Post-quantum: ML-DSA-65 (uses rand_core 0.10 via PqOsRng bridge)
    let pq_signing = MlDsa65::key_gen(&mut PqOsRng);
    let pq_verifying = PqKeypair::verifying_key(&pq_signing);

    let signing_key = HybridSigningKey {
        classical: ClassicalSigningKey { inner: ed_signing },
        pq: PqSigningKey {
            inner: Box::new(pq_signing),
        },
    };

    let verifying_key = HybridVerifyingKey {
        classical: ClassicalVerifyingKey {
            inner: ed_verifying,
        },
        pq: PqVerifyingKey {
            inner: pq_verifying,
        },
    };

    Ok((signing_key, verifying_key))
}

// --- Signing ---

/// Sign a message with hybrid signatures.
///
/// The domain separator is prepended to the message before signing to
/// prevent cross-protocol signature reuse.
///
/// - `signing_key`: The signer's hybrid signing key.
/// - `domain_sep`: Domain separation string (e.g., `b"AegisPQ-v1-sign"`).
/// - `message`: The message to sign.
pub fn sign(
    signing_key: &HybridSigningKey,
    domain_sep: &[u8],
    message: &[u8],
) -> Result<HybridSignature, CoreError> {
    let separated = domain_separated_message(domain_sep, message);

    // Ed25519 signature (signature 2.x Signer trait)
    let ed_sig: Ed25519Signature = Ed25519Signer::sign(&signing_key.classical.inner, &separated);

    // ML-DSA-65 signature (signature 3.x Signer trait)
    let pq_sig: ml_dsa::Signature<MlDsa65> = PqSigner::sign(&*signing_key.pq.inner, &separated);

    Ok(HybridSignature {
        classical: ed_sig.to_bytes().to_vec(),
        pq: {
            let sig_repr = PqSigEncoding::to_bytes(&pq_sig);
            let sig_ref: &[u8] = sig_repr.as_ref();
            sig_ref.to_vec()
        },
    })
}

/// Verify a hybrid signature.
///
/// **Both** the Ed25519 and ML-DSA-65 signatures must verify.
///
/// - `verifying_key`: The signer's hybrid verifying key.
/// - `domain_sep`: Domain separation string (must match what was used during signing).
/// - `message`: The original message.
/// - `signature`: The hybrid signature to verify.
pub fn verify(
    verifying_key: &HybridVerifyingKey,
    domain_sep: &[u8],
    message: &[u8],
    signature: &HybridSignature,
) -> Result<(), CoreError> {
    let separated = domain_separated_message(domain_sep, message);

    // Verify Ed25519 (signature 2.x Verifier trait)
    let ed_sig = Ed25519Signature::from_slice(&signature.classical)
        .map_err(|_| CoreError::SignatureVerificationFailed)?;

    Ed25519Verifier::verify(&verifying_key.classical.inner, &separated, &ed_sig)
        .map_err(|_| CoreError::SignatureVerificationFailed)?;

    // Verify ML-DSA-65 (signature 3.x Verifier trait)
    let pq_sig = <ml_dsa::Signature<MlDsa65> as TryFrom<&[u8]>>::try_from(signature.pq.as_slice())
        .map_err(|_| CoreError::SignatureVerificationFailed)?;

    PqVerifier::verify(&verifying_key.pq.inner, &separated, &pq_sig)
        .map_err(|_| CoreError::SignatureVerificationFailed)?;

    Ok(())
}

/// Construct a domain-separated message.
///
/// Format: `[domain_sep_len: u32 BE][domain_sep][message]`
///
/// The length prefix prevents ambiguity between different domain separators.
fn domain_separated_message(domain_sep: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + domain_sep.len() + message.len());
    out.extend_from_slice(&(domain_sep.len() as u32).to_be_bytes());
    out.extend_from_slice(domain_sep);
    out.extend_from_slice(message);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DOMAIN: &[u8] = b"AegisPQ-v1-test-sign";

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, vk) = generate_keypair().unwrap();
        let message = b"Hello, post-quantum world!";

        let sig = sign(&sk, TEST_DOMAIN, message).unwrap();
        verify(&vk, TEST_DOMAIN, message, &sig).unwrap();
    }

    #[test]
    fn wrong_message_fails_verification() {
        let (sk, vk) = generate_keypair().unwrap();

        let sig = sign(&sk, TEST_DOMAIN, b"correct message").unwrap();
        let result = verify(&vk, TEST_DOMAIN, b"wrong message", &sig);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_domain_fails_verification() {
        let (sk, vk) = generate_keypair().unwrap();
        let message = b"test";

        let sig = sign(&sk, b"domain-a", message).unwrap();
        let result = verify(&vk, b"domain-b", message, &sig);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (sk1, _vk1) = generate_keypair().unwrap();
        let (_sk2, vk2) = generate_keypair().unwrap();

        let sig = sign(&sk1, TEST_DOMAIN, b"msg").unwrap();
        let result = verify(&vk2, TEST_DOMAIN, b"msg", &sig);

        assert!(result.is_err());
    }

    #[test]
    fn signature_serialization_roundtrip() {
        let (sk, vk) = generate_keypair().unwrap();
        let message = b"serialize me";

        let sig = sign(&sk, TEST_DOMAIN, message).unwrap();
        let bytes = sig.to_bytes();
        let sig2 = HybridSignature::from_bytes(&bytes).unwrap();

        verify(&vk, TEST_DOMAIN, message, &sig2).unwrap();
    }

    #[test]
    fn signature_deserialization_rejects_truncated() {
        assert!(HybridSignature::from_bytes(&[0, 1, 2]).is_err());
        assert!(HybridSignature::from_bytes(&[0, 64]).is_err());
    }

    #[test]
    fn empty_message_works() {
        let (sk, vk) = generate_keypair().unwrap();

        let sig = sign(&sk, TEST_DOMAIN, b"").unwrap();
        verify(&vk, TEST_DOMAIN, b"", &sig).unwrap();
    }

    #[test]
    fn domain_separation_prevents_cross_protocol() {
        let (sk, vk) = generate_keypair().unwrap();
        let message = b"same message";

        let sig_a = sign(&sk, b"protocol-a", message).unwrap();
        let sig_b = sign(&sk, b"protocol-b", message).unwrap();

        verify(&vk, b"protocol-a", message, &sig_a).unwrap();
        verify(&vk, b"protocol-b", message, &sig_b).unwrap();

        assert!(verify(&vk, b"protocol-b", message, &sig_a).is_err());
        assert!(verify(&vk, b"protocol-a", message, &sig_b).is_err());
    }
}
