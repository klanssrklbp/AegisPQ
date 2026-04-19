//! Passphrase-based key wrapping and unwrapping.
//!
//! Private key material is encrypted at rest using a key derived from the
//! user's passphrase via Argon2id (memory-hard KDF), then sealed with
//! AES-256-GCM.
//!
//! ## Domain separation
//!
//! The wrapping AAD includes the domain string `"AegisPQ-v1-identity-wrap"`
//! and the identity ID, preventing cross-identity key material confusion.

use aegispq_core::{aead, kdf};
use crate::error::StoreError;

/// Domain separator for identity key wrapping.
const IDENTITY_WRAP_DOMAIN: &[u8] = b"AegisPQ-v1-identity-wrap";

/// Encrypt private key material under a passphrase-derived key.
///
/// - `passphrase`: User's passphrase bytes.
/// - `salt`: 16-byte random salt (stored alongside the ciphertext).
/// - `params`: Argon2id cost parameters.
/// - `identity_id`: The identity these keys belong to (bound via AAD).
/// - `plaintext_keys`: Serialized private key bundle to encrypt.
///
/// Returns the AEAD output: `nonce || ciphertext || tag`.
pub fn wrap_key_material(
    passphrase: &[u8],
    salt: &[u8; kdf::ARGON2_SALT_LEN],
    params: &kdf::Argon2Params,
    identity_id: &[u8; 16],
    plaintext_keys: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut derived = kdf::argon2id_derive(passphrase, salt, params)?;
    let wrap_key = aead::AeadKey::from_slice(derived.as_bytes())?;

    let aad = build_wrap_aad(identity_id);
    let sealed =
        aead::seal(aead::Algorithm::Aes256Gcm, &wrap_key, &aad, plaintext_keys, None)?;

    // DerivedKey is zeroized on drop; AeadKey is zeroized on drop.
    drop(wrap_key);
    let _ = &mut derived; // ensure not optimized away before drop

    Ok(sealed)
}

/// Decrypt private key material using a passphrase-derived key.
///
/// Returns the plaintext private key bundle, or `InvalidPassphrase` if the
/// passphrase is wrong (AEAD tag verification fails).
pub fn unwrap_key_material(
    passphrase: &[u8],
    salt: &[u8; kdf::ARGON2_SALT_LEN],
    params: &kdf::Argon2Params,
    identity_id: &[u8; 16],
    encrypted_keys: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let derived = kdf::argon2id_derive(passphrase, salt, params)?;
    let wrap_key = aead::AeadKey::from_slice(derived.as_bytes())?;

    let aad = build_wrap_aad(identity_id);
    let plaintext = aead::open(aead::Algorithm::Aes256Gcm, &wrap_key, &aad, encrypted_keys)
        .map_err(|_| StoreError::InvalidPassphrase)?;

    Ok(plaintext)
}

/// Build the wrapping AAD: `domain || identity_id`.
fn build_wrap_aad(identity_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IDENTITY_WRAP_DOMAIN.len() + 16);
    aad.extend_from_slice(IDENTITY_WRAP_DOMAIN);
    aad.extend_from_slice(identity_id);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> kdf::Argon2Params {
        // Use minimum params for fast tests.
        kdf::Argon2Params {
            memory_kib: 65_536,
            iterations: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let passphrase = b"correct horse battery staple";
        let salt = [0x42u8; kdf::ARGON2_SALT_LEN];
        let params = test_params();
        let identity_id = [0xAA; 16];
        let secret_keys = b"these are my secret keys -- ed25519 + ml-dsa + x25519 + ml-kem";

        let encrypted = wrap_key_material(passphrase, &salt, &params, &identity_id, secret_keys)
            .unwrap();

        let decrypted =
            unwrap_key_material(passphrase, &salt, &params, &identity_id, &encrypted).unwrap();

        assert_eq!(&decrypted, secret_keys);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let salt = [0x42u8; kdf::ARGON2_SALT_LEN];
        let params = test_params();
        let identity_id = [0xAA; 16];
        let secret_keys = b"secret";

        let encrypted =
            wrap_key_material(b"right", &salt, &params, &identity_id, secret_keys).unwrap();

        let result =
            unwrap_key_material(b"wrong", &salt, &params, &identity_id, &encrypted);

        assert!(matches!(result, Err(StoreError::InvalidPassphrase)));
    }

    #[test]
    fn wrong_identity_id_fails() {
        let passphrase = b"passphrase";
        let salt = [0x42u8; kdf::ARGON2_SALT_LEN];
        let params = test_params();
        let secret_keys = b"secret";

        let encrypted =
            wrap_key_material(passphrase, &salt, &params, &[0x01; 16], secret_keys).unwrap();

        // Try to unwrap with a different identity ID (AAD mismatch).
        let result =
            unwrap_key_material(passphrase, &salt, &params, &[0x02; 16], &encrypted);

        assert!(matches!(result, Err(StoreError::InvalidPassphrase)));
    }

    #[test]
    fn different_salts_produce_different_ciphertexts() {
        let passphrase = b"passphrase";
        let params = test_params();
        let identity_id = [0xAA; 16];
        let secret_keys = b"secret";

        let e1 =
            wrap_key_material(passphrase, &[0x01; kdf::ARGON2_SALT_LEN], &params, &identity_id, secret_keys)
                .unwrap();
        let e2 =
            wrap_key_material(passphrase, &[0x02; kdf::ARGON2_SALT_LEN], &params, &identity_id, secret_keys)
                .unwrap();

        // Different salts → different wrapping keys → different ciphertext.
        assert_ne!(e1, e2);
    }
}
