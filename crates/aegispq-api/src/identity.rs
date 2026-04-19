//! Identity management: creation, loading, export, and import.

use aegispq_core::{kdf, kem, nonce, sig};
use aegispq_protocol::identity::{self, IdentityId};
use aegispq_store::error::StoreError;
use aegispq_store::fs::FileStore;
use aegispq_store::keystore;
use aegispq_store::record::{ContactRecord, IdentityRecord, IdentityStatus};
use zeroize::Zeroize;

use crate::error::Error;
use crate::types::{Identity, PublicIdentity};

/// Create a new identity protected by a passphrase.
///
/// Generates all key pairs, encrypts the private keys with the passphrase,
/// and persists the identity record to the store. Uses production-grade
/// Argon2id parameters (256 MiB, 3 iterations).
///
/// For test environments, use [`create_identity_with_params`] with
/// [`kdf::Argon2Params::testing()`] to avoid slow key derivation.
pub fn create_identity(
    display_name: &str,
    passphrase: &[u8],
    store: &FileStore,
) -> Result<Identity, Error> {
    create_identity_with_params(display_name, passphrase, store, kdf::Argon2Params::default())
}

/// Create a new identity with custom Argon2id parameters.
///
/// Same as [`create_identity`] but allows overriding the key derivation
/// parameters. Use [`kdf::Argon2Params::testing()`] in test code to keep
/// tests fast.
pub fn create_identity_with_params(
    display_name: &str,
    passphrase: &[u8],
    store: &FileStore,
    params: kdf::Argon2Params,
) -> Result<Identity, Error> {
    // Generate key pairs.
    let (signing_key, verifying_key) = sig::generate_keypair()?;
    let kem_keypair = kem::generate_keypair()?;
    let kem_public = kem::public_key(&kem_keypair);
    let identity_id = identity::generate_identity_id();

    // Serialize private keys into a bundle.
    let mut private_bundle = serialize_private_keys(&signing_key, &kem_keypair);

    // Generate salt and encrypt the bundle.
    let salt: [u8; kdf::ARGON2_SALT_LEN] = nonce::random_bytes()?;
    let encrypted =
        keystore::wrap_key_material(passphrase, &salt, &params, &identity_id, &private_bundle)
            .map_err(map_store_error)?;

    // Zeroize the plaintext bundle.
    private_bundle.zeroize();

    // Build and save the record.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = IdentityRecord {
        identity_id,
        display_name: display_name.to_string(),
        created_at: now,
        status: IdentityStatus::Active,
        ed25519_pk: verifying_key.classical.to_bytes().to_vec(),
        ml_dsa_pk: verifying_key.pq.to_bytes(),
        x25519_pk: kem_public.classical.to_bytes().to_vec(),
        ml_kem_pk: kem_public.pq.to_bytes(),
        encrypted_private_keys: encrypted,
        argon2_salt: salt,
        argon2_memory_kib: params.memory_kib,
        argon2_iterations: params.iterations,
        argon2_parallelism: params.parallelism,
    };

    store.save_identity(&record).map_err(map_store_error)?;

    Ok(Identity {
        identity_id,
        display_name: display_name.to_string(),
        status: IdentityStatus::Active,
        signing_key,
        verifying_key,
        kem_keypair,
        kem_public,
    })
}

/// Load an existing identity from the store, decrypting with the passphrase.
pub fn load_identity(
    identity_id: &IdentityId,
    passphrase: &[u8],
    store: &FileStore,
) -> Result<Identity, Error> {
    let record = store.load_identity(identity_id).map_err(map_store_error)?;

    // Decrypt private keys.
    let params = kdf::Argon2Params {
        memory_kib: record.argon2_memory_kib,
        iterations: record.argon2_iterations,
        parallelism: record.argon2_parallelism,
    };
    let mut private_bundle = keystore::unwrap_key_material(
        passphrase,
        &record.argon2_salt,
        &params,
        identity_id,
        &record.encrypted_private_keys,
    )
    .map_err(map_store_error)?;

    // Reconstruct keys.
    let result = reconstruct_keys(&private_bundle, &record);
    private_bundle.zeroize();
    let (signing_key, verifying_key, kem_keypair, kem_public) = result?;

    Ok(Identity {
        identity_id: record.identity_id,
        display_name: record.display_name,
        status: record.status,
        signing_key,
        verifying_key,
        kem_keypair,
        kem_public,
    })
}

/// List all identity IDs in the store.
pub fn list_identities(store: &FileStore) -> Result<Vec<IdentityId>, Error> {
    store.list_identities().map_err(map_store_error)
}

/// Import a remote party's public key as a contact.
pub fn import_contact(
    public: &PublicIdentity,
    store: &FileStore,
) -> Result<(), Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = ContactRecord {
        identity_id: public.identity_id,
        display_name: public.display_name.clone(),
        ed25519_pk: public.verifying_key.classical.to_bytes().to_vec(),
        ml_dsa_pk: public.verifying_key.pq.to_bytes(),
        x25519_pk: public.kem_public.classical.to_bytes().to_vec(),
        ml_kem_pk: public.kem_public.pq.to_bytes(),
        imported_at: now,
        status: public.status,
    };

    store.save_contact(&record).map_err(map_store_error)
}

/// Load a contact from the store.
pub fn load_contact(
    identity_id: &IdentityId,
    store: &FileStore,
) -> Result<PublicIdentity, Error> {
    let record = store.load_contact(identity_id).map_err(map_store_error)?;
    reconstruct_public_identity(&record)
}

/// List all contact IDs in the store.
pub fn list_contacts(store: &FileStore) -> Result<Vec<IdentityId>, Error> {
    store.list_contacts().map_err(map_store_error)
}

/// Domain separator for key package signatures.
const KEY_PACKAGE_SIGN_DOMAIN: &[u8] = b"AegisPQ-v1-key-package";

/// Export a local identity as a signed key package (binary).
///
/// The key package contains the public keys, display name, and a hybrid
/// signature that recipients verify before trusting the keys.
pub fn export_key_package(identity: &Identity) -> Result<Vec<u8>, Error> {
    use aegispq_core::{hash, sig};
    use aegispq_protocol::identity::KeyPackage;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut pkg = KeyPackage {
        identity_id: identity.identity_id,
        display_name: identity.display_name.clone(),
        ed25519_pk: identity.verifying_key.classical.to_bytes().to_vec(),
        ml_dsa_pk: identity.verifying_key.pq.to_bytes(),
        x25519_pk: identity.kem_public.classical.to_bytes().to_vec(),
        ml_kem_pk: identity.kem_public.pq.to_bytes(),
        created_at: now,
        signature: Vec::new(),
    };

    let signable = pkg.signable_bytes();
    let hash = hash::blake3_hash(&signable);
    let signature = sig::sign(&identity.signing_key, KEY_PACKAGE_SIGN_DOMAIN, &hash)?;
    pkg.signature = signature.to_bytes();

    Ok(pkg.to_bytes())
}

/// Import a signed key package and save it as a contact.
///
/// Verifies the embedded hybrid signature before trusting the keys.
/// Returns the imported public identity.
pub fn import_key_package(
    bytes: &[u8],
    store: &FileStore,
) -> Result<PublicIdentity, Error> {
    use aegispq_core::{hash, kem, sig};
    use aegispq_protocol::identity::KeyPackage;

    let pkg = KeyPackage::from_bytes(bytes)?;

    // Reconstruct verifying key from the package to verify self-signature.
    let ed_pk: [u8; 32] = pkg
        .ed25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 public key in key package" })?;
    let classical_vk =
        sig::ClassicalVerifyingKey::from_bytes(&ed_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 verifying key in key package" })?;
    let pq_vk =
        sig::PqVerifyingKey::from_bytes(&pkg.ml_dsa_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "ML-DSA-65 verifying key in key package" })?;
    let verifying_key = sig::HybridVerifyingKey {
        classical: classical_vk,
        pq: pq_vk,
    };

    // Verify the self-signature.
    let signable = pkg.signable_bytes();
    let hash_val = hash::blake3_hash(&signable);
    let sig_parsed = sig::HybridSignature::from_bytes(&pkg.signature)?;
    sig::verify(
        &verifying_key,
        KEY_PACKAGE_SIGN_DOMAIN,
        &hash_val,
        &sig_parsed,
    )
    .map_err(|_| Error::AuthenticationFailed)?;

    // Reconstruct KEM public key.
    let x_pk: [u8; 32] = pkg
        .x25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "X25519 public key in key package" })?;
    let classical_pk = kem::ClassicalPublicKey::from_bytes(x_pk);
    let pq_pk = kem::PqPublicKey::from_bytes(&pkg.ml_kem_pk)
        .map_err(|_| Error::InvalidKeyMaterial { context: "ML-KEM-768 public key in key package" })?;

    let public = PublicIdentity {
        identity_id: pkg.identity_id,
        display_name: pkg.display_name,
        status: IdentityStatus::Active,
        verifying_key,
        kem_public: kem::HybridPublicKey {
            classical: classical_pk,
            pq: pq_pk,
        },
    };

    import_contact(&public, store)?;

    Ok(public)
}

/// Load an identity record's display name without decrypting keys.
///
/// Useful for listing identities without requiring the passphrase.
pub fn load_identity_name(
    identity_id: &IdentityId,
    store: &FileStore,
) -> Result<String, Error> {
    let record = store.load_identity(identity_id).map_err(map_store_error)?;
    Ok(record.display_name)
}

/// Load a contact's display name.
pub fn load_contact_name(
    identity_id: &IdentityId,
    store: &FileStore,
) -> Result<String, Error> {
    let record = store.load_contact(identity_id).map_err(map_store_error)?;
    Ok(record.display_name)
}

/// Domain separator for revocation certificate signatures.
const REVOKE_SIGN_DOMAIN: &[u8] = aegispq_protocol::revocation::REVOKE_DOMAIN;

/// Revoke a local identity. Returns a revocation certificate for distribution.
///
/// Marks the identity as revoked in the store and produces a signed certificate
/// that contacts can import to learn about the revocation.
pub fn revoke_identity(
    identity: &Identity,
    reason: aegispq_protocol::revocation::RevocationReason,
    store: &FileStore,
) -> Result<Vec<u8>, Error> {
    use aegispq_core::{hash, sig};
    use aegispq_protocol::revocation::RevocationCertificate;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut cert = RevocationCertificate {
        identity_id: identity.identity_id,
        reason,
        effective_at: now,
        signature: Vec::new(),
    };

    // Sign the certificate.
    let signable = cert.signable_bytes();
    let hash = hash::blake3_hash(&signable);
    let signature = sig::sign(&identity.signing_key, REVOKE_SIGN_DOMAIN, &hash)?;
    cert.signature = signature.to_bytes();

    // Mark the local identity as revoked.
    let mut record = store.load_identity(&identity.identity_id).map_err(map_store_error)?;
    record.status = IdentityStatus::Revoked;
    store.save_identity(&record).map_err(map_store_error)?;

    Ok(cert.to_bytes())
}

/// Import a revocation certificate and mark the corresponding contact as revoked.
///
/// Verifies the certificate's hybrid signature against the contact's public
/// keys before updating the contact's status.
pub fn import_revocation(
    bytes: &[u8],
    store: &FileStore,
) -> Result<IdentityId, Error> {
    use aegispq_core::{hash, sig};
    use aegispq_protocol::revocation::RevocationCertificate;

    let cert = RevocationCertificate::from_bytes(bytes)?;

    // Load the contact to verify the signature.
    let record = store.load_contact(&cert.identity_id).map_err(map_store_error)?;
    let public = reconstruct_public_identity(&record)?;

    // Verify the self-signature.
    let signable = cert.signable_bytes();
    let hash_val = hash::blake3_hash(&signable);
    let sig_parsed = sig::HybridSignature::from_bytes(&cert.signature)?;
    sig::verify(
        &public.verifying_key,
        REVOKE_SIGN_DOMAIN,
        &hash_val,
        &sig_parsed,
    )
    .map_err(|_| Error::AuthenticationFailed)?;

    // Mark the contact as revoked.
    let mut updated = record;
    updated.status = IdentityStatus::Revoked;
    store.save_contact(&updated).map_err(map_store_error)?;

    Ok(cert.identity_id)
}

/// Check the identity status of a local identity record (without decrypting keys).
pub fn load_identity_status(
    identity_id: &IdentityId,
    store: &FileStore,
) -> Result<IdentityStatus, Error> {
    let record = store.load_identity(identity_id).map_err(map_store_error)?;
    Ok(record.status)
}

/// Domain separator for rotation certificate signatures.
const ROTATE_SIGN_DOMAIN: &[u8] = aegispq_protocol::rotation::ROTATE_DOMAIN;

/// Rotate a local identity with production-grade Argon2id parameters.
///
/// See [`rotate_identity_with_params`] for details. For tests, use the
/// `_with_params` variant with [`kdf::Argon2Params::testing()`].
pub fn rotate_identity(
    old_identity: &Identity,
    new_display_name: &str,
    new_passphrase: &[u8],
    store: &FileStore,
) -> Result<(Identity, Vec<u8>), Error> {
    rotate_identity_with_params(
        old_identity,
        new_display_name,
        new_passphrase,
        store,
        kdf::Argon2Params::default(),
    )
}

/// Rotate a local identity with custom Argon2id parameters.
///
/// Generates new key pairs, marks the old identity as Rotated, saves the new
/// identity, and returns a dual-signed rotation certificate for distribution
/// to contacts.
///
/// Returns `(new_identity, certificate_bytes)`.
pub fn rotate_identity_with_params(
    old_identity: &Identity,
    new_display_name: &str,
    new_passphrase: &[u8],
    store: &FileStore,
    params: kdf::Argon2Params,
) -> Result<(Identity, Vec<u8>), Error> {
    use aegispq_core::{hash, sig};
    use aegispq_protocol::rotation::RotationCertificate;

    // Generate new key pairs.
    let (new_signing_key, new_verifying_key) = sig::generate_keypair()?;
    let new_kem_keypair = kem::generate_keypair()?;
    let new_kem_public = kem::public_key(&new_kem_keypair);
    let new_identity_id = aegispq_protocol::identity::generate_identity_id();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the certificate (signatures filled in below).
    let mut cert = RotationCertificate {
        old_identity_id: old_identity.identity_id,
        new_identity_id,
        effective_at: now,
        new_ed25519_pk: new_verifying_key.classical.to_bytes().to_vec(),
        new_ml_dsa_pk: new_verifying_key.pq.to_bytes(),
        new_x25519_pk: new_kem_public.classical.to_bytes().to_vec(),
        new_ml_kem_pk: new_kem_public.pq.to_bytes(),
        new_display_name: new_display_name.to_string(),
        old_signature: Vec::new(),
        new_signature: Vec::new(),
    };

    // Old key signs new public keys.
    let old_signable = cert.old_signable_bytes();
    let old_hash = hash::blake3_hash(&old_signable);
    let old_sig = sig::sign(&old_identity.signing_key, ROTATE_SIGN_DOMAIN, &old_hash)?;
    cert.old_signature = old_sig.to_bytes();

    // New key signs old identity reference.
    let new_signable = cert.new_signable_bytes();
    let new_hash = hash::blake3_hash(&new_signable);
    let new_sig = sig::sign(&new_signing_key, ROTATE_SIGN_DOMAIN, &new_hash)?;
    cert.new_signature = new_sig.to_bytes();

    // Mark old identity as Rotated.
    let mut old_record = store
        .load_identity(&old_identity.identity_id)
        .map_err(map_store_error)?;
    old_record.status = IdentityStatus::Rotated;
    store.save_identity(&old_record).map_err(map_store_error)?;

    // Save new identity to store.
    let mut new_private_bundle = serialize_private_keys(&new_signing_key, &new_kem_keypair);
    let salt: [u8; kdf::ARGON2_SALT_LEN] = nonce::random_bytes()?;
    let encrypted =
        keystore::wrap_key_material(new_passphrase, &salt, &params, &new_identity_id, &new_private_bundle)
            .map_err(map_store_error)?;
    new_private_bundle.zeroize();

    let new_record = IdentityRecord {
        identity_id: new_identity_id,
        display_name: new_display_name.to_string(),
        created_at: now,
        status: IdentityStatus::Active,
        ed25519_pk: new_verifying_key.classical.to_bytes().to_vec(),
        ml_dsa_pk: new_verifying_key.pq.to_bytes(),
        x25519_pk: new_kem_public.classical.to_bytes().to_vec(),
        ml_kem_pk: new_kem_public.pq.to_bytes(),
        encrypted_private_keys: encrypted,
        argon2_salt: salt,
        argon2_memory_kib: params.memory_kib,
        argon2_iterations: params.iterations,
        argon2_parallelism: params.parallelism,
    };
    store.save_identity(&new_record).map_err(map_store_error)?;

    let new_identity = Identity {
        identity_id: new_identity_id,
        display_name: new_display_name.to_string(),
        status: IdentityStatus::Active,
        signing_key: new_signing_key,
        verifying_key: new_verifying_key,
        kem_keypair: new_kem_keypair,
        kem_public: new_kem_public,
    };

    Ok((new_identity, cert.to_bytes()))
}

/// Import a rotation certificate from a contact.
///
/// Verifies both signatures (old key vouches for new, new key vouches for old),
/// then updates the contact's keys to the new ones.
pub fn import_rotation(
    bytes: &[u8],
    store: &FileStore,
) -> Result<IdentityId, Error> {
    use aegispq_core::{hash, sig};
    use aegispq_protocol::rotation::RotationCertificate;

    let cert = RotationCertificate::from_bytes(bytes)?;

    // Load the existing contact (old identity) to verify the old signature.
    let old_record = store
        .load_contact(&cert.old_identity_id)
        .map_err(map_store_error)?;
    let old_public = reconstruct_public_identity(&old_record)?;

    // Verify the OLD key's signature over the new public keys.
    let old_signable = cert.old_signable_bytes();
    let old_hash = hash::blake3_hash(&old_signable);
    let old_sig = sig::HybridSignature::from_bytes(&cert.old_signature)?;
    sig::verify(
        &old_public.verifying_key,
        ROTATE_SIGN_DOMAIN,
        &old_hash,
        &old_sig,
    )
    .map_err(|_| Error::AuthenticationFailed)?;

    // Reconstruct the new verifying key to verify the new signature.
    let new_ed_pk: [u8; 32] = cert
        .new_ed25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 public key in rotation cert" })?;
    let new_classical_vk =
        sig::ClassicalVerifyingKey::from_bytes(&new_ed_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 verifying key in rotation cert" })?;
    let new_pq_vk =
        sig::PqVerifyingKey::from_bytes(&cert.new_ml_dsa_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "ML-DSA-65 verifying key in rotation cert" })?;
    let new_verifying_key = sig::HybridVerifyingKey {
        classical: new_classical_vk,
        pq: new_pq_vk,
    };

    // Verify the NEW key's signature.
    let new_signable = cert.new_signable_bytes();
    let new_hash = hash::blake3_hash(&new_signable);
    let new_sig = sig::HybridSignature::from_bytes(&cert.new_signature)?;
    sig::verify(
        &new_verifying_key,
        ROTATE_SIGN_DOMAIN,
        &new_hash,
        &new_sig,
    )
    .map_err(|_| Error::AuthenticationFailed)?;

    // Mark the old contact as Rotated.
    let mut old_updated = old_record;
    old_updated.status = IdentityStatus::Rotated;
    store.save_contact(&old_updated).map_err(map_store_error)?;

    // Save the new contact.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let new_contact = ContactRecord {
        identity_id: cert.new_identity_id,
        display_name: cert.new_display_name.clone(),
        ed25519_pk: cert.new_ed25519_pk,
        ml_dsa_pk: cert.new_ml_dsa_pk,
        x25519_pk: cert.new_x25519_pk,
        ml_kem_pk: cert.new_ml_kem_pk,
        imported_at: now,
        status: IdentityStatus::Active,
    };
    store.save_contact(&new_contact).map_err(map_store_error)?;

    Ok(cert.new_identity_id)
}

/// Format a 16-byte identity ID as hex.
pub(crate) fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Return an `IdentityRevoked` error for the given identity.
pub(crate) fn revoked_error(id: &[u8; 16]) -> Error {
    Error::IdentityRevoked {
        identity_id: hex_id(id),
    }
}

// ---------------------------------------------------------------------------
// Private key bundle serialization
// ---------------------------------------------------------------------------

/// Format: `[ed25519_sk: 32][ml_dsa_seed: 32][x25519_sk: 32][ml_kem_dk_len: u16 BE][ml_kem_dk]`
fn serialize_private_keys(
    signing_key: &sig::HybridSigningKey,
    kem_keypair: &kem::HybridKeyPair,
) -> Vec<u8> {
    let ed_sk = signing_key.classical.to_bytes();
    let pq_seed = signing_key.pq.to_bytes();
    let x_sk = kem_keypair.classical_secret.to_bytes();
    let pq_dk = kem_keypair.pq_secret.to_bytes();

    let mut buf = Vec::with_capacity(32 + pq_seed.len() + 32 + 2 + pq_dk.len());
    buf.extend_from_slice(&ed_sk);
    buf.extend_from_slice(&pq_seed);
    buf.extend_from_slice(&x_sk);
    buf.extend_from_slice(&(pq_dk.len() as u16).to_be_bytes());
    buf.extend_from_slice(&pq_dk);
    buf
}

/// Reconstruct full key objects from private bundle + record's public keys.
fn reconstruct_keys(
    bundle: &[u8],
    record: &IdentityRecord,
) -> Result<
    (
        sig::HybridSigningKey,
        sig::HybridVerifyingKey,
        kem::HybridKeyPair,
        kem::HybridPublicKey,
    ),
    Error,
> {
    let mut pos = 0;

    // Ed25519 signing key.
    let ed_sk = read_fixed::<32>(bundle, &mut pos)?;
    let classical_signing = sig::ClassicalSigningKey::from_bytes(&ed_sk);

    // ML-DSA-65 seed.
    let pq_seed = read_fixed::<32>(bundle, &mut pos)?;
    let pq_signing = sig::PqSigningKey::from_bytes(&pq_seed)
        .map_err(|_| Error::InvalidKeyMaterial { context: "ML-DSA-65 signing key in identity record" })?;

    // X25519 secret key.
    let x_sk = read_fixed::<32>(bundle, &mut pos)?;
    let classical_secret = kem::ClassicalSecretKey::from_bytes(x_sk);

    // ML-KEM-768 decapsulation key.
    let dk_len = read_u16(bundle, &mut pos)? as usize;
    if pos + dk_len > bundle.len() {
        return Err(Error::TruncatedInput);
    }
    let pq_secret = kem::PqSecretKey::from_bytes(&bundle[pos..pos + dk_len])
        .map_err(|_| Error::InvalidKeyMaterial { context: "ML-KEM-768 secret key in identity record" })?;

    // Reconstruct public keys from the record.
    let ed_pk_arr: [u8; 32] = record
        .ed25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 public key in identity record" })?;
    let classical_verifying =
        sig::ClassicalVerifyingKey::from_bytes(&ed_pk_arr)
            .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 verifying key in identity record" })?;

    let pq_verifying =
        sig::PqVerifyingKey::from_bytes(&record.ml_dsa_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "ML-DSA-65 verifying key in identity record" })?;

    let x_pk_arr: [u8; 32] = record
        .x25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "X25519 public key in identity record" })?;
    let classical_public = kem::ClassicalPublicKey::from_bytes(x_pk_arr);

    let pq_public = kem::PqPublicKey::from_bytes(&record.ml_kem_pk)
        .map_err(|_| Error::InvalidKeyMaterial { context: "ML-KEM-768 public key in identity record" })?;

    let signing_key = sig::HybridSigningKey {
        classical: classical_signing,
        pq: pq_signing,
    };
    let verifying_key = sig::HybridVerifyingKey {
        classical: classical_verifying.clone(),
        pq: pq_verifying.clone(),
    };
    let kem_public_key = kem::HybridPublicKey {
        classical: classical_public.clone(),
        pq: pq_public.clone(),
    };
    let kem_kp = kem::HybridKeyPair {
        classical_secret,
        classical_public,
        pq_secret,
        pq_public,
    };

    Ok((signing_key, verifying_key, kem_kp, kem_public_key))
}

/// Reconstruct a PublicIdentity from a ContactRecord.
fn reconstruct_public_identity(record: &ContactRecord) -> Result<PublicIdentity, Error> {
    let ed_pk: [u8; 32] = record
        .ed25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 public key in contact record" })?;
    let classical_vk =
        sig::ClassicalVerifyingKey::from_bytes(&ed_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "Ed25519 verifying key in contact record" })?;
    let pq_vk =
        sig::PqVerifyingKey::from_bytes(&record.ml_dsa_pk)
            .map_err(|_| Error::InvalidKeyMaterial { context: "ML-DSA-65 verifying key in contact record" })?;

    let x_pk: [u8; 32] = record
        .x25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial { context: "X25519 public key in contact record" })?;
    let classical_pk = kem::ClassicalPublicKey::from_bytes(x_pk);
    let pq_pk = kem::PqPublicKey::from_bytes(&record.ml_kem_pk)
        .map_err(|_| Error::InvalidKeyMaterial { context: "ML-KEM-768 public key in contact record" })?;

    Ok(PublicIdentity {
        identity_id: record.identity_id,
        display_name: record.display_name.clone(),
        status: record.status,
        verifying_key: sig::HybridVerifyingKey {
            classical: classical_vk,
            pq: pq_vk,
        },
        kem_public: kem::HybridPublicKey {
            classical: classical_pk,
            pq: pq_pk,
        },
    })
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N], Error> {
    if *pos + N > data.len() {
        return Err(Error::TruncatedInput);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    Ok(arr)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, Error> {
    if *pos + 2 > data.len() {
        return Err(Error::TruncatedInput);
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_store_error(e: StoreError) -> Error {
    match e {
        StoreError::InvalidPassphrase => Error::InvalidPassphrase,
        StoreError::IdentityNotFound { identity_id } => {
            Error::StorageError(format!("identity not found: {identity_id}"))
        }
        StoreError::ContactNotFound { identity_id } => {
            Error::StorageError(format!("contact not found: {identity_id}"))
        }
        StoreError::CorruptRecord { reason } => Error::StorageError(reason.to_string()),
        StoreError::Io(e) => Error::StorageError(e.to_string()),
        StoreError::Crypto(e) => Error::Core(e),
    }
}
