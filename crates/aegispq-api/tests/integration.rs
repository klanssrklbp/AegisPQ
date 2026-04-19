//! End-to-end integration tests for the aegispq-api crate.
//!
//! These tests exercise the full stack: identity creation, contact import,
//! file encryption/decryption, and standalone signing/verification.

use aegispq_api::encrypt;
use aegispq_api::identity;
use aegispq_api::sign;
use aegispq_api::types::{EncryptOptions, Identity, PublicIdentity};
use aegispq_api::IdentityStatus;
use aegispq_core::kdf;
use aegispq_protocol::padding::PaddingScheme;
use aegispq_protocol::Suite;
use aegispq_store::fs::FileStore;
use tempfile::TempDir;

/// Helper: create a FileStore backed by a temporary directory.
fn temp_store() -> (TempDir, FileStore) {
    let dir = TempDir::new().unwrap();
    let store = FileStore::open(dir.path()).unwrap();
    (dir, store)
}

/// Helper: create an identity with fast (test-only) Argon2 parameters.
fn fast_create(name: &str, passphrase: &[u8], store: &FileStore) -> Identity {
    identity::create_identity_with_params(name, passphrase, store, kdf::Argon2Params::testing())
        .unwrap()
}

/// Helper: rotate an identity with fast (test-only) Argon2 parameters.
fn fast_rotate(
    old: &Identity,
    name: &str,
    passphrase: &[u8],
    store: &FileStore,
) -> (Identity, Vec<u8>) {
    identity::rotate_identity_with_params(old, name, passphrase, store, kdf::Argon2Params::testing())
        .unwrap()
}

/// Helper: extract the public portion of an identity.
fn to_public(ident: &Identity) -> PublicIdentity {
    PublicIdentity {
        identity_id: ident.identity_id,
        display_name: ident.display_name.clone(),
        status: ident.status,
        verifying_key: ident.verifying_key.clone(),
        kem_public: ident.kem_public.clone(),
    }
}

// ---------------------------------------------------------------------------
// Identity management
// ---------------------------------------------------------------------------

#[test]
fn create_and_load_identity() {
    let (_dir, store) = temp_store();
    let passphrase = b"hunter2";

    let created = identity::create_identity_with_params("Alice", passphrase, &store, kdf::Argon2Params::testing()).unwrap();
    let loaded = identity::load_identity(&created.identity_id, passphrase, &store).unwrap();

    assert_eq!(created.identity_id, loaded.identity_id);
    assert_eq!(created.display_name, loaded.display_name);
    assert_eq!(
        created.verifying_key.classical.to_bytes(),
        loaded.verifying_key.classical.to_bytes()
    );
}

#[test]
fn wrong_passphrase_rejected() {
    let (_dir, store) = temp_store();

    let created = identity::create_identity_with_params("Bob", b"correct", &store, kdf::Argon2Params::testing()).unwrap();
    let result = identity::load_identity(&created.identity_id, b"wrong", &store);

    assert!(result.is_err());
}

#[test]
fn list_identities() {
    let (_dir, store) = temp_store();

    fast_create("Alice", b"p1", &store);
    fast_create("Bob", b"p2", &store);

    let ids = identity::list_identities(&store).unwrap();
    assert_eq!(ids.len(), 2);
}

#[test]
fn import_and_load_contact() {
    let (_dir1, store1) = temp_store();
    let (_dir2, store2) = temp_store();

    // Alice creates an identity.
    let alice = fast_create("Alice", b"pass", &store1);

    // Bob imports Alice's public identity.
    let alice_public = to_public(&alice);
    identity::import_contact(&alice_public, &store2).unwrap();

    // Bob can load Alice's contact.
    let loaded = identity::load_contact(&alice.identity_id, &store2).unwrap();
    assert_eq!(loaded.identity_id, alice.identity_id);
    assert_eq!(loaded.display_name, "Alice");
}

// ---------------------------------------------------------------------------
// File encryption / decryption
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);

    // Alice imports Bob as a contact (for encryption).
    let bob_public = to_public(&bob);

    // Bob imports Alice as a contact (for sender verification during decryption).
    let alice_public = to_public(&alice);
    identity::import_contact(&alice_public, &store).unwrap();

    let plaintext = b"Hello Bob, this is a secret message from Alice!";
    let options = EncryptOptions::default();

    let ciphertext = encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &options).unwrap();

    // Bob decrypts using store-integrated path.
    let decrypted = encrypt::decrypt_file(&ciphertext, &bob, &store).unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_identity_id, alice.identity_id);
}

#[test]
fn encrypt_decrypt_with_explicit_sender() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);

    let bob_public = to_public(&bob);
    let alice_public = to_public(&alice);

    let plaintext = b"explicit sender path";
    let options = EncryptOptions::default();

    let ciphertext = encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &options).unwrap();

    // Bob decrypts with explicit sender (no store lookup).
    let decrypted =
        encrypt::decrypt_file_with_sender(&ciphertext, &bob, &alice_public).unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_identity_id, alice.identity_id);
}

#[test]
fn encrypt_xchacha_suite() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);

    let bob_public = to_public(&bob);
    let alice_public = to_public(&alice);

    let plaintext = b"XChaCha20-Poly1305 test through the API layer";
    let options = EncryptOptions {
        padding: PaddingScheme::FixedBlock,
        chunk_size: 0,
        suite: Suite::HybridV1XChaCha,
    };

    let ciphertext = encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &options).unwrap();

    let decrypted =
        encrypt::decrypt_file_with_sender(&ciphertext, &bob, &alice_public).unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
}

#[test]
fn multi_recipient_encryption() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);
    let carol = fast_create("Carol", b"pass", &store);

    let bob_public = to_public(&bob);
    let carol_public = to_public(&carol);
    let alice_public = to_public(&alice);

    let plaintext = b"Confidential: for Bob and Carol only";
    let options = EncryptOptions::default();

    let ciphertext =
        encrypt::encrypt_file(plaintext, &alice, &[&bob_public, &carol_public], &options).unwrap();

    // Both Bob and Carol can decrypt.
    let bob_pt =
        encrypt::decrypt_file_with_sender(&ciphertext, &bob, &alice_public).unwrap();
    assert_eq!(bob_pt.plaintext, plaintext);

    let carol_pt =
        encrypt::decrypt_file_with_sender(&ciphertext, &carol, &alice_public).unwrap();
    assert_eq!(carol_pt.plaintext, plaintext);
}

#[test]
fn wrong_recipient_cannot_decrypt() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);
    let eve = fast_create("Eve", b"pass", &store);

    let bob_public = to_public(&bob);
    let alice_public = to_public(&alice);

    let plaintext = b"not for Eve";
    let options = EncryptOptions::default();

    let ciphertext = encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &options).unwrap();

    // Eve cannot decrypt.
    let result = encrypt::decrypt_file_with_sender(&ciphertext, &eve, &alice_public);
    assert!(result.is_err());
}

#[test]
fn extract_sender_id_from_ciphertext() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);

    let bob_public = to_public(&bob);

    let ciphertext =
        encrypt::encrypt_file(b"test", &alice, &[&bob_public], &EncryptOptions::default())
            .unwrap();

    let sender_id = encrypt::extract_sender_id(&ciphertext).unwrap();
    assert_eq!(sender_id, alice.identity_id);
}

// ---------------------------------------------------------------------------
// Standalone signing / verification
// ---------------------------------------------------------------------------

#[test]
fn sign_verify_roundtrip() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let alice_public = to_public(&alice);

    let data = b"This document is hereby signed.";
    let signature = sign::sign(&alice, data).unwrap();

    assert!(sign::verify(&alice_public, data, &signature).unwrap());
}

#[test]
fn verify_wrong_data_returns_false() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let alice_public = to_public(&alice);

    let signature = sign::sign(&alice, b"original").unwrap();

    assert!(!sign::verify(&alice_public, b"tampered", &signature).unwrap());
}

#[test]
fn verify_wrong_key_returns_false() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);
    let bob_public = to_public(&bob);

    let data = b"signed by Alice";
    let signature = sign::sign(&alice, data).unwrap();

    // Verify with Bob's key should fail.
    assert!(!sign::verify(&bob_public, data, &signature).unwrap());
}

#[test]
fn sign_empty_data() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let alice_public = to_public(&alice);

    let signature = sign::sign(&alice, b"").unwrap();
    assert!(sign::verify(&alice_public, b"", &signature).unwrap());
}

// ---------------------------------------------------------------------------
// Key package export / import
// ---------------------------------------------------------------------------

#[test]
fn export_import_key_package_roundtrip() {
    let (_dir1, store1) = temp_store();
    let (_dir2, store2) = temp_store();

    let alice = fast_create("Alice", b"pass", &store1);
    let fp_original = alice.fingerprint();

    // Alice exports her public key package.
    let pkg_bytes = identity::export_key_package(&alice).unwrap();

    // Bob imports Alice's key package.
    let imported = identity::import_key_package(&pkg_bytes, &store2).unwrap();

    assert_eq!(imported.identity_id, alice.identity_id);
    assert_eq!(imported.display_name, "Alice");
    assert_eq!(imported.fingerprint(), fp_original);

    // Bob can now load Alice as a contact.
    let loaded = identity::load_contact(&alice.identity_id, &store2).unwrap();
    assert_eq!(loaded.fingerprint(), fp_original);
}

#[test]
fn tampered_key_package_rejected() {
    let (_dir1, store1) = temp_store();
    let (_dir2, store2) = temp_store();

    let alice = fast_create("Alice", b"pass", &store1);
    let mut pkg_bytes = identity::export_key_package(&alice).unwrap();

    // Tamper with a byte in the middle of the package.
    let mid = pkg_bytes.len() / 2;
    pkg_bytes[mid] ^= 0xFF;

    // Import should fail (signature verification or parsing).
    let result = identity::import_key_package(&pkg_bytes, &store2);
    assert!(result.is_err());
}

#[test]
fn encrypt_decrypt_via_key_package() {
    let (_dir1, store_alice) = temp_store();
    let (_dir2, store_bob) = temp_store();

    // Alice and Bob each create identities in separate stores.
    let alice = fast_create("Alice", b"pass", &store_alice);
    let bob = fast_create("Bob", b"pass", &store_bob);

    // Exchange key packages.
    let alice_pkg = identity::export_key_package(&alice).unwrap();
    let bob_pkg = identity::export_key_package(&bob).unwrap();
    let bob_public = identity::import_key_package(&bob_pkg, &store_alice).unwrap();
    identity::import_key_package(&alice_pkg, &store_bob).unwrap();

    // Alice encrypts for Bob.
    let plaintext = b"Full roundtrip via key package exchange!";
    let options = EncryptOptions::default();
    let ciphertext =
        encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &options).unwrap();

    // Bob decrypts (store-integrated path looks up Alice as sender).
    let decrypted = encrypt::decrypt_file(&ciphertext, &bob, &store_bob).unwrap();
    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_identity_id, alice.identity_id);
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_consistent_across_load() {
    let (_dir, store) = temp_store();

    let created = fast_create("Alice", b"pass", &store);
    let fp1 = created.fingerprint();

    let loaded = identity::load_identity(&created.identity_id, b"pass", &store).unwrap();
    let fp2 = loaded.fingerprint();

    assert_eq!(fp1, fp2);
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn revoke_identity_marks_local_as_revoked() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    assert_eq!(alice.status, IdentityStatus::Active);

    let _cert_bytes = identity::revoke_identity(
        &alice,
        aegispq_api::RevocationReason::Retired,
        &store,
    )
    .unwrap();

    // Reload from store — should now be Revoked.
    let status = identity::load_identity_status(&alice.identity_id, &store).unwrap();
    assert_eq!(status, IdentityStatus::Revoked);
}

#[test]
fn revoked_identity_cannot_encrypt() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);
    let bob_public = to_public(&bob);

    // Revoke Alice.
    identity::revoke_identity(&alice, aegispq_api::RevocationReason::Compromised, &store).unwrap();

    // Reload Alice (now revoked).
    let alice_revoked = identity::load_identity(&alice.identity_id, b"pass", &store).unwrap();
    assert_eq!(alice_revoked.status, IdentityStatus::Revoked);

    // Encrypting should fail.
    let result = encrypt::encrypt_file(b"test", &alice_revoked, &[&bob_public], &EncryptOptions::default());
    assert!(result.is_err());
}

#[test]
fn revoked_identity_cannot_sign() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);

    identity::revoke_identity(&alice, aegispq_api::RevocationReason::Retired, &store).unwrap();

    let alice_revoked = identity::load_identity(&alice.identity_id, b"pass", &store).unwrap();

    let result = sign::sign(&alice_revoked, b"should fail");
    assert!(result.is_err());
}

#[test]
fn revoked_identity_can_still_decrypt() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);

    let alice_public = to_public(&alice);
    let bob_public = to_public(&bob);
    identity::import_contact(&alice_public, &store).unwrap();

    // Encrypt while Alice is still active.
    let plaintext = b"secret message for Bob";
    let ciphertext = encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &EncryptOptions::default()).unwrap();

    // Revoke Bob.
    identity::revoke_identity(&bob, aegispq_api::RevocationReason::Retired, &store).unwrap();
    let bob_revoked = identity::load_identity(&bob.identity_id, b"pass", &store).unwrap();
    assert_eq!(bob_revoked.status, IdentityStatus::Revoked);

    // Bob can still decrypt old ciphertexts (read-only access per spec).
    let decrypted = encrypt::decrypt_file(&ciphertext, &bob_revoked, &store).unwrap();
    assert_eq!(decrypted.plaintext, plaintext);
}

#[test]
fn cannot_encrypt_to_revoked_contact() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);

    // Create a revoked PublicIdentity for Bob.
    let mut bob_public = to_public(&bob);
    bob_public.status = IdentityStatus::Revoked;

    let result = encrypt::encrypt_file(b"test", &alice, &[&bob_public], &EncryptOptions::default());
    assert!(result.is_err());
}

#[test]
fn import_revocation_certificate() {
    let (_dir1, store_alice) = temp_store();
    let (_dir2, store_bob) = temp_store();

    let alice = fast_create("Alice", b"pass", &store_alice);

    // Bob imports Alice's key package.
    let pkg = identity::export_key_package(&alice).unwrap();
    identity::import_key_package(&pkg, &store_bob).unwrap();

    // Alice revokes herself and generates a certificate.
    let cert_bytes = identity::revoke_identity(
        &alice,
        aegispq_api::RevocationReason::Compromised,
        &store_alice,
    )
    .unwrap();

    // Bob imports the revocation certificate.
    let revoked_id = identity::import_revocation(&cert_bytes, &store_bob).unwrap();
    assert_eq!(revoked_id, alice.identity_id);

    // Alice is now revoked in Bob's store.
    let alice_contact = identity::load_contact(&alice.identity_id, &store_bob).unwrap();
    assert_eq!(alice_contact.status, IdentityStatus::Revoked);
}

#[test]
fn tampered_revocation_certificate_rejected() {
    let (_dir1, store_alice) = temp_store();
    let (_dir2, store_bob) = temp_store();

    let alice = fast_create("Alice", b"pass", &store_alice);

    let pkg = identity::export_key_package(&alice).unwrap();
    identity::import_key_package(&pkg, &store_bob).unwrap();

    let mut cert_bytes = identity::revoke_identity(
        &alice,
        aegispq_api::RevocationReason::Retired,
        &store_alice,
    )
    .unwrap();

    // Tamper with the certificate.
    let mid = cert_bytes.len() / 2;
    cert_bytes[mid] ^= 0xFF;

    let result = identity::import_revocation(&cert_bytes, &store_bob);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

#[test]
fn rotate_identity_creates_new_and_marks_old() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"old_pass", &store);
    let old_id = alice.identity_id;

    let (new_alice, _cert_bytes) =
        fast_rotate(&alice, "Alice (v2)", b"new_pass", &store);

    // New identity should be active with different ID.
    assert_ne!(new_alice.identity_id, old_id);
    assert_eq!(new_alice.display_name, "Alice (v2)");
    assert_eq!(new_alice.status, IdentityStatus::Active);

    // Old identity should be marked Rotated.
    let old_status = identity::load_identity_status(&old_id, &store).unwrap();
    assert_eq!(old_status, IdentityStatus::Rotated);

    // New identity can be loaded with the new passphrase.
    let loaded = identity::load_identity(&new_alice.identity_id, b"new_pass", &store).unwrap();
    assert_eq!(loaded.identity_id, new_alice.identity_id);
}

#[test]
fn import_rotation_certificate_updates_contact() {
    let (_dir1, store_alice) = temp_store();
    let (_dir2, store_bob) = temp_store();

    // Alice creates identity, Bob imports her key package.
    let alice = fast_create("Alice", b"pass", &store_alice);
    let pkg = identity::export_key_package(&alice).unwrap();
    identity::import_key_package(&pkg, &store_bob).unwrap();

    // Alice rotates.
    let (new_alice, cert_bytes) =
        fast_rotate(&alice, "Alice (v2)", b"new_pass", &store_alice);

    // Bob imports the rotation certificate.
    let new_id = identity::import_rotation(&cert_bytes, &store_bob).unwrap();
    assert_eq!(new_id, new_alice.identity_id);

    // Old contact is now Rotated in Bob's store.
    let old_contact = identity::load_contact(&alice.identity_id, &store_bob).unwrap();
    assert_eq!(old_contact.status, IdentityStatus::Rotated);

    // New contact is Active.
    let new_contact = identity::load_contact(&new_alice.identity_id, &store_bob).unwrap();
    assert_eq!(new_contact.status, IdentityStatus::Active);
    assert_eq!(new_contact.display_name, "Alice (v2)");
}

#[test]
fn encrypt_decrypt_after_rotation() {
    let (_dir1, store_alice) = temp_store();
    let (_dir2, store_bob) = temp_store();

    // Alice creates identity, exchanges key packages with Bob.
    let alice = fast_create("Alice", b"pass", &store_alice);
    let bob = fast_create("Bob", b"pass", &store_bob);

    let alice_pkg = identity::export_key_package(&alice).unwrap();
    let bob_pkg = identity::export_key_package(&bob).unwrap();
    let bob_public = identity::import_key_package(&bob_pkg, &store_alice).unwrap();
    identity::import_key_package(&alice_pkg, &store_bob).unwrap();

    // Alice rotates.
    let (new_alice, cert_bytes) =
        fast_rotate(&alice, "Alice (v2)", b"new_pass", &store_alice);

    // Bob imports the rotation certificate and re-imports new Alice as contact.
    identity::import_rotation(&cert_bytes, &store_bob).unwrap();

    // Alice also needs Bob imported in her new store context.
    // (bob_public was imported into store_alice earlier, still valid)

    // New Alice encrypts for Bob.
    let plaintext = b"Post-rotation message from Alice v2";
    let ciphertext = encrypt::encrypt_file(
        plaintext,
        &new_alice,
        &[&bob_public],
        &EncryptOptions::default(),
    )
    .unwrap();

    // Bob needs new Alice as a contact to verify sender.
    // She's already there from the rotation import.
    let decrypted = encrypt::decrypt_file(&ciphertext, &bob, &store_bob).unwrap();
    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_identity_id, new_alice.identity_id);
}

#[test]
fn tampered_rotation_certificate_rejected() {
    let (_dir1, store_alice) = temp_store();
    let (_dir2, store_bob) = temp_store();

    let alice = fast_create("Alice", b"pass", &store_alice);
    let pkg = identity::export_key_package(&alice).unwrap();
    identity::import_key_package(&pkg, &store_bob).unwrap();

    let (_new_alice, mut cert_bytes) =
        fast_rotate(&alice, "Alice (v2)", b"new_pass", &store_alice);

    // Tamper with the certificate.
    let mid = cert_bytes.len() / 2;
    cert_bytes[mid] ^= 0xFF;

    let result = identity::import_rotation(&cert_bytes, &store_bob);
    assert!(result.is_err());
}

#[test]
fn rotated_identity_cannot_encrypt() {
    let (_dir, store) = temp_store();

    let alice = fast_create("Alice", b"pass", &store);
    let bob = fast_create("Bob", b"pass", &store);
    let bob_public = to_public(&bob);

    // Rotate Alice (marks old as Rotated).
    fast_rotate(&alice, "Alice (v2)", b"new_pass", &store);

    // Reload old Alice — should be Rotated, which also blocks encrypt/sign.
    let old_alice = identity::load_identity(&alice.identity_id, b"pass", &store).unwrap();
    assert_eq!(old_alice.status, IdentityStatus::Rotated);

    // Old identity should not be usable for new encryption.
    let result = encrypt::encrypt_file(
        b"test",
        &old_alice,
        &[&bob_public],
        &EncryptOptions::default(),
    );
    assert!(result.is_err());
}
