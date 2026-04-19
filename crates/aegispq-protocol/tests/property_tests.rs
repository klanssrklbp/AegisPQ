//! Property-based tests for aegispq-protocol.
//!
//! Uses proptest to exercise invariants that must hold for *all* inputs,
//! not just hand-picked test vectors.

use proptest::prelude::*;

use aegispq_core::{kem, sig};
use aegispq_protocol::file::{encrypt, decrypt, RecipientInfo};
use aegispq_protocol::identity::{KeyPackage, IDENTITY_ID_LEN};
use aegispq_protocol::padding::{pad, unpad, PaddingScheme};
use aegispq_protocol::revocation::{RevocationCertificate, RevocationReason};
use aegispq_protocol::rotation::RotationCertificate;
use aegispq_protocol::Suite;

// ---------------------------------------------------------------------------
// Helpers — keygen is slow, so we generate identities once per test function.
// ---------------------------------------------------------------------------

struct TestIdentity {
    identity_id: [u8; IDENTITY_ID_LEN],
    signing_key: sig::HybridSigningKey,
    verifying_key: sig::HybridVerifyingKey,
    kem_keypair: kem::HybridKeyPair,
    kem_public: kem::HybridPublicKey,
}

fn make_identity() -> TestIdentity {
    let identity_id: [u8; IDENTITY_ID_LEN] =
        aegispq_core::nonce::random_bytes().unwrap();
    let (signing_key, verifying_key) = sig::generate_keypair().unwrap();
    let kem_keypair = kem::generate_keypair().unwrap();
    let kem_public = kem::public_key(&kem_keypair);
    TestIdentity {
        identity_id,
        signing_key,
        verifying_key,
        kem_keypair,
        kem_public,
    }
}

// ---------------------------------------------------------------------------
// 1. Roundtrip: encrypt then decrypt recovers plaintext
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn encrypt_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let sender = make_identity();
        let recipient = make_identity();

        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            &plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        prop_assert_eq!(decrypted, plaintext);
    }
}

// ---------------------------------------------------------------------------
// 2. Tamper detection: flipping any single byte in ciphertext causes failure
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn tamper_detection(flip_offset in 12usize..1000) {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"tamper detection test payload";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let mut encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Flip a byte at a valid index within the ciphertext.
        let idx = flip_offset % encrypted.len();
        encrypted[idx] ^= 0xFF;

        let result = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );

        prop_assert!(result.is_err(), "decrypt should fail after tampering at byte {}", idx);
    }
}

// ---------------------------------------------------------------------------
// 3. Trailing data rejection
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn trailing_data_rejection(extra in proptest::collection::vec(any::<u8>(), 1..64)) {
        let sender = make_identity();
        let recipient = make_identity();

        let plaintext = b"trailing data test";
        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let mut encrypted = encrypt(
            plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        encrypted.extend_from_slice(&extra);

        let result = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        );

        prop_assert!(result.is_err(), "decrypt should fail with trailing data");
    }
}

// ---------------------------------------------------------------------------
// 4. Padding roundtrip for all PaddingScheme variants
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn padding_roundtrip_power_of_two(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let padded = pad(&data, PaddingScheme::PowerOfTwo, 0);
        let recovered = unpad(&padded).unwrap();
        prop_assert_eq!(recovered, data);
    }

    #[test]
    fn padding_roundtrip_fixed_block(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let padded = pad(&data, PaddingScheme::FixedBlock, 4096);
        let recovered = unpad(&padded).unwrap();
        prop_assert_eq!(recovered, data);
    }

    #[test]
    fn padding_roundtrip_none(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let padded = pad(&data, PaddingScheme::None, 0);
        let recovered = unpad(&padded).unwrap();
        prop_assert_eq!(recovered, data);
    }
}

// ---------------------------------------------------------------------------
// 5. Key package roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn key_package_roundtrip(
        identity_id in proptest::collection::vec(any::<u8>(), 16..=16),
        display_name in "[a-zA-Z0-9 ]{0,64}",
        sig_bytes in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut id = [0u8; IDENTITY_ID_LEN];
        id.copy_from_slice(&identity_id);

        let kp = KeyPackage {
            identity_id: id,
            display_name: display_name.clone(),
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            created_at: 1711800000,
            signature: sig_bytes.clone(),
        };

        let bytes = kp.to_bytes();
        let parsed = KeyPackage::from_bytes(&bytes).unwrap();

        prop_assert_eq!(parsed.identity_id, id);
        prop_assert_eq!(&parsed.display_name, &display_name);
        prop_assert_eq!(&parsed.ed25519_pk, &kp.ed25519_pk);
        prop_assert_eq!(&parsed.ml_dsa_pk, &kp.ml_dsa_pk);
        prop_assert_eq!(&parsed.x25519_pk, &kp.x25519_pk);
        prop_assert_eq!(&parsed.ml_kem_pk, &kp.ml_kem_pk);
        prop_assert_eq!(parsed.created_at, kp.created_at);
        prop_assert_eq!(&parsed.signature, &sig_bytes);
    }
}

// ---------------------------------------------------------------------------
// 6. Revocation certificate roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn revocation_cert_roundtrip(
        identity_id in proptest::collection::vec(any::<u8>(), 16..=16),
        reason_byte in 1u8..=3u8,
        effective_at in any::<u64>(),
        signature in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut id = [0u8; IDENTITY_ID_LEN];
        id.copy_from_slice(&identity_id);

        let reason = RevocationReason::from_byte(reason_byte).unwrap();

        let cert = RevocationCertificate {
            identity_id: id,
            reason,
            effective_at,
            signature: signature.clone(),
        };

        let bytes = cert.to_bytes();
        let parsed = RevocationCertificate::from_bytes(&bytes).unwrap();

        prop_assert_eq!(parsed.identity_id, id);
        prop_assert_eq!(parsed.reason, reason);
        prop_assert_eq!(parsed.effective_at, effective_at);
        prop_assert_eq!(&parsed.signature, &signature);
    }
}

// ---------------------------------------------------------------------------
// 7b. Encrypt/decrypt across all padding modes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    #[test]
    fn encrypt_decrypt_all_padding_modes(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        padding_choice in 0u8..3,
    ) {
        let padding = match padding_choice {
            0 => PaddingScheme::None,
            1 => PaddingScheme::PowerOfTwo,
            _ => PaddingScheme::FixedBlock,
        };
        let block_size = if matches!(padding, PaddingScheme::FixedBlock) { 4096 } else { 0 };

        let sender = make_identity();
        let recipient = make_identity();

        let recipients = [RecipientInfo {
            identity_id: recipient.identity_id,
            kem_public_key: recipient.kem_public,
        }];

        let encrypted = encrypt(
            &plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            padding,
            block_size,
        )
        .unwrap();

        let decrypted = decrypt(
            &encrypted,
            &recipient.kem_keypair,
            &recipient.identity_id,
            &sender.verifying_key,
        )
        .unwrap();

        prop_assert_eq!(decrypted, plaintext);
    }
}

// ---------------------------------------------------------------------------
// 8. Recipient mismatch: a non-recipient's key material cannot decrypt
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn recipient_mismatch_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let sender = make_identity();
        let intended = make_identity();
        let stranger = make_identity();

        let recipients = [RecipientInfo {
            identity_id: intended.identity_id,
            kem_public_key: intended.kem_public,
        }];

        let encrypted = encrypt(
            &plaintext,
            &sender.signing_key,
            &sender.identity_id,
            &recipients,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        )
        .unwrap();

        // Stranger attempts to decrypt with their own key material. Must fail:
        // they have no recipient slot in the file (NotRecipient) AND their
        // key wouldn't decapsulate even if they did.
        let stranger_result = decrypt(
            &encrypted,
            &stranger.kem_keypair,
            &stranger.identity_id,
            &sender.verifying_key,
        );
        prop_assert!(stranger_result.is_err(), "stranger must not decrypt");

        // Intended recipient trying to pass off as a different identity ID
        // (ID mismatch) must also fail at slot lookup.
        let wrong_id_result = decrypt(
            &encrypted,
            &intended.kem_keypair,
            &stranger.identity_id, // wrong ID
            &sender.verifying_key,
        );
        prop_assert!(wrong_id_result.is_err(), "ID mismatch must reject");
    }
}

// ---------------------------------------------------------------------------
// 9. Serialization stability: parse -> reserialize produces identical bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn key_package_reserialize_stable(
        identity_id in proptest::collection::vec(any::<u8>(), 16..=16),
        display_name in "[a-zA-Z0-9 ]{0,32}",
        created_at in any::<u64>(),
        sig in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut id = [0u8; IDENTITY_ID_LEN];
        id.copy_from_slice(&identity_id);

        let original = KeyPackage {
            identity_id: id,
            display_name,
            ed25519_pk: vec![0x11; 32],
            ml_dsa_pk: vec![0x22; 1952],
            x25519_pk: vec![0x33; 32],
            ml_kem_pk: vec![0x44; 1184],
            created_at,
            signature: sig,
        };

        let bytes_a = original.to_bytes();
        let parsed = KeyPackage::from_bytes(&bytes_a).unwrap();
        let bytes_b = parsed.to_bytes();

        prop_assert_eq!(bytes_a, bytes_b, "reserializing a parsed key package must match");
    }

    #[test]
    fn revocation_cert_reserialize_stable(
        identity_id in proptest::collection::vec(any::<u8>(), 16..=16),
        reason_byte in 1u8..=3u8,
        effective_at in any::<u64>(),
        signature in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut id = [0u8; IDENTITY_ID_LEN];
        id.copy_from_slice(&identity_id);

        let cert = RevocationCertificate {
            identity_id: id,
            reason: RevocationReason::from_byte(reason_byte).unwrap(),
            effective_at,
            signature,
        };

        let bytes_a = cert.to_bytes();
        let parsed = RevocationCertificate::from_bytes(&bytes_a).unwrap();
        let bytes_b = parsed.to_bytes();

        prop_assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn rotation_cert_reserialize_stable(
        old_id in proptest::collection::vec(any::<u8>(), 16..=16),
        new_id in proptest::collection::vec(any::<u8>(), 16..=16),
        effective_at in any::<u64>(),
        display_name in "[a-zA-Z0-9 ]{0,32}",
    ) {
        let mut old_identity_id = [0u8; IDENTITY_ID_LEN];
        old_identity_id.copy_from_slice(&old_id);
        let mut new_identity_id = [0u8; IDENTITY_ID_LEN];
        new_identity_id.copy_from_slice(&new_id);

        let cert = RotationCertificate {
            old_identity_id,
            new_identity_id,
            effective_at,
            new_ed25519_pk: vec![1; 32],
            new_ml_dsa_pk: vec![2; 1952],
            new_x25519_pk: vec![3; 32],
            new_ml_kem_pk: vec![4; 1184],
            new_display_name: display_name,
            old_signature: vec![0xAA; 64],
            new_signature: vec![0xBB; 64],
        };

        let bytes_a = cert.to_bytes();
        let parsed = RotationCertificate::from_bytes(&bytes_a).unwrap();
        let bytes_b = parsed.to_bytes();

        prop_assert_eq!(bytes_a, bytes_b);
    }
}

// ---------------------------------------------------------------------------
// 10. Rotation certificate roundtrip (by-value)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn rotation_cert_roundtrip(
        old_id in proptest::collection::vec(any::<u8>(), 16..=16),
        new_id in proptest::collection::vec(any::<u8>(), 16..=16),
        effective_at in any::<u64>(),
        display_name in "[a-zA-Z0-9 ]{0,64}",
        old_sig in proptest::collection::vec(any::<u8>(), 0..128),
        new_sig in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut old_identity_id = [0u8; IDENTITY_ID_LEN];
        old_identity_id.copy_from_slice(&old_id);
        let mut new_identity_id = [0u8; IDENTITY_ID_LEN];
        new_identity_id.copy_from_slice(&new_id);

        let cert = RotationCertificate {
            old_identity_id,
            new_identity_id,
            effective_at,
            new_ed25519_pk: vec![1; 32],
            new_ml_dsa_pk: vec![2; 1952],
            new_x25519_pk: vec![3; 32],
            new_ml_kem_pk: vec![4; 1184],
            new_display_name: display_name.clone(),
            old_signature: old_sig.clone(),
            new_signature: new_sig.clone(),
        };

        let bytes = cert.to_bytes();
        let parsed = RotationCertificate::from_bytes(&bytes).unwrap();

        prop_assert_eq!(parsed.old_identity_id, old_identity_id);
        prop_assert_eq!(parsed.new_identity_id, new_identity_id);
        prop_assert_eq!(parsed.effective_at, effective_at);
        prop_assert_eq!(&parsed.new_ed25519_pk, &cert.new_ed25519_pk);
        prop_assert_eq!(&parsed.new_ml_dsa_pk, &cert.new_ml_dsa_pk);
        prop_assert_eq!(&parsed.new_x25519_pk, &cert.new_x25519_pk);
        prop_assert_eq!(&parsed.new_ml_kem_pk, &cert.new_ml_kem_pk);
        prop_assert_eq!(&parsed.new_display_name, &display_name);
        prop_assert_eq!(&parsed.old_signature, &old_sig);
        prop_assert_eq!(&parsed.new_signature, &new_sig);
    }
}
