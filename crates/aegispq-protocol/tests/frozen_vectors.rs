//! Frozen protocol test vectors.
//!
//! This file tests that serialized protocol objects remain byte-for-byte
//! identical across code changes. Each test constructs a deterministic
//! fixture (no randomness), serializes it, and compares against a frozen
//! binary file checked into the repo under `tests/vectors/v1/`.
//!
//! ## Workflow
//!
//! 1. Run `cargo test -p aegispq-protocol --test frozen_vectors -- --ignored`
//!    to (re)generate the `.bin` fixtures.
//! 2. Run the normal test suite — each test loads its fixture and validates
//!    that the current code produces **identical** bytes and that all parsed
//!    fields match expectations.
//!
//! If a legitimate protocol change invalidates a fixture, bump the version
//! directory (`v2/`) and regenerate. Do **not** silently overwrite `v1/`
//! fixtures — they document what the first release shipped.

use std::path::PathBuf;

use aegispq_protocol::envelope::HEADER_SIZE;
use aegispq_protocol::identity::{KeyPackage, IDENTITY_ID_LEN};
use aegispq_protocol::revocation::{RevocationCertificate, RevocationReason};
use aegispq_protocol::rotation::RotationCertificate;
use aegispq_protocol::{FormatType, MAGIC};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("v1")
}

// ---------------------------------------------------------------------------
// Deterministic fixtures
// ---------------------------------------------------------------------------

/// A key package with every field set to a deterministic, memorable value.
fn fixture_key_package() -> KeyPackage {
    KeyPackage {
        identity_id: [0x01; IDENTITY_ID_LEN],
        display_name: "TestUser".to_string(),
        ed25519_pk: vec![0x11; 32],
        ml_dsa_pk: vec![0x22; 1952],
        x25519_pk: vec![0x33; 32],
        ml_kem_pk: vec![0x44; 1184],
        created_at: 1_700_000_000,
        signature: vec![0x55; 128],
    }
}

/// A revocation certificate with deterministic fields.
fn fixture_revocation_cert() -> RevocationCertificate {
    RevocationCertificate {
        identity_id: [0xAA; IDENTITY_ID_LEN],
        reason: RevocationReason::Compromised,
        effective_at: 1_700_100_000,
        signature: vec![0xBB; 96],
    }
}

/// A rotation certificate with deterministic fields.
fn fixture_rotation_cert() -> RotationCertificate {
    RotationCertificate {
        old_identity_id: [0xCC; IDENTITY_ID_LEN],
        new_identity_id: [0xDD; IDENTITY_ID_LEN],
        effective_at: 1_700_200_000,
        new_display_name: "Rotated".to_string(),
        new_ed25519_pk: vec![0xE1; 32],
        new_ml_dsa_pk: vec![0xE2; 1952],
        new_x25519_pk: vec![0xE3; 32],
        new_ml_kem_pk: vec![0xE4; 1184],
        old_signature: vec![0xF1; 64],
        new_signature: vec![0xF2; 64],
    }
}

// ---------------------------------------------------------------------------
// Generator tests (#[ignore] — run explicitly to create fixtures)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn generate_key_package_vector() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = fixture_key_package().to_bytes();
    std::fs::write(dir.join("key_package.bin"), &bytes).unwrap();
    eprintln!(
        "wrote key_package.bin ({} bytes) to {}",
        bytes.len(),
        dir.display()
    );
}

#[test]
#[ignore]
fn generate_revocation_cert_vector() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = fixture_revocation_cert().to_bytes();
    std::fs::write(dir.join("revocation_cert.bin"), &bytes).unwrap();
    eprintln!(
        "wrote revocation_cert.bin ({} bytes) to {}",
        bytes.len(),
        dir.display()
    );
}

#[test]
#[ignore]
fn generate_rotation_cert_vector() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = fixture_rotation_cert().to_bytes();
    std::fs::write(dir.join("rotation_cert.bin"), &bytes).unwrap();
    eprintln!(
        "wrote rotation_cert.bin ({} bytes) to {}",
        bytes.len(),
        dir.display()
    );
}

// ---------------------------------------------------------------------------
// Validation tests (run normally)
// ---------------------------------------------------------------------------

#[test]
fn key_package_vector_stable() {
    let fixture_path = vectors_dir().join("key_package.bin");
    let frozen = std::fs::read(&fixture_path).unwrap_or_else(|_| {
        panic!(
            "frozen vector not found at {}. Run with --ignored to generate.",
            fixture_path.display()
        )
    });

    // Current code must produce identical bytes.
    let fresh = fixture_key_package().to_bytes();
    assert_eq!(
        frozen, fresh,
        "key_package.bin has drifted from the current serializer — \
         protocol format may have changed"
    );

    // Validate header prefix.
    assert_eq!(&frozen[0..4], &MAGIC);
    assert_eq!(frozen[4], FormatType::KeyPackage as u8);

    // Parse and verify every field.
    let parsed = KeyPackage::from_bytes(&frozen).expect("frozen key package must parse");
    assert_eq!(parsed.identity_id, [0x01; IDENTITY_ID_LEN]);
    assert_eq!(parsed.display_name, "TestUser");
    assert_eq!(parsed.ed25519_pk, vec![0x11; 32]);
    assert_eq!(parsed.ml_dsa_pk, vec![0x22; 1952]);
    assert_eq!(parsed.x25519_pk, vec![0x33; 32]);
    assert_eq!(parsed.ml_kem_pk, vec![0x44; 1184]);
    assert_eq!(parsed.created_at, 1_700_000_000);
    assert_eq!(parsed.signature, vec![0x55; 128]);
}

#[test]
fn revocation_cert_vector_stable() {
    let fixture_path = vectors_dir().join("revocation_cert.bin");
    let frozen = std::fs::read(&fixture_path).unwrap_or_else(|_| {
        panic!(
            "frozen vector not found at {}. Run with --ignored to generate.",
            fixture_path.display()
        )
    });

    let fresh = fixture_revocation_cert().to_bytes();
    assert_eq!(
        frozen, fresh,
        "revocation_cert.bin has drifted from the current serializer"
    );

    // Validate header prefix.
    assert_eq!(&frozen[0..4], &MAGIC);
    assert_eq!(frozen[4], FormatType::RevocationCertificate as u8);

    let parsed = RevocationCertificate::from_bytes(&frozen).expect("frozen revocation cert must parse");
    assert_eq!(parsed.identity_id, [0xAA; IDENTITY_ID_LEN]);
    assert_eq!(parsed.reason, RevocationReason::Compromised);
    assert_eq!(parsed.effective_at, 1_700_100_000);
    assert_eq!(parsed.signature, vec![0xBB; 96]);
}

#[test]
fn rotation_cert_vector_stable() {
    let fixture_path = vectors_dir().join("rotation_cert.bin");
    let frozen = std::fs::read(&fixture_path).unwrap_or_else(|_| {
        panic!(
            "frozen vector not found at {}. Run with --ignored to generate.",
            fixture_path.display()
        )
    });

    let fresh = fixture_rotation_cert().to_bytes();
    assert_eq!(
        frozen, fresh,
        "rotation_cert.bin has drifted from the current serializer"
    );

    // Validate header prefix.
    assert_eq!(&frozen[0..4], &MAGIC);
    assert_eq!(frozen[4], FormatType::RotationCertificate as u8);

    let parsed = RotationCertificate::from_bytes(&frozen).expect("frozen rotation cert must parse");
    assert_eq!(parsed.old_identity_id, [0xCC; IDENTITY_ID_LEN]);
    assert_eq!(parsed.new_identity_id, [0xDD; IDENTITY_ID_LEN]);
    assert_eq!(parsed.effective_at, 1_700_200_000);
    assert_eq!(parsed.new_display_name, "Rotated");
    assert_eq!(parsed.new_ed25519_pk, vec![0xE1; 32]);
    assert_eq!(parsed.new_ml_dsa_pk, vec![0xE2; 1952]);
    assert_eq!(parsed.new_x25519_pk, vec![0xE3; 32]);
    assert_eq!(parsed.new_ml_kem_pk, vec![0xE4; 1184]);
    assert_eq!(parsed.old_signature, vec![0xF1; 64]);
    assert_eq!(parsed.new_signature, vec![0xF2; 64]);
}

// ---------------------------------------------------------------------------
// Size stability — catch accidental growth/shrinkage
// ---------------------------------------------------------------------------

#[test]
fn key_package_vector_size_pinned() {
    let frozen = std::fs::read(vectors_dir().join("key_package.bin")).unwrap();
    // Header(12) + identity_id(16) + name_len(2) + "TestUser"(8)
    // + 4 × (len_prefix(2) + key_bytes) + timestamp(8) + sig_len(2) + sig(128)
    // = 12 + 16 + 2 + 8 + (2+32 + 2+1952 + 2+32 + 2+1184) + 8 + 2 + 128
    // = 12 + 16 + 10 + 3206 + 138 = 3382
    let expected_size = HEADER_SIZE + 16 + 2 + 8 + (2 + 32) + (2 + 1952) + (2 + 32) + (2 + 1184) + 8 + 2 + 128;
    assert_eq!(
        frozen.len(),
        expected_size,
        "key package wire size must not change without a version bump"
    );
}

#[test]
fn revocation_cert_vector_size_pinned() {
    let frozen = std::fs::read(vectors_dir().join("revocation_cert.bin")).unwrap();
    // Header(12) + identity_id(16) + reason(1) + effective_at(8) + sig_len(2) + sig(96)
    let expected_size = HEADER_SIZE + 16 + 1 + 8 + 2 + 96;
    assert_eq!(
        frozen.len(),
        expected_size,
        "revocation cert wire size must not change without a version bump"
    );
}

#[test]
fn rotation_cert_vector_size_pinned() {
    let frozen = std::fs::read(vectors_dir().join("rotation_cert.bin")).unwrap();
    // Header(12) + old_id(16) + new_id(16) + effective_at(8)
    // + 4 × (len_prefix(2) + key) + name_len(2) + "Rotated"(7)
    // + 2 × (sig_len(2) + sig(64))
    let expected_size = HEADER_SIZE + 16 + 16 + 8
        + (2 + 32) + (2 + 1952) + (2 + 32) + (2 + 1184)
        + 2 + 7
        + (2 + 64) + (2 + 64);
    assert_eq!(
        frozen.len(),
        expected_size,
        "rotation cert wire size must not change without a version bump"
    );
}

// ---------------------------------------------------------------------------
// Conformance tests — tamper, truncation, trailing data
// ---------------------------------------------------------------------------

/// Flipping any single byte in the payload (past the header) should cause
/// a parse-field mismatch or at least not crash.
#[test]
fn key_package_single_byte_tamper_detected() {
    let frozen = std::fs::read(vectors_dir().join("key_package.bin")).unwrap();
    let reference = fixture_key_package();

    // Skip header (12 bytes) and tamper each subsequent byte.
    for i in HEADER_SIZE..frozen.len() {
        let mut tampered = frozen.clone();
        tampered[i] ^= 0xFF;

        // Must not panic. Either it fails to parse or parses with different fields.
        match KeyPackage::from_bytes(&tampered) {
            Err(_) => {} // expected — tampered data rejected
            Ok(parsed) => {
                // If it parses, at least one field must differ from the reference.
                let differs = parsed.identity_id != reference.identity_id
                    || parsed.display_name != reference.display_name
                    || parsed.ed25519_pk != reference.ed25519_pk
                    || parsed.ml_dsa_pk != reference.ml_dsa_pk
                    || parsed.x25519_pk != reference.x25519_pk
                    || parsed.ml_kem_pk != reference.ml_kem_pk
                    || parsed.created_at != reference.created_at
                    || parsed.signature != reference.signature;
                assert!(
                    differs,
                    "tamper at byte {i} was not detected: parsed fields match original"
                );
            }
        }
    }
}

#[test]
fn revocation_cert_single_byte_tamper_detected() {
    let frozen = std::fs::read(vectors_dir().join("revocation_cert.bin")).unwrap();
    let reference = fixture_revocation_cert();

    for i in HEADER_SIZE..frozen.len() {
        let mut tampered = frozen.clone();
        tampered[i] ^= 0xFF;

        match RevocationCertificate::from_bytes(&tampered) {
            Err(_) => {}
            Ok(parsed) => {
                let differs = parsed.identity_id != reference.identity_id
                    || parsed.reason != reference.reason
                    || parsed.effective_at != reference.effective_at
                    || parsed.signature != reference.signature;
                assert!(
                    differs,
                    "tamper at byte {i} was not detected in revocation cert"
                );
            }
        }
    }
}

#[test]
fn rotation_cert_single_byte_tamper_detected() {
    let frozen = std::fs::read(vectors_dir().join("rotation_cert.bin")).unwrap();
    let reference = fixture_rotation_cert();

    for i in HEADER_SIZE..frozen.len() {
        let mut tampered = frozen.clone();
        tampered[i] ^= 0xFF;

        match RotationCertificate::from_bytes(&tampered) {
            Err(_) => {}
            Ok(parsed) => {
                let differs = parsed.old_identity_id != reference.old_identity_id
                    || parsed.new_identity_id != reference.new_identity_id
                    || parsed.effective_at != reference.effective_at
                    || parsed.new_display_name != reference.new_display_name
                    || parsed.new_ed25519_pk != reference.new_ed25519_pk
                    || parsed.new_ml_dsa_pk != reference.new_ml_dsa_pk
                    || parsed.new_x25519_pk != reference.new_x25519_pk
                    || parsed.new_ml_kem_pk != reference.new_ml_kem_pk
                    || parsed.old_signature != reference.old_signature
                    || parsed.new_signature != reference.new_signature;
                assert!(
                    differs,
                    "tamper at byte {i} was not detected in rotation cert"
                );
            }
        }
    }
}

/// Truncating the vector at any point below the full size must fail to parse.
#[test]
fn key_package_truncation_rejected() {
    let frozen = std::fs::read(vectors_dir().join("key_package.bin")).unwrap();
    for len in 0..frozen.len() {
        assert!(
            KeyPackage::from_bytes(&frozen[..len]).is_err(),
            "key package truncated to {len} bytes should fail to parse"
        );
    }
}

#[test]
fn revocation_cert_truncation_rejected() {
    let frozen = std::fs::read(vectors_dir().join("revocation_cert.bin")).unwrap();
    for len in 0..frozen.len() {
        assert!(
            RevocationCertificate::from_bytes(&frozen[..len]).is_err(),
            "revocation cert truncated to {len} bytes should fail to parse"
        );
    }
}

#[test]
fn rotation_cert_truncation_rejected() {
    let frozen = std::fs::read(vectors_dir().join("rotation_cert.bin")).unwrap();
    for len in 0..frozen.len() {
        assert!(
            RotationCertificate::from_bytes(&frozen[..len]).is_err(),
            "rotation cert truncated to {len} bytes should fail to parse"
        );
    }
}

/// Appending trailing bytes must be rejected.
#[test]
fn key_package_trailing_data_rejected() {
    let mut data = std::fs::read(vectors_dir().join("key_package.bin")).unwrap();
    data.push(0x00);
    assert!(
        KeyPackage::from_bytes(&data).is_err(),
        "key package with trailing byte must be rejected"
    );
}

#[test]
fn revocation_cert_trailing_data_rejected() {
    let mut data = std::fs::read(vectors_dir().join("revocation_cert.bin")).unwrap();
    data.push(0x00);
    assert!(
        RevocationCertificate::from_bytes(&data).is_err(),
        "revocation cert with trailing byte must be rejected"
    );
}

#[test]
fn rotation_cert_trailing_data_rejected() {
    let mut data = std::fs::read(vectors_dir().join("rotation_cert.bin")).unwrap();
    data.push(0x00);
    assert!(
        RotationCertificate::from_bytes(&data).is_err(),
        "rotation cert with trailing byte must be rejected"
    );
}

/// A key package's bytes must not parse as a revocation or rotation certificate.
#[test]
fn cross_format_rejection() {
    let kp_data = std::fs::read(vectors_dir().join("key_package.bin")).unwrap();
    let rev_data = std::fs::read(vectors_dir().join("revocation_cert.bin")).unwrap();
    let rot_data = std::fs::read(vectors_dir().join("rotation_cert.bin")).unwrap();

    // Key package data should not parse as revocation or rotation.
    assert!(RevocationCertificate::from_bytes(&kp_data).is_err());
    assert!(RotationCertificate::from_bytes(&kp_data).is_err());

    // Revocation data should not parse as key package or rotation.
    assert!(KeyPackage::from_bytes(&rev_data).is_err());
    assert!(RotationCertificate::from_bytes(&rev_data).is_err());

    // Rotation data should not parse as key package or revocation.
    assert!(KeyPackage::from_bytes(&rot_data).is_err());
    assert!(RevocationCertificate::from_bytes(&rot_data).is_err());
}
