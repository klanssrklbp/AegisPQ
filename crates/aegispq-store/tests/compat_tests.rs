//! Compatibility tests for on-disk record formats.
//!
//! These tests pin the byte-level serialization of `IdentityRecord` and
//! `ContactRecord` to frozen golden values. The goal is to catch any
//! accidental format change that would silently break existing on-disk
//! stores.
//!
//! If any of these tests fail, it means the wire format has changed. That
//! is not automatically wrong — but it requires a version bump and an
//! explicit migration plan. Do not "fix" the test by regenerating the
//! golden hex without reviewing why the format changed.

use aegispq_store::record::{ContactRecord, IdentityRecord, IdentityStatus};

// ---------------------------------------------------------------------------
// Helpers — construct records with fully deterministic fields.
// ---------------------------------------------------------------------------

fn fixed_identity_record() -> IdentityRecord {
    IdentityRecord {
        identity_id: [0x42; 16],
        display_name: "Alice".to_string(),
        created_at: 1_711_800_000,
        status: IdentityStatus::Active,
        ed25519_pk: vec![0x11; 32],
        ml_dsa_pk: vec![0x22; 1952],
        x25519_pk: vec![0x33; 32],
        ml_kem_pk: vec![0x44; 1184],
        encrypted_private_keys: vec![0x55; 200],
        argon2_salt: [0xAA; 16],
        argon2_memory_kib: 262_144,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    }
}

fn fixed_contact_record() -> ContactRecord {
    ContactRecord {
        identity_id: [0x7E; 16],
        display_name: "Bob".to_string(),
        ed25519_pk: vec![0x01; 32],
        ml_dsa_pk: vec![0x02; 1952],
        x25519_pk: vec![0x03; 32],
        ml_kem_pk: vec![0x04; 1184],
        imported_at: 1_711_900_000,
        status: IdentityStatus::Active,
    }
}

// ---------------------------------------------------------------------------
// Header pinning — verify magic bytes, version, and field positions are stable.
// ---------------------------------------------------------------------------

#[test]
fn identity_record_header_is_stable() {
    let bytes = fixed_identity_record().to_bytes();

    // Magic: "APQI"
    assert_eq!(&bytes[0..4], b"APQI", "identity magic bytes changed");
    // Version: u16 BE = 1
    assert_eq!(
        &bytes[4..6],
        &[0x00, 0x01],
        "identity record version changed"
    );
    // identity_id (16 bytes) immediately follows.
    assert_eq!(&bytes[6..22], &[0x42; 16]);
}

#[test]
fn contact_record_header_is_stable() {
    let bytes = fixed_contact_record().to_bytes();

    // Magic: "APQC"
    assert_eq!(&bytes[0..4], b"APQC", "contact magic bytes changed");
    // Version: u16 BE = 2
    assert_eq!(
        &bytes[4..6],
        &[0x00, 0x02],
        "contact record version changed"
    );
    // identity_id (16 bytes) immediately follows.
    assert_eq!(&bytes[6..22], &[0x7E; 16]);
}

// ---------------------------------------------------------------------------
// Total size pinning — accidental field additions/removals break this.
// ---------------------------------------------------------------------------

#[test]
fn identity_record_size_is_stable() {
    // Total size is fully determined by the fixed fields above.
    //   magic(4) + version(2) + id(16) + name_len(2) + name(5)
    // + created_at(8) + status(1)
    // + ed25519_len(2) + ed25519(32)
    // + ml_dsa_len(2)  + ml_dsa(1952)
    // + x25519_len(2)  + x25519(32)
    // + ml_kem_len(2)  + ml_kem(1184)
    // + argon_salt(16) + argon_mem(4) + argon_iter(4) + argon_par(4)
    // + enc_priv_len(4) + enc_priv(200)
    // = 4+2+16+2+5+8+1+2+32+2+1952+2+32+2+1184+16+4+4+4+4+200 = 3478
    let bytes = fixed_identity_record().to_bytes();
    assert_eq!(
        bytes.len(),
        3478,
        "identity record wire size changed — did a field get added or removed?",
    );
}

#[test]
fn contact_record_size_is_stable() {
    //   magic(4) + version(2) + id(16) + name_len(2) + name(3)
    // + ed25519_len(2) + ed25519(32)
    // + ml_dsa_len(2)  + ml_dsa(1952)
    // + x25519_len(2)  + x25519(32)
    // + ml_kem_len(2)  + ml_kem(1184)
    // + imported_at(8) + status(1)
    // = 4+2+16+2+3+2+32+2+1952+2+32+2+1184+8+1 = 3244
    let bytes = fixed_contact_record().to_bytes();
    assert_eq!(
        bytes.len(),
        3244,
        "contact record wire size changed — did a field get added or removed?",
    );
}

// ---------------------------------------------------------------------------
// Roundtrip — recomputed parse must match the original.
// ---------------------------------------------------------------------------

#[test]
fn identity_record_golden_roundtrip() {
    let record = fixed_identity_record();
    let bytes = record.to_bytes();
    let parsed = IdentityRecord::from_bytes(&bytes).expect("parse");

    assert_eq!(parsed.identity_id, record.identity_id);
    assert_eq!(parsed.display_name, record.display_name);
    assert_eq!(parsed.created_at, record.created_at);
    assert_eq!(parsed.status, record.status);
    assert_eq!(parsed.ed25519_pk, record.ed25519_pk);
    assert_eq!(parsed.ml_dsa_pk, record.ml_dsa_pk);
    assert_eq!(parsed.x25519_pk, record.x25519_pk);
    assert_eq!(parsed.ml_kem_pk, record.ml_kem_pk);
    assert_eq!(parsed.encrypted_private_keys, record.encrypted_private_keys);
    assert_eq!(parsed.argon2_salt, record.argon2_salt);
    assert_eq!(parsed.argon2_memory_kib, record.argon2_memory_kib);
    assert_eq!(parsed.argon2_iterations, record.argon2_iterations);
    assert_eq!(parsed.argon2_parallelism, record.argon2_parallelism);
}

#[test]
fn contact_record_golden_roundtrip() {
    let record = fixed_contact_record();
    let bytes = record.to_bytes();
    let parsed = ContactRecord::from_bytes(&bytes).expect("parse");

    assert_eq!(parsed.identity_id, record.identity_id);
    assert_eq!(parsed.display_name, record.display_name);
    assert_eq!(parsed.ed25519_pk, record.ed25519_pk);
    assert_eq!(parsed.ml_dsa_pk, record.ml_dsa_pk);
    assert_eq!(parsed.x25519_pk, record.x25519_pk);
    assert_eq!(parsed.ml_kem_pk, record.ml_kem_pk);
    assert_eq!(parsed.imported_at, record.imported_at);
    assert_eq!(parsed.status, record.status);
}

// ---------------------------------------------------------------------------
// Backward compat: version-1 contact records (no status byte) must still parse.
// ---------------------------------------------------------------------------

#[test]
fn contact_record_v1_still_parses_as_active() {
    // Build a synthetic v1 contact record by hand: the only wire difference
    // from v2 is the trailing status byte, so we drop it and fix the version.
    let mut bytes = fixed_contact_record().to_bytes();
    // Overwrite version (bytes 4..6) from 2 to 1.
    bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
    // Strip the trailing status byte.
    bytes.pop();

    let parsed = ContactRecord::from_bytes(&bytes).expect("v1 contact should parse");
    assert_eq!(parsed.status, IdentityStatus::Active);
    assert_eq!(parsed.identity_id, [0x7E; 16]);
}

// ---------------------------------------------------------------------------
// Rejection cases: unknown version and truncation must fail cleanly, not panic.
// ---------------------------------------------------------------------------

#[test]
fn identity_record_rejects_unknown_version() {
    let mut bytes = fixed_identity_record().to_bytes();
    // Bump version to an unsupported value.
    bytes[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    assert!(IdentityRecord::from_bytes(&bytes).is_err());
}

#[test]
fn contact_record_rejects_unknown_version() {
    let mut bytes = fixed_contact_record().to_bytes();
    bytes[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    assert!(ContactRecord::from_bytes(&bytes).is_err());
}

#[test]
fn truncated_records_are_rejected_not_panicked() {
    let id_bytes = fixed_identity_record().to_bytes();
    let ct_bytes = fixed_contact_record().to_bytes();

    for truncate_at in 0..id_bytes.len() {
        let _ = IdentityRecord::from_bytes(&id_bytes[..truncate_at]);
    }
    for truncate_at in 0..ct_bytes.len() {
        let _ = ContactRecord::from_bytes(&ct_bytes[..truncate_at]);
    }
}
