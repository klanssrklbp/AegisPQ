//! Wire format compatibility tests.
//!
//! These tests pin the **exact byte positions** of every field in stable
//! on-the-wire structures. They are intentionally brittle: any accidental
//! reordering, widening, or byte-order flip will fail loudly here before it
//! escapes into a release.
//!
//! Every fixture in this file corresponds to a format documented in
//! `docs/COMPATIBILITY.md` (or its successor). If you need to intentionally
//! change any of these layouts, bump the protocol version in
//! `aegispq_protocol::version::CURRENT` and update these tests — do **not**
//! silently "fix" them.

use aegispq_protocol::envelope::{Header, HEADER_SIZE};
use aegispq_protocol::revocation::{RevocationCertificate, RevocationReason};
use aegispq_protocol::rotation::RotationCertificate;
use aegispq_protocol::{version, FormatType, Suite, MAGIC};

// ---------------------------------------------------------------------------
// Envelope header (12 bytes, stable since v1)
// ---------------------------------------------------------------------------
//
// Offset  Size  Field
// 0       4     Magic: 0x41 0x50 0x51 0x01
// 4       1     Format type
// 5       2     Protocol version (big-endian u16)
// 7       1     Suite identifier
// 8       4     Payload length (big-endian u32)

#[test]
fn envelope_header_is_exactly_twelve_bytes() {
    assert_eq!(HEADER_SIZE, 12, "envelope header size is part of the stable v1 wire format");
}

#[test]
fn envelope_header_magic_is_frozen() {
    assert_eq!(
        MAGIC,
        [0x41, 0x50, 0x51, 0x01],
        "envelope magic bytes are frozen for protocol v1"
    );
}

#[test]
fn envelope_header_field_positions_are_stable() {
    let header = Header {
        format_type: FormatType::EncryptedFile,
        version: version::CURRENT,
        suite: Suite::HybridV1,
        payload_length: 0x12345678,
    };
    let bytes = header.to_bytes();

    // Magic occupies bytes 0..4
    assert_eq!(&bytes[0..4], &[0x41, 0x50, 0x51, 0x01], "magic bytes misaligned");

    // Format type at offset 4 (EncryptedFile = 0x01)
    assert_eq!(bytes[4], 0x01, "format_type byte misaligned");

    // Version (big-endian) at offsets 5..7
    assert_eq!(&bytes[5..7], &[0x00, 0x01], "version bytes misaligned");

    // Suite at offset 7 (HybridV1 = 0x01)
    assert_eq!(bytes[7], 0x01, "suite byte misaligned");

    // Payload length (big-endian) at offsets 8..12
    assert_eq!(&bytes[8..12], &[0x12, 0x34, 0x56, 0x78], "payload_length bytes misaligned");
}

#[test]
fn envelope_header_all_format_types_encode_to_their_expected_byte() {
    // If any of these change, the wire format is broken.
    let cases: &[(FormatType, u8)] = &[
        (FormatType::EncryptedFile, 0x01),
        (FormatType::KeyPackage, 0x02),
        (FormatType::SessionMessage, 0x03),
        (FormatType::RevocationCertificate, 0x04),
        (FormatType::RotationCertificate, 0x05),
        (FormatType::RecoveryBlob, 0x06),
        (FormatType::SignedDocument, 0x07),
    ];
    for (ft, expected) in cases {
        let h = Header {
            format_type: *ft,
            version: version::CURRENT,
            suite: Suite::HybridV1,
            payload_length: 0,
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes[4], *expected, "format_type {:?} must encode to {:#x}", ft, expected);
    }
}

#[test]
fn envelope_header_all_suites_encode_to_their_expected_byte() {
    let cases: &[(Suite, u8)] = &[
        (Suite::HybridV1, 0x01),
        (Suite::HybridV1XChaCha, 0x02),
    ];
    for (suite, expected) in cases {
        let h = Header {
            format_type: FormatType::EncryptedFile,
            version: version::CURRENT,
            suite: *suite,
            payload_length: 0,
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes[7], *expected, "suite {:?} must encode to {:#x}", suite, expected);
    }
}

#[test]
fn envelope_header_version_is_big_endian() {
    let h = Header {
        format_type: FormatType::EncryptedFile,
        version: 0x00AB,
        suite: Suite::HybridV1,
        payload_length: 0,
    };
    let bytes = h.to_bytes();
    // Big-endian: high byte first.
    assert_eq!(bytes[5], 0x00);
    assert_eq!(bytes[6], 0xAB);
}

#[test]
fn envelope_header_payload_length_is_big_endian() {
    let h = Header {
        format_type: FormatType::EncryptedFile,
        version: version::CURRENT,
        suite: Suite::HybridV1,
        payload_length: 0xDEADBEEF,
    };
    let bytes = h.to_bytes();
    assert_eq!(&bytes[8..12], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

// ---------------------------------------------------------------------------
// Certificate prefix stability
// ---------------------------------------------------------------------------
//
// Both revocation and rotation certificates begin with the standard 12-byte
// envelope header, so parsers that only know "this is some signed cert" can
// route based on FormatType before parsing any body.

#[test]
fn revocation_certificate_starts_with_envelope_header() {
    let cert = RevocationCertificate {
        identity_id: [0x11; 16],
        reason: RevocationReason::Compromised,
        effective_at: 1_700_000_000,
        signature: vec![0x22; 64],
    };
    let bytes = cert.to_bytes();

    assert!(bytes.len() >= HEADER_SIZE, "certificate shorter than header");
    assert_eq!(&bytes[0..4], &MAGIC, "revocation cert must start with magic");
    assert_eq!(
        bytes[4],
        FormatType::RevocationCertificate as u8,
        "revocation cert format_type must be at offset 4"
    );
    // Version big-endian at 5..7
    assert_eq!(&bytes[5..7], &version::CURRENT.to_be_bytes());

    // A freshly-built cert must round-trip through from_bytes.
    let parsed = RevocationCertificate::from_bytes(&bytes).expect("parse frozen layout");
    assert_eq!(parsed.identity_id, cert.identity_id);
    assert_eq!(parsed.reason, RevocationReason::Compromised);
    assert_eq!(parsed.effective_at, cert.effective_at);
}

#[test]
fn rotation_certificate_starts_with_envelope_header() {
    let cert = RotationCertificate {
        old_identity_id: [0xAA; 16],
        new_identity_id: [0xBB; 16],
        effective_at: 1_700_000_000,
        new_display_name: "Alice".to_string(),
        new_ed25519_pk: vec![0x11; 32],
        new_ml_dsa_pk: vec![0x22; 1952],
        new_x25519_pk: vec![0x33; 32],
        new_ml_kem_pk: vec![0x44; 1184],
        old_signature: vec![0x55; 64],
        new_signature: vec![0x66; 64],
    };
    let bytes = cert.to_bytes();

    assert!(bytes.len() >= HEADER_SIZE, "certificate shorter than header");
    assert_eq!(&bytes[0..4], &MAGIC, "rotation cert must start with magic");
    assert_eq!(
        bytes[4],
        FormatType::RotationCertificate as u8,
        "rotation cert format_type must be at offset 4"
    );
    // Version big-endian at 5..7
    assert_eq!(&bytes[5..7], &version::CURRENT.to_be_bytes());

    let parsed = RotationCertificate::from_bytes(&bytes).expect("parse frozen layout");
    assert_eq!(parsed.old_identity_id, cert.old_identity_id);
    assert_eq!(parsed.new_identity_id, cert.new_identity_id);
    assert_eq!(parsed.effective_at, cert.effective_at);
    assert_eq!(parsed.new_display_name, "Alice");
}

// ---------------------------------------------------------------------------
// Cross-type sanity: a header written by one type cannot be parsed as another
// ---------------------------------------------------------------------------

#[test]
fn parser_rejects_wrong_format_type_for_revocation() {
    // Build a valid rotation cert, then hand its bytes to the revocation parser.
    let cert = RotationCertificate {
        old_identity_id: [0xAA; 16],
        new_identity_id: [0xBB; 16],
        effective_at: 0,
        new_display_name: "X".to_string(),
        new_ed25519_pk: vec![0x11; 32],
        new_ml_dsa_pk: vec![0x22; 1952],
        new_x25519_pk: vec![0x33; 32],
        new_ml_kem_pk: vec![0x44; 1184],
        old_signature: vec![0x55; 64],
        new_signature: vec![0x66; 64],
    };
    let rotation_bytes = cert.to_bytes();

    // A strict parser should not accept the wrong format_type.
    let result = RevocationCertificate::from_bytes(&rotation_bytes);
    assert!(
        result.is_err(),
        "revocation parser must reject bytes with format_type = RotationCertificate"
    );
}
