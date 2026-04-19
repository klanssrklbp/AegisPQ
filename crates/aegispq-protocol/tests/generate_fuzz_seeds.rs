//! Generate fuzz corpus seed files.
//!
//! Run with `--ignored` to write seed files to `fuzz/corpus/<target>/`:
//!
//! ```sh
//! cargo test -p aegispq-protocol --test generate_fuzz_seeds -- --ignored
//! ```
//!
//! Each seed is a structurally interesting input: valid serialized objects,
//! truncated variants, magic-corrupted variants, and zero-length inputs.
//! The fuzzer uses these as starting points for mutation-based exploration.

use std::path::{Path, PathBuf};

use aegispq_protocol::envelope::{Header, HEADER_SIZE};
use aegispq_protocol::identity::{KeyPackage, IDENTITY_ID_LEN};
use aegispq_protocol::revocation::{RevocationCertificate, RevocationReason};
use aegispq_protocol::rotation::RotationCertificate;
use aegispq_protocol::{FormatType, Suite, MAGIC};

fn corpus_dir(target: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fuzz")
        .join("corpus")
        .join(target);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_seed(dir: &Path, name: &str, data: &[u8]) {
    std::fs::write(dir.join(name), data).unwrap();
}

// ---------------------------------------------------------------------------
// Helper: build valid objects
// ---------------------------------------------------------------------------

fn valid_header() -> [u8; HEADER_SIZE] {
    Header {
        format_type: FormatType::EncryptedFile,
        version: 1,
        suite: Suite::HybridV1,
        payload_length: 0,
    }
    .to_bytes()
}

fn valid_key_package_bytes() -> Vec<u8> {
    KeyPackage {
        identity_id: [0x01; IDENTITY_ID_LEN],
        display_name: "Seed".to_string(),
        ed25519_pk: vec![0x11; 32],
        ml_dsa_pk: vec![0x22; 1952],
        x25519_pk: vec![0x33; 32],
        ml_kem_pk: vec![0x44; 1184],
        created_at: 1_700_000_000,
        signature: vec![0x55; 128],
    }
    .to_bytes()
}

fn valid_revocation_bytes() -> Vec<u8> {
    RevocationCertificate {
        identity_id: [0xAA; IDENTITY_ID_LEN],
        reason: RevocationReason::Compromised,
        effective_at: 1_700_100_000,
        signature: vec![0xBB; 96],
    }
    .to_bytes()
}

fn valid_rotation_bytes() -> Vec<u8> {
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
    .to_bytes()
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn generate_all_fuzz_seeds() {
    // --- fuzz_envelope ---
    {
        let dir = corpus_dir("fuzz_envelope");
        write_seed(&dir, "valid_header", &valid_header());
        write_seed(&dir, "empty", &[]);
        write_seed(&dir, "just_magic", &MAGIC);
        write_seed(&dir, "truncated_5", &valid_header()[..5]);
        write_seed(&dir, "truncated_8", &valid_header()[..8]);
        // Bad magic.
        let mut bad_magic = valid_header();
        bad_magic[0] = 0xFF;
        write_seed(&dir, "bad_magic", &bad_magic);
        // Unknown format type.
        let mut bad_fmt = valid_header();
        bad_fmt[4] = 0xFF;
        write_seed(&dir, "unknown_format", &bad_fmt);
        // Future version.
        let mut future_ver = valid_header();
        future_ver[5..7].copy_from_slice(&999u16.to_be_bytes());
        write_seed(&dir, "future_version", &future_ver);
        // Unknown suite.
        let mut bad_suite = valid_header();
        bad_suite[7] = 0xFF;
        write_seed(&dir, "unknown_suite", &bad_suite);
        // All zeros.
        write_seed(&dir, "all_zeros_12", &[0u8; 12]);
        // All 0xFF.
        write_seed(&dir, "all_ff_12", &[0xFF; 12]);
        eprintln!("wrote {} seeds to {}", 11, dir.display());
    }

    // --- fuzz_key_package ---
    {
        let dir = corpus_dir("fuzz_key_package");
        let valid = valid_key_package_bytes();
        write_seed(&dir, "valid", &valid);
        write_seed(&dir, "empty", &[]);
        write_seed(&dir, "header_only", &valid[..HEADER_SIZE]);
        write_seed(&dir, "truncated_half", &valid[..valid.len() / 2]);
        // Corrupt magic.
        let mut bad = valid.clone();
        bad[0] = 0x00;
        write_seed(&dir, "bad_magic", &bad);
        // Wrong format type.
        let mut wrong_ft = valid.clone();
        wrong_ft[4] = FormatType::EncryptedFile as u8;
        write_seed(&dir, "wrong_format_type", &wrong_ft);
        // Trailing data.
        let mut trail = valid.clone();
        trail.extend_from_slice(&[0xDE, 0xAD]);
        write_seed(&dir, "trailing_data", &trail);
        eprintln!("wrote {} seeds to {}", 7, dir.display());
    }

    // --- fuzz_revocation ---
    {
        let dir = corpus_dir("fuzz_revocation");
        let valid = valid_revocation_bytes();
        write_seed(&dir, "valid", &valid);
        write_seed(&dir, "empty", &[]);
        write_seed(&dir, "header_only", &valid[..HEADER_SIZE]);
        write_seed(&dir, "truncated_half", &valid[..valid.len() / 2]);
        let mut bad_reason = valid.clone();
        // Reason byte is at HEADER_SIZE + IDENTITY_ID_LEN.
        bad_reason[HEADER_SIZE + IDENTITY_ID_LEN] = 0xFF;
        write_seed(&dir, "invalid_reason", &bad_reason);
        let mut trail = valid.clone();
        trail.push(0xFF);
        write_seed(&dir, "trailing_data", &trail);
        eprintln!("wrote {} seeds to {}", 6, dir.display());
    }

    // --- fuzz_rotation ---
    {
        let dir = corpus_dir("fuzz_rotation");
        let valid = valid_rotation_bytes();
        write_seed(&dir, "valid", &valid);
        write_seed(&dir, "empty", &[]);
        write_seed(&dir, "header_only", &valid[..HEADER_SIZE]);
        write_seed(&dir, "truncated_quarter", &valid[..valid.len() / 4]);
        write_seed(&dir, "truncated_half", &valid[..valid.len() / 2]);
        let mut trail = valid.clone();
        trail.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        write_seed(&dir, "trailing_data", &trail);
        eprintln!("wrote {} seeds to {}", 6, dir.display());
    }

    // --- fuzz_decrypt / fuzz_stream_decrypt ---
    // These targets feed raw bytes to decrypt. A valid encrypted file requires
    // real crypto keygen, so we only provide structurally interesting stubs.
    for target in &["fuzz_decrypt", "fuzz_stream_decrypt"] {
        let dir = corpus_dir(target);
        write_seed(&dir, "empty", &[]);
        write_seed(&dir, "valid_header_no_payload", &valid_header());
        // Header claiming a huge payload.
        let mut big = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1,
            payload_length: 0xFFFFFFFF,
        }
        .to_bytes()
        .to_vec();
        big.extend_from_slice(&[0u8; 64]);
        write_seed(&dir, "huge_payload_claim", &big);
        // Minimum header + some random-ish payload.
        let mut small_payload = valid_header().to_vec();
        small_payload.extend_from_slice(&[0xAA; 256]);
        write_seed(&dir, "small_payload", &small_payload);
        // XChaCha suite variant.
        let xchacha_hdr = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1XChaCha,
            payload_length: 128,
        }
        .to_bytes();
        let mut xchacha = xchacha_hdr.to_vec();
        xchacha.extend_from_slice(&[0x55; 128]);
        write_seed(&dir, "xchacha_stub", &xchacha);
        eprintln!("wrote {} seeds to {}", 5, dir.display());
    }

    // --- fuzz_record ---
    {
        let dir = corpus_dir("fuzz_record");
        write_seed(&dir, "empty", &[]);
        // Identity record magic.
        write_seed(&dir, "identity_magic_only", b"APQI");
        // Contact record magic.
        write_seed(&dir, "contact_magic_only", b"APQC");
        // Short identity stub (magic + version + some bytes).
        let mut id_stub = b"APQI".to_vec();
        id_stub.extend_from_slice(&1u16.to_be_bytes());
        id_stub.extend_from_slice(&[0u8; 64]);
        write_seed(&dir, "identity_stub", &id_stub);
        // Short contact stub.
        let mut ct_stub = b"APQC".to_vec();
        ct_stub.extend_from_slice(&1u16.to_be_bytes());
        ct_stub.extend_from_slice(&[0u8; 64]);
        write_seed(&dir, "contact_stub", &ct_stub);
        // All zeros.
        write_seed(&dir, "all_zeros_128", &[0u8; 128]);
        eprintln!("wrote {} seeds to {}", 6, dir.display());
    }
}
