//! End-to-end CLI tests.
//!
//! These tests drive the real `aegispq` binary via `assert_cmd` and exercise
//! the full encrypt/decrypt/sign/verify lifecycle against an isolated
//! temporary data directory. Passphrases are piped on stdin (the CLI falls
//! back from its tty prompt when stdin is not a terminal).
//!
//! The `AEGISPQ_FAST_KDF=1` environment variable switches the CLI to
//! testing Argon2 parameters so that identity creation finishes in a few
//! milliseconds instead of the hardened cost we use in production. It must
//! never be set outside tests.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a CLI invocation pre-wired to a temporary data directory and the
/// fast-KDF escape hatch.
fn cli(data_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("aegispq").expect("binary built");
    cmd.env("AEGISPQ_DATA_DIR", data_dir.path())
        .env("AEGISPQ_FAST_KDF", "1")
        // Unset terminal vars so rpassword doesn't try to open /dev/tty.
        .env_remove("RUST_BACKTRACE");
    cmd
}

/// Create an identity via the CLI and return its hex ID by parsing the
/// --json output.
fn create_identity(data_dir: &TempDir, name: &str, passphrase: &str) -> String {
    let assert = cli(data_dir)
        .args(["--json", "identity", "create", "--name", name])
        .write_stdin(format!("{passphrase}\n{passphrase}\n"))
        .assert()
        .success();

    let out = assert.get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("valid json from identity create");
    assert_eq!(v["command"], "identity.create");
    assert_eq!(v["name"], name);
    v["id"].as_str().expect("id field").to_string()
}

/// Export a key package for the identity at `id` and return the path.
fn export_key_package(data_dir: &TempDir, id: &str, passphrase: &str, out: PathBuf) -> PathBuf {
    cli(data_dir)
        .args([
            "--json",
            "identity",
            "export",
            id,
            "--output",
            out.to_str().unwrap(),
        ])
        .write_stdin(format!("{passphrase}\n"))
        .assert()
        .success();
    out
}

/// Import a contact key package from `path`.
fn import_contact(data_dir: &TempDir, path: &Path) -> Value {
    let assert = cli(data_dir)
        .args(["--json", "contact", "import", path.to_str().unwrap()])
        .assert()
        .success();
    let out = assert.get_output().stdout.clone();
    serde_json::from_slice(&out).expect("valid json from contact import")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn identity_create_and_list_produces_valid_json() {
    let data = TempDir::new().unwrap();

    let id = create_identity(&data, "Alice", "correct-horse-battery-staple");
    assert_eq!(id.len(), 32, "identity ID should be 16 bytes of hex");

    let assert = cli(&data)
        .args(["--json", "identity", "list"])
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["command"], "identity.list");
    let list = v["identities"].as_array().expect("array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], id);
    assert_eq!(list[0]["name"], "Alice");
    assert_eq!(list[0]["status"], "active");
}

#[test]
fn identity_fingerprint_matches_contact_inspect() {
    let data = TempDir::new().unwrap();

    let alice_id = create_identity(&data, "Alice", "alice-passphrase");

    // Get Alice's local fingerprint.
    let assert = cli(&data)
        .args(["--json", "identity", "fingerprint", &alice_id])
        .write_stdin("alice-passphrase\n")
        .assert()
        .success();
    let fp_local: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let local_fp = fp_local["fingerprint"].as_str().unwrap().to_string();

    // Export and re-import as a contact in a fresh data dir.
    let pkg = data.path().join("alice.pub.apq");
    export_key_package(&data, &alice_id, "alice-passphrase", pkg.clone());

    let bob_data = TempDir::new().unwrap();
    let import_json = import_contact(&bob_data, &pkg);
    assert_eq!(import_json["command"], "contact.import");
    assert_eq!(import_json["fingerprint"], local_fp);

    // `contact inspect` should print the same fingerprint.
    let assert = cli(&bob_data)
        .args(["--json", "contact", "inspect", &alice_id])
        .assert()
        .success();
    let inspect: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(inspect["command"], "contact.inspect");
    assert_eq!(inspect["fingerprint"], local_fp);
}

#[test]
fn encrypt_decrypt_roundtrip_via_cli() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");
    let bob_id = create_identity(&bob_data, "Bob", "bob-pw");

    // Alice exports her key package and Bob imports it.
    let alice_pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    // Bob exports his key package and Alice imports it.
    let bob_pkg = bob_data.path().join("bob.pub.apq");
    export_key_package(&bob_data, &bob_id, "bob-pw", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    // Alice writes a plaintext file and encrypts it for Bob.
    let work = TempDir::new().unwrap();
    let plaintext_path = work.path().join("secret.txt");
    let ciphertext_path = work.path().join("secret.txt.apq");
    let decrypted_path = work.path().join("secret.txt.out");
    let message = b"the quick brown fox jumps over the lazy dog";
    std::fs::write(&plaintext_path, message).unwrap();

    cli(&alice_data)
        .args([
            "--json",
            "encrypt",
            "--file",
            plaintext_path.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
            "--output",
            ciphertext_path.to_str().unwrap(),
        ])
        .write_stdin("alice-pw\n")
        .assert()
        .success();

    assert!(ciphertext_path.exists(), "ciphertext file should exist");

    // Bob decrypts and the output matches.
    let assert = cli(&bob_data)
        .args([
            "--json",
            "decrypt",
            "--file",
            ciphertext_path.to_str().unwrap(),
            "--identity",
            &bob_id,
            "--output",
            decrypted_path.to_str().unwrap(),
        ])
        .write_stdin("bob-pw\n")
        .assert()
        .success();

    let decrypt_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(decrypt_json["command"], "decrypt");
    assert_eq!(decrypt_json["sender_id"], alice_id);

    let recovered = std::fs::read(&decrypted_path).unwrap();
    assert_eq!(recovered, message);
}

#[test]
fn decrypt_of_tampered_file_leaves_no_plaintext() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");
    let bob_id = create_identity(&bob_data, "Bob", "bob-pw");

    let alice_pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("bob.pub.apq");
    export_key_package(&bob_data, &bob_id, "bob-pw", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    let work = TempDir::new().unwrap();
    let plaintext_path = work.path().join("doc.txt");
    let ciphertext_path = work.path().join("doc.txt.apq");
    let decrypted_path = work.path().join("doc.txt.out");
    std::fs::write(&plaintext_path, b"sensitive payload that must not leak").unwrap();

    cli(&alice_data)
        .args([
            "encrypt",
            "--file",
            plaintext_path.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
            "--output",
            ciphertext_path.to_str().unwrap(),
        ])
        .write_stdin("alice-pw\n")
        .assert()
        .success();

    // Tamper with a byte well inside the ciphertext body.
    {
        let mut bytes = std::fs::read(&ciphertext_path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&ciphertext_path, bytes).unwrap();
    }

    cli(&bob_data)
        .args([
            "decrypt",
            "--file",
            ciphertext_path.to_str().unwrap(),
            "--identity",
            &bob_id,
            "--output",
            decrypted_path.to_str().unwrap(),
        ])
        .write_stdin("bob-pw\n")
        .assert()
        .failure();

    assert!(
        !decrypted_path.exists(),
        "decrypted file must not exist after signature verification failure"
    );
}

#[test]
fn sign_and_verify_detached_signature() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");

    let alice_pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let work = TempDir::new().unwrap();
    let doc = work.path().join("doc.txt");
    let sig = work.path().join("doc.txt.apqsig");
    std::fs::write(&doc, b"important announcement").unwrap();

    cli(&alice_data)
        .args([
            "sign",
            "--file",
            doc.to_str().unwrap(),
            "--identity",
            &alice_id,
            "--output",
            sig.to_str().unwrap(),
        ])
        .write_stdin("alice-pw\n")
        .assert()
        .success();

    let assert = cli(&bob_data)
        .args([
            "--json",
            "verify",
            "--file",
            doc.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--signer",
            &alice_id,
        ])
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["command"], "verify");
    assert_eq!(v["valid"], true);

    // Tamper the document and verify fails.
    std::fs::write(&doc, b"different announcement").unwrap();
    cli(&bob_data)
        .args([
            "verify",
            "--file",
            doc.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--signer",
            &alice_id,
        ])
        .assert()
        .failure();
}

#[test]
fn json_error_output_on_bad_input() {
    let data = TempDir::new().unwrap();

    // Reference a non-existent identity ID.
    let assert = cli(&data)
        .args([
            "--json",
            "identity",
            "export",
            "00000000000000000000000000000000",
        ])
        .write_stdin("whatever\n")
        .assert()
        .failure();

    let out = assert.get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("error is json");
    assert!(v.get("error").is_some(), "error field must be present");
    assert!(
        v.get("error_kind").is_some(),
        "error_kind field must be present"
    );
}

// ---------------------------------------------------------------------------
// Hardening tests — bad passphrase, revoked contacts, rotation import, etc.
// ---------------------------------------------------------------------------

#[test]
fn wrong_passphrase_is_rejected() {
    let data = TempDir::new().unwrap();
    let id = create_identity(&data, "Alice", "correct-password");

    // Try to export with the wrong passphrase.
    cli(&data)
        .args(["--json", "identity", "export", &id])
        .write_stdin("wrong-password\n")
        .assert()
        .failure();
}

#[test]
fn empty_passphrase_is_rejected() {
    let data = TempDir::new().unwrap();

    // Empty passphrase should fail.
    cli(&data)
        .args(["identity", "create", "--name", "Nobody"])
        .write_stdin("\n\n")
        .assert()
        .failure();
}

#[test]
fn mismatched_passphrase_confirmation_is_rejected() {
    let data = TempDir::new().unwrap();

    // Passphrase and confirmation do not match.
    cli(&data)
        .args(["identity", "create", "--name", "Mismatch"])
        .write_stdin("password-one\npassword-two\n")
        .assert()
        .failure();
}

#[test]
fn encrypt_to_revoked_contact_fails() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");
    let bob_id = create_identity(&bob_data, "Bob", "bob-pw");

    // Exchange key packages.
    let alice_pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("bob.pub.apq");
    export_key_package(&bob_data, &bob_id, "bob-pw", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    // Bob revokes himself and Alice imports the revocation.
    let rev_cert_path = bob_data.path().join("bob.rev.apq");
    cli(&bob_data)
        .args([
            "identity",
            "revoke",
            &bob_id,
            "--reason",
            "compromised",
            "--output",
            rev_cert_path.to_str().unwrap(),
        ])
        .write_stdin("bob-pw\n")
        .assert()
        .success();

    cli(&alice_data)
        .args([
            "contact",
            "import-revocation",
            rev_cert_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Alice tries to encrypt for revoked Bob — must fail.
    let work = TempDir::new().unwrap();
    let plaintext_path = work.path().join("msg.txt");
    std::fs::write(&plaintext_path, b"should not encrypt").unwrap();

    cli(&alice_data)
        .args([
            "encrypt",
            "--file",
            plaintext_path.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
        ])
        .write_stdin("alice-pw\n")
        .assert()
        .failure();
}

#[test]
fn revoke_and_inspect_shows_revoked_status() {
    let data = TempDir::new().unwrap();
    let alice_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");

    // Export and import as contact.
    let pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", pkg.clone());
    import_contact(&data, &pkg);

    // Alice revokes.
    let rev_path = alice_data.path().join("alice.rev.apq");
    cli(&alice_data)
        .args([
            "identity",
            "revoke",
            &alice_id,
            "--reason",
            "retired",
            "--output",
            rev_path.to_str().unwrap(),
        ])
        .write_stdin("alice-pw\n")
        .assert()
        .success();

    // Import revocation.
    cli(&data)
        .args(["contact", "import-revocation", rev_path.to_str().unwrap()])
        .assert()
        .success();

    // Inspect should show revoked.
    let assert = cli(&data)
        .args(["--json", "contact", "inspect", &alice_id])
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["status"], "revoked");
}

#[test]
fn rotation_import_creates_new_contact() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");

    // Bob imports Alice as contact.
    let pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", pkg.clone());
    import_contact(&bob_data, &pkg);

    // Alice rotates.
    let rot_path = alice_data.path().join("alice.rot.apq");
    let assert = cli(&alice_data)
        .args([
            "--json",
            "identity",
            "rotate",
            &alice_id,
            "--output",
            rot_path.to_str().unwrap(),
        ])
        .write_stdin("alice-pw\nnew-pw\nnew-pw\n")
        .assert()
        .success();
    let rot_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let new_alice_id = rot_json["new_id"].as_str().unwrap().to_string();

    // Bob imports the rotation certificate.
    let assert = cli(&bob_data)
        .args([
            "--json",
            "contact",
            "import-rotation",
            rot_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let import_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(import_json["command"], "contact.import_rotation");
    assert_eq!(import_json["new_id"], new_alice_id);

    // New contact should be inspectable and active.
    let assert = cli(&bob_data)
        .args(["--json", "contact", "inspect", &new_alice_id])
        .assert()
        .success();
    let inspect: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(inspect["status"], "active");

    // Old contact should be rotated.
    let assert = cli(&bob_data)
        .args(["--json", "contact", "inspect", &alice_id])
        .assert()
        .success();
    let inspect_old: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(inspect_old["status"], "rotated");
}

#[test]
fn json_error_envelope_has_consistent_shape() {
    let data = TempDir::new().unwrap();

    // Several different error scenarios should all produce {error: "..."} JSON.
    let error_cases: Vec<Vec<&str>> = vec![
        // Non-existent identity.
        vec![
            "--json",
            "identity",
            "fingerprint",
            "deadbeefdeadbeefdeadbeefdeadbeef",
        ],
        // Non-existent contact.
        vec![
            "--json",
            "contact",
            "inspect",
            "deadbeefdeadbeefdeadbeefdeadbeef",
        ],
        // Invalid hex in identity ID (odd number of chars).
        vec!["--json", "identity", "export", "not-valid-hex"],
    ];

    for args in &error_cases {
        let assert = cli(&data)
            .args(args)
            .write_stdin("dummy\n")
            .assert()
            .failure();

        let out = assert.get_output().stdout.clone();
        let v: Value = serde_json::from_slice(&out).unwrap_or_else(|_| {
            panic!(
                "expected JSON error output for args {:?}, got: {}",
                args,
                String::from_utf8_lossy(&out)
            )
        });
        assert!(
            v.get("error").is_some(),
            "args {:?}: JSON error envelope must have 'error' field, got: {}",
            args,
            v
        );
        assert!(
            v["error"].is_string(),
            "args {:?}: 'error' field must be a string",
            args
        );
        assert!(
            v.get("error_kind").is_some(),
            "args {:?}: JSON error envelope must have 'error_kind' field, got: {}",
            args,
            v
        );
        assert!(
            v["error_kind"].is_string(),
            "args {:?}: 'error_kind' field must be a string",
            args
        );
    }
}

#[test]
fn contact_list_empty_produces_valid_json() {
    let data = TempDir::new().unwrap();

    let assert = cli(&data)
        .args(["--json", "contact", "list"])
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["command"], "contact.list");
    assert_eq!(v["contacts"].as_array().unwrap().len(), 0);
}

#[test]
fn encrypt_with_recipients_file() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();
    let carol_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "alice-pw");
    let bob_id = create_identity(&bob_data, "Bob", "bob-pw");
    let carol_id = create_identity(&carol_data, "Carol", "carol-pw");

    // Exchange keys: Alice gets Bob and Carol as contacts.
    let bob_pkg = bob_data.path().join("bob.pub.apq");
    export_key_package(&bob_data, &bob_id, "bob-pw", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    let carol_pkg = carol_data.path().join("carol.pub.apq");
    export_key_package(&carol_data, &carol_id, "carol-pw", carol_pkg.clone());
    import_contact(&alice_data, &carol_pkg);

    // Bob and Carol need Alice as contact to decrypt.
    let alice_pkg = alice_data.path().join("alice.pub.apq");
    export_key_package(&alice_data, &alice_id, "alice-pw", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);
    import_contact(&carol_data, &alice_pkg);

    // Write a recipients file with Bob and Carol's IDs.
    let work = TempDir::new().unwrap();
    let recipients_file = work.path().join("recipients.txt");
    std::fs::write(
        &recipients_file,
        format!("# Team recipients\n{bob_id}\n{carol_id}\n"),
    )
    .unwrap();

    let plaintext_path = work.path().join("team-doc.txt");
    let ciphertext_path = work.path().join("team-doc.txt.apq");
    std::fs::write(&plaintext_path, b"team document content").unwrap();

    // Encrypt using --recipients-file.
    cli(&alice_data)
        .args([
            "encrypt",
            "--file",
            plaintext_path.to_str().unwrap(),
            "--recipients-file",
            recipients_file.to_str().unwrap(),
            "--identity",
            &alice_id,
            "--output",
            ciphertext_path.to_str().unwrap(),
        ])
        .write_stdin("alice-pw\n")
        .assert()
        .success();

    // Both Bob and Carol can decrypt.
    let bob_out = work.path().join("bob-out.txt");
    cli(&bob_data)
        .args([
            "decrypt",
            "--file",
            ciphertext_path.to_str().unwrap(),
            "--identity",
            &bob_id,
            "--output",
            bob_out.to_str().unwrap(),
        ])
        .write_stdin("bob-pw\n")
        .assert()
        .success();
    assert_eq!(std::fs::read(&bob_out).unwrap(), b"team document content");

    let carol_out = work.path().join("carol-out.txt");
    cli(&carol_data)
        .args([
            "decrypt",
            "--file",
            ciphertext_path.to_str().unwrap(),
            "--identity",
            &carol_id,
            "--output",
            carol_out.to_str().unwrap(),
        ])
        .write_stdin("carol-pw\n")
        .assert()
        .success();
    assert_eq!(std::fs::read(&carol_out).unwrap(), b"team document content");
}

#[test]
fn identity_list_empty_produces_valid_json() {
    let data = TempDir::new().unwrap();

    let assert = cli(&data)
        .args(["--json", "identity", "list"])
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["command"], "identity.list");
    assert_eq!(v["identities"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Version command and bridge foundation tests
// ---------------------------------------------------------------------------

#[test]
fn version_command_json_has_stable_fields() {
    let data = TempDir::new().unwrap();

    let assert = cli(&data).args(["--json", "version"]).assert().success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();

    assert_eq!(v["command"], "version");
    assert!(v["version"].is_string(), "version field must be a string");
    assert!(
        v["protocol_version"].is_number(),
        "protocol_version must be a number"
    );
    assert!(v["min_protocol_version"].is_number());

    // Suites array must contain our two known suites.
    let suites = v["suites"].as_array().expect("suites array");
    assert!(suites.contains(&Value::String("HybridV1".into())));
    assert!(suites.contains(&Value::String("HybridV1XChaCha".into())));

    // Capabilities must be an array of strings.
    let caps = v["capabilities"].as_array().expect("capabilities array");
    assert!(caps.len() >= 10, "should have at least 10 capabilities");
    for cap in caps {
        assert!(cap.is_string(), "each capability must be a string");
    }

    // Exit codes map must be present.
    let codes = &v["exit_codes"];
    assert_eq!(codes["success"], 0);
    assert_eq!(codes["general"], 1);
    assert_eq!(codes["auth"], 2);
    assert_eq!(codes["integrity"], 3);
    assert_eq!(codes["io"], 4);
    assert_eq!(codes["usage"], 5);
}

#[test]
fn version_command_human_shows_version() {
    let data = TempDir::new().unwrap();

    let assert = cli(&data).args(["version"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("aegispq"),
        "human version should contain binary name"
    );
    assert!(
        stdout.contains("Protocol:"),
        "should mention protocol version"
    );
}

// ---------------------------------------------------------------------------
// Exit code contract tests
// ---------------------------------------------------------------------------

#[test]
fn exit_code_2_on_wrong_passphrase() {
    let data = TempDir::new().unwrap();
    let id = create_identity(&data, "Alice", "correct");

    let assert = cli(&data)
        .args(["identity", "export", &id])
        .write_stdin("wrong\n")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(code, 2, "wrong passphrase should exit with code 2 (auth)");
}

#[test]
fn exit_code_3_on_tampered_signature() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let work = TempDir::new().unwrap();
    let doc = work.path().join("d.txt");
    let sig = work.path().join("d.sig");
    std::fs::write(&doc, b"original").unwrap();

    cli(&alice_data)
        .args([
            "sign",
            "--file",
            doc.to_str().unwrap(),
            "--identity",
            &alice_id,
            "--output",
            sig.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();

    // Tamper the document so verification fails.
    std::fs::write(&doc, b"tampered").unwrap();

    let assert = cli(&bob_data)
        .args([
            "verify",
            "--file",
            doc.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--signer",
            &alice_id,
        ])
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 3,
        "invalid signature should exit with code 3 (integrity)"
    );
}

#[test]
fn exit_code_3_on_revoked_encrypt() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let bob_id = create_identity(&bob_data, "Bob", "b");

    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("b.pub.apq");
    export_key_package(&bob_data, &bob_id, "b", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    // Revoke Bob.
    let rev = bob_data.path().join("b.rev.apq");
    cli(&bob_data)
        .args([
            "identity",
            "revoke",
            &bob_id,
            "--output",
            rev.to_str().unwrap(),
        ])
        .write_stdin("b\n")
        .assert()
        .success();
    cli(&alice_data)
        .args(["contact", "import-revocation", rev.to_str().unwrap()])
        .assert()
        .success();

    let work = TempDir::new().unwrap();
    let f = work.path().join("f.txt");
    std::fs::write(&f, b"test").unwrap();

    let assert = cli(&alice_data)
        .args([
            "encrypt",
            "--file",
            f.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
        ])
        .write_stdin("a\n")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 3,
        "encrypt to revoked contact should exit with code 3"
    );
}

#[test]
fn exit_code_5_on_bad_hex_id() {
    let data = TempDir::new().unwrap();

    let assert = cli(&data)
        .args(["--json", "identity", "export", "not-hex"])
        .write_stdin("x\n")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(code, 5, "bad hex ID should exit with code 5 (usage)");

    // Verify JSON output has error_kind=usage.
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["error_kind"], "usage");
}

#[test]
fn verify_invalid_signature_json_has_error_envelope() {
    // When --json verify fails, it should emit a standard error envelope,
    // not a success envelope with valid=false.
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let work = TempDir::new().unwrap();
    let doc = work.path().join("d.txt");
    let sig_file = work.path().join("d.sig");
    std::fs::write(&doc, b"hello").unwrap();

    cli(&alice_data)
        .args([
            "sign",
            "--file",
            doc.to_str().unwrap(),
            "--identity",
            &alice_id,
            "--output",
            sig_file.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();

    // Tamper.
    std::fs::write(&doc, b"tampered").unwrap();

    let assert = cli(&bob_data)
        .args([
            "--json",
            "verify",
            "--file",
            doc.to_str().unwrap(),
            "--signature",
            sig_file.to_str().unwrap(),
            "--signer",
            &alice_id,
        ])
        .assert()
        .failure();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert!(v.get("error").is_some(), "should have error field");
    assert_eq!(v["error_kind"], "integrity");
}

// ---------------------------------------------------------------------------
// Task 6: Full lifecycle tests — revocation and rotation
// ---------------------------------------------------------------------------

#[test]
fn revocation_full_lifecycle() {
    // Create Alice and Bob, exchange keys.
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let bob_id = create_identity(&bob_data, "Bob", "b");

    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("b.pub.apq");
    export_key_package(&bob_data, &bob_id, "b", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    // Alice encrypts a file for Bob BEFORE revocation.
    let work = TempDir::new().unwrap();
    let msg = work.path().join("msg.txt");
    let ct = work.path().join("msg.txt.apq");
    std::fs::write(&msg, b"pre-revocation secret").unwrap();

    cli(&alice_data)
        .args([
            "encrypt",
            "--file",
            msg.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
            "--output",
            ct.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();

    // Alice revokes herself. Bob imports the revocation.
    let rev_cert = alice_data.path().join("a.rev.apq");
    let assert = cli(&alice_data)
        .args([
            "--json",
            "identity",
            "revoke",
            &alice_id,
            "--reason",
            "compromised",
            "--output",
            rev_cert.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();
    let rev_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(rev_json["command"], "identity.revoke");
    assert_eq!(rev_json["reason"], "compromised");

    let assert = cli(&bob_data)
        .args([
            "--json",
            "contact",
            "import-revocation",
            rev_cert.to_str().unwrap(),
        ])
        .assert()
        .success();
    let import_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(import_json["command"], "contact.import_revocation");
    assert_eq!(import_json["status"], "revoked");

    // Verify: contact inspect shows revoked.
    let assert = cli(&bob_data)
        .args(["--json", "contact", "inspect", &alice_id])
        .assert()
        .success();
    let inspect: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(inspect["status"], "revoked");

    // Verify: Bob CAN still decrypt the pre-revocation file.
    let dec = work.path().join("msg-dec.txt");
    cli(&bob_data)
        .args([
            "decrypt",
            "--file",
            ct.to_str().unwrap(),
            "--identity",
            &bob_id,
            "--output",
            dec.to_str().unwrap(),
        ])
        .write_stdin("b\n")
        .assert()
        .success();
    assert_eq!(std::fs::read(&dec).unwrap(), b"pre-revocation secret");

    // Verify: Bob CANNOT encrypt to revoked Alice.
    let msg2 = work.path().join("msg2.txt");
    std::fs::write(&msg2, b"should fail").unwrap();
    cli(&bob_data)
        .args([
            "encrypt",
            "--file",
            msg2.to_str().unwrap(),
            "--to",
            &alice_id,
            "--identity",
            &bob_id,
        ])
        .write_stdin("b\n")
        .assert()
        .failure();

    // Verify: identity list shows revoked status.
    let assert = cli(&alice_data)
        .args(["--json", "identity", "list"])
        .assert()
        .success();
    let list: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let ids = list["identities"].as_array().unwrap();
    assert_eq!(ids[0]["status"], "revoked");
}

#[test]
fn rotation_full_lifecycle_with_encrypt_decrypt() {
    // Create Alice and Bob, exchange keys.
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let bob_id = create_identity(&bob_data, "Bob", "b");

    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("b.pub.apq");
    export_key_package(&bob_data, &bob_id, "b", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    // Alice rotates to new identity.
    let rot_cert = alice_data.path().join("a.rot.apq");
    let assert = cli(&alice_data)
        .args([
            "--json",
            "identity",
            "rotate",
            &alice_id,
            "--output",
            rot_cert.to_str().unwrap(),
        ])
        .write_stdin("a\nnew-a\nnew-a\n")
        .assert()
        .success();
    let rot_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(rot_json["command"], "identity.rotate");
    let new_alice_id = rot_json["new_id"].as_str().unwrap().to_string();
    assert_ne!(new_alice_id, alice_id, "new ID must differ from old");

    // Bob imports the rotation certificate.
    let assert = cli(&bob_data)
        .args([
            "--json",
            "contact",
            "import-rotation",
            rot_cert.to_str().unwrap(),
        ])
        .assert()
        .success();
    let import_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(import_json["command"], "contact.import_rotation");
    assert_eq!(import_json["new_id"], new_alice_id);
    assert_eq!(import_json["status"], "active");

    // Verify: contact inspect shows old=rotated, new=active.
    let assert = cli(&bob_data)
        .args(["--json", "contact", "inspect", &alice_id])
        .assert()
        .success();
    let old_inspect: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(old_inspect["status"], "rotated");

    let assert = cli(&bob_data)
        .args(["--json", "contact", "inspect", &new_alice_id])
        .assert()
        .success();
    let new_inspect: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(new_inspect["status"], "active");

    // Verify: Bob CANNOT encrypt to old (rotated) Alice.
    let work = TempDir::new().unwrap();
    let msg = work.path().join("m.txt");
    std::fs::write(&msg, b"test").unwrap();
    cli(&bob_data)
        .args([
            "encrypt",
            "--file",
            msg.to_str().unwrap(),
            "--to",
            &alice_id,
            "--identity",
            &bob_id,
        ])
        .write_stdin("b\n")
        .assert()
        .failure();

    // New Alice needs Bob as a contact to encrypt to him.
    // (She already has Bob imported from before rotation, same store.)

    // Bob encrypts to NEW Alice, and NEW Alice decrypts.
    let ct = work.path().join("m.apq");
    cli(&bob_data)
        .args([
            "encrypt",
            "--file",
            msg.to_str().unwrap(),
            "--to",
            &new_alice_id,
            "--identity",
            &bob_id,
            "--output",
            ct.to_str().unwrap(),
        ])
        .write_stdin("b\n")
        .assert()
        .success();

    let dec = work.path().join("m-dec.txt");
    let assert = cli(&alice_data)
        .args([
            "--json",
            "decrypt",
            "--file",
            ct.to_str().unwrap(),
            "--identity",
            &new_alice_id,
            "--output",
            dec.to_str().unwrap(),
        ])
        .write_stdin("new-a\n")
        .assert()
        .success();
    assert_eq!(std::fs::read(&dec).unwrap(), b"test");

    let dec_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(dec_json["command"], "decrypt");
    assert_eq!(dec_json["sender_id"], bob_id);

    // Verify: identity list shows both old (rotated) and new (active).
    let assert = cli(&alice_data)
        .args(["--json", "identity", "list"])
        .assert()
        .success();
    let list: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let ids = list["identities"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    let statuses: Vec<&str> = ids.iter().map(|i| i["status"].as_str().unwrap()).collect();
    assert!(
        statuses.contains(&"rotated"),
        "old identity should be rotated"
    );
    assert!(
        statuses.contains(&"active"),
        "new identity should be active"
    );
}

// ---------------------------------------------------------------------------
// Task 7: Large-file streaming and multi-recipient tests
// ---------------------------------------------------------------------------

#[test]
fn large_file_streaming_roundtrip() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let bob_id = create_identity(&bob_data, "Bob", "b");

    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("b.pub.apq");
    export_key_package(&bob_data, &bob_id, "b", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    // Generate a 1 MB file with a deterministic pattern.
    let work = TempDir::new().unwrap();
    let plaintext_path = work.path().join("large.bin");
    let ciphertext_path = work.path().join("large.bin.apq");
    let decrypted_path = work.path().join("large.dec.bin");

    let size = 1_048_576; // 1 MB
    let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    std::fs::write(&plaintext_path, &plaintext).unwrap();

    // Encrypt.
    let assert = cli(&alice_data)
        .args([
            "--json",
            "encrypt",
            "--file",
            plaintext_path.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
            "--output",
            ciphertext_path.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();
    let enc_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(enc_json["command"], "encrypt");
    let ct_size = enc_json["output_bytes"].as_u64().unwrap();
    assert!(
        ct_size > size as u64,
        "ciphertext should be larger than plaintext"
    );

    // Decrypt.
    let assert = cli(&bob_data)
        .args([
            "--json",
            "decrypt",
            "--file",
            ciphertext_path.to_str().unwrap(),
            "--identity",
            &bob_id,
            "--output",
            decrypted_path.to_str().unwrap(),
        ])
        .write_stdin("b\n")
        .assert()
        .success();
    let dec_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(dec_json["bytes"], size);

    // Verify exact byte match.
    let recovered = std::fs::read(&decrypted_path).unwrap();
    assert_eq!(recovered.len(), size);
    assert_eq!(recovered, plaintext);
}

#[test]
fn five_recipient_encrypt_decrypt() {
    // Create sender + 5 recipients.
    let sender_data = TempDir::new().unwrap();
    let sender_id = create_identity(&sender_data, "Sender", "s");

    let mut recipient_data: Vec<TempDir> = Vec::new();
    let mut recipient_ids: Vec<String> = Vec::new();

    for i in 0..5 {
        let data = TempDir::new().unwrap();
        let name = format!("R{i}");
        let pass = format!("r{i}");
        let id = create_identity(&data, &name, &pass);

        // Export recipient key package and sender imports it.
        let pkg = data.path().join(format!("{name}.pub.apq"));
        export_key_package(&data, &id, &pass, pkg.clone());
        import_contact(&sender_data, &pkg);

        // Each recipient imports sender's key (for decrypt verification).
        let sender_pkg = sender_data.path().join("sender.pub.apq");
        if i == 0 {
            export_key_package(&sender_data, &sender_id, "s", sender_pkg.clone());
        }
        import_contact(&data, &sender_pkg);

        recipient_ids.push(id);
        recipient_data.push(data);
    }

    // Build a recipients file with all 5 IDs.
    let work = TempDir::new().unwrap();
    let recipients_file = work.path().join("recipients.txt");
    let content: String = recipient_ids.iter().map(|id| format!("{id}\n")).collect();
    std::fs::write(&recipients_file, &content).unwrap();

    let plaintext_path = work.path().join("shared.txt");
    let ciphertext_path = work.path().join("shared.txt.apq");
    std::fs::write(&plaintext_path, b"shared secret for 5 recipients").unwrap();

    // Encrypt using recipients file.
    let assert = cli(&sender_data)
        .args([
            "--json",
            "encrypt",
            "--file",
            plaintext_path.to_str().unwrap(),
            "--recipients-file",
            recipients_file.to_str().unwrap(),
            "--identity",
            &sender_id,
            "--output",
            ciphertext_path.to_str().unwrap(),
        ])
        .write_stdin("s\n")
        .assert()
        .success();
    let enc_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let recipients_arr = enc_json["recipients"].as_array().unwrap();
    assert_eq!(
        recipients_arr.len(),
        5,
        "should have 5 recipients in JSON output"
    );

    // Each recipient decrypts.
    for (i, (data, id)) in recipient_data.iter().zip(&recipient_ids).enumerate() {
        let dec = work.path().join(format!("dec-{i}.txt"));
        cli(data)
            .args([
                "decrypt",
                "--file",
                ciphertext_path.to_str().unwrap(),
                "--identity",
                id,
                "--output",
                dec.to_str().unwrap(),
            ])
            .write_stdin(format!("r{i}\n"))
            .assert()
            .success();
        assert_eq!(
            std::fs::read(&dec).unwrap(),
            b"shared secret for 5 recipients",
            "recipient {i} should recover original plaintext"
        );
    }
}

#[test]
fn xchacha_suite_roundtrip() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let bob_id = create_identity(&bob_data, "Bob", "b");

    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);

    let bob_pkg = bob_data.path().join("b.pub.apq");
    export_key_package(&bob_data, &bob_id, "b", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    let work = TempDir::new().unwrap();
    let msg = work.path().join("msg.txt");
    let ct = work.path().join("msg.apq");
    let dec = work.path().join("msg.dec");
    std::fs::write(&msg, b"xchacha test payload").unwrap();

    // Encrypt with --suite xchacha.
    let assert = cli(&alice_data)
        .args([
            "--json",
            "encrypt",
            "--file",
            msg.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
            "--suite",
            "xchacha",
            "--output",
            ct.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();
    let enc_json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(enc_json["suite"], "xchacha");

    // Decrypt.
    cli(&bob_data)
        .args([
            "decrypt",
            "--file",
            ct.to_str().unwrap(),
            "--identity",
            &bob_id,
            "--output",
            dec.to_str().unwrap(),
        ])
        .write_stdin("b\n")
        .assert()
        .success();
    assert_eq!(std::fs::read(&dec).unwrap(), b"xchacha test payload");
}

#[test]
fn non_recipient_cannot_decrypt() {
    let alice_data = TempDir::new().unwrap();
    let bob_data = TempDir::new().unwrap();
    let eve_data = TempDir::new().unwrap();

    let alice_id = create_identity(&alice_data, "Alice", "a");
    let bob_id = create_identity(&bob_data, "Bob", "b");
    let eve_id = create_identity(&eve_data, "Eve", "e");

    // Exchange keys between Alice and Bob only.
    let alice_pkg = alice_data.path().join("a.pub.apq");
    export_key_package(&alice_data, &alice_id, "a", alice_pkg.clone());
    import_contact(&bob_data, &alice_pkg);
    import_contact(&eve_data, &alice_pkg); // Eve knows Alice but isn't a recipient.

    let bob_pkg = bob_data.path().join("b.pub.apq");
    export_key_package(&bob_data, &bob_id, "b", bob_pkg.clone());
    import_contact(&alice_data, &bob_pkg);

    let work = TempDir::new().unwrap();
    let msg = work.path().join("m.txt");
    let ct = work.path().join("m.apq");
    std::fs::write(&msg, b"for Bob only").unwrap();

    // Alice encrypts for Bob only.
    cli(&alice_data)
        .args([
            "encrypt",
            "--file",
            msg.to_str().unwrap(),
            "--to",
            &bob_id,
            "--identity",
            &alice_id,
            "--output",
            ct.to_str().unwrap(),
        ])
        .write_stdin("a\n")
        .assert()
        .success();

    // Eve tries to decrypt — should fail with exit code 3.
    let eve_out = work.path().join("eve-out.txt");
    let assert = cli(&eve_data)
        .args([
            "--json",
            "decrypt",
            "--file",
            ct.to_str().unwrap(),
            "--identity",
            &eve_id,
            "--output",
            eve_out.to_str().unwrap(),
        ])
        .write_stdin("e\n")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(code, 3, "non-recipient decrypt should exit with code 3");
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["error_kind"], "not_recipient");
    assert!(
        !eve_out.exists(),
        "no output file should be created for non-recipient"
    );
}
