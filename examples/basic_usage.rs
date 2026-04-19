//! Basic AegisPQ usage: identity management, encryption, signing.
//!
//! Run with: cargo run --example basic_usage

use aegispq::prelude::*;
use aegispq::store::FileStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = FileStore::open(dir.path())?;

    // --- Identity creation ---
    println!("=== Identity Management ===\n");

    let alice = aegispq::identity::create_identity("Alice", b"alice-passphrase", &store)?;
    println!("Created Alice: {}", alice.fingerprint());

    let bob = aegispq::identity::create_identity("Bob", b"bob-passphrase", &store)?;
    println!("Created Bob:   {}", bob.fingerprint());

    // Export and import key packages (simulates out-of-band exchange).
    let alice_pkg = aegispq::identity::export_key_package(&alice)?;
    let bob_pkg = aegispq::identity::export_key_package(&bob)?;

    let bob_public = aegispq::identity::import_key_package(&bob_pkg, &store)?;
    let _alice_in_bob = aegispq::identity::import_key_package(&alice_pkg, &store)?;

    println!("Key packages exchanged.\n");

    // --- File encryption ---
    println!("=== File Encryption ===\n");

    let plaintext = b"Top secret: post-quantum cats are real.";
    let options = EncryptOptions::default();

    let ciphertext = aegispq::encrypt::encrypt_file(plaintext, &alice, &[&bob_public], &options)?;
    println!(
        "Encrypted {} bytes -> {} bytes ciphertext",
        plaintext.len(),
        ciphertext.len()
    );

    let decrypted = aegispq::encrypt::decrypt_file(&ciphertext, &bob, &store)?;
    assert_eq!(&decrypted.plaintext, plaintext);
    println!(
        "Bob decrypted: {:?}",
        std::str::from_utf8(&decrypted.plaintext)?
    );
    println!("Sender confirmed: Alice\n");

    // --- Standalone signing ---
    println!("=== Digital Signatures ===\n");

    let document = b"I hereby certify this document.";
    let signature = aegispq::sign::sign(&alice, document)?;
    println!(
        "Signed {} bytes -> {} byte hybrid signature",
        document.len(),
        signature.len()
    );

    let alice_public = PublicIdentity {
        identity_id: alice.identity_id,
        display_name: alice.display_name.clone(),
        status: alice.status,
        verifying_key: alice.verifying_key.clone(),
        kem_public: alice.kem_public.clone(),
    };

    let valid = aegispq::sign::verify(&alice_public, document, &signature)?;
    println!(
        "Verification: {}\n",
        if valid { "VALID" } else { "INVALID" }
    );

    // --- Streaming encryption ---
    println!("=== Streaming Encryption ===\n");

    let large_data = vec![0xABu8; 100_000];
    let mut input = &large_data[..];
    let mut ciphertext_stream = Vec::new();

    aegispq::encrypt::encrypt_file_stream(
        &mut input,
        &mut ciphertext_stream,
        large_data.len() as u64,
        &alice,
        &[&bob_public],
        &options,
    )?;
    println!(
        "Streamed {} bytes -> {} bytes",
        large_data.len(),
        ciphertext_stream.len()
    );

    let verified = aegispq::encrypt::decrypt_file_stream_verified(
        &mut &ciphertext_stream[..],
        &bob,
        &alice_public,
    )?;
    assert_eq!(verified.len(), large_data.len());
    println!("Stream-decrypted and verified: {} bytes\n", verified.len());

    println!("All operations completed successfully.");
    Ok(())
}
