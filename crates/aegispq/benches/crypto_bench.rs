//! Benchmarks for AegisPQ cryptographic operations.
//!
//! Run with: cargo bench

#![allow(unused)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use aegispq_core::{aead, hash, kem, sig, nonce, kdf};
use aegispq_protocol::file::{self, RecipientInfo};
use aegispq_protocol::padding::PaddingScheme;
use aegispq_protocol::identity::{IdentityId, IDENTITY_ID_LEN};
use aegispq_protocol::Suite;

// ---------------------------------------------------------------------------
// Minimal benchmark harness (no external deps)
// ---------------------------------------------------------------------------

struct BenchResult {
    name: String,
    iterations: u64,
    total: Duration,
}

impl BenchResult {
    fn per_op(&self) -> Duration {
        self.total / self.iterations as u32
    }

    fn ops_per_sec(&self) -> f64 {
        self.iterations as f64 / self.total.as_secs_f64()
    }
}

fn bench<F: FnMut()>(name: &str, target_secs: f64, mut f: F) -> BenchResult {
    // Warmup.
    f();

    // Calibrate: run for ~0.5s to estimate iterations.
    let calibrate_start = Instant::now();
    let mut count = 0u64;
    while calibrate_start.elapsed().as_secs_f64() < 0.5 {
        f();
        count += 1;
    }
    let calibrate_elapsed = calibrate_start.elapsed();

    let estimated_per_op = calibrate_elapsed.as_secs_f64() / count as f64;
    let target_iters = ((target_secs / estimated_per_op) as u64).max(3);

    // Measured run.
    let start = Instant::now();
    for _ in 0..target_iters {
        black_box(f());
    }
    let total = start.elapsed();

    BenchResult {
        name: name.to_string(),
        iterations: target_iters,
        total,
    }
}

fn report(results: &[BenchResult]) {
    println!("\n{:<40} {:>12} {:>12} {:>10}", "Benchmark", "per op", "ops/s", "iters");
    println!("{}", "-".repeat(78));
    for r in results {
        let per_op = r.per_op();
        let per_op_str = if per_op.as_millis() > 0 {
            format!("{:.2} ms", per_op.as_secs_f64() * 1000.0)
        } else {
            format!("{:.2} us", per_op.as_secs_f64() * 1_000_000.0)
        };
        println!(
            "{:<40} {:>12} {:>12.1} {:>10}",
            r.name,
            per_op_str,
            r.ops_per_sec(),
            r.iterations,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Benchmark targets
// ---------------------------------------------------------------------------

fn main() {
    let mut results = Vec::new();

    // --- Key generation ---
    results.push(bench("sig::generate_keypair", 2.0, || {
        let _ = black_box(sig::generate_keypair().unwrap());
    }));

    results.push(bench("kem::generate_keypair", 2.0, || {
        let _ = black_box(kem::generate_keypair().unwrap());
    }));

    // --- KEM ---
    let kem_kp = kem::generate_keypair().unwrap();
    let kem_pk = kem::public_key(&kem_kp);
    let context = b"bench-context";

    results.push(bench("kem::encapsulate", 2.0, || {
        let _ = black_box(kem::encapsulate(&kem_pk, context).unwrap());
    }));

    let encap = kem::encapsulate(&kem_pk, context).unwrap();
    results.push(bench("kem::decapsulate", 2.0, || {
        let _ = black_box(kem::decapsulate(
            &kem_kp,
            &encap.classical_ephemeral_pk,
            encap.pq_ciphertext.as_bytes(),
            context,
        ).unwrap());
    }));

    // --- Signing ---
    let (sk, vk) = sig::generate_keypair().unwrap();
    let msg_32 = [0u8; 32];
    let msg_1k = vec![0u8; 1024];
    let domain = b"bench-domain";

    results.push(bench("sig::sign (32 B)", 2.0, || {
        let _ = black_box(sig::sign(&sk, domain, &msg_32).unwrap());
    }));

    results.push(bench("sig::sign (1 KiB)", 2.0, || {
        let _ = black_box(sig::sign(&sk, domain, &msg_1k).unwrap());
    }));

    let sig_32 = sig::sign(&sk, domain, &msg_32).unwrap();
    results.push(bench("sig::verify (32 B)", 2.0, || {
        let _ = black_box(sig::verify(&vk, domain, &msg_32, &sig_32).unwrap());
    }));

    // --- AEAD ---
    let aead_key = aead::AeadKey::from_slice(&[0x42u8; 32]).unwrap();
    let pt_1k = vec![0u8; 1024];
    let pt_64k = vec![0u8; 65536];
    let aad = b"bench-aad";

    results.push(bench("aead::seal AES-256-GCM (1 KiB)", 2.0, || {
        let _ = black_box(aead::seal(aead::Algorithm::Aes256Gcm, &aead_key, aad, &pt_1k, None).unwrap());
    }));

    results.push(bench("aead::seal AES-256-GCM (64 KiB)", 2.0, || {
        let _ = black_box(aead::seal(aead::Algorithm::Aes256Gcm, &aead_key, aad, &pt_64k, None).unwrap());
    }));

    results.push(bench("aead::seal XChaCha20 (1 KiB)", 2.0, || {
        let _ = black_box(aead::seal(aead::Algorithm::XChaCha20Poly1305, &aead_key, aad, &pt_1k, None).unwrap());
    }));

    let ct_1k = aead::seal(aead::Algorithm::Aes256Gcm, &aead_key, aad, &pt_1k, None).unwrap();
    results.push(bench("aead::open AES-256-GCM (1 KiB)", 2.0, || {
        let _ = black_box(aead::open(aead::Algorithm::Aes256Gcm, &aead_key, aad, &ct_1k).unwrap());
    }));

    // --- Hashing ---
    let hash_64k = vec![0u8; 65536];
    results.push(bench("blake3 hash (64 KiB)", 2.0, || {
        let _ = black_box(hash::blake3_hash(&hash_64k));
    }));

    // --- File encrypt/decrypt (in-memory, 1 KiB payload) ---
    let sender_id: IdentityId = nonce::random_bytes().unwrap();
    let recip_kp = kem::generate_keypair().unwrap();
    let recip_pk = kem::public_key(&recip_kp);
    let recip_id: IdentityId = nonce::random_bytes().unwrap();
    let (sender_sk, sender_vk) = sig::generate_keypair().unwrap();
    let recip_info = [RecipientInfo {
        identity_id: recip_id,
        kem_public_key: recip_pk,
    }];
    let payload_1k = vec![0xABu8; 1024];

    results.push(bench("file::encrypt (1 KiB)", 2.0, || {
        let _ = black_box(file::encrypt(
            &payload_1k,
            &sender_sk,
            &sender_id,
            &recip_info,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        ).unwrap());
    }));

    let encrypted_1k = file::encrypt(
        &payload_1k,
        &sender_sk,
        &sender_id,
        &recip_info,
        Suite::HybridV1,
        PaddingScheme::PowerOfTwo,
        0,
    ).unwrap();

    results.push(bench("file::decrypt (1 KiB)", 2.0, || {
        let _ = black_box(file::decrypt(
            &encrypted_1k,
            &recip_kp,
            &recip_id,
            &sender_vk,
        ).unwrap());
    }));

    // --- File encrypt/decrypt (streaming, 64 KiB payload) ---
    let payload_64k = vec![0xABu8; 65536];

    results.push(bench("file::encrypt_stream (64 KiB)", 2.0, || {
        let mut out = Vec::new();
        let _ = black_box(file::encrypt_stream(
            &mut &payload_64k[..],
            &mut out,
            payload_64k.len() as u64,
            &sender_sk,
            &sender_id,
            &recip_info,
            Suite::HybridV1,
            PaddingScheme::PowerOfTwo,
            0,
        ).unwrap());
    }));

    let mut encrypted_64k = Vec::new();
    file::encrypt_stream(
        &mut &payload_64k[..],
        &mut encrypted_64k,
        payload_64k.len() as u64,
        &sender_sk,
        &sender_id,
        &recip_info,
        Suite::HybridV1,
        PaddingScheme::PowerOfTwo,
        0,
    ).unwrap();

    results.push(bench("file::decrypt_stream (64 KiB)", 2.0, || {
        let mut out = Vec::new();
        let _ = black_box(file::decrypt_stream(
            &mut &encrypted_64k[..],
            &mut out,
            &recip_kp,
            &recip_id,
            &sender_vk,
        ).unwrap());
    }));

    report(&results);
}
