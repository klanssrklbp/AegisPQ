#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the hybrid signature parser — must never panic.
    // Covers both the length-prefixed classical (Ed25519) and PQ (ML-DSA-65)
    // signature components, including truncated, oversized, and malformed inputs.
    let _ = aegispq_core::sig::HybridSignature::from_bytes(data);
});
