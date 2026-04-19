#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the in-memory decrypt path with fixed keys.
    // The goal is to find panics, not valid decryptions.
    let kem_kp = aegispq_core::kem::generate_keypair().unwrap();
    let identity_id: [u8; 16] = [0u8; 16];
    let (_, vk) = aegispq_core::sig::generate_keypair().unwrap();

    let _ = aegispq_protocol::file::decrypt(data, &kem_kp, &identity_id, &vk);
});
