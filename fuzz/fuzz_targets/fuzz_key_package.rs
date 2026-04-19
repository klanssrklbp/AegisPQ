#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the key package parser — must never panic.
    let _ = aegispq_protocol::identity::KeyPackage::from_bytes(data);
});
