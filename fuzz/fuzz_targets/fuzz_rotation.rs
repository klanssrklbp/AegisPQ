#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the rotation certificate parser — must never panic.
    let _ = aegispq_protocol::rotation::RotationCertificate::from_bytes(data);
});
