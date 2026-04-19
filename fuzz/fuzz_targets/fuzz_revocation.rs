#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the revocation certificate parser — must never panic.
    let _ = aegispq_protocol::revocation::RevocationCertificate::from_bytes(data);
});
