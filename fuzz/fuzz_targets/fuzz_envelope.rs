#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the envelope header parser — must never panic.
    let _ = aegispq_protocol::envelope::Header::from_bytes(data);
});
