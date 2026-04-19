#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the identity and contact record parsers — must never panic.
    let _ = aegispq_store::record::IdentityRecord::from_bytes(data);
    let _ = aegispq_store::record::ContactRecord::from_bytes(data);
});
