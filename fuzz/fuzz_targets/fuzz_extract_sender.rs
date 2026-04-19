#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the high-level extract_sender_id entry point — the first thing
    // the API does when receiving an encrypted file from an untrusted source.
    // Exercises envelope header parsing + sender ID extraction from the
    // encrypted file header. Must never panic on arbitrary input.
    let _ = aegispq_api::encrypt::extract_sender_id(data);
});
