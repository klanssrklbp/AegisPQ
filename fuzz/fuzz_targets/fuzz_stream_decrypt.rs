#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the streaming decrypt path with fixed keys.
    // Keygen per input is acceptable — the fuzzer exercises the parser, not the crypto.
    let kem_kp = aegispq_core::kem::generate_keypair().unwrap();
    let identity_id: [u8; 16] = [0u8; 16];
    let (_, vk) = aegispq_core::sig::generate_keypair().unwrap();

    let mut reader = std::io::Cursor::new(data);
    let mut writer: Vec<u8> = Vec::new();

    let _ = aegispq_protocol::file::decrypt_stream(
        &mut reader,
        &mut writer,
        &kem_kp,
        &identity_id,
        &vk,
    );
});
