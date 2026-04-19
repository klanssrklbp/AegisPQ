
# AegisPQ vs age — encrypt/decrypt benchmark

- Host: Linux 6.18.5+kali-amd64 x86_64
- Rust toolchain: rustc 1.95.0 (59807616e 2026-04-14)
- aegispq: aegispq 0.1.0
- rage (age): rage 0.11.1
- Iterations per cell (best of): 5
- AegisPQ uses hybrid X25519+ML-KEM-768 KEM, Ed25519+ML-DSA-65 signature, AES-256-GCM AEAD.
- age uses X25519, ChaCha20-Poly1305, no signature.

## Throughput (seconds, lower is better)

| File size | aegispq encrypt | age encrypt | aegispq decrypt | age decrypt |
|---|---|---|---|---|
| 1 KiB | 0.127s | 0.004s | 0.130s | 0.006s |
| 64 KiB | 0.126s | 0.004s | 0.137s | 0.004s |
| 1 MiB | 0.137s | 0.006s | 0.142s | 0.006s |
| 16 MiB | 0.277s | 0.034s | 0.300s | 0.045s |

## Output size overhead (bytes added to plaintext)

| File size | aegispq ciphertext | aegispq overhead | age ciphertext | age overhead |
|---|---|---|---|---|
| 1 KiB | 6714 B | 5690 B | 1282 B | 258 B |
| 64 KiB | 135738 B | 70202 B | 65844 B | 308 B |
| 1 MiB | 2101850 B | 1053274 B | 1049126 B | 550 B |
| 16 MiB | 33560090 B | 16782874 B | 16781580 B | 4364 B |

## How to read these numbers

The two tools solve different problems. AegisPQ includes features that age does not: a hybrid post-quantum KEM, a hybrid sender signature, and a default padding scheme that rounds output up to the next power of two to resist file-size fingerprinting. Each of those shows up in the numbers here.

**Fixed per-file overhead.** AegisPQ adds roughly 5.6 KiB that age does not: a hybrid signature (Ed25519 + ML-DSA-65 ≈ 3.4 KiB), a hybrid KEM ciphertext (X25519 + ML-KEM-768 ≈ 1.1 KiB), and a slightly larger envelope header. age stores only a small X25519 wrap (~100 B per recipient) and has no signature or post-quantum component.

**Padding overhead.** AegisPQ currently applies the `PowerOfTwo` padding scheme, which rounds payload length up to the next power of two — that is why the 1 MiB row shows ~2× ciphertext: the 1 MiB payload plus header bytes rounds up to the 2 MiB bucket. This is a deliberate tradeoff for traffic-analysis resistance. The library API (`aegispq_protocol::file::encrypt`) takes a `PaddingScheme` argument if you need a different bucket size or `PaddingScheme::None`; the CLI does not yet expose this knob.

**Startup cost dominates small files.** Both tools have a fixed process-startup + keygen/signing cost per invocation. ML-DSA-65 signing is the slowest step in AegisPQ's encrypt path; expect ~100 ms of fixed cost before any bytes are touched. For streaming many small files, amortize by using the library API directly rather than the CLI.

**Bulk throughput.** At 16 MiB the ratio stabilizes: AegisPQ ≈ 1 / (age throughput × 8), dominated by AEAD speed and the extra padding write. Both tools use AES-NI / ChaCha20 hardware paths.

**Reproducibility.** Wall-clock best-of-5 on an unloaded machine. CPU frequency scaling and disk cache state shift absolute numbers; the ratios are the portable signal. Regenerate with `scripts/bench-vs-age.sh`.
