# Protocol v1 Test Vectors

Frozen binary fixtures for the AegisPQ v1 wire format.

These files are checked into version control and must **never** be modified
in place. If the protocol format changes, create a `v2/` directory with new
fixtures and update the test expectations accordingly.

## Files

| File | Format Type | Description |
|------|-------------|-------------|
| `key_package.bin` | `0x02` (KeyPackage) | Deterministic key package with known field values |
| `revocation_cert.bin` | `0x04` (RevocationCertificate) | Revocation cert for reason=Compromised |
| `rotation_cert.bin` | `0x05` (RotationCertificate) | Rotation cert with dual signatures |

## Regenerating

```sh
cargo test -p aegispq-protocol --test frozen_vectors -- --ignored
```

This overwrites the `.bin` files with freshly-serialized fixtures. Only do
this after a **deliberate, reviewed** protocol change.

## Fixture field values

All fixtures use repeating-byte patterns for easy visual inspection in a
hex editor:

- Identity IDs: `0x01*16`, `0xAA*16`, `0xCC*16`, `0xDD*16`
- Ed25519 keys: `0x11*32` or `0xE1*32`
- ML-DSA keys: `0x22*1952` or `0xE2*1952`
- X25519 keys: `0x33*32` or `0xE3*32`
- ML-KEM keys: `0x44*1184` or `0xE4*1184`
- Signatures: `0x55*128`, `0xBB*96`, `0xF1*64`, `0xF2*64`
- Timestamps: `1700000000`, `1700100000`, `1700200000`
