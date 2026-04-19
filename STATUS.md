# AegisPQ Implementation Status

**Version:** 0.1.0
**Last updated:** 2026-04-02

---

## Implemented

### Core Cryptographic Primitives (`aegispq-core`)

- [x] AEAD encryption/decryption (AES-256-GCM, XChaCha20-Poly1305)
- [x] Hybrid KEM: X25519 + ML-KEM-768 (FIPS 203)
- [x] Hybrid signatures: Ed25519 + ML-DSA-65 (FIPS 204)
- [x] HKDF-SHA-512 key derivation
- [x] Argon2id passphrase-based key derivation (configurable params, enforced minimums)
- [x] BLAKE3 hashing (single-shot and incremental/streaming)
- [x] SHA-256/SHA-512 hashing (for interoperability)
- [x] Zeroization of secret key material

### Protocol Layer (`aegispq-protocol`)

- [x] Envelope header: magic bytes, version, format type, suite identifier
- [x] File encryption format (multi-recipient, per-chunk AEAD, trailing hybrid signature)
- [x] In-memory file encryption and decryption
- [x] Streaming file encryption and decryption
- [x] Identity creation and key package export/import
- [x] Revocation certificates (with reason codes: Compromised, Superseded, Retired)
- [x] Rotation certificates (old-key-signs-new-key chaining)
- [x] Padding (size-class-based metadata minimization)
- [x] Version negotiation (current: v1, strict rejection of unknown versions)
- [x] Suite selection: HybridV1 (AES-256-GCM), HybridV1XChaCha (XChaCha20-Poly1305)

### High-Level API (`aegispq-api`)

- [x] Encrypt/decrypt for identified recipients
- [x] Streaming encrypt/decrypt with I/O readers and writers
- [x] Identity management (create, export key package, import key package)
- [x] Revocation issuance and verification
- [x] Rotation issuance and verification

### Storage (`aegispq-store`)

- [x] `FileStore`: filesystem-backed persistent storage
- [x] Identity records with status tracking (Active, Rotated, Revoked)
- [x] Atomic writes via temp-file-then-rename pattern
- [x] Key package storage and lookup

### CLI (`aegispq-cli`)

- [x] `encrypt` / `decrypt` commands (streaming I/O)
- [x] `identity create` / `list` / `export` / `revoke` / `rotate` / `fingerprint`
- [x] `contact import` / `import-revocation` / `import-rotation` / `list` / `inspect`
- [x] `sign` / `verify` standalone commands
- [x] Machine-readable `--json` output on every subcommand
- [x] Passphrase zeroization on all code paths
- [x] Temp-file pattern for safe streaming decryption (signature verified before output promoted)

### Testing and Quality

- [x] Unit tests across all crates
- [x] Integration tests (cross-crate encrypt/decrypt round-trips)
- [x] Property tests (proptest): roundtrips, tamper detection, trailing data rejection
- [x] Fuzz targets: `fuzz_envelope`, `fuzz_key_package`, `fuzz_decrypt`,
  `fuzz_revocation`, `fuzz_rotation`, `fuzz_stream_decrypt`, `fuzz_record`
- [x] Benchmarks (KEM, signatures, file encrypt/decrypt)
- [x] `#![forbid(unsafe_code)]` enforced in all crates
- [x] `#![warn(missing_docs)]` enforced in all crates

---

## Reserved Format Types (Not Yet Implemented)

The following format type identifiers are defined in the `FormatType` enum
but do not have corresponding protocol implementations:

| Byte | Name | Purpose |
|------|------|---------|
| `0x03` | `SessionMessage` | Interactive session messaging protocol with forward secrecy via ephemeral key exchange. |
| `0x06` | `RecoveryBlob` | Pre-shared recovery key blob for device-loss recovery without third-party trust. |
| `0x07` | `SignedDocument` | Detached or embedded signature format for document signing without encryption. |

These are reserved to prevent format-type collisions. Parsing a header with
one of these types will succeed at the envelope level but there is no
encode/decode implementation behind it.

---

## Planned

The following items are on the roadmap but have no implementation yet:

### Near-Term

- [ ] **Session protocol** (`SessionMessage`): Interactive key exchange with
  ephemeral DH, ratcheting, and forward secrecy for real-time messaging.
- [ ] **Recovery blobs** (`RecoveryBlob`): Shamir secret sharing or
  passphrase-wrapped recovery keys for device-loss scenarios.
- [ ] **Signed documents** (`SignedDocument`): Standalone hybrid signature
  format for signing without encryption.
- [ ] **Key discovery**: Mechanism for distributing and discovering key
  packages (directory server, DNS-based, or out-of-band protocol).

### Medium-Term

- [ ] **FFI bindings**: C-compatible FFI layer for integration with Python,
  JavaScript, Go, and other languages.
- [ ] **WASM build**: WebAssembly target for browser and edge environments
  (with documented side-channel caveats).
- [ ] **GUI application**: Graphical interface for file encryption, identity
  management, and contact verification.

### Long-Term

- [ ] **External security audit**: Independent third-party review of the
  cryptographic implementation and protocol design.
- [ ] **Hardware key storage**: Integration with platform keychains and
  hardware security modules (HSM, TPM, Secure Enclave).
- [ ] **Reproducible builds**: Fully reproducible build pipeline for
  verifiable binary distribution.
- [ ] **Algorithm migration tooling**: Automated re-encryption when
  algorithm suites are deprecated or upgraded.
