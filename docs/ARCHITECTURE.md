# AegisPQ Architecture

## Crate dependency graph

```
aegispq (facade / re-export crate)
  |
  +-- aegispq-api (high-level API: identity, encrypt, sign)
  |     |
  |     +-- aegispq-protocol (wire formats, envelope, certs)
  |     |     |
  |     |     +-- aegispq-core (raw crypto primitives)
  |     |
  |     +-- aegispq-store (on-disk encrypted storage)
  |           |
  |           +-- aegispq-core
  |
  +-- aegispq-cli (command-line interface, depends on aegispq-api)
```

All crates use `#![forbid(unsafe_code)]`.

## Crate responsibilities

### aegispq-core

Raw cryptographic building blocks. No protocol awareness.

- `aead` — AES-256-GCM and XChaCha20-Poly1305 authenticated encryption
- `hash` — BLAKE3 hashing with transcript (length-prefixed multi-input) mode
- `kdf` — Argon2id passphrase hashing and HKDF key derivation
- `kem` — Hybrid KEM: X25519 + ML-KEM-768 encapsulation/decapsulation
- `sig` — Hybrid signatures: Ed25519 + ML-DSA-65 signing/verification
- `nonce` — GCM nonce counter and XChaCha random nonce generation

### aegispq-protocol

Wire format definitions. Handles serialization, not crypto operations.

- `envelope` — 12-byte header parser/builder (magic, format type, version, suite, length)
- `file` — Encrypted file format: multi-recipient KEM slots, chunked AEAD, sender signature
- `identity` — KeyPackage serialization, fingerprint computation
- `padding` — Plaintext padding (None, PowerOfTwo, FixedBlock)
- `revocation` — RevocationCertificate construction and parsing
- `rotation` — RotationCertificate construction and parsing
- `version` — Protocol version constants

### aegispq-store

Filesystem-backed encrypted storage for identities and contacts.

- `fs::FileStore` — Directory-tree storage with atomic writes and file permissions
- `record` — IdentityRecord / ContactRecord binary serialization
- `keystore` — Passphrase-protected key wrapping (Argon2id + AES-256-GCM)

### aegispq-api

High-level operations that compose protocol + store + core.

- `identity` — Create, load, export, import, revoke, rotate identities
- `encrypt` — In-memory, streaming, and path-based file encryption/decryption
- `sign` — Standalone hybrid signing and verification
- `types` — Public data types (Identity, PublicIdentity, EncryptOptions)
- `error` — User-facing error types

### aegispq (facade)

Re-exports the public API surface. Users depend on this single crate.
Splits API into stable (identity, encrypt, sign, types, error, store) and
advanced (protocol, core) tiers.

### aegispq-cli

Command-line interface. Depends only on aegispq-api.

- Subcommands: identity {create,list,export,revoke,rotate,fingerprint},
  contact {import,import-revocation,import-rotation,list,inspect},
  encrypt, decrypt, sign, verify
- `--json` mode for machine-readable output
- Passphrase input via tty prompt or piped stdin
- `AEGISPQ_FAST_KDF=1` escape hatch for test automation

## Key design decisions

**Hybrid construction:** Every asymmetric operation combines classical
(X25519/Ed25519) and post-quantum (ML-KEM-768/ML-DSA-65) algorithms.
Security requires breaking *both*.

**No unsafe code:** The entire workspace forbids unsafe code. All crypto
is delegated to audited dependencies (RustCrypto, ml-kem, ml-dsa).

**Atomic storage writes:** FileStore writes to a temp file then renames,
preventing partial/corrupt records on crash.

**Sender-authenticated encryption:** Every encrypted file carries a hybrid
signature. The CLI's decrypt command verifies the signature before exposing
any plaintext at the output path (temp-file-then-rename pattern).

**Chunked AEAD:** Large files are encrypted in chunks with per-chunk
authentication tags, enabling streaming decryption with early tamper detection.

## Test infrastructure

- **Unit tests:** Each crate has inline `#[cfg(test)]` modules
- **Integration tests:** `aegispq-api/tests/integration.rs` (30 tests)
- **CLI e2e tests:** `aegispq-cli/tests/cli.rs` (15 tests, uses assert_cmd)
- **Property tests:** `aegispq-protocol/tests/property_tests.rs` (14 tests, proptest)
- **Wire compat tests:** `aegispq-protocol/tests/wire_format_compat.rs` (10 tests)
- **Frozen vectors:** `aegispq-protocol/tests/frozen_vectors.rs` + `tests/vectors/v1/`
- **Storage compat tests:** `aegispq-store/tests/compat_tests.rs` (10 tests)
- **Fuzzing:** 7 targets under `fuzz/fuzz_targets/` with 46 corpus seeds

## Good first issues

If you're looking to contribute, these areas are approachable:

- Add more CLI integration tests for edge cases
- Expand fuzz corpus with interesting inputs
- Improve error messages in `aegispq-api/src/error.rs`
- Add `Display` implementations for protocol types
- Write examples in `examples/` directory
- Improve documentation strings on public API items
