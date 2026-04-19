# Contributing to AegisPQ

Thank you for your interest in contributing to AegisPQ. This document
describes how to build, test, and submit changes.

## Getting Started

### Prerequisites

- **Rust toolchain:** Stable Rust >= 1.80.0 (see `rust-version` in
  `Cargo.toml`).
- **Nightly Rust** (optional): Required only for running fuzz targets.
- **Git:** For version control and submitting pull requests.

### Repository Structure

AegisPQ is organized as a Cargo workspace with the following crates:

| Crate | Path | Purpose |
|-------|------|---------|
| `aegispq` | `crates/aegispq` | Public facade crate. Re-exports the stable API surface. |
| `aegispq-core` | `crates/aegispq-core` | Low-level cryptographic primitives (AEAD, KEM, signatures, KDF, hashing). |
| `aegispq-protocol` | `crates/aegispq-protocol` | Protocol layer: envelope parsing, file encryption format, identity, revocation, rotation, padding. |
| `aegispq-store` | `crates/aegispq-store` | Persistent storage for identities, key packages, and trust records (`FileStore`). |
| `aegispq-api` | `crates/aegispq-api` | High-level API: encrypt/decrypt, identity management, key package operations. |
| `aegispq-cli` | `crates/aegispq-cli` | Command-line interface. |

## Building

```sh
cargo build
```

To build in release mode (with LTO, single codegen unit, and overflow
checks):

```sh
cargo build --release
```

## Testing

Run the full test suite:

```sh
cargo test
```

Run tests for a specific crate:

```sh
cargo test -p aegispq-core
cargo test -p aegispq-protocol
```

## Benchmarks

Benchmarks live in the `aegispq` facade crate:

```sh
cargo bench -p aegispq
```

## Fuzzing

Fuzz targets are in the `fuzz/` directory and require the nightly toolchain
and `cargo-fuzz`:

```sh
cargo install cargo-fuzz   # if not already installed
```

Available targets:

- `fuzz_envelope` -- Envelope header parsing.
- `fuzz_key_package` -- Key package import/export.
- `fuzz_decrypt` -- In-memory file decryption with arbitrary input.
- `fuzz_stream_decrypt` -- Streaming file decryption with arbitrary input.
- `fuzz_revocation` -- Revocation certificate parsing.
- `fuzz_rotation` -- Rotation certificate parsing.
- `fuzz_record` -- `IdentityRecord` and `ContactRecord` on-disk parsers.

Run a target:

```sh
cd fuzz/
cargo +nightly fuzz run fuzz_envelope
cargo +nightly fuzz run fuzz_decrypt
```

If you add new protocol parsers or extend existing ones, add a
corresponding fuzz target.

## Code Style

### Mandatory Lints

Every crate in the workspace enforces:

```rust
#![forbid(unsafe_code)]
#![warn(missing_docs)]
```

- **No `unsafe` code.** The entire crate tree forbids unsafe blocks. If a
  dependency requires unsafe, it must be an audited, well-maintained crate
  (e.g., `aes-gcm`, `ed25519-dalek`).
- **Document all public items.** Every public function, struct, enum, trait,
  and module must have a doc comment.

### General Guidelines

- No emojis in source code, comments, or doc strings.
- Follow standard `rustfmt` formatting. Run `cargo fmt` before committing.
- Run `cargo clippy` and address all warnings.
- Prefer explicit error types (`thiserror`) over `.unwrap()` or `.expect()`
  in library code. Panics are acceptable only in tests and CLI argument
  validation.
- Use `zeroize` for any type that holds secret key material.
- Use constant-time comparisons (`subtle`) for secret-dependent branching.

## Submitting Changes

### Pull Request Expectations

1. **Tests are required.** Every PR must include tests that cover the new or
   changed behavior. This includes:
   - Unit tests for new functions.
   - Integration tests for cross-crate interactions.
   - Negative tests for error paths and malformed inputs.

2. **Doc comments on public API.** Any new public item must have a doc
   comment explaining its purpose, parameters, return value, and any
   security considerations.

3. **Security-sensitive changes need review.** Changes to the following
   areas require explicit review from a maintainer with cryptographic
   expertise before merging:
   - Cryptographic operations (AEAD, KEM, signatures, KDF, hashing).
   - Nonce generation or management.
   - Key material handling (generation, storage, zeroization).
   - Protocol parsing (envelope, file format, key packages).
   - Padding or metadata handling.

4. **One concern per PR.** Keep pull requests focused. A PR that adds a
   feature should not also refactor unrelated code.

5. **Describe the change.** The PR description should explain what changed,
   why, and how to verify it. For security-relevant changes, include an
   assessment of the security impact.

### Workflow

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, following the code style guidelines above.
3. Run the full test suite (`cargo test`) and lints (`cargo fmt --check`,
   `cargo clippy`).
4. Push your branch and open a pull request against `main`.
5. Respond to review feedback.

### Commit Messages

- Use imperative mood ("Add streaming decrypt", not "Added streaming
  decrypt").
- Keep the subject line under 72 characters.
- Reference related issues where applicable (e.g., "Fixes #42").

## Reporting Security Issues

Do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

By contributing to AegisPQ, you agree that your contributions will be
licensed under the same terms as the project: MIT OR Apache-2.0
(dual-licensed).
