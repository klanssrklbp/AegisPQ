<p align="center">
  <strong>AegisPQ</strong><br>
  Hybrid post-quantum file encryption for Rust
</p>

<p align="center">
  <a href="https://github.com/klanssrklbp/AegisPQ/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/klanssrklbp/AegisPQ/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://github.com/klanssrklbp/AegisPQ/actions/workflows/supply-chain.yml"><img src="https://img.shields.io/github/actions/workflow/status/klanssrklbp/AegisPQ/supply-chain.yml?branch=main&label=supply-chain" alt="Supply chain"></a>
  <a href="https://github.com/klanssrklbp/AegisPQ/releases/latest"><img src="https://img.shields.io/github/v/release/klanssrklbp/AegisPQ?label=release&color=blue" alt="Latest release"></a>
  <a href="docs/VERIFYING_RELEASES.md"><img src="https://img.shields.io/badge/signed-cosign%20%2B%20SLSA-brightgreen" alt="Signed releases"></a>
  <a href="https://github.com/klanssrklbp/AegisPQ/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.80%2B-orange" alt="Rust Version">
  <img src="https://img.shields.io/badge/status-experimental-yellow" alt="Status">
  <img src="https://img.shields.io/badge/unsafe-forbidden-brightgreen" alt="No Unsafe">
</p>

---

AegisPQ is an open-source Rust toolkit for **hybrid post-quantum file encryption**, **sender authentication**, and **signed identity exchange**. It combines classical and post-quantum algorithms so that security holds even if one family is broken.

> **Warning:** AegisPQ is experimental and pre-audit. It has not undergone independent security review. Do not use it for high-risk data without understanding the implications.

## Features

- **Hybrid encryption** -- X25519 + ML-KEM-768 key exchange; AES-256-GCM or XChaCha20-Poly1305 symmetric encryption
- **Hybrid signatures** -- Ed25519 + ML-DSA-65 for sender authentication on every encrypted file
- **Multi-recipient encryption** -- Encrypt once for any number of recipients
- **Identity lifecycle** -- Create, rotate, and revoke identities with cryptographic chain of custody
- **Streaming I/O** -- Encrypt and decrypt large files without loading them into memory
- **No unsafe code** -- `#![forbid(unsafe_code)]` enforced across the entire crate tree
- **Atomic writes** -- Decryption uses temp-file-then-rename; no partial output on crash or tampering
- **Machine-readable output** -- `--json` flag on every CLI command for scripting and CI

## Install

### Pre-built binary (recommended)

Pre-built binaries for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64) are published on the [releases page](https://github.com/klanssrklbp/AegisPQ/releases). Every release is signed with [cosign](https://github.com/sigstore/cosign) keyless signing via GitHub's OIDC identity and carries a [SLSA v1](https://slsa.dev/) build-provenance attestation.

```bash
# Pick the release and target triple that match your platform:
VER=v0.1.0
TARGET=x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin, x86_64-pc-windows-msvc
BASE=https://github.com/klanssrklbp/AegisPQ/releases/download/$VER

# Download the archive, the canonical SHA256SUMS manifest, and the cosign material for the manifest.
curl -fLO "$BASE/aegispq-$VER-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
curl -fLO "$BASE/SHA256SUMS.sig"
curl -fLO "$BASE/SHA256SUMS.pem"

# 1. Verify the archive's digest is in the manifest.
sha256sum --check --ignore-missing SHA256SUMS

# 2. Verify the manifest itself was signed by *this* repo's release.yml workflow.
cosign verify-blob \
  --certificate       SHA256SUMS.pem \
  --signature         SHA256SUMS.sig \
  --certificate-identity-regexp \
      '^https://github\.com/klanssrklbp/AegisPQ/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer  https://token.actions.githubusercontent.com \
  SHA256SUMS

# 3. Install.
tar xzf "aegispq-$VER-$TARGET.tar.gz"
sudo install "aegispq-$VER-$TARGET/aegispq" /usr/local/bin/aegispq
```

See [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) for the full three-layer verification procedure (checksums + cosign + `gh attestation verify`).

### From source

```bash
# Requires Rust 1.80+:
cargo install --path crates/aegispq-cli

# Or build a release binary manually:
./scripts/build-release.sh
sudo cp target/release/aegispq /usr/local/bin/
```

### Inspect and complete

```bash
aegispq --version             # Version string
aegispq version               # Version, protocol revision, and capability flags (add --json for machine output)
```

Shell completions (Bash, Zsh, Fish, PowerShell, Elvish):

```bash
aegispq completions bash > /etc/bash_completion.d/aegispq
aegispq completions zsh  > "${fpath[1]}/_aegispq"
```

## Quick Start

```bash
# Create identities for Alice and Bob
echo -e "passphrase\npassphrase" | aegispq identity create --name "Alice"
echo -e "passphrase\npassphrase" | aegispq identity create --name "Bob"

# Export and exchange public keys
echo "passphrase" | aegispq identity export <ALICE_ID> --output alice.pub.apq
echo "passphrase" | aegispq identity export <BOB_ID> --output bob.pub.apq
aegispq contact import bob.pub.apq    # Alice imports Bob's key
aegispq contact import alice.pub.apq  # Bob imports Alice's key

# Alice encrypts a file for Bob
echo "passphrase" | aegispq encrypt \
  --file report.pdf --to <BOB_ID> --identity <ALICE_ID>

# Bob decrypts and verifies Alice's signature
echo "passphrase" | aegispq decrypt \
  --file report.pdf.apq --identity <BOB_ID>
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full team workflow tutorial, and the [examples/](examples/) directory for runnable scripts.

## Architecture

AegisPQ is organized as a Cargo workspace:

```
crates/
  aegispq-core      Low-level cryptographic primitives (AEAD, KEM, signatures, KDF, hashing)
  aegispq-protocol  Wire formats: envelopes, encrypted files, key packages, certificates
  aegispq-store     Persistent storage for identities and contacts (atomic file I/O)
  aegispq-api       High-level API: encrypt/decrypt, identity management, signing
  aegispq-cli       Command-line interface
  aegispq           Public facade crate (re-exports stable API surface)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design breakdown.

## Cryptography

| Function | Classical | Post-Quantum | Standard |
|----------|-----------|-------------|----------|
| Key exchange | X25519 | ML-KEM-768 | FIPS 203 |
| Signatures | Ed25519 | ML-DSA-65 | FIPS 204 |
| Symmetric encryption | AES-256-GCM | -- | |
| Symmetric encryption (alt) | XChaCha20-Poly1305 | -- | |
| Key derivation | HKDF-SHA-512 | -- | |
| Passphrase KDF | Argon2id | -- | |
| Hashing | BLAKE3 | -- | |

Every operation uses hybrid constructions: an attacker must break **both** the classical and post-quantum component to compromise security. See [DESIGN.md](DESIGN.md) for the authoritative protocol specification, [THREAT_MODEL.md](THREAT_MODEL.md) for the threat model, and [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for wire-format and backwards-compatibility guarantees.

## Security Properties

- **Sender authentication** -- Every encrypted file carries a hybrid signature. Decryption verifies the sender before writing any plaintext.
- **Forward secrecy** -- Ephemeral key exchange per encryption operation.
- **Tamper detection** -- AEAD + trailing signature. Corrupted or modified files are rejected with no output.
- **Key zeroization** -- All secret key material is zeroized on drop via the `zeroize` crate.
- **Constant-time comparisons** -- Secret-dependent operations use the `subtle` crate.

## Testing

```bash
cargo test                    # 240+ tests across all crates
cargo bench -p aegispq        # Benchmarks (KEM, signatures, encrypt/decrypt)
cargo +nightly fuzz run <target>  # 9 fuzz targets with seed corpora
```

The test suite includes unit tests, integration tests, property-based tests, frozen binary test vectors (protocol + encrypted file + signature), wire format compatibility tests, CLI end-to-end tests, and cross-platform CI on every push.

For throughput and output-size comparisons against [age](https://age-encryption.org/), see [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Project Status

AegisPQ is under active development. The following is implemented and tested:

- Identity creation, export, import, rotation, and revocation
- Multi-recipient file encryption and decryption (in-memory and streaming)
- Standalone file signing and verification
- CLI with JSON output, structured error codes, and scripting support

See [STATUS.md](STATUS.md) for the detailed implementation checklist and roadmap.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, code style, testing requirements, and PR expectations.

**Security issues:** Do not open public issues. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
