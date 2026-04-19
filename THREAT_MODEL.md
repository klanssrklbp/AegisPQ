# AegisPQ Threat Model

This document summarizes the threat model for AegisPQ. For the full
specification, see [DESIGN.md](DESIGN.md) (Sections 3-5).

---

## What AegisPQ Protects

### Confidentiality (Hybrid KEM)

All encryption uses a hybrid key encapsulation mechanism combining X25519
(classical) and ML-KEM-768 (post-quantum, FIPS 203). The shared secret is
derived via HKDF-SHA-512 over the concatenation of both shared secrets, so
an attacker must break **both** algorithms to recover plaintext.

Symmetric encryption uses AES-256-GCM (with hardware acceleration where
available) or XChaCha20-Poly1305, selected per suite.

### Integrity (AEAD)

All ciphertext is authenticated. AegisPQ never produces unauthenticated
ciphertext. File encryption uses per-chunk AEAD tags, and the overall file
is bound by a sender signature covering the entire ciphertext.

### Authentication (Hybrid Signatures)

Sender identity is established through hybrid signatures combining Ed25519
(classical) and ML-DSA-65 (post-quantum, FIPS 204). Both signatures must
verify for authentication to succeed. This prevents forgery even if one
signature scheme is broken.

---

## Trust Model

- **Out-of-band fingerprint verification.** AegisPQ does not operate a
  certificate authority or centralized trust infrastructure. Users are
  responsible for verifying recipient fingerprints through an out-of-band
  channel (in person, secure voice call, etc.) before trusting a key
  package.

- **Local store is trusted.** The `FileStore` (or any `Store`
  implementation) is assumed to be on a trusted local filesystem. If an
  attacker can modify the store, they can substitute key material. AegisPQ
  does not provide tamper detection for the store itself; it relies on
  OS-level file permissions and full-disk encryption.

- **Device is trusted at key generation time.** If the device is
  compromised when identity keys are generated, all derived security
  properties are void.

- **OS CSPRNG is trustworthy.** All randomness comes from the operating
  system's cryptographically secure random number generator. AegisPQ does
  not maintain its own entropy pool.

---

## Cryptographic Assumptions

AegisPQ's security rests on a **dual-assumption** model:

1. **Classical assumption:** The hardness of the Elliptic Curve
   Diffie-Hellman problem (X25519) and the hardness of the Elliptic Curve
   Discrete Logarithm problem (Ed25519).

2. **Post-quantum assumption:** The hardness of the Module Learning With
   Errors problem (ML-KEM-768, ML-DSA-65).

**Security requires breaking BOTH the classical and post-quantum
algorithms.** The hybrid construction is designed so that:

- If classical algorithms are broken (e.g., by a cryptographically relevant
  quantum computer), the post-quantum algorithms still provide security.
- If post-quantum algorithms are broken (e.g., by a novel lattice attack),
  the classical algorithms still provide security.
- The HKDF combiner ensures the derived secret is at least as strong as the
  strongest input.

This dual-assumption design is a transitional measure. Once confidence in
post-quantum algorithms matures through years of cryptanalysis, future
versions may offer PQ-only suites.

---

## What Is NOT Protected

### Metadata

AegisPQ does not fully conceal metadata. The following are visible to an
observer with access to the ciphertext:

- **File sizes.** Padding mitigates exact-size leakage (files are padded to
  the next size class boundary), but approximate sizes are still inferable.
- **Recipient count.** The number of recipient slots in an encrypted file
  header reveals how many recipients were addressed.
- **Format identification.** AegisPQ ciphertext is identifiable by its
  magic bytes (`APQ\x01`). The format type, suite identifier, and protocol
  version are in cleartext in the envelope header.
- **Timing.** Timestamps in revocation and rotation certificates are in
  cleartext (they are freshness hints, not secrets).

AegisPQ does not provide sender or receiver anonymity. If anonymity is
required, AegisPQ should be used inside an anonymity transport (e.g., Tor).

### Local Key Compromise

If an attacker gains access to the identity key material on disk and can
defeat the passphrase-derived encryption (Argon2id), they can impersonate
the user and decrypt messages addressed to that identity. AegisPQ mitigates
this with aggressive Argon2id parameters (default: 256 MiB memory, 3
iterations, 4-way parallelism) but cannot prevent brute-force against weak
passphrases.

Forward secrecy for interactive sessions (using ephemeral key exchange)
limits the damage: past session keys remain safe even if the long-term key
is compromised.

### Side Channels

AegisPQ uses constant-time implementations where available (via the
`subtle` crate and constant-time primitives in `ed25519-dalek`,
`x25519-dalek`, `aes-gcm`) but cannot guarantee side-channel resistance on
all platforms. In particular:

- WebAssembly targets may not execute constant-time code reliably.
- Shared hosting or virtualized environments may expose timing information
  through resource contention.
- AegisPQ does not defend against power analysis, electromagnetic
  emanation, or other physical side channels.

---

## Known Limitations

### Streaming Decryption and Signature Verification

Streaming decryption writes plaintext chunks to the output before the
sender's signature over the complete ciphertext has been verified. Each
individual chunk is AEAD-authenticated (protecting integrity and
confidentiality at the chunk level), but the binding between the chunk
sequence and the sender's identity is not confirmed until the trailing
signature is checked.

**Mitigation:** The CLI and the path-based API (`decrypt_file_to_path`)
use a temp-file pattern -- streaming output goes to a temporary file, and
only after signature verification succeeds is the temp file renamed to the
final output path. If verification fails, the temp file is deleted. For
library users, `decrypt_file_stream_verified` buffers all output in memory
and returns it only after the sender signature is verified, providing the
strongest guarantee at the cost of O(file_size) memory. Applications using
the raw streaming API should implement an equivalent pattern.

### Configurable Argon2id Parameters

The `Argon2Params` struct allows callers to configure memory cost,
iteration count, and parallelism. A minimum floor is enforced (64 MiB
memory, 2 iterations), but callers must use production-appropriate defaults
(256 MiB, 3 iterations, 4 parallelism) for passphrase-derived key
encryption. Using the enforced minimums rather than the recommended defaults
reduces resistance to brute-force attacks.

### No Authenticated Store

The local `FileStore` writes identity records, key packages, and trust
data to disk. These files are not individually signed or MAC'd by AegisPQ.
Integrity of the store depends on OS-level protections (file permissions,
full-disk encryption). A local attacker who can write to the store can
substitute key packages.

---

## Attack Surfaces

### File Parsers

The protocol layer includes parsers for:

- Envelope headers (magic bytes, version, format type, suite).
- Encrypted file format (recipient slots, ciphertext chunks, trailing
  signature).
- Key packages (public key bundles with identity binding).
- Revocation certificates.
- Rotation certificates.

All parsers enforce strict length checks and reject unknown format types or
suite identifiers. Parsers are covered by fuzz targets (run nightly in CI):

- `fuzz_envelope` -- Envelope header parsing.
- `fuzz_key_package` -- Key package import.
- `fuzz_decrypt` -- Full file decryption path.
- `fuzz_stream_decrypt` -- Streaming decryption path.
- `fuzz_revocation` -- Revocation certificate parsing.
- `fuzz_rotation` -- Rotation certificate parsing.
- `fuzz_record` -- On-disk identity/contact record parsing.
- `fuzz_signature` -- Hybrid signature deserialization.
- `fuzz_extract_sender` -- Sender ID extraction from encrypted files.

### Key Package Import

Importing a key package from an untrusted source is a critical trust
boundary. AegisPQ validates the self-signature on key packages (the
identity must sign its own public keys), but users must still verify
fingerprints out-of-band.

### Revocation and Rotation Certificates

Revocation and rotation certificates are signed by the identity's existing
key. An attacker who compromises the signing key can issue fraudulent
revocations or rotations. Once a revocation is accepted, the key is marked
as unusable for new operations. Rotation certificates chain the old key to
the new key via a signature from the old key.

---

## Post-Quantum Readiness

AegisPQ implements NIST-standardized post-quantum algorithms:

| Function | Algorithm | Standard | Security Level |
|----------|-----------|----------|----------------|
| Key encapsulation | ML-KEM-768 | FIPS 203 | Level 3 (~128-bit PQ) |
| Digital signature | ML-DSA-65 | FIPS 204 | Level 3 (~128-bit PQ) |

Both are used in hybrid mode alongside their classical counterparts
(X25519, Ed25519). The protocol is versioned and crypto-agile: if NIST
revises these standards or new attacks emerge, updated algorithm suites can
be introduced in new protocol versions without breaking backward
compatibility for existing ciphertext.

The symmetric layer (AES-256-GCM, BLAKE3, HKDF-SHA-512) uses 256-bit keys,
providing a ~128-bit post-quantum security margin under Grover's algorithm.
