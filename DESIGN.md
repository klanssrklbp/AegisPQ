# AegisPQ — Design Specification

**Version:** 0.1.0-draft
**Date:** 2026-03-30
**Status:** Pre-implementation specification
**License:** To be determined (see Section 20)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Definition](#2-project-definition)
3. [Assumptions](#3-assumptions)
4. [Threat Model](#4-threat-model)
5. [Security Objectives](#5-security-objectives)
6. [Non-Goals](#6-non-goals)
7. [Chosen Cryptographic Approach](#7-chosen-cryptographic-approach)
8. [System Architecture](#8-system-architecture)
9. [Protocols and Data Flows](#9-protocols-and-data-flows)
10. [Data Formats and Versioning](#10-data-formats-and-versioning)
11. [APIs and Module Boundaries](#11-apis-and-module-boundaries)
12. [Repository Structure](#12-repository-structure)
13. [Build, Test, and Release Pipeline](#13-build-test-and-release-pipeline)
14. [Security Hardening Checklist](#14-security-hardening-checklist)
15. [Migration and Crypto-Agility Plan](#15-migration-and-crypto-agility-plan)
16. [Product Roadmap](#16-product-roadmap)
17. [Adoption and Packaging Strategy](#17-adoption-and-packaging-strategy)
18. [Donation and Sponsorship Model](#18-donation-and-sponsorship-model)
19. [Documentation Plan](#19-documentation-plan)
20. [Governance and Maintenance Model](#20-governance-and-maintenance-model)
21. [Open Questions and Risks](#21-open-questions-and-risks)

---

## 1. Executive Summary

AegisPQ is an open-source encryption platform that provides identity-aware, post-quantum-ready, crypto-agile protection for files, messages, secrets, and API payloads. It does not replace AES or any other cryptographic primitive; it builds on top of standard, audited primitives — including AES-256-GCM, X25519, ML-KEM-768, ML-DSA-65, Ed25519, BLAKE3, and Argon2id — to deliver a complete system with key management, versioned protocols, secure defaults, forward secrecy, key rotation, revocation, recovery, and metadata minimization. The goal is a practical product that can be adopted by individuals, developers, and organizations, audited by independent cryptographers, funded through transparent donations and sponsorships, and maintained for many years without requiring trust in any single entity or primitive family.

---

## 2. Project Definition

### 2.1 What AegisPQ Is

AegisPQ is a **cryptographic platform** — a layered system that combines:

- A **core cryptographic library** implementing standard primitives behind a misuse-resistant API.
- A **protocol layer** defining versioned message and file encryption formats with key management, identity binding, forward secrecy, and post-quantum hybrid key establishment.
- A **CLI tool** for encrypting/decrypting files, managing identities, and rotating keys.
- **SDK bindings** (initially Rust, then C FFI, Python, and JavaScript/WASM) for embedding AegisPQ into applications.
- A **specification** describing all protocols, formats, and security properties so that independent implementations and audits are possible.

### 2.2 What AegisPQ Is Not

- **Not a new cipher.** AegisPQ does not invent, replace, or claim to improve upon AES, ChaCha20, or any symmetric primitive.
- **Not a messaging app.** It provides encryption primitives and protocols that a messaging app could use, but it is not a user-facing chat application.
- **Not a certificate authority or PKI.** It provides local identity and key management. It does not operate a centralized trust hierarchy.
- **Not a VPN or transport layer.** It encrypts data at rest and data in transit at the application layer. It does not replace TLS, WireGuard, or network-layer encryption.
- **Not a password manager.** It can encrypt secrets, but it does not manage website credentials, browser autofill, or vault sync.

### 2.3 User Groups

| Group | Primary Use Case |
|-------|-----------------|
| **Individuals** | Encrypt personal files, sign documents, manage personal keys |
| **Developers** | Embed encryption in applications via SDK; encrypt secrets in CI/CD |
| **Security teams** | Evaluate, audit, and deploy AegisPQ within organizational infrastructure |
| **Organizations** | Encrypt data at rest, manage team keys, enforce rotation policies, meet compliance requirements for post-quantum readiness |

### 2.4 Problem Statement

Existing encryption tools typically offer one of:
- A single primitive (e.g., `openssl enc -aes-256-cbc`) with no key management, no identity binding, and no upgrade path.
- A full application (e.g., Signal, age) that is excellent within its scope but not designed as a reusable platform for diverse use cases.
- Enterprise key management systems that are proprietary, expensive, and difficult to audit.

AegisPQ fills the gap: a **free, open, auditable platform** that provides system-level encryption with secure defaults, post-quantum readiness, and crypto-agility, usable as both a standalone tool and an embeddable library.

---

## 3. Assumptions

### 3.1 Platform Assumptions

- **A1.** The host operating system provides a cryptographically secure random number generator (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes` on macOS/iOS). AegisPQ will not attempt to seed its own entropy pool.
- **A2.** The host provides memory protection (virtual memory, process isolation). AegisPQ will use `mlock` and zeroization where available but cannot defend against a fully compromised kernel.
- **A3.** The Rust compiler and its standard library are not backdoored. This assumption is partially mitigable through reproducible builds and compiler diversity (see Section 13).
- **A4.** Clocks may be unreliable. AegisPQ will use timestamps for freshness hints but will never use wall-clock time as the sole input to a security decision.

### 3.2 Trust Assumptions

- **A5.** The user's device is trusted at the time of key generation. If the device is compromised during key generation, all derived security properties are void.
- **A6.** The user is responsible for protecting their identity key material. AegisPQ will encrypt identity keys at rest using a passphrase-derived key (Argon2id) and will support hardware-backed key storage where available, but cannot prevent a user from choosing a weak passphrase.
- **A7.** No single cryptographic primitive is assumed to be permanently secure. The system is designed so that any primitive can be replaced without redesigning the protocol.
- **A8.** Post-quantum algorithms (ML-KEM, ML-DSA) are assumed to be secure against known quantum attacks based on current NIST evaluation. They are used in hybrid mode alongside classical algorithms so that security degrades gracefully if either family is broken.

### 3.3 Deployment Assumptions

- **A9.** AegisPQ may be deployed in air-gapped environments. All operations must work offline. Key distribution and revocation require explicit sync steps, not always-on connectivity.
- **A10.** AegisPQ may be used on resource-constrained devices (e.g., Raspberry Pi, CI runners). Performance-critical paths must have bounded memory usage and predictable latency.
- **A11.** AegisPQ artifacts may pass through untrusted storage (cloud drives, email attachments, USB drives). All ciphertext formats must be self-authenticating and tamper-evident.

### 3.4 Assumptions That May Change

- **A12.** NIST post-quantum standards (FIPS 203, FIPS 204) may be revised. AegisPQ must be able to adopt updated parameters or replacement algorithms.
- **A13.** New side-channel attacks against ML-KEM or ML-DSA may emerge. The hybrid design (Section 7) mitigates this during the transition period.
- **A14.** WebAssembly support for constant-time operations is incomplete as of 2026. WASM builds may have weaker side-channel resistance than native builds. This must be documented.

---

## 4. Threat Model

### 4.1 Adversary Classes

| Adversary | Capabilities | Example |
|-----------|-------------|---------|
| **Passive network observer** | Can record all ciphertext in transit; cannot modify | ISP, backbone tap |
| **Active network attacker** | Can intercept, modify, replay, and inject messages | Compromised router, hostile Wi-Fi |
| **Endpoint malware** | Can read memory, files, and keystrokes on one endpoint | Trojan, RAT |
| **Stolen-device attacker** | Has physical access to a powered-off device | Theft, border seizure |
| **Insider attacker** | Has legitimate access to some keys or infrastructure | Rogue employee |
| **Nation-state attacker** | Combines network, endpoint, legal compulsion, and large compute | Intelligence agency |
| **Future quantum attacker** | Has a cryptographically relevant quantum computer | Projected 2030–2045 |
| **Supply-chain attacker** | Can compromise dependencies, build tools, or distribution channels | Dependency hijack, CI compromise |
| **AI-assisted attacker** | Uses automated tools for vulnerability discovery, fuzzing, and exploit generation | Automated exploit frameworks |

### 4.2 Attack Surfaces

| Surface | Threats | Mitigations (reference) |
|---------|---------|------------------------|
| **Ciphertext at rest** | Brute force, known-plaintext, padding oracle, format confusion | AEAD (Section 7), versioned formats (Section 10) |
| **Ciphertext in transit** | Replay, reorder, truncation, injection | Sequence numbers, AEAD, session binding (Section 9) |
| **Key material at rest** | Theft from disk | Passphrase-derived encryption, `mlock`, zeroization (Section 14) |
| **Key exchange** | MITM, downgrade, quantum harvest-now-decrypt-later | Hybrid KEM, out-of-band verification, version pinning (Sections 7, 9) |
| **Identity** | Impersonation, key substitution | Signatures, identity binding in protocol (Section 9) |
| **Metadata** | Traffic analysis, correlation, timing | Metadata minimization, padding, no plaintext headers (Section 9) |
| **Software supply chain** | Backdoored dependencies, compromised builds | Reproducible builds, dependency pinning, code signing (Section 13) |
| **User error** | Weak passphrase, key reuse, accidental plaintext exposure | Secure defaults, entropy checks, warnings (Sections 8, 14) |
| **Protocol downgrade** | Forcing use of deprecated algorithm suite | Strict version negotiation, no fallback to removed suites (Section 15) |

### 4.3 Security Properties Per Threat

| Property | Definition | Priority |
|----------|-----------|----------|
| **Confidentiality** | Only intended recipients can read plaintext | Mandatory |
| **Integrity** | Any modification to ciphertext is detected before decryption | Mandatory |
| **Authenticity** | The sender's identity is cryptographically bound to the message | Mandatory |
| **Forward secrecy** | Compromise of long-term keys does not reveal past session keys | Mandatory for sessions; best-effort for one-shot file encryption |
| **Post-quantum confidentiality** | Ciphertext recorded today remains confidential against future quantum computers | Mandatory (via hybrid KEM) |
| **Post-quantum authenticity** | Signatures remain unforgeable against quantum computers | Mandatory (via hybrid signatures) |
| **Replay resistance** | Replayed messages are detected and rejected | Mandatory for sessions; handled by nonce uniqueness for files |
| **Downgrade resistance** | An attacker cannot force use of a weaker algorithm suite | Mandatory |
| **Metadata minimization** | Ciphertext leaks as little metadata as possible (no plaintext filenames, no recipient list in cleartext) | Best-effort; see limitations in Section 6 |
| **Availability** | The system degrades gracefully under attack; denial-of-service is mitigated where feasible | Best-effort |

### 4.4 Failure Modes

- **Key compromise:** If a long-term identity key is compromised, the attacker can impersonate the user and decrypt future messages. Past session keys (generated with ephemeral Diffie-Hellman) remain safe (forward secrecy). Revocation must be propagated to contacts.
- **Algorithm break:** If one primitive family (classical or post-quantum) is broken, the hybrid construction ensures the other family still provides security. This is a temporary bridge; the broken family must be removed in a subsequent version.
- **Implementation bug:** A bug in AEAD, KDF, or nonce handling could void all security properties. Mitigation: small auditable core, extensive testing including known-answer tests, fuzzing, and property tests.
- **Nonce reuse:** AES-256-GCM is catastrophically broken on nonce reuse. Mitigation: nonces are derived from a counter concatenated with random bytes; the counter is persisted; the API does not accept user-supplied nonces.
- **Passphrase weakness:** If the user chooses a weak passphrase for identity key encryption, a stolen-device attacker can brute-force it. Mitigation: Argon2id with aggressive parameters, entropy estimation warning (not enforcement — users may have legitimate reasons for low-entropy passphrases in automated environments).

---

## 5. Security Objectives

### 5.1 Mandatory Objectives

| ID | Objective | Verification |
|----|-----------|-------------|
| **SO-1** | All encryption uses authenticated encryption (AEAD). No unauthenticated ciphertext is ever produced. | Code audit, known-answer tests |
| **SO-2** | All key exchange uses hybrid classical + post-quantum KEM. | Protocol audit, test vectors |
| **SO-3** | All signatures use hybrid classical + post-quantum signatures. | Protocol audit, test vectors |
| **SO-4** | Forward secrecy is provided for all interactive sessions via ephemeral key exchange. | Protocol analysis |
| **SO-5** | Nonces are never reused within the same key. Counter + random derivation with persistence. | Property tests, fuzzing |
| **SO-6** | Key material is zeroized from memory after use. | Code audit, runtime tests on supported platforms |
| **SO-7** | Ciphertext formats are versioned. Unknown versions cause hard rejection, not silent fallback. | Negative tests |
| **SO-8** | Algorithm downgrade is prevented by binding the negotiated suite into the session transcript. | Protocol audit |
| **SO-9** | Key rotation is a first-class operation with explicit transition semantics. | Integration tests |
| **SO-10** | Revocation is explicit and propagated. Revoked keys cannot be used for new operations. | Integration tests |
| **SO-11** | All randomness comes from the OS CSPRNG. No userspace seeding, no custom PRNGs. | Code audit |
| **SO-12** | Secrets never appear in logs, error messages, telemetry, or crash reports. | Grep audit, runtime tests |

### 5.2 Best-Effort Objectives

| ID | Objective | Notes |
|----|-----------|-------|
| **SO-13** | Metadata minimization: ciphertext does not reveal plaintext size (within padding granularity), filename, or recipient identity to a passive observer. | Padding adds overhead; size classes are configurable. Recipient identity may be needed for routing in some use cases. |
| **SO-14** | Resistance to timing side channels in software. | Constant-time implementations are used where available. WASM and some platforms may not guarantee constant-time execution. |
| **SO-15** | Secure recovery: a user can recover from a lost device using a pre-shared recovery key without trusting a third party. | Requires the user to have generated and stored a recovery key in advance. |
| **SO-16** | Resistance to denial-of-service via resource exhaustion during decryption. | Bounded memory allocation, size checks before processing. |

---

## 6. Non-Goals

- **NG-1. Anonymity.** AegisPQ does not provide sender or receiver anonymity. It minimizes metadata where practical, but it is not a Tor-like anonymity system. If anonymity is required, AegisPQ should be used inside an anonymity transport.
- **NG-2. Absolute security.** No system is unconditionally secure. AegisPQ provides computational security against defined adversary classes using current best practices. A sufficiently powerful adversary (e.g., one who compromises both the endpoint and all key material) will defeat any software-only system.
- **NG-3. DRM or access control enforcement.** AegisPQ encrypts data. It does not prevent a legitimate recipient from copying, forwarding, or re-encrypting the plaintext. Access control after decryption is out of scope.
- **NG-4. Steganography.** AegisPQ does not hide the fact that encryption is being used. Ciphertext is identifiable as AegisPQ ciphertext.
- **NG-5. Replacing TLS or WireGuard.** AegisPQ operates at the application layer. It complements, not replaces, transport-layer encryption.
- **NG-6. Custom primitive invention.** AegisPQ will never define a new block cipher, hash function, or asymmetric algorithm. It uses only standardized, peer-reviewed constructions.
- **NG-7. Performance competition with hardware AES-NI.** AegisPQ's value is at the system level. The core symmetric primitive (AES-256-GCM) will use hardware acceleration where available, but the platform's overhead (key management, hybrid KEM, padding) will always exceed raw AES throughput.
- **NG-8. Blockchain or decentralized consensus.** Key management and revocation are handled through explicit user actions and signed revocation certificates, not consensus protocols.

---

## 7. Chosen Cryptographic Approach

### 7.1 Design Principles

1. **Hybrid by default.** Every asymmetric operation combines a classical and a post-quantum algorithm. Security holds if either family is secure.
2. **AEAD everywhere.** No plaintext is ever encrypted without authentication. No ciphertext is ever processed without verifying its tag first.
3. **Domain separation.** Every KDF call, every signature, and every AEAD context includes a unique domain separation string to prevent cross-protocol attacks.
4. **Conservative parameter choices.** 256-bit symmetric security. 128-bit post-quantum security level (NIST Level 3 or higher).
5. **No user-supplied nonces.** All nonces are generated internally.

### 7.2 Primitive Selection

| Function | Algorithm | Standard | Rationale |
|----------|-----------|----------|-----------|
| **Symmetric encryption** | AES-256-GCM | NIST SP 800-38D | Ubiquitous hardware support (AES-NI), well-analyzed, 256-bit key for post-quantum margin. GCM provides AEAD. |
| **Symmetric encryption (alt)** | XChaCha20-Poly1305 | IETF RFC 8439 + XChaCha extension | Software-friendly, 192-bit nonce eliminates nonce-reuse risk for random nonces. Used as fallback when AES-NI is unavailable or when random nonces are preferred over counter nonces. |
| **Hashing** | BLAKE3 | BLAKE3 specification (2020) | Fast, parallelizable, extendable output, keyed mode, no length-extension attacks. Used for content hashing and tree hashing of large files. |
| **Hashing (interop)** | SHA-256, SHA-512 | FIPS 180-4 | Used only where interoperability with external systems requires SHA-2 (e.g., certificate fingerprints). |
| **KDF (passphrase)** | Argon2id | RFC 9106 | Memory-hard, resistant to GPU/ASIC attacks. Used to derive encryption keys from user passphrases. Parameters: 256 MiB memory, 3 iterations, 4 parallelism (adjustable per platform, documented minimum: 64 MiB, 2 iterations). |
| **KDF (key derivation)** | HKDF-SHA-512 | RFC 5869 | Standard extract-and-expand KDF. Used to derive session keys, sub-keys, and domain-separated keys from shared secrets. |
| **Classical key exchange** | X25519 | RFC 7748 | Widely deployed, fast, constant-time implementations available. Provides ~128-bit classical security. |
| **Post-quantum KEM** | ML-KEM-768 | FIPS 203 | NIST-standardized lattice-based KEM. Security Level 3 (~128-bit post-quantum security). Chosen over ML-KEM-1024 for smaller ciphertext/key sizes; Level 3 is sufficient for the target security margin. |
| **Classical signature** | Ed25519 | RFC 8032 | Deterministic, fast, small signatures. Widely supported. |
| **Post-quantum signature** | ML-DSA-65 | FIPS 204 | NIST-standardized lattice-based signature. Security Level 3. Chosen over ML-DSA-87 for smaller signature size; Level 3 is sufficient. |
| **Randomness** | OS CSPRNG | Platform-specific | `getrandom(2)` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes` on Apple. Accessed via Rust's `getrandom` crate. |

### 7.3 Hybrid Key Exchange

The hybrid key exchange combines X25519 and ML-KEM-768 so that the shared secret is secure if either algorithm is secure.

```
Initiator:
  1. Generate ephemeral X25519 keypair (ek_x, dk_x)
  2. Generate ephemeral ML-KEM-768 keypair (ek_m, dk_m)
  3. Send (ek_x, ek_m) to responder

Responder:
  1. Perform X25519: ss_x = X25519(dk_responder, ek_x)
  2. Perform ML-KEM-768 encapsulation: (ct_m, ss_m) = Encaps(ek_m)
  3. Send (ek_x_responder, ct_m) to initiator

Both sides:
  shared_secret = HKDF-SHA-512(
    salt = "AegisPQ-v1-hybrid-kex",
    ikm  = ss_x || ss_m,
    info = transcript_hash
  )
```

The `transcript_hash` is a BLAKE3 hash of all exchanged public values, preventing transcript manipulation.

**Why this works:** If X25519 is broken (e.g., by a quantum computer), `ss_m` from ML-KEM-768 still provides post-quantum security. If ML-KEM-768 is broken (e.g., by a novel lattice attack), `ss_x` from X25519 still provides classical security. The HKDF combiner ensures that the combined secret is at least as strong as the strongest input.

### 7.4 Hybrid Signatures

Hybrid signatures concatenate a classical and post-quantum signature over the same message.

```
Sign(message):
  sig_ed = Ed25519.Sign(sk_ed, domain_sep || message)
  sig_ml = ML-DSA-65.Sign(sk_ml, domain_sep || message)
  return (sig_ed, sig_ml)

Verify(message, sig_ed, sig_ml):
  ok_ed = Ed25519.Verify(pk_ed, domain_sep || message, sig_ed)
  ok_ml = ML-DSA-65.Verify(pk_ml, domain_sep || message, sig_ml)
  return ok_ed AND ok_ml
```

**Both signatures must verify.** This is the conservative choice: an attacker must forge both to succeed. The tradeoff is larger signature size (~2.5 KB for ML-DSA-65 + 64 bytes for Ed25519). This is acceptable for identity and protocol signatures; it would be excessive for per-packet signing in a high-throughput stream (which AegisPQ does not do — AEAD handles per-record authentication).

### 7.5 Nonce Management

For AES-256-GCM (96-bit nonce):
- Nonce = 32-bit counter (big-endian) || 64-bit random value
- The random value is generated once per key and stored alongside the key
- The counter is incremented for each encryption and persisted
- Maximum encryptions per key: 2^32 (enforced; rotation is required before exhaustion)
- This construction avoids both random-nonce birthday collisions and counter-only predictability

For XChaCha20-Poly1305 (192-bit nonce):
- Nonce = 192 bits from CSPRNG
- Birthday bound at 192 bits allows ~2^96 random nonces per key, making collision negligible
- No counter needed; each encryption generates a fresh random nonce

### 7.6 Key Hierarchy

```
Identity Key (long-term, passphrase-protected)
├── Signing Key Pair (Ed25519 + ML-DSA-65)
│   └── Signs: identity assertions, key packages, revocations
├── Static Key Exchange Key Pair (X25519 + ML-KEM-768)
│   └── Used for: asynchronous encryption (when recipient is offline)
└── Pre-Key Bundles (ephemeral, signed by Signing Key)
    └── Ephemeral X25519 + ML-KEM-768 keys for forward-secret sessions

Session Key (ephemeral, derived via hybrid KEM + HKDF)
├── Sending Chain Key → Message Keys (AEAD)
└── Receiving Chain Key → Message Keys (AEAD)

File Encryption Key (per-file, random)
├── Derived from: session key or standalone key
└── Used with: AES-256-GCM or XChaCha20-Poly1305
```

### 7.7 Domain Separation Strings

Every cryptographic operation includes a context string to prevent cross-protocol attacks:

| Operation | Domain Separator |
|-----------|-----------------|
| Hybrid KEM | `"AegisPQ-v1-hybrid-kex"` |
| Session key derivation | `"AegisPQ-v1-session-key"` |
| Message encryption | `"AegisPQ-v1-message-aead"` |
| File encryption | `"AegisPQ-v1-file-aead"` |
| Identity key encryption | `"AegisPQ-v1-identity-wrap"` |
| Signing | `"AegisPQ-v1-sign"` |
| Revocation | `"AegisPQ-v1-revoke"` |
| Recovery | `"AegisPQ-v1-recovery"` |
| Key rotation | `"AegisPQ-v1-rotate"` |

The version tag (`v1`) ensures that protocol upgrades produce different derived keys even with the same input material.

### 7.8 What Happens if a Primitive Weakens

| Scenario | Impact | Response |
|----------|--------|----------|
| AES-256 weakened | Symmetric encryption compromised if XChaCha20 fallback is not in use | Release new suite version defaulting to XChaCha20-Poly1305; deprecate AES-256-GCM suite |
| X25519 broken (quantum) | Classical KEM fails; ML-KEM-768 still protects confidentiality | Hybrid design absorbs the break; remove X25519 in next major version |
| ML-KEM-768 broken | Post-quantum KEM fails; X25519 still protects against classical attackers | Hybrid design absorbs the break; replace ML-KEM with successor |
| Ed25519 broken (quantum) | Classical signatures forgeable; ML-DSA-65 still protects authenticity | Hybrid design absorbs the break; remove Ed25519 in next major version |
| ML-DSA-65 broken | Post-quantum signatures forgeable; Ed25519 still protects against classical attackers | Hybrid design absorbs the break; replace ML-DSA with successor |
| BLAKE3 weakened | Content hashing and KDF affected | Switch to SHA-3 or successor; HKDF-SHA-512 for key derivation is unaffected |
| Argon2id weakened | Passphrase-derived keys become easier to brute-force | Increase parameters or migrate to successor memory-hard KDF |

---

## 8. System Architecture

### 8.1 Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                      User Layer                          │
│  ┌──────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │ CLI  │  │ Rust SDK │  │ Python   │  │ JS/WASM    │  │
│  │      │  │          │  │ SDK      │  │ SDK        │  │
│  └──┬───┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘  │
│     │           │              │               │         │
│  ┌──┴───────────┴──────────────┴───────────────┴──────┐  │
│  │              aegispq-api (public API crate)        │  │
│  │  Misuse-resistant interface. No crypto internals   │  │
│  │  exposed. Type-safe error handling.                │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │                                │
│  ┌──────────────────────┴─────────────────────────────┐  │
│  │           aegispq-protocol (protocol crate)        │  │
│  │  Session management, key exchange, envelope        │  │
│  │  construction, version negotiation, state machine  │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │                                │
│  ┌──────────────────────┴─────────────────────────────┐  │
│  │           aegispq-core (crypto core crate)         │  │
│  │  Thin wrappers around audited crypto libraries.    │  │
│  │  AEAD, KEM, signatures, KDF, hashing, nonce mgmt. │  │
│  │  No business logic. ~2,000 lines target.           │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │                                │
│  ┌──────────────────────┴─────────────────────────────┐  │
│  │        External crypto libraries (dependencies)     │  │
│  │  ring / aws-lc-rs, ml-kem, ml-dsa, blake3,        │  │
│  │  argon2, x25519-dalek, ed25519-dalek               │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │           aegispq-store (storage crate)            │  │
│  │  Key store, identity store, session store.         │  │
│  │  File-backed (SQLite or flat files). Encrypted.    │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 8.2 Trust Boundaries

| Boundary | Trusted Side | Untrusted Side |
|----------|-------------|----------------|
| **Process boundary** | AegisPQ process memory | Other processes, OS kernel (partially trusted for memory isolation) |
| **Core crypto boundary** | `aegispq-core` internals | Everything above (API, CLI, SDKs) — these cannot access raw key material directly |
| **Storage boundary** | Encrypted key store | Filesystem (considered hostile — all stored keys are encrypted) |
| **Network boundary** | Local protocol state | All network data (considered hostile — all received data is authenticated before processing) |
| **Build boundary** | Signed release artifacts | Build environment (mitigated by reproducible builds) |

### 8.3 Auditability

The **aegispq-core** crate is the security-critical kernel. Design targets:

- **< 3,000 lines of Rust** (excluding tests and generated code)
- **Zero `unsafe` blocks** (enforced by `#![forbid(unsafe_code)]`)
- **No I/O** — pure computation, all inputs and outputs are byte slices and typed structures
- **No allocations on the hot path** where feasible (stack-based buffers for keys, nonces)
- **100% branch coverage** in CI (measured by `cargo-tarpaulin` or `llvm-cov`)

This small surface allows a focused external audit. The protocol and API crates are larger but can be audited independently.

### 8.4 Component Responsibilities

| Crate | Responsibility | External Dependencies |
|-------|---------------|----------------------|
| `aegispq-core` | AEAD encrypt/decrypt, KEM encaps/decaps, sign/verify, KDF, hash, nonce generation, zeroization | `ring` or `aws-lc-rs`, `ml-kem`, `ml-dsa`, `blake3`, `argon2`, `zeroize` |
| `aegispq-protocol` | Envelope construction, session state machine, key exchange orchestration, version negotiation, key rotation logic | `aegispq-core`, `serde` |
| `aegispq-store` | Encrypted storage of identity keys, session state, pre-key bundles, revocation lists | `aegispq-core`, `rusqlite` (optional), `serde` |
| `aegispq-api` | Public API surface, input validation, error types, misuse-resistant wrappers | `aegispq-protocol`, `aegispq-store` |
| `aegispq-cli` | Command-line interface, file I/O, user interaction, passphrase prompting | `aegispq-api`, `clap`, `rpassword` |
| `aegispq-ffi` | C-compatible FFI for Python, JS, and other language bindings | `aegispq-api` |

---

## 9. Protocols and Data Flows

### 9.1 Identity Creation

```
User Action: aegispq identity create --name "Alice"

1. Generate Ed25519 keypair (sk_ed, pk_ed)
2. Generate ML-DSA-65 keypair (sk_ml, pk_ml)
3. Generate X25519 keypair (sk_x, pk_x)
4. Generate ML-KEM-768 keypair (sk_m, pk_m)
5. Prompt user for passphrase
6. Derive wrapping key:
   wrap_key = Argon2id(passphrase, random_salt, params)
7. Encrypt private keys:
   encrypted_bundle = AES-256-GCM(
     key = wrap_key,
     nonce = random,
     aad = "AegisPQ-v1-identity-wrap" || identity_id,
     plaintext = sk_ed || sk_ml || sk_x || sk_m
   )
8. Store identity:
   {
     identity_id: random UUID,
     version: 1,
     public_keys: { ed25519: pk_ed, ml_dsa_65: pk_ml, x25519: pk_x, ml_kem_768: pk_m },
     encrypted_private_keys: encrypted_bundle,
     argon2_params: { salt, memory, iterations, parallelism },
     created_at: timestamp,
     status: "active"
   }
9. Generate and sign initial pre-key bundle (10 one-time pre-keys)
10. Optionally generate recovery key (see Section 9.10)

Output: Identity fingerprint = BLAKE3(canonical(public_keys))[0..32] displayed as hex
```

### 9.2 Key Package Export (for sharing public identity)

```
1. Serialize public keys + identity metadata
2. Sign with hybrid signature:
   sig = HybridSign(sk_ed, sk_ml, "AegisPQ-v1-identity-export" || serialized_data)
3. Encode as versioned key package:
   {
     format: "aegispq-keypackage",
     version: 1,
     identity_id: ...,
     public_keys: { ... },
     signature: (sig_ed, sig_ml),
     pre_keys: [ signed one-time pre-keys ],
     expires_at: timestamp (optional)
   }
4. Output as base64 or binary file (.aegispq-key)
```

### 9.3 Key Exchange (Interactive Session Setup)

When both parties are online:

```
Alice → Bob:
  1. Alice fetches Bob's key package (out of band or from a key server)
  2. Alice verifies Bob's key package signature (both Ed25519 and ML-DSA-65)
  3. Alice verifies Bob's fingerprint (out-of-band comparison)
  4. Alice generates ephemeral X25519 keypair (ek_x_a, dk_x_a)
  5. Alice generates ephemeral ML-KEM-768 keypair (ek_m_a, dk_m_a)
  6. Alice sends session initiation:
     { version: 1, suite: "hybrid-v1", ek_x_a, ek_m_a, alice_identity_id }

Bob → Alice:
  7. Bob verifies Alice's identity (fetches her key package, verifies signature)
  8. Bob computes X25519 shared secret: ss_x = X25519(dk_x_b_ephemeral, ek_x_a)
  9. Bob encapsulates ML-KEM-768: (ct_m, ss_m) = ML-KEM-768.Encaps(ek_m_a)
  10. Bob computes transcript hash:
      th = BLAKE3("AegisPQ-v1-transcript" || version || suite || ek_x_a || ek_m_a || ek_x_b || ct_m)
  11. Bob derives session key:
      session_key = HKDF-SHA-512(
        salt = "AegisPQ-v1-session-key",
        ikm = ss_x || ss_m,
        info = th || alice_identity_id || bob_identity_id
      )
  12. Bob sends: { ek_x_b, ct_m, confirmation_mac }
      where confirmation_mac = HMAC-SHA-512(session_key, "AegisPQ-v1-confirm" || th)

Alice:
  13. Alice computes ss_x = X25519(dk_x_a, ek_x_b)
  14. Alice decapsulates: ss_m = ML-KEM-768.Decaps(dk_m_a, ct_m)
  15. Alice derives same session_key via same HKDF
  16. Alice verifies confirmation_mac
  17. Session established. Both sides derive sending/receiving chain keys.

State: ESTABLISHED
```

### 9.4 Session Ratcheting (for ongoing message exchange)

After session establishment, AegisPQ uses a symmetric ratchet for message keys:

```
For each message:
  1. chain_key_{n+1} = HKDF-SHA-512(
       salt = "AegisPQ-v1-chain",
       ikm = chain_key_n,
       info = "advance"
     )
  2. message_key_n = HKDF-SHA-512(
       salt = "AegisPQ-v1-message-key",
       ikm = chain_key_n,
       info = "message" || message_counter
     )
  3. Encrypt message:
     ciphertext = AES-256-GCM(
       key = message_key_n,
       nonce = derived_from_counter,
       aad = "AegisPQ-v1-message-aead" || session_id || message_counter || sender_id,
       plaintext = padded_message
     )
  4. Zeroize message_key_n and chain_key_n from memory
  5. Increment message_counter
```

Periodic re-keying: After every N messages (default: 100) or T seconds (default: 3600), a new ephemeral key exchange is performed (DH ratchet step) to restore forward secrecy for the new epoch.

### 9.5 File Encryption (One-Shot)

```
User Action: aegispq encrypt --file secret.pdf --to bob_fingerprint

1. Read Bob's key package, verify signature
2. Generate random file encryption key (FEK): 32 bytes from CSPRNG
3. Perform hybrid KEM against Bob's static KE key:
   ss_x = X25519(ephemeral_sk, bob_pk_x)
   (ct_m, ss_m) = ML-KEM-768.Encaps(bob_pk_m)
4. Derive key-wrapping key:
   kek = HKDF-SHA-512(
     salt = "AegisPQ-v1-file-kek",
     ikm = ss_x || ss_m,
     info = bob_identity_id || ephemeral_pk_x
   )
5. Wrap FEK:
   wrapped_fek = AES-256-GCM(key = kek, nonce = random, aad = file_header, plaintext = FEK)
6. Encrypt file in chunks (1 MiB default):
   For each chunk_i:
     ct_i = AES-256-GCM(
       key = FEK,
       nonce = counter_nonce(i),
       aad = "AegisPQ-v1-file-aead" || file_id || chunk_index || is_final_chunk,
       plaintext = padded_chunk_i
     )
7. Sign the complete ciphertext:
   sig = HybridSign(alice_sk, "AegisPQ-v1-file-sign" || BLAKE3(header || all_ct))
8. Assemble output:
   {
     format: "aegispq-encrypted-file",
     version: 1,
     suite: "hybrid-v1",
     sender_identity_id: alice_id,
     recipient_slots: [
       { recipient_id: bob_id, ephemeral_pk_x, ct_m, wrapped_fek, nonce }
     ],
     chunks: [ ct_0, ct_1, ... ],
     signature: sig,
     padding_scheme: "power-of-2"
   }

Output: secret.pdf.aegispq
```

**Multi-recipient:** Additional recipient slots can be added by wrapping the same FEK under each recipient's public keys. Each slot is independent; compromising one recipient's key does not help attack another's slot.

### 9.6 File Decryption

```
User Action: aegispq decrypt --file secret.pdf.aegispq

1. Parse header, verify format version
2. Find recipient slot matching local identity
3. If no matching slot: error "Not a recipient of this file"
4. Verify sender signature (both Ed25519 and ML-DSA-65)
5. If signature invalid: error "Sender authentication failed" (do not decrypt)
6. Perform hybrid key exchange:
   ss_x = X25519(local_sk_x, ephemeral_pk_x)
   ss_m = ML-KEM-768.Decaps(local_sk_m, ct_m)
7. Derive KEK via same HKDF
8. Unwrap FEK
9. Decrypt chunks in order, verifying each AEAD tag
10. If any chunk fails authentication: error "File corrupted or tampered"
    (stop immediately, do not output partial plaintext)
11. Remove padding
12. Output plaintext file

Output: secret.pdf
```

### 9.7 Secure Sharing (Group or Team)

For sharing a secret with multiple recipients:

```
1. Generate random FEK
2. For each recipient R_i:
   a. Perform hybrid KEM against R_i's public keys
   b. Derive per-recipient KEK
   c. Wrap FEK under that KEK
   d. Include recipient slot in envelope
3. Encrypt payload with FEK
4. Sign the complete envelope
```

Revocation from a group: Re-encrypt with a new FEK, excluding the revoked member. There is no retroactive revocation of already-delivered ciphertext (this is a fundamental impossibility, not a design gap).

### 9.8 Key Rotation

```
User Action: aegispq identity rotate

1. Generate new key pairs (Ed25519, ML-DSA-65, X25519, ML-KEM-768)
2. Create rotation certificate:
   {
     old_identity_id: ...,
     new_public_keys: { ... },
     effective_at: timestamp,
     signed_by_old_key: HybridSign(old_sk, "AegisPQ-v1-rotate" || new_public_keys),
     signed_by_new_key: HybridSign(new_sk, "AegisPQ-v1-rotate" || old_public_keys)
   }
3. Dual-signed: old key vouches for new, new key vouches for old.
   This creates a verifiable chain even if one key pair is later compromised.
4. Encrypt new private keys under (possibly new) passphrase
5. Store new identity alongside old (old marked as "rotated")
6. Export rotation certificate for distribution to contacts
7. Old key remains available for decrypting old ciphertexts but is not used for new operations

Grace period: Contacts should accept both old and new keys for a configurable period
(default: 30 days) after rotation, then reject the old key.
```

### 9.9 Revocation

```
User Action: aegispq identity revoke --reason compromised

1. Create revocation certificate:
   {
     identity_id: ...,
     reason: "compromised" | "superseded" | "retired",
     effective_at: timestamp,
     signature: HybridSign(sk, "AegisPQ-v1-revoke" || identity_id || reason || timestamp)
   }
2. If the key is believed compromised, the revocation is best-effort:
   an attacker who has the key can also create a counter-revocation.
   This is an inherent limitation of any system without a centralized authority.
3. Distribute revocation certificate to contacts and key servers
4. Mark local identity as "revoked"
5. Revoked keys cannot encrypt, sign, or establish new sessions
6. Revoked keys CAN still decrypt old ciphertexts (read-only access to historical data)
```

### 9.10 Recovery

```
User Action: aegispq recovery create

1. Generate recovery key: 32 bytes from CSPRNG
2. Display as mnemonic (BIP-39 24-word encoding) or hex
3. Encrypt identity private keys under recovery key:
   recovery_blob = AES-256-GCM(
     key = HKDF-SHA-512("AegisPQ-v1-recovery", recovery_key, identity_id),
     nonce = random,
     aad = identity_id,
     plaintext = private_key_bundle
   )
4. Store recovery_blob (can be backed up to separate storage)
5. User stores recovery key offline (paper, hardware token, safe)

Recovery:
1. User provides recovery key (mnemonic or hex)
2. Derive key via same HKDF
3. Decrypt recovery_blob
4. Re-encrypt private keys under new passphrase
5. Identity restored
```

### 9.11 Downgrade Handling

- The `suite` field in every message, session initiation, and file envelope specifies the algorithm suite.
- The `version` field specifies the protocol version.
- A recipient configured for `hybrid-v1` will **reject** messages tagged with a weaker suite (e.g., a hypothetical `classical-v1` that omits post-quantum algorithms).
- There is no automatic negotiation toward weaker suites. If the sender and recipient disagree on suite, the operation fails with an explicit error.
- Deprecated suites are removed from the codebase after a migration period (see Section 15), not merely deprioritized.
- The suite identifier is included in AEAD additional data and HKDF info, so any attempt to re-tag ciphertext with a different suite causes authentication failure.

### 9.12 Replay Handling

**Sessions:** Each message includes a monotonically increasing counter bound to the session ID. The recipient maintains a counter window (default: 256 messages) and rejects:
- Counter values already seen (exact duplicate)
- Counter values below the window floor (stale replay)

**Files:** File encryption is one-shot; there is no built-in replay detection for files because files are static artifacts. If replay detection is needed (e.g., for API payloads), the application layer should include a nonce or timestamp in the plaintext and track seen values.

### 9.13 Corruption Handling

- **Header corruption:** Parsing fails; error returned before any decryption attempt.
- **Ciphertext corruption:** AEAD tag verification fails; error returned, no plaintext emitted.
- **Partial file corruption:** Per-chunk AEAD detects which chunk is corrupted. Error includes chunk index for diagnostics. No partial plaintext is ever emitted from a corrupted file — either the entire file decrypts successfully or the entire operation fails.
- **Key store corruption:** SQLite integrity check on open. If corrupted, recovery from backup or recovery key is required. AegisPQ does not attempt to repair corrupted key stores.

### 9.14 Offline and Online Behavior

- **Fully offline:** Identity creation, file encryption/decryption, signing/verification all work without network access.
- **Key exchange requires both parties to exchange messages** but does not require simultaneous online presence. Alice can encrypt to Bob's static public key (asynchronous encryption) even if Bob is offline; Bob decrypts when he comes online.
- **Revocation propagation requires distribution.** In an offline environment, revocation certificates must be exchanged manually (e.g., via USB drive, printed QR code).
- **Pre-key bundles can be pre-generated** and distributed in advance for asynchronous forward-secret sessions.

### 9.15 Version Negotiation

```
Initiator sends: { supported_versions: [1], preferred_version: 1, supported_suites: ["hybrid-v1"] }
Responder selects: highest mutually supported version + suite
If no overlap: hard failure with error "Incompatible protocol version or suite"
Selected version and suite are bound into the session transcript (cannot be modified post-negotiation)
```

Future versions (2, 3, ...) may add new suites. Old versions are deprecated on a published schedule (see Section 15).

---

## 10. Data Formats and Versioning

### 10.1 Encoding Choice

**Primary encoding: BARE (Binary Application Record Encoding)** for all wire and storage formats.

Rationale:
- Canonical (no equivalent but different encodings of the same data)
- Compact (no field names on the wire)
- Simple to implement (~200 lines for a decoder)
- Schema-defined (parsers are generated from schema, reducing hand-written parsing bugs)
- No ambiguity (unlike JSON, CBOR, or Protocol Buffers, BARE has one canonical encoding per value)

**Secondary encoding: Base64url (RFC 4648)** for text representations (CLI output, key export).

**Why not Protocol Buffers:** Protobuf allows multiple valid encodings of the same message (field reordering, default elision), which complicates signature verification over serialized data. BARE's canonical encoding avoids this.

**Why not CBOR:** CBOR is more flexible but has canonicalization pitfalls (multiple valid float encodings, indefinite-length containers). BARE is simpler and sufficient.

### 10.2 Versioned Envelope Format

Every AegisPQ data object begins with a fixed header:

```
Offset  Size  Field
0       4     Magic bytes: 0x41 0x50 0x51 0x01 ("APQ\x01")
4       1     Format type:
                0x01 = encrypted file
                0x02 = key package
                0x03 = session message
                0x04 = revocation certificate
                0x05 = rotation certificate
                0x06 = recovery blob
                0x07 = signed document
5       2     Protocol version (big-endian uint16)
7       1     Suite identifier:
                0x01 = hybrid-v1 (X25519+ML-KEM-768, Ed25519+ML-DSA-65, AES-256-GCM)
                0x02 = hybrid-v1-xchacha (same but XChaCha20-Poly1305 for symmetric)
8       4     Payload length (big-endian uint32, max 4 GiB per envelope)
12      ...   BARE-encoded payload (format-type-specific)
```

### 10.3 Unknown Version Handling

- If `version > max_supported_version`: return error `UnsupportedVersion { found, max_supported }`. Do not attempt to parse the payload.
- If `suite` is unrecognized: return error `UnsupportedSuite { found }`. Do not attempt to parse the payload.
- If `format_type` is unrecognized: return error `UnknownFormat { found }`. Do not attempt to parse the payload.
- **No silent fallback. No guessing. No partial parsing.**

### 10.4 Backward Compatibility

- Version N+1 must be able to **read** version N ciphertext (decryption backward compatibility).
- Version N+1 **never produces** version N ciphertext (no write backward compatibility).
- Deprecated versions are supported for decryption for a fixed period (default: 2 years after deprecation announcement), then removed.
- The `min_supported_version` is a compile-time constant that advances over time.

### 10.5 Key Package Format

```
KeyPackage {
  identity_id: [u8; 16],          // UUID
  display_name: string,            // UTF-8, max 256 bytes
  ed25519_public_key: [u8; 32],
  ml_dsa_65_public_key: [u8; 1952],
  x25519_public_key: [u8; 32],
  ml_kem_768_public_key: [u8; 1184],
  pre_keys: Vec<SignedPreKey>,     // Signed ephemeral keys
  created_at: u64,                 // Unix timestamp
  expires_at: Option<u64>,         // Optional expiry
  signature_ed25519: [u8; 64],
  signature_ml_dsa_65: [u8; 3293],
}

SignedPreKey {
  pre_key_id: u32,
  x25519_public_key: [u8; 32],
  ml_kem_768_public_key: [u8; 1184],
  signature_ed25519: [u8; 64],
  signature_ml_dsa_65: [u8; 3293],
}
```

### 10.6 Encrypted File Format

```
EncryptedFile {
  file_id: [u8; 16],              // Random, for tracking/deduplication
  sender_identity_id: [u8; 16],
  recipient_slots: Vec<RecipientSlot>,
  chunk_size: u32,                 // Default: 1,048,576 (1 MiB)
  padding_scheme: u8,             // 0x01 = power-of-2, 0x02 = fixed-block
  chunks: Vec<EncryptedChunk>,
  signature_ed25519: [u8; 64],
  signature_ml_dsa_65: [u8; 3293],
}

RecipientSlot {
  recipient_identity_id: [u8; 16],
  ephemeral_x25519_pk: [u8; 32],
  ml_kem_768_ciphertext: [u8; 1088],
  wrapped_fek: [u8; 32 + 16],     // FEK + GCM tag
  wrapped_fek_nonce: [u8; 12],
}

EncryptedChunk {
  ciphertext: Vec<u8>,            // Includes GCM tag (16 bytes appended)
  nonce: [u8; 12],
}
```

### 10.7 Parsing Safety

- All lengths are checked against the remaining buffer before reading.
- Maximum field sizes are enforced (e.g., `display_name` ≤ 256 bytes, `recipient_slots` ≤ 1000, `chunks` ≤ 4,194,304).
- Integer overflow is prevented by Rust's default overflow checks (and explicit checked arithmetic in release builds).
- Malformed data causes an immediate error return; no partial state is retained.

---

## 11. APIs and Module Boundaries

### 11.1 Design Principles

- **Misuse-resistant:** The API makes it hard to do the wrong thing. No function accepts a raw nonce. No function returns an unauthenticated plaintext.
- **Type-safe:** Keys, ciphertexts, signatures, and identities are distinct types, not raw byte arrays at the API boundary.
- **Infallible where possible:** Operations that cannot fail do not return `Result`.
- **Small surface:** The public API exposes ~20 functions. Internal modules are `pub(crate)`.

### 11.2 Core Types

```rust
// aegispq-api/src/types.rs

/// A local identity with key material.
pub struct Identity { /* opaque */ }

/// A remote party's public identity.
pub struct PublicIdentity { /* opaque */ }

/// A fingerprint for out-of-band verification.
pub struct Fingerprint([u8; 32]);

/// An established encrypted session.
pub struct Session { /* opaque */ }

/// Encrypted file output.
pub struct EncryptedFile { /* opaque, wraps Vec<u8> */ }

/// Encrypted message output.
pub struct EncryptedMessage { /* opaque */ }

/// A recovery key for identity backup.
pub struct RecoveryKey { /* opaque, zeroize on drop */ }

/// A rotation certificate.
pub struct RotationCertificate { /* opaque */ }

/// A revocation certificate.
pub struct RevocationCertificate { /* opaque */ }
```

### 11.3 Error Types

```rust
// aegispq-api/src/error.rs

#[derive(Debug)]
pub enum Error {
    /// The passphrase was incorrect (AEAD tag verification failed during key unwrap).
    InvalidPassphrase,

    /// The ciphertext or signature failed authentication.
    AuthenticationFailed,

    /// The file or message is corrupted (AEAD tag failure on a specific chunk).
    IntegrityError { chunk_index: Option<u32> },

    /// The protocol version or suite is not supported.
    UnsupportedVersion { found: u16, max_supported: u16 },
    UnsupportedSuite { found: u8 },

    /// The recipient identity was not found in the ciphertext's recipient list.
    NotARecipient,

    /// The identity has been revoked and cannot be used for this operation.
    IdentityRevoked { identity_id: [u8; 16] },

    /// The key has exceeded its maximum usage count and must be rotated.
    KeyExhausted,

    /// The session state is invalid for this operation.
    InvalidSessionState { expected: &'static str, found: &'static str },

    /// Storage I/O error (does not leak file paths in Display impl).
    StorageError(String),

    /// The input data exceeds maximum allowed size.
    InputTooLarge { max_bytes: u64 },

    /// An internal error that should not occur in correct usage.
    /// Contains a static string (never dynamic data that could leak secrets).
    Internal(&'static str),
}
```

**Important:** Error messages never contain key material, plaintext fragments, or file paths. The `Display` implementation produces safe-to-log messages.

### 11.4 Identity Management API

```rust
// aegispq-api/src/identity.rs

/// Create a new identity protected by a passphrase.
pub fn create_identity(
    display_name: &str,
    passphrase: &SecretString,
    store: &mut Store,
) -> Result<Identity, Error>;

/// Load an existing identity from storage.
pub fn load_identity(
    identity_id: &[u8; 16],
    passphrase: &SecretString,
    store: &Store,
) -> Result<Identity, Error>;

/// Export the public portion of an identity as a key package.
pub fn export_public_key(
    identity: &Identity,
) -> Result<Vec<u8>, Error>;

/// Import a remote party's public key package.
pub fn import_public_key(
    key_package_bytes: &[u8],
    store: &mut Store,
) -> Result<PublicIdentity, Error>;

/// Get the fingerprint for out-of-band verification.
pub fn fingerprint(identity: &Identity) -> Fingerprint;
pub fn fingerprint_public(public_identity: &PublicIdentity) -> Fingerprint;

/// Rotate identity keys. Returns a rotation certificate for distribution.
pub fn rotate_identity(
    identity: &Identity,
    new_passphrase: &SecretString,
    store: &mut Store,
) -> Result<(Identity, RotationCertificate), Error>;

/// Revoke an identity. Returns a revocation certificate for distribution.
pub fn revoke_identity(
    identity: &Identity,
    reason: RevocationReason,
    store: &mut Store,
) -> Result<RevocationCertificate, Error>;

/// Import a rotation certificate from a contact.
pub fn import_rotation(
    certificate_bytes: &[u8],
    store: &mut Store,
) -> Result<(), Error>;

/// Import a revocation certificate.
pub fn import_revocation(
    certificate_bytes: &[u8],
    store: &mut Store,
) -> Result<(), Error>;
```

### 11.5 Encryption API

```rust
// aegispq-api/src/encrypt.rs

/// Encrypt a file for one or more recipients.
pub fn encrypt_file(
    plaintext: &[u8],
    sender: &Identity,
    recipients: &[&PublicIdentity],
    options: EncryptOptions,
) -> Result<Vec<u8>, Error>;

/// Decrypt a file.
pub fn decrypt_file(
    ciphertext: &[u8],
    recipient: &Identity,
    store: &Store,    // for sender verification
) -> Result<DecryptedFile, Error>;

/// Encrypt a message within a session (for ongoing communication).
pub fn encrypt_message(
    session: &mut Session,
    plaintext: &[u8],
) -> Result<EncryptedMessage, Error>;

/// Decrypt a message within a session.
pub fn decrypt_message(
    session: &mut Session,
    ciphertext: &EncryptedMessage,
) -> Result<Vec<u8>, Error>;

pub struct EncryptOptions {
    /// Padding scheme. Default: PowerOfTwo.
    pub padding: PaddingScheme,
    /// Chunk size in bytes. Default: 1 MiB.
    pub chunk_size: u32,
    /// Symmetric algorithm preference. Default: Aes256Gcm.
    pub symmetric_algorithm: SymmetricAlgorithm,
}

pub struct DecryptedFile {
    pub plaintext: Vec<u8>,
    pub sender_fingerprint: Fingerprint,
    pub sender_identity_id: [u8; 16],
    pub sender_verified: bool,
}

pub enum PaddingScheme {
    /// Pad to next power of 2 (default, good for hiding file size).
    PowerOfTwo,
    /// Pad to fixed block size.
    FixedBlock(u32),
    /// No padding (not recommended; leaks exact plaintext size).
    None,
}

pub enum SymmetricAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}
```

### 11.6 Signing API

```rust
// aegispq-api/src/sign.rs

/// Sign arbitrary data.
pub fn sign(
    identity: &Identity,
    data: &[u8],
) -> Result<Vec<u8>, Error>;  // Returns serialized hybrid signature

/// Verify a signature.
pub fn verify(
    public_identity: &PublicIdentity,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, Error>;
```

### 11.7 Session API

```rust
// aegispq-api/src/session.rs

/// Initiate a session with a remote party.
pub fn initiate_session(
    local: &Identity,
    remote: &PublicIdentity,
    store: &mut Store,
) -> Result<(Session, Vec<u8>), Error>;  // Returns session + initiation message

/// Respond to a session initiation.
pub fn accept_session(
    local: &Identity,
    initiation_message: &[u8],
    store: &mut Store,
) -> Result<(Session, Vec<u8>), Error>;  // Returns session + response message

/// Complete session setup after receiving response.
pub fn complete_session(
    session: &mut Session,
    response_message: &[u8],
) -> Result<(), Error>;
```

### 11.8 Recovery API

```rust
// aegispq-api/src/recovery.rs

/// Generate a recovery key and recovery blob for an identity.
pub fn create_recovery(
    identity: &Identity,
) -> Result<(RecoveryKey, Vec<u8>), Error>;  // Returns key + encrypted blob

/// Recover an identity from a recovery key and blob.
pub fn recover_identity(
    recovery_key: &RecoveryKey,
    recovery_blob: &[u8],
    new_passphrase: &SecretString,
    store: &mut Store,
) -> Result<Identity, Error>;
```

### 11.9 Streaming API (for large files)

```rust
// aegispq-api/src/stream.rs

/// Create a streaming encryptor for large files.
pub fn encrypt_file_stream(
    sender: &Identity,
    recipients: &[&PublicIdentity],
    options: EncryptOptions,
) -> Result<FileEncryptor, Error>;

impl FileEncryptor {
    /// Write a chunk of plaintext. Produces encrypted chunks.
    pub fn write_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    /// Finalize the encryption. Produces final chunk + signature.
    pub fn finalize(self) -> Result<Vec<u8>, Error>;
}

/// Create a streaming decryptor for large files.
pub fn decrypt_file_stream(
    header_bytes: &[u8],
    recipient: &Identity,
    store: &Store,
) -> Result<FileDecryptor, Error>;

impl FileDecryptor {
    /// Decrypt a chunk. Returns plaintext only if AEAD verifies.
    pub fn decrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Error>;
    /// Verify the final signature after all chunks.
    pub fn verify_signature(self, signature: &[u8]) -> Result<bool, Error>;
}
```

---

## 12. Repository Structure

```
aegispq/
├── Cargo.toml                    # Workspace root
├── LICENSE-MIT                   # Dual license
├── LICENSE-APACHE                # Dual license
├── README.md                     # Project overview, quick start
├── SECURITY.md                   # Vulnerability disclosure policy
├── CHANGELOG.md                  # Release notes
├── CONTRIBUTING.md               # Contribution guidelines
├── CODE_OF_CONDUCT.md            # Contributor covenant
├── DESIGN.md                     # This document
│
├── spec/                         # Protocol specifications
│   ├── v1/
│   │   ├── overview.md           # Protocol v1 overview
│   │   ├── formats.md            # Data format specification
│   │   ├── key-exchange.md       # Key exchange protocol
│   │   ├── file-encryption.md    # File encryption protocol
│   │   ├── session.md            # Session protocol
│   │   ├── identity.md           # Identity management
│   │   └── test-vectors.json     # Canonical test vectors
│   └── threat-model.md           # Published threat model
│
├── crates/
│   ├── aegispq-core/             # Crypto core (~2,000 lines)
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── aead.rs           # AES-256-GCM, XChaCha20-Poly1305
│   │   │   ├── kem.rs            # Hybrid KEM (X25519 + ML-KEM-768)
│   │   │   ├── sig.rs            # Hybrid signatures (Ed25519 + ML-DSA-65)
│   │   │   ├── kdf.rs            # HKDF-SHA-512, Argon2id
│   │   │   ├── hash.rs           # BLAKE3
│   │   │   ├── nonce.rs          # Nonce generation and management
│   │   │   └── zeroize.rs        # Zeroization helpers
│   │   └── tests/
│   │       ├── known_answer.rs   # KAT from spec/v1/test-vectors.json
│   │       └── property.rs       # Property-based tests
│   │
│   ├── aegispq-protocol/         # Protocol layer
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── envelope.rs       # Envelope construction/parsing
│   │   │   ├── session.rs        # Session state machine
│   │   │   ├── file.rs           # File encryption protocol
│   │   │   ├── identity.rs       # Identity operations
│   │   │   ├── version.rs        # Version negotiation
│   │   │   ├── padding.rs        # Padding schemes
│   │   │   └── ratchet.rs        # Symmetric ratchet
│   │   └── tests/
│   │
│   ├── aegispq-store/            # Storage layer
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── keystore.rs       # Encrypted key storage
│   │       ├── session_store.rs  # Session state persistence
│   │       └── migrations.rs     # Storage schema migrations
│   │
│   ├── aegispq-api/              # Public API
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs
│   │       ├── error.rs
│   │       ├── identity.rs
│   │       ├── encrypt.rs
│   │       ├── sign.rs
│   │       ├── session.rs
│   │       ├── recovery.rs
│   │       └── stream.rs
│   │
│   ├── aegispq-cli/              # Command-line interface
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── commands/
│   │       │   ├── identity.rs
│   │       │   ├── encrypt.rs
│   │       │   ├── decrypt.rs
│   │       │   ├── sign.rs
│   │       │   ├── verify.rs
│   │       │   └── recovery.rs
│   │       └── output.rs         # Structured output (JSON, text)
│   │
│   └── aegispq-ffi/              # C FFI for language bindings
│       ├── Cargo.toml
│       ├── src/
│       │   └── lib.rs
│       └── include/
│           └── aegispq.h         # Generated C header (cbindgen)
│
├── bindings/
│   ├── python/                   # Python bindings (PyO3)
│   │   ├── pyproject.toml
│   │   └── src/
│   └── js/                       # JavaScript/WASM bindings (wasm-bindgen)
│       ├── package.json
│       └── src/
│
├── examples/
│   ├── encrypt_file.rs
│   ├── create_identity.rs
│   ├── session_demo.rs
│   └── multi_recipient.rs
│
├── tests/
│   ├── integration/              # Cross-crate integration tests
│   │   ├── full_flow.rs
│   │   ├── rotation.rs
│   │   ├── revocation.rs
│   │   ├── recovery.rs
│   │   └── interop.rs            # Cross-version interop tests
│   ├── fuzz/                     # Fuzzing targets
│   │   ├── fuzz_envelope_parse.rs
│   │   ├── fuzz_decrypt.rs
│   │   └── fuzz_key_package.rs
│   └── negative/                 # Tests that must fail correctly
│       ├── tampered_ciphertext.rs
│       ├── wrong_recipient.rs
│       ├── revoked_identity.rs
│       └── unsupported_version.rs
│
├── benches/
│   ├── encrypt.rs
│   ├── decrypt.rs
│   ├── kem.rs
│   └── sign.rs
│
├── tools/
│   ├── generate_test_vectors.rs  # Generates spec/v1/test-vectors.json
│   └── audit_deps.sh             # cargo-audit + cargo-deny wrapper
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                # Build + test + lint + fuzz
    │   ├── release.yml           # Tagged release + signing
    │   └── audit.yml             # Weekly dependency audit
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── security.md
    └── dependabot.yml
```

### 12.1 Naming Conventions

- Crate names: `aegispq-{component}` (lowercase, hyphenated)
- Module names: `snake_case`
- Types: `PascalCase`
- Functions: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Domain separation strings: `"AegisPQ-v{N}-{operation}"`
- File extensions: `.aegispq` (encrypted file), `.aegispq-key` (key package), `.aegispq-rev` (revocation)

---

## 13. Build, Test, and Release Pipeline

### 13.1 Reproducible Builds

- Pin Rust toolchain version in `rust-toolchain.toml` (e.g., `1.80.0`).
- Use `Cargo.lock` committed to the repository.
- CI builds in a pinned container image (hash-pinned, not tag-pinned).
- Release builds include a build manifest: `{ rust_version, target_triple, cargo_lock_hash, source_commit, build_timestamp }`.
- Third parties can reproduce the build by checking out the same commit and using the same toolchain.

### 13.2 Dependency Policy

- **Minimum dependencies.** Every dependency must be justified in a `deny.toml` allowlist.
- **cargo-deny** enforces: license allowlist (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC), no duplicate versions, no known advisories.
- **cargo-audit** runs weekly and on every PR.
- **cargo-vet** (or equivalent) for supply-chain review: every dependency must be audited or certified by a trusted reviewer before it enters the tree.
- **Dependency updates** are batched monthly, reviewed for changelog entries, and tested before merge. Security-critical updates are fast-tracked.

### 13.3 Code Signing

- Release binaries are signed with a project Ed25519 key (ironic bootstrap: the initial signing key is not AegisPQ-protected).
- Signatures are published alongside release artifacts.
- The signing key's public half is embedded in the repository, the project website, and multiple keyserver-like locations.
- Future: sign releases with AegisPQ itself once the toolchain is stable (dogfooding).

### 13.4 CI Stages

| Stage | Trigger | Actions |
|-------|---------|---------|
| **Lint** | Every push/PR | `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo deny check` |
| **Build** | Every push/PR | `cargo build --release` on Linux x86_64, macOS ARM64, Windows x86_64 |
| **Unit tests** | Every push/PR | `cargo test` across all crates |
| **Integration tests** | Every push/PR | `cargo test --test '*'` in `tests/integration/` |
| **Property tests** | Every push/PR | `cargo test` with `proptest` (capped at 1000 cases in CI, more in nightly) |
| **Known-answer tests** | Every push/PR | Verify against `spec/v1/test-vectors.json` |
| **Negative tests** | Every push/PR | `tests/negative/` — verify expected failures |
| **Fuzzing** | Nightly | `cargo-fuzz` on all targets, 1 hour per target |
| **Coverage** | Weekly | `cargo-tarpaulin` or `llvm-cov`, report to dashboard |
| **Dependency audit** | Weekly + every PR | `cargo audit`, `cargo deny` |
| **Benchmarks** | On release branches | `cargo bench`, compared against previous release |
| **WASM build** | Every push/PR | `wasm-pack build` for JS bindings |
| **Cross-compilation** | On release | ARM64 Linux, musl static builds |

### 13.5 Release Process

1. Create release branch `release/vX.Y.Z` from `main`.
2. Update version numbers in all `Cargo.toml` files.
3. Update `CHANGELOG.md` with release notes.
4. Run full CI pipeline including benchmarks.
5. Tag the commit: `git tag -s vX.Y.Z`.
6. Build release artifacts (static binaries for Linux/macOS/Windows, source tarball).
7. Sign all artifacts with the project release key.
8. Publish to:
   - GitHub Releases (binaries + signatures)
   - crates.io (Rust crates)
   - PyPI (Python bindings)
   - npm (JS/WASM bindings)
9. Announce on project mailing list and website.

### 13.6 Rollback

- If a release introduces a regression, publish a new patch release with the fix.
- Never yank a crates.io release for non-security reasons (it breaks downstream builds).
- For security issues: yank the affected version, publish a patched version, and issue a security advisory.

### 13.7 Secure Update

- AegisPQ does not include an auto-updater. Auto-updaters are a significant attack surface and are out of scope for a crypto library.
- Package managers (apt, brew, cargo, pip, npm) handle updates.
- The CLI can optionally check for newer versions (opt-in, no automatic download): `aegispq --check-update` fetches a signed version manifest and compares.

---

## 14. Security Hardening Checklist

### 14.1 Compiler and Build

- [ ] `#![forbid(unsafe_code)]` in `aegispq-core`, `aegispq-protocol`, `aegispq-api`
- [ ] `#![deny(warnings)]` in all crates
- [ ] Release builds with `opt-level = 2` (not `3`; `3` enables more aggressive optimizations that can introduce timing variations)
- [ ] LTO (link-time optimization) enabled for release builds (reduces binary size, enables cross-crate inlining of crypto operations)
- [ ] Stack protector enabled (`-C overflow-checks=yes` — default in Rust)
- [ ] Position-independent executable (`-C relocation-model=pic`)

### 14.2 Secret Handling

- [ ] All secret key types implement `Zeroize` and `ZeroizeOnDrop` (from the `zeroize` crate)
- [ ] Secret types do NOT implement `Debug`, `Display`, `Serialize`, or `Clone`
- [ ] Secret buffers allocated with `mlock` where the OS supports it (best-effort; failure to `mlock` is not fatal)
- [ ] Passphrase input uses `rpassword` (no echo to terminal)
- [ ] Temporary files containing plaintext are never created; encryption/decryption operates on in-memory buffers or streaming I/O with immediate encryption

### 14.3 Logging and Error Handling

- [ ] No key material, plaintext, or passphrases in log output at any level
- [ ] Error types use static strings for internal errors, not formatted dynamic data
- [ ] File paths in error messages are optional and off by default
- [ ] Panic messages do not contain secrets (review all `unwrap()` and `expect()` calls)
- [ ] No telemetry is collected. The library has no network access except when explicitly performing key exchange.

### 14.4 Randomness

- [ ] All randomness sourced from `getrandom` crate (OS CSPRNG)
- [ ] Boot-time entropy check: if `getrandom` returns an error (e.g., entropy pool not initialized), fail loudly rather than falling back
- [ ] No userspace PRNG seeding, no `rand::thread_rng()` for cryptographic operations
- [ ] Test builds can inject deterministic randomness for reproducibility (behind `#[cfg(test)]` only, never in release builds)

### 14.5 Constant-Time Operations

- [ ] Key comparison uses `subtle::ConstantTimeEq`
- [ ] MAC verification uses constant-time comparison
- [ ] No branching on secret data in `aegispq-core`
- [ ] Document known exceptions: Argon2id is inherently variable-time (acceptable for passphrase hashing); ML-KEM and ML-DSA reference implementations may have variable-time operations (use audited constant-time implementations when available)

### 14.6 Dependency Hygiene

- [ ] `cargo-deny` in CI: license check, advisory check, ban list
- [ ] `cargo-vet` or `cargo-crev`: trust review for all dependencies
- [ ] Maximum dependency depth monitored (alert if transitive dependency count exceeds threshold)
- [ ] No build scripts (`build.rs`) that download code or execute network requests
- [ ] All C dependencies (if any, via `aws-lc-rs` or `ring`) are vendored and hash-verified

### 14.7 Anti-Downgrade

- [ ] Suite identifier is bound into AEAD additional data and HKDF info strings
- [ ] Version and suite are verified before any decryption attempt
- [ ] Deprecated suites are removed from the codebase, not merely deprioritized
- [ ] No `allow_legacy` or `unsafe_mode` flag

### 14.8 Abuse Resistance

- [ ] Argon2id parameters enforced at minimum floor (cannot be reduced below 64 MiB / 2 iterations via API)
- [ ] Maximum ciphertext size enforced (4 GiB per envelope; prevents memory exhaustion)
- [ ] Maximum recipient count enforced (1,000 per file; prevents header inflation)
- [ ] Maximum pre-key count per identity enforced (100; prevents storage exhaustion)

### 14.9 Incident Response

- [ ] `SECURITY.md` in the repository root with disclosure instructions
- [ ] Dedicated security contact email (e.g., security@aegispq.org)
- [ ] 90-day disclosure timeline with expedited patching
- [ ] Pre-written advisory template for common vulnerability classes

---

## 15. Migration and Crypto-Agility Plan

### 15.1 Suite Versioning

Each combination of algorithms is a **suite**. Suites are identified by a single byte in the envelope header.

| Suite ID | Algorithms | Status |
|----------|-----------|--------|
| `0x01` | X25519+ML-KEM-768, Ed25519+ML-DSA-65, AES-256-GCM, HKDF-SHA-512, BLAKE3, Argon2id | Active (v1 default) |
| `0x02` | X25519+ML-KEM-768, Ed25519+ML-DSA-65, XChaCha20-Poly1305, HKDF-SHA-512, BLAKE3, Argon2id | Active (v1 alternate) |
| `0x03`–`0xFF` | Reserved for future suites | — |

### 15.2 Adding a New Suite

1. Define the new suite in a new protocol version specification.
2. Implement the suite in `aegispq-core`.
3. Add test vectors to `spec/vN/test-vectors.json`.
4. Release as a new minor version. The new suite is opt-in initially.
5. After a transition period (minimum 6 months), make the new suite the default.
6. After an additional transition period (minimum 12 months), deprecate the old suite.

### 15.3 Deprecating a Suite

1. Announce deprecation with at least 12 months' notice.
2. Log a warning when the deprecated suite is used for encryption.
3. Continue supporting decryption of deprecated-suite ciphertext for 24 months.
4. After 24 months, remove the suite from the codebase. Ciphertext encrypted with the removed suite must be re-encrypted before the removal deadline.

### 15.4 Algorithm Replacement

If a specific algorithm within a suite is broken:

1. Release a patch that disables the broken algorithm for new operations immediately.
2. If the broken algorithm is one half of a hybrid (e.g., ML-KEM-768 is broken but X25519 is fine), the hybrid still provides security from the unbroken half. Issue guidance to re-encrypt with a new suite when available.
3. Define a replacement suite with a successor algorithm.
4. Follow the "Adding a New Suite" process with compressed timelines appropriate to the severity.

### 15.5 Mixed-Fleet Migration

In an organization where some users have updated and others have not:

- New-version users can still decrypt old-suite ciphertext (backward compatibility).
- New-version users produce new-suite ciphertext by default.
- Old-version users cannot decrypt new-suite ciphertext (they must update).
- The organization can enforce a minimum suite version via a policy file that AegisPQ reads from a configurable location.

### 15.6 Avoiding Lock-In

- AegisPQ does not depend on any single cryptographic library. The `aegispq-core` crate abstracts over crypto backends via internal traits.
- If `ring` ceases maintenance, the backend can be switched to `aws-lc-rs` or `rustcrypto` crates with no API change.
- If NIST post-quantum standards are revised, only `aegispq-core` needs to change. The protocol, API, and CLI layers are unaffected (they reference suites, not individual algorithms).

---

## 16. Product Roadmap

### Phase 0: Specification and Research (Months 1–2)

**Deliverables:**
- Finalized protocol specification (spec/v1/)
- Test vectors for all operations
- Threat model published
- Dependency selection finalized and audited
- Repository scaffold with CI

**Exit criteria:**
- Specification reviewed by at least 2 external cryptography-knowledgeable reviewers
- All test vectors are self-consistent and cross-checked

### Phase 1: Crypto Core (Months 2–4)

**Deliverables:**
- `aegispq-core` crate: AEAD, hybrid KEM, hybrid signatures, KDF, hashing, nonce management
- Known-answer tests passing against spec vectors
- Property tests and fuzzing targets

**Exit criteria:**
- 100% branch coverage in `aegispq-core`
- Zero `unsafe` blocks
- All fuzzing targets run for minimum 8 hours without crash

### Phase 2: Protocol Layer (Months 4–6)

**Deliverables:**
- `aegispq-protocol` crate: envelope construction, session state machine, file encryption, version negotiation
- `aegispq-store` crate: encrypted key store, session store
- Integration tests for full encrypt/decrypt flows

**Exit criteria:**
- All protocol flows from Section 9 are implemented and tested
- Cross-version interop tests pass (version 1 only at this stage, but the test infrastructure exists)

### Phase 3: Public API and CLI (Months 6–8)

**Deliverables:**
- `aegispq-api` crate: misuse-resistant public API
- `aegispq-cli`: all commands (identity, encrypt, decrypt, sign, verify, rotate, revoke, recover)
- User-facing documentation (man pages, `--help` text, quick start guide)
- Example programs

**Exit criteria:**
- CLI is usable for basic file encryption, identity management, and key rotation
- API docs pass `cargo doc --no-deps` with zero warnings
- At least 5 worked examples

### Phase 4: Language Bindings (Months 8–10)

**Deliverables:**
- `aegispq-ffi` crate: C FFI with generated header
- Python bindings (PyO3)
- JavaScript/WASM bindings (wasm-bindgen)
- Binding-specific tests and examples

**Exit criteria:**
- Bindings pass the same integration test suite as the Rust API
- Bindings are documented with language-idiomatic examples

### Phase 5: Beta Release (Month 10)

**Deliverables:**
- Public beta release on GitHub, crates.io, PyPI, npm
- Published specification
- Published threat model
- Bug bounty program (limited scope, funded if resources allow)
- Call for community review

**Exit criteria:**
- No known security issues
- API is considered stable (no breaking changes expected before 1.0)
- At least 10 external users/testers have provided feedback

### Phase 6: Security Audit (Months 10–14)

**Deliverables:**
- Engage an independent security audit firm (e.g., NCC Group, Trail of Bits, Cure53, or X41)
- Scope: `aegispq-core` (mandatory), `aegispq-protocol` (mandatory), `aegispq-api` (recommended)
- Fix all findings rated High or Critical before 1.0
- Publish audit report in full (redacting only active exploits during fix window)

**Exit criteria:**
- Audit complete with all High/Critical findings resolved
- Audit report published
- Re-audit of fixes confirmed by auditor

### Phase 7: Production Release (Month 14–15)

**Deliverables:**
- Version 1.0.0 release
- Stable API guarantee (semver)
- Long-term support (LTS) commitment for 1.x line (minimum 3 years)
- Package distribution via Homebrew, APT repository, cargo, pip, npm

**Exit criteria:**
- Audit-clean release
- All documentation complete
- Donation/sponsorship infrastructure in place

### Phase 8: Ongoing Maintenance (Month 15+)

**Activities:**
- Security patch releases within 72 hours of confirmed vulnerability
- Dependency updates monthly
- Quarterly fuzzing campaigns (extended duration)
- Annual re-assessment of algorithm choices
- Community engagement, issue triage, PR review
- Roadmap planning for v2 (new suites, new features based on user feedback)

---

## 17. Adoption and Packaging Strategy

### 17.1 Distribution Channels

| Channel | Artifact | Audience |
|---------|----------|----------|
| **GitHub Releases** | Signed static binaries (Linux, macOS, Windows) | All users |
| **crates.io** | `aegispq-core`, `aegispq-protocol`, `aegispq-api`, `aegispq-cli` | Rust developers |
| **PyPI** | `aegispq` Python package | Python developers |
| **npm** | `@aegispq/core` WASM package | JavaScript developers |
| **Homebrew** | `aegispq` formula | macOS CLI users |
| **APT repository** | `aegispq` .deb package | Debian/Ubuntu CLI users |
| **Docker Hub** | `aegispq/cli` minimal container | CI/CD pipelines |
| **Flathub / Snap** | Deferred to post-1.0 based on demand | Desktop Linux users |

### 17.2 Developer Experience

- **Quick start:** `cargo install aegispq-cli && aegispq identity create && aegispq encrypt --file secret.txt --to <fingerprint>`
- **SDK quick start:** 5-line Rust example, 5-line Python example, 5-line JS example in README
- **API documentation:** Hosted on docs.rs (Rust), ReadTheDocs (Python), project website (JS)
- **Examples repository:** Curated examples for common use cases (file encryption, CI secret management, API payload encryption, key rotation automation)
- **Error messages:** Every error includes a short explanation and a link to the relevant documentation section

### 17.3 Organizational Adoption

- **Policy file support:** Organizations can distribute a `aegispq-policy.toml` that enforces minimum suite versions, key rotation schedules, and Argon2id parameters.
- **Centralized key package distribution:** Organizations can host key packages on an internal HTTPS endpoint. AegisPQ can fetch key packages from a configurable URL (with certificate pinning option).
- **Audit trail:** The CLI can produce structured JSON logs (opt-in) of all operations for compliance purposes. Logs never contain plaintext or key material.
- **FIPS mode:** Deferred to post-1.0. If required, a FIPS-validated backend (e.g., AWS-LC with FIPS certification) can be substituted into `aegispq-core` via the backend trait.

### 17.4 Positioning

AegisPQ is positioned as:

> "The encryption toolkit for teams that need more than `openssl enc` but less than a full PKI. Post-quantum ready, crypto-agile, auditable, open source."

It is **not** positioned as:
- "Better than AES" (misleading; AES is a component, not a competitor)
- "Unbreakable" (no such thing)
- "The Signal replacement" (AegisPQ is a library/CLI, not a messaging app)

---

## 18. Donation and Sponsorship Model

### 18.1 Funding Needs

| Category | Estimated Annual Cost | Priority |
|----------|-----------------------|----------|
| **Security audit (initial)** | $50,000–$150,000 (one-time) | Critical |
| **Security audit (periodic)** | $30,000–$80,000/year | High |
| **Infrastructure** (CI, hosting, signing HSM) | $3,000–$10,000/year | High |
| **Bug bounty program** | $5,000–$20,000/year | Medium |
| **Maintainer stipend** (1–2 part-time) | $20,000–$80,000/year | High |
| **Documentation and technical writing** | $5,000–$15,000/year | Medium |
| **Community support** (issue triage, PR review) | Volunteer + maintainer time | Ongoing |

### 18.2 Funding Sources

**Individual donations:**
- GitHub Sponsors
- Open Collective
- Liberapay
- One-time donations via cryptocurrency (Bitcoin, Monero) for users who prefer privacy

**Corporate sponsorship:**
- Tiered sponsorship via Open Collective or GitHub Sponsors
- Sponsors receive: logo on project website, mention in release notes, early access to security advisories (all public information, just earlier notification)
- Sponsors do NOT receive: influence over cryptographic decisions, private features, or priority support for non-security issues

**Grants:**
- Open Technology Fund (OTF)
- NLnet Foundation
- Sovereign Tech Fund (STF)
- Mozilla Open Source Support (MOSS)
- Internet Security Research Group (ISRG) / Let's Encrypt model

**Contract work:**
- Organizations that need custom integration, FIPS certification support, or expedited feature development can fund that work through a transparent contract. The resulting code must be open source.

### 18.3 Sponsorship Tiers

| Tier | Amount (monthly) | Benefits |
|------|-----------------|----------|
| **Supporter** | $5–$49 | Name in SUPPORTERS.md, warm feeling |
| **Backer** | $50–$499 | Logo (small) on project website |
| **Sponsor** | $500–$4,999 | Logo (medium) on project website + README, mention in release notes |
| **Principal Sponsor** | $5,000+ | Logo (large) on project website + README, quarterly update call with maintainers, early security advisory notification |

### 18.4 Transparency

- All income and expenses are published quarterly via Open Collective (which provides built-in financial transparency).
- Audit costs are published with the audit report.
- Maintainer stipends are disclosed in aggregate.
- No anonymous corporate sponsorship (individual donations may be anonymous).

### 18.5 Independence Safeguards

- **No single sponsor may fund more than 40% of the project's annual budget.** If a sponsor exceeds this threshold, the project will actively seek additional sponsors to rebalance.
- **Cryptographic decisions are made by the maintainer team based on published criteria (security, standards compliance, auditability), not sponsor preference.**
- **Sponsors cannot request backdoors, weakened defaults, or proprietary features.** Any such request will be publicly disclosed and the sponsorship terminated.
- **The project's domain, signing keys, and infrastructure credentials are held by at least 2 maintainers, not by any sponsor.**

### 18.6 Donation Page Language

```
AegisPQ is free, open-source software maintained by volunteers and part-time
contributors. Your support funds:

- Independent security audits (our most critical expense)
- Ongoing maintenance and security patches
- Bug bounty rewards for responsible disclosure
- Infrastructure (CI, hosting, code signing)
- Documentation and developer experience

We do not sell your data. We do not offer premium features.
Every dollar goes to making encryption more accessible and more secure.

[Donate via GitHub Sponsors] [Donate via Open Collective]
```

### 18.7 Sponsor Page Language

```
These organizations support AegisPQ's mission of accessible, auditable,
post-quantum-ready encryption. Sponsorship supports audits, maintenance,
and infrastructure. Sponsors do not influence cryptographic design decisions.

[Principal Sponsors]
[Sponsors]
[Backers]

Interested in sponsoring? See our sponsorship tiers: [link]
```

---

## 19. Documentation Plan

### 19.1 Documentation Required at 1.0 Launch

| Document | Location | Audience |
|----------|----------|----------|
| **README.md** | Repository root | All |
| **Quick start guide** | `docs/quickstart.md` + website | New users |
| **CLI reference** | `docs/cli.md` + man pages | CLI users |
| **Rust API reference** | docs.rs (auto-generated) | Rust developers |
| **Python API reference** | ReadTheDocs | Python developers |
| **JS/WASM API reference** | Project website | JS developers |
| **Architecture overview** | `docs/architecture.md` | Contributors, auditors |
| **Protocol specification** | `spec/v1/` | Auditors, implementers |
| **Threat model** | `spec/threat-model.md` | Security teams, auditors |
| **Security policy** | `SECURITY.md` | Security researchers |
| **Contribution guide** | `CONTRIBUTING.md` | Contributors |
| **Build instructions** | `docs/building.md` | Contributors, packagers |
| **Key management guide** | `docs/key-management.md` | All users |
| **Migration guide** | `docs/migration.md` | Users upgrading between versions |
| **FAQ** | `docs/faq.md` + website | All |

### 19.2 Specification Strategy

- Protocol specifications are versioned alongside the code in `spec/v{N}/`.
- Specifications are written in Markdown for readability and version control.
- Each specification includes: overview, data formats (with byte-level diagrams), state machines, security properties, and test vectors.
- Specifications are the authoritative reference. If the code disagrees with the spec, it is a bug in the code (unless the spec is being intentionally revised, in which case the spec is updated first).

### 19.3 Changelog and Release Notes

- `CHANGELOG.md` follows Keep a Changelog format.
- Every release includes: summary, breaking changes (if any), new features, bug fixes, security fixes, dependency updates.
- Security fixes are tagged with `[SECURITY]` and include CVE identifiers when applicable.

### 19.4 Versioning Docs with Software

- Documentation lives in the repository, not a separate docs repo.
- docs.rs automatically versions Rust API docs per release.
- The project website pulls docs from tagged releases, ensuring version-specific documentation is accessible.
- Migration guides are cumulative: the guide for v1→v3 includes all steps from v1→v2 and v2→v3.

---

## 20. Governance and Maintenance Model

### 20.1 Decision-Making

- **Security decisions** (algorithm selection, protocol changes, vulnerability response): require consensus among core maintainers with explicit sign-off from at least one maintainer who has cryptographic expertise. If consensus cannot be reached, the most conservative option is chosen.
- **Feature decisions:** require one maintainer approval via PR review.
- **Release decisions:** require two maintainer approvals (four-eyes principle).

### 20.2 Roles

| Role | Count | Responsibilities |
|------|-------|-----------------|
| **Core maintainer** | 2–4 | Security decisions, release approval, key custody, audit oversight |
| **Maintainer** | 2–6 | Code review, issue triage, feature implementation |
| **Contributor** | Unlimited | PR submissions, bug reports, documentation |
| **Security advisor** | 1–2 (external) | Review security-critical changes, advise on cryptographic decisions |

### 20.3 Code Review Policy

- All changes to `aegispq-core` require review by a core maintainer.
- All changes to `aegispq-protocol` require review by at least one maintainer.
- All other changes require review by at least one maintainer.
- No self-merging (the author cannot be the sole reviewer).
- Security-sensitive changes (flagged by label or file path) require two reviews.

### 20.4 Vulnerability Disclosure

1. Researcher reports vulnerability to `security@aegispq.org` (encrypted with the project's PGP key or AegisPQ key once available).
2. Maintainer acknowledges within 48 hours.
3. Fix developed in private branch.
4. Fix reviewed by at least 2 maintainers.
5. Coordinated disclosure: patch release + advisory published simultaneously.
6. Default disclosure timeline: 90 days. Extended to 120 days if the fix requires a protocol change.
7. Reporter credited unless they request anonymity.

### 20.5 Audit Handling

- Audit findings are prioritized: Critical (fix before release), High (fix before next release), Medium (fix within 3 months), Low/Informational (tracked, fix opportunistically).
- The full audit report is published after all Critical and High findings are resolved.
- A summary of findings, their status, and the fix commit hashes is maintained in `docs/audit-log.md`.

### 20.6 Bus-Factor Reduction

- At least 2 core maintainers must have access to: domain registration, signing keys, CI secrets, crates.io publish rights, and Open Collective administration.
- Key material (signing keys) is backed up using Shamir's Secret Sharing (3-of-5 threshold) held by core maintainers, stored in separate physical locations.
- If the project's maintainer count drops below 2, the project will issue a public call for new maintainers and, if necessary, transfer stewardship to a host organization (e.g., a Linux Foundation project, Apache Foundation, or similar).

### 20.7 License

Dual-licensed under **MIT** and **Apache-2.0**, consistent with the Rust ecosystem convention. This maximizes adoption across corporate, academic, and individual users.

---

## 21. Open Questions and Risks

### 21.1 Unresolved Design Choices

| Question | Options | Current Leaning | Notes |
|----------|---------|----------------|-------|
| **Primary crypto backend** | `ring` vs `aws-lc-rs` vs RustCrypto | `aws-lc-rs` | `ring` has uncertain maintenance; `aws-lc-rs` is AWS-backed with FIPS option. RustCrypto is pure Rust but less audited for some primitives. Needs evaluation at Phase 0. |
| **ML-KEM / ML-DSA implementation** | `pqcrypto` vs `ml-kem`/`ml-dsa` crates vs vendor | `ml-kem`/`ml-dsa` crates | These are the emerging standard Rust crates tracking FIPS 203/204. Maturity must be verified. |
| **Storage backend** | SQLite vs flat files vs both | SQLite with flat-file fallback | SQLite is robust and supports atomic operations. Flat files are simpler and more portable. Both can be supported behind a trait. |
| **Symmetric algorithm default** | AES-256-GCM vs XChaCha20-Poly1305 | AES-256-GCM | AES-NI makes GCM faster on most hardware. XChaCha20 is the safer default (larger nonce, no AES-NI dependency). This is a real tradeoff — hardware benchmarks needed at Phase 1. |
| **Key package distribution** | Manual-only vs optional key server protocol | Manual-only for 1.0 | Key server introduces significant attack surface. Defer to post-1.0. |
| **Session ratchet complexity** | Simple symmetric ratchet vs full Double Ratchet | Simple symmetric with periodic DH ratchet | Full Double Ratchet (Signal Protocol) is complex and may be over-engineered for a library/CLI tool. The simpler approach provides forward secrecy with periodic re-keying. Revisit if messaging becomes a primary use case. |

### 21.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **ML-KEM or ML-DSA implementation bugs** | Medium | High | Use only audited implementations; add extensive KATs; participate in NIST validation |
| **Side-channel attacks on post-quantum implementations** | Medium | High | Use constant-time implementations; hybrid design limits blast radius; document WASM limitations |
| **Nonce reuse due to counter persistence failure** | Low | Critical | Counter + random nonce construction; integrity-checked counter persistence; fallback to XChaCha20 with random nonces if counter cannot be persisted |
| **BARE encoding library bugs** | Low | Medium | Use a well-tested BARE implementation or write a minimal one with extensive tests; canonical encoding simplifies validation |
| **Large ciphertext overhead from hybrid KEM + padding** | Certain | Low | ML-KEM-768 ciphertext adds ~1 KB per recipient; padding adds up to 2x for small files. Acceptable for the target use cases; documented clearly. |
| **Argon2id parameter selection too aggressive for embedded/CI** | Medium | Medium | Provide configurable parameters with enforced minimums; document recommended parameters per platform class |

### 21.3 Operational Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Insufficient funding for audit** | Medium | Critical | Apply to multiple grants (OTF, NLnet, STF) early; build community to demonstrate demand; consider staged audits (core first) |
| **Maintainer burnout or departure** | Medium | High | Bus-factor reduction (Section 20.6); maintainer stipends; clear governance for succession |
| **Low adoption due to crowded market** | Medium | Medium | Focus on developer experience, clear differentiation (hybrid PQ + crypto-agility + library-first design), and organizational use cases |
| **NIST revises FIPS 203/204 significantly** | Low | High | Crypto-agility plan (Section 15) absorbs this; hybrid design provides buffer time |
| **Supply-chain attack on a dependency** | Low | Critical | cargo-vet, cargo-deny, reproducible builds, minimal dependency surface |

### 21.4 Conservative Fallbacks

For every open question, the conservative fallback is:

- **If unsure about a crypto backend:** use the most audited option, even if it has more C code.
- **If unsure about an algorithm default:** choose the one that is harder to misuse (XChaCha20-Poly1305 over AES-256-GCM if nonce management is uncertain).
- **If unsure about a feature:** leave it out of 1.0. A missing feature can be added; a broken feature must be supported forever.
- **If unsure about a security claim:** do not make the claim. State what is known and what is assumed.

---

## Self-Check

- [x] No cryptographic primitive was invented.
- [x] No absolute security claim was made.
- [x] Build, release, security, testing, and recovery are specified.
- [x] A realistic sponsorship and donation plan is included.
- [x] Primitives are clearly separated from platform architecture.
- [x] AES is treated as a building block, not the whole solution.
- [x] The project is defined as a product with adoption strategy.
- [x] Maintainability after launch is addressed (governance, bus factor, LTS).
- [x] All major production concerns are specified or explicitly marked as open questions.

---

*End of specification.*
