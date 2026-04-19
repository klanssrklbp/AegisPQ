# AegisPQ Compatibility Matrix

This document defines the stability guarantees for AegisPQ's wire formats,
on-disk storage, and algorithm suites. It is the authoritative reference for
what a given version of the software can produce and consume.

## Protocol version

| Field | Value |
|-------|-------|
| Current version | `1` |
| Minimum supported version | `1` |

The protocol version is encoded as a big-endian `u16` at bytes 5-6 of every
envelope header. Parsers hard-reject any version outside
`[MIN_SUPPORTED, CURRENT]`.

When a breaking wire-format change is necessary:

1. Bump `CURRENT` in `aegispq_protocol::version`.
2. Create a `tests/vectors/v<N>/` directory with new frozen fixtures.
3. Update `MIN_SUPPORTED` only when old-format support is intentionally dropped.
4. Document the change in the changelog.

## Envelope header (stable since v1)

```
Offset  Size  Field               Notes
0       4     Magic: APQ\x01      Frozen. Never changes.
4       1     FormatType          See table below.
5       2     Version (BE u16)    Currently 1.
7       1     Suite               See table below.
8       4     Payload length (BE) Byte count of everything after the header.
```

Total: **12 bytes**, pinned by `wire_format_compat.rs` tests.

## Format types

| Byte | Name | Status |
|------|------|--------|
| `0x01` | EncryptedFile | Stable |
| `0x02` | KeyPackage | Stable |
| `0x03` | SessionMessage | Reserved (not implemented) |
| `0x04` | RevocationCertificate | Stable |
| `0x05` | RotationCertificate | Stable |
| `0x06` | RecoveryBlob | Reserved (not implemented) |
| `0x07` | SignedDocument | Reserved (not implemented) |

New format types may be added without bumping the protocol version.
Existing byte assignments are frozen.

## Algorithm suites

| Byte | Name | Algorithms | Status |
|------|------|------------|--------|
| `0x01` | HybridV1 | X25519+ML-KEM-768, Ed25519+ML-DSA-65, AES-256-GCM, BLAKE3, Argon2id | Stable |
| `0x02` | HybridV1XChaCha | Same as HybridV1 but XChaCha20-Poly1305 for symmetric | Stable |

Byte assignments are frozen. New suites get new byte values.

## On-disk storage formats

| Record type | Magic | Current version | Notes |
|-------------|-------|----------------|-------|
| IdentityRecord | `APQI` | 1 | Fixed size: 3478 bytes (v1) |
| ContactRecord | `APQC` | 1 | Fixed size: 3244 bytes (v1) |

Storage records use their own 4-byte magic and u16 version, independent of
the envelope header. This allows storage format evolution without changing
the wire protocol.

Both record sizes are pinned by `compat_tests.rs`.

## Backward compatibility policy

| Scenario | Behavior |
|----------|----------|
| Receiving a v1 file on a v1+ build | Always supported |
| Receiving a v2 file on a v1 build | Hard rejection (`UnsupportedVersion`) |
| Unknown FormatType byte | Hard rejection (`UnknownFormat`) |
| Unknown Suite byte | Hard rejection (`UnsupportedSuite`) |
| Unknown storage record version | Hard rejection |
| Trailing bytes after declared payload | Hard rejection (`TrailingData`) |

There is no silent fallback. Every unknown field is a hard error.

## CLI JSON contract

When `--json` is passed, the CLI emits structured JSON to stdout:

**Success:** command-specific JSON object with a `"command"` field.

**Error:** `{"error": "<message>", "error_kind": "<kind>"}` where `error_kind` is one of:

| Kind | Meaning | Exit code |
|------|---------|-----------|
| `auth` | Wrong passphrase, empty passphrase, mismatch | 2 |
| `revoked` | Identity is revoked | 3 |
| `integrity` | Authentication / integrity failure | 3 |
| `not_recipient` | Not a recipient of this ciphertext | 3 |
| `unsupported` | Version or suite not supported | 1 |
| `io` | File I/O error | 4 |
| `corrupt` | Invalid key material or truncated data | 1 |
| `too_large` | Input exceeds size limit | 1 |
| `unknown` | Unclassified error | 1 |

Exit codes: `0` = success, `1` = general error, `2` = auth error,
`3` = integrity/verification failure, `4` = I/O error.

## Frozen test vectors

Binary fixtures under `crates/aegispq-protocol/tests/vectors/v1/` are
checked into version control and must not be modified. They are validated
by `frozen_vectors.rs` on every test run.

If the protocol format changes, create a `v2/` directory. Do not overwrite `v1/`.

## Deprecation process

Before removing support for any format, suite, or storage version:

1. Log a deprecation warning for at least one minor release.
2. Update `MIN_SUPPORTED` or equivalent constant.
3. Remove the old test vectors from the active test path (keep in repo for reference).
4. Document in the changelog with migration guidance.
