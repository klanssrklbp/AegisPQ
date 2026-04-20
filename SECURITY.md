# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Only the latest patch release of the 0.1.x series receives security fixes.
Older versions will not be patched; users should upgrade.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, report vulnerabilities through GitHub's private security advisory
feature:

1. Navigate to the [Security Advisories page](https://github.com/klanssrklbp/AegisPQ/security/advisories).
2. Click **"New draft security advisory"**.
3. Fill in the description with as much detail as possible, including:
   - Affected component (crate name, module, function).
   - Steps to reproduce or a proof-of-concept.
   - Impact assessment (what an attacker can achieve).
   - Suggested fix, if you have one.
4. Submit the advisory. A maintainer will acknowledge receipt within 72 hours.

If you are unable to use GitHub Security Advisories, email
**security@aegispq.org** with the subject line `[VULN] <short description>`.
Encrypt your email with the project maintainer's PGP key if one is published
on the repository.

## Scope

### In Scope

The following categories of issues are considered security vulnerabilities:

- Bugs in cryptographic operations (incorrect encryption, decryption,
  signing, verification, key derivation, or nonce handling).
- Authentication or authorization bypasses (e.g., decryption without the
  correct key, signature forgery, revocation bypass).
- Key material leaks (secret keys appearing in logs, error messages,
  unzeroized memory, or serialized output).
- Padding oracle or timing side-channel attacks exploitable in practice.
- Format parsing bugs that lead to memory safety issues or incorrect
  cryptographic operations.
- Dependency vulnerabilities that affect AegisPQ's security properties.

### Out of Scope

The following are **not** considered security vulnerabilities for the
purposes of this policy:

- Denial of service via large or malformed inputs (resource exhaustion).
  AegisPQ applies bounded checks but does not guarantee availability under
  adversarial input sizes.
- Theoretical post-quantum attacks that do not yet have a practical
  demonstration. AegisPQ uses hybrid constructions (classical + PQ) so that
  security holds if either algorithm family remains secure.
- Attacks that require prior compromise of the local machine or key
  material (these are outside AegisPQ's trust boundary).
- Side-channel attacks that require physical access to the hardware.
- Issues in example code, documentation, or non-shipped tooling.

## Audit Status

AegisPQ has **not** undergone an external security audit. The codebase
includes extensive internal testing:

- **260+ unit and integration tests** covering identity lifecycle,
  encryption/decryption, signing/verification, key rotation, and revocation.
- **9 fuzz targets** covering every parser and untrusted-input entry point,
  run nightly in CI.
- **Frozen test vectors** for encrypted files (AES-256-GCM and
  XChaCha20-Poly1305) and detached signatures, ensuring backward
  compatibility across code changes.
- **CI pipeline** with formatting, linting (clippy), cross-platform tests
  (Linux, macOS, Windows), MSRV verification, and fuzz smoke tests on every
  push.

No independent third-party review has been conducted as of this writing.
An external audit is planned and will be announced when scheduled. Until
then, users should evaluate the project's suitability for their threat model
accordingly.

## Disclosure Timeline

AegisPQ follows a coordinated disclosure process with a **90-day** timeline:

1. **Day 0:** Vulnerability report received and acknowledged (within 72 hours).
2. **Day 1-14:** Maintainers triage the report, confirm the vulnerability,
   and assess severity.
3. **Day 14-75:** Maintainers develop and test a fix. The reporter is kept
   informed of progress.
4. **Day 75-90:** Fix is released. A security advisory is published on
   GitHub with full details, including affected versions and upgrade
   instructions.
5. **Day 90:** If a fix is not yet ready, the reporter may disclose the
   vulnerability publicly. Maintainers will coordinate to minimize the
   window of exposure.

In exceptional cases (e.g., active exploitation in the wild), the timeline
may be accelerated. Maintainers and reporters should communicate openly
about any timeline adjustments.

## Verifying Downloads

Binary releases on the [releases page](https://github.com/klanssrklbp/AegisPQ/releases)
are signed with [cosign](https://github.com/sigstore/cosign) keyless signing
via GitHub Actions' OIDC identity (logged to the Rekor transparency log)
and carry [SLSA v1](https://slsa.dev/) build-provenance attestations.

**Do not install a release binary that fails any of the three verification
layers** — checksum, cosign signature, and build-provenance attestation.
See [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) for the
step-by-step procedure.

A failed verification on an asset downloaded directly from GitHub is a
supply-chain incident; report it via the private advisory process above.

## Security Design

For a detailed description of AegisPQ's threat model, cryptographic
assumptions, and security properties, see:

- [DESIGN.md](DESIGN.md) -- Authoritative specification (Sections 4-5).
- [THREAT_MODEL.md](THREAT_MODEL.md) -- Condensed threat model summary.
