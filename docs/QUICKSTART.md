# AegisPQ Quickstart: Secure File Exchange for Teams

This guide walks through a complete team workflow: onboarding, key exchange,
encrypted file sharing, and handling key rotation.

## Install

```bash
# From source (requires Rust 1.80+):
cargo install --path crates/aegispq-cli

# Or build a release binary:
./scripts/build-release.sh
sudo cp target/release/aegispq /usr/local/bin/
```

Verify installation:

```bash
aegispq --version
# aegispq 0.1.0
```

## 1. Create your identity

Each team member creates an identity protected by a passphrase:

```bash
aegispq identity create --name "Alice"
# Passphrase: ********
# Confirm passphrase: ********
# Identity created.
#   ID:          a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
#   Name:        Alice
#   Fingerprint: 42586a38 70b0e2ea 6436e418 ...
```

Save your ID — you'll share it with teammates. The passphrase protects
your private keys at rest and is required for encryption, decryption, and signing.

## 2. Export and share your public key

Export your key package (contains only public keys):

```bash
aegispq identity export a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 \
  --output alice.pub.apq
# Public key exported to: alice.pub.apq
#   Fingerprint: 42586a38 70b0e2ea 6436e418 ...
```

Send `alice.pub.apq` to your teammates via any channel (email, Slack, etc.).
The file contains only public keys — it is safe to share openly.

## 3. Import teammates' key packages

When you receive a teammate's key package:

```bash
aegispq contact import bob.pub.apq
# Contact imported: Bob (b0b1b2b3b4b5b6b7b8b9babbbcbdbebf)
#
#   Fingerprint: 36784e7f eaf62eef 3fa2ec90 ...
#
#   IMPORTANT: Verify this fingerprint with Bob via a trusted
#   channel (phone, in person) before encrypting sensitive data.
```

**Verify the fingerprint.** Call Bob and read the fingerprint aloud, or
compare in person. This one step prevents man-in-the-middle attacks.

## 4. Encrypt a file for teammates

For a single recipient:

```bash
aegispq encrypt \
  --file report.pdf \
  --to b0b1b2b3b4b5b6b7b8b9babbbcbdbebf \
  --identity a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
# Encrypted: report.pdf -> report.pdf.apq
#   Suite: aes
#   Recipients:
#     Bob (b0b1b2b3...)
#   Output: 48231 bytes
```

For multiple recipients, use `--to` multiple times or a recipients file:

```bash
# Create a recipients file (one ID per line, # for comments):
cat > team-recipients.txt << EOF
# Engineering team
b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
EOF

aegispq encrypt \
  --file report.pdf \
  --recipients-file team-recipients.txt \
  --identity a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

## 5. Decrypt a file

```bash
aegispq decrypt \
  --file report.pdf.apq \
  --identity b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
# Decrypted: report.pdf.apq -> report.pdf
#   Sender verified: Alice (a1b2c3d4...)
#   48000 bytes recovered
```

The sender's signature is verified before any plaintext is written to disk.
If verification fails, no output file is created.

## 6. Sign and verify files

Sign a document (creates a detached signature):

```bash
aegispq sign \
  --file announcement.txt \
  --identity a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
# Signed: announcement.txt -> announcement.txt.apqsig
```

Verify a signature:

```bash
aegispq verify \
  --file announcement.txt \
  --signature announcement.txt.apqsig \
  --signer a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
# Signature VALID.
#   Signer: Alice (a1b2c3d4...)
```

## 7. Handle key rotation

If a team member suspects their key is compromised:

```bash
# The owner rotates (creates new keys, old key vouches for new):
aegispq identity rotate a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
# Identity rotated.
#   Old ID: a1b2c3d4...
#   New ID: d4e5f6a7...
#   Certificate: a1b2c3d4....rot.apq
#
# Distribute this certificate to your contacts.
```

Teammates import the rotation certificate:

```bash
aegispq contact import-rotation alice.rot.apq
# Rotation imported: Alice (d4e5f6a7...)
#   Status: ACTIVE
#
#   Use the new ID above for future encryption to this contact.
#   The old identity has been marked as rotated.
```

The rotation certificate is dual-signed: the old key vouches for the new key,
and the new key vouches for the old key. This creates a verifiable chain of custody.

## 8. Handle revocation

If a key is definitely compromised and should never be trusted again:

```bash
aegispq identity revoke a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 \
  --reason compromised
# Identity revoked.
#   Certificate: a1b2c3d4....rev.apq
```

Teammates import the revocation:

```bash
aegispq contact import-revocation alice.rev.apq
# Revocation imported for: Alice (a1b2c3d4...)
#   Status: REVOKED
```

After revocation, encryption to that identity is blocked. Existing encrypted
files from the revoked identity can still be decrypted.

## Scripting and CI

All commands support `--json` for machine-readable output:

```bash
aegispq --json identity list | jq '.identities[].id'
aegispq --json encrypt --file data.bin --to "$BOB_ID" --identity "$MY_ID"
```

Passphrases can be piped on stdin for non-interactive use:

```bash
echo "my-passphrase" | aegispq encrypt --file data.bin --to "$BOB_ID" --identity "$MY_ID"
```

See `examples/` for complete runnable scripts.

## Failure modes

| Scenario | What happens | Exit code |
|----------|-------------|-----------|
| Wrong passphrase | Error: "invalid passphrase" | 2 |
| Encrypt to revoked contact | Error: "identity revoked" | 3 |
| Decrypt tampered file | Error, no output file created | 3 |
| Decrypt as wrong recipient | Error: "not a recipient" | 3 |
| File not found | Error: "No such file" | 4 |

No plaintext is ever written to disk unless authentication succeeds.

## Security properties

- **Post-quantum ready:** Every operation uses hybrid classical + post-quantum
  algorithms. An attacker must break both to compromise security.
- **Sender authentication:** Every encrypted file is signed. You always know who sent it.
- **No unsafe code:** The entire codebase uses `#![forbid(unsafe_code)]`.
- **Atomic writes:** Decryption uses temp-file-then-rename. Crash-safe, no partial output.
