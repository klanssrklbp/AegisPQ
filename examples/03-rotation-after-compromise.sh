#!/usr/bin/env bash
# ============================================================================
# Example: Key rotation after a suspected compromise
# ============================================================================
#
# Scenario: Alice suspects her key may have been compromised. She:
#   1. Rotates to a new identity (old key signs off on the new one)
#   2. Distributes the rotation certificate to her contacts
#   3. Contacts import the certificate and update their records
#   4. Future encryption uses Alice's new keys
#
# This demonstrates the cryptographic chain of custody: the rotation
# certificate is dual-signed by both old and new keys, so contacts can
# verify the transition is legitimate.

set -euo pipefail

ALICE_DIR=$(mktemp -d)
BOB_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$ALICE_DIR" "$BOB_DIR" "$WORK_DIR"' EXIT

export AEGISPQ_FAST_KDF=1

echo "=== Setup: Alice and Bob exchange keys ==="
echo ""

ALICE_JSON=$(echo -e "old-passphrase\nold-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" --json identity create --name "Alice")
ALICE_OLD_ID=$(echo "$ALICE_JSON" | jq -r '.id')

BOB_JSON=$(echo -e "bob-pass\nbob-pass" | \
  aegispq --data-dir "$BOB_DIR" --json identity create --name "Bob")
BOB_ID=$(echo "$BOB_JSON" | jq -r '.id')

# Exchange keys.
echo "old-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" identity export "$ALICE_OLD_ID" \
    --output "$WORK_DIR/alice-old.pub.apq"
echo "bob-pass" | \
  aegispq --data-dir "$BOB_DIR" identity export "$BOB_ID" \
    --output "$WORK_DIR/bob.pub.apq"

aegispq --data-dir "$BOB_DIR" contact import "$WORK_DIR/alice-old.pub.apq"
aegispq --data-dir "$ALICE_DIR" contact import "$WORK_DIR/bob.pub.apq"

echo "Alice's old ID: $ALICE_OLD_ID"
echo "Bob's ID:       $BOB_ID"

echo ""
echo "=== Alice suspects compromise and rotates her keys ==="
echo ""

# The rotation command:
#   - Creates a new identity with new keys
#   - Signs a rotation certificate with BOTH old and new keys
#   - Marks the old identity as rotated locally
ROTATE_JSON=$(echo -e "old-passphrase\nnew-passphrase\nnew-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" --json identity rotate "$ALICE_OLD_ID" \
    --output "$WORK_DIR/alice.rot.apq")
ALICE_NEW_ID=$(echo "$ROTATE_JSON" | jq -r '.new_id')

echo "Alice rotated:"
echo "  Old ID: $ALICE_OLD_ID"
echo "  New ID: $ALICE_NEW_ID"
echo "  Certificate: $WORK_DIR/alice.rot.apq"

echo ""
echo "=== Bob imports the rotation certificate ==="
echo ""

# Bob's software verifies both signatures on the certificate, then:
#   - Adds the new identity as an active contact
#   - Marks the old identity as rotated
aegispq --data-dir "$BOB_DIR" contact import-rotation "$WORK_DIR/alice.rot.apq"

echo ""
echo "=== Verify: Bob's contact list shows the transition ==="
echo ""

aegispq --data-dir "$BOB_DIR" --json contact list | jq '.contacts'

echo ""
echo "=== Bob encrypts to Alice's NEW identity ==="
echo ""

echo "Welcome back, Alice! Here is the updated report." > "$WORK_DIR/reply.txt"

echo "bob-pass" | \
  aegispq --data-dir "$BOB_DIR" encrypt \
    --file "$WORK_DIR/reply.txt" \
    --to "$ALICE_NEW_ID" \
    --identity "$BOB_ID" \
    --output "$WORK_DIR/reply.txt.apq"

echo ""
echo "=== Alice decrypts with her new keys ==="
echo ""

echo "new-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" decrypt \
    --file "$WORK_DIR/reply.txt.apq" \
    --identity "$ALICE_NEW_ID" \
    --output "$WORK_DIR/reply-decrypted.txt"

echo ""
echo "Decrypted: $(cat "$WORK_DIR/reply-decrypted.txt")"

echo ""
echo "=== Verify: encrypting to the OLD identity fails ==="
echo ""

if echo "bob-pass" | \
  aegispq --data-dir "$BOB_DIR" encrypt \
    --file "$WORK_DIR/reply.txt" \
    --to "$ALICE_OLD_ID" \
    --identity "$BOB_ID" \
    --output "$WORK_DIR/should-fail.apq" 2>/dev/null; then
  echo "UNEXPECTED: encryption to rotated identity should have failed"
  exit 1
else
  echo "CORRECT: encryption to rotated identity was rejected (exit code $?)"
fi

echo ""
echo "SUCCESS: Key rotation completed. Old keys retired, new keys in use."
