#!/usr/bin/env bash
# ============================================================================
# Example: Alice and Bob exchange encrypted files
# ============================================================================
#
# This script demonstrates the complete lifecycle:
#   1. Alice and Bob each create an identity
#   2. They exchange key packages (public keys)
#   3. Alice encrypts a file for Bob
#   4. Bob decrypts it and verifies Alice's signature
#   5. Bob signs a reply
#
# Prerequisites: aegispq binary in PATH (cargo install --path crates/aegispq-cli)
#
# For automated testing, set AEGISPQ_FAST_KDF=1 to skip slow key derivation.
# NEVER use this in production.

set -euo pipefail

# Use temporary directories to simulate separate machines.
ALICE_DIR=$(mktemp -d)
BOB_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$ALICE_DIR" "$BOB_DIR" "$WORK_DIR"' EXIT

export AEGISPQ_FAST_KDF=1  # Remove this line for production use

echo "=== Step 1: Create identities ==="
echo ""

ALICE_JSON=$(echo -e "alice-passphrase\nalice-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" --json identity create --name "Alice")
ALICE_ID=$(echo "$ALICE_JSON" | jq -r '.id')
echo "Alice's identity: $ALICE_ID"

BOB_JSON=$(echo -e "bob-passphrase\nbob-passphrase" | \
  aegispq --data-dir "$BOB_DIR" --json identity create --name "Bob")
BOB_ID=$(echo "$BOB_JSON" | jq -r '.id')
echo "Bob's identity:   $BOB_ID"

echo ""
echo "=== Step 2: Exchange key packages ==="
echo ""

# Alice exports her public key.
echo "alice-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" identity export "$ALICE_ID" \
    --output "$WORK_DIR/alice.pub.apq"

# Bob exports his public key.
echo "bob-passphrase" | \
  aegispq --data-dir "$BOB_DIR" identity export "$BOB_ID" \
    --output "$WORK_DIR/bob.pub.apq"

# Alice imports Bob's key package.
aegispq --data-dir "$ALICE_DIR" contact import "$WORK_DIR/bob.pub.apq"

# Bob imports Alice's key package.
aegispq --data-dir "$BOB_DIR" contact import "$WORK_DIR/alice.pub.apq"

echo ""
echo "=== Step 3: Alice encrypts a file for Bob ==="
echo ""

echo "This is a secret message from Alice to Bob." > "$WORK_DIR/message.txt"

echo "alice-passphrase" | \
  aegispq --data-dir "$ALICE_DIR" encrypt \
    --file "$WORK_DIR/message.txt" \
    --to "$BOB_ID" \
    --identity "$ALICE_ID" \
    --output "$WORK_DIR/message.txt.apq"

echo ""
echo "=== Step 4: Bob decrypts the file ==="
echo ""

echo "bob-passphrase" | \
  aegispq --data-dir "$BOB_DIR" decrypt \
    --file "$WORK_DIR/message.txt.apq" \
    --identity "$BOB_ID" \
    --output "$WORK_DIR/message-decrypted.txt"

echo ""
echo "=== Verification ==="
echo ""
echo "Original:  $(cat "$WORK_DIR/message.txt")"
echo "Decrypted: $(cat "$WORK_DIR/message-decrypted.txt")"

if diff -q "$WORK_DIR/message.txt" "$WORK_DIR/message-decrypted.txt" > /dev/null 2>&1; then
  echo ""
  echo "SUCCESS: Files match. Encryption roundtrip verified."
else
  echo ""
  echo "FAILURE: Files do not match!"
  exit 1
fi
