#!/usr/bin/env bash
# ============================================================================
# Example: Group encryption with a recipients file
# ============================================================================
#
# A team lead encrypts a document for multiple recipients using a
# recipients file. This pattern is useful for CI pipelines and scripts
# that encrypt artifacts for a fixed set of team members.
#
# The recipients file format is simple: one hex identity ID per line.
# Lines starting with # are comments. Blank lines are ignored.

set -euo pipefail

LEAD_DIR=$(mktemp -d)
MEMBER1_DIR=$(mktemp -d)
MEMBER2_DIR=$(mktemp -d)
MEMBER3_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$LEAD_DIR" "$MEMBER1_DIR" "$MEMBER2_DIR" "$MEMBER3_DIR" "$WORK_DIR"' EXIT

export AEGISPQ_FAST_KDF=1

echo "=== Create identities ==="
echo ""

create_identity() {
  local dir=$1 name=$2 pass=$3
  local json
  json=$(echo -e "${pass}\n${pass}" | \
    aegispq --data-dir "$dir" --json identity create --name "$name")
  echo "$json" | jq -r '.id'
}

LEAD_ID=$(create_identity "$LEAD_DIR" "Team Lead" "lead-pass")
M1_ID=$(create_identity "$MEMBER1_DIR" "Alice" "alice-pass")
M2_ID=$(create_identity "$MEMBER2_DIR" "Bob" "bob-pass")
M3_ID=$(create_identity "$MEMBER3_DIR" "Carol" "carol-pass")

echo "Lead:  $LEAD_ID"
echo "Alice: $M1_ID"
echo "Bob:   $M2_ID"
echo "Carol: $M3_ID"

echo ""
echo "=== Exchange key packages ==="
echo ""

export_and_import() {
  local from_dir=$1 from_id=$2 from_pass=$3 to_dir=$4 pkg_path=$5
  echo "$from_pass" | \
    aegispq --data-dir "$from_dir" identity export "$from_id" --output "$pkg_path"
  aegispq --data-dir "$to_dir" contact import "$pkg_path"
}

# Lead needs all members as contacts.
export_and_import "$MEMBER1_DIR" "$M1_ID" "alice-pass" "$LEAD_DIR" "$WORK_DIR/alice.pub.apq"
export_and_import "$MEMBER2_DIR" "$M2_ID" "bob-pass" "$LEAD_DIR" "$WORK_DIR/bob.pub.apq"
export_and_import "$MEMBER3_DIR" "$M3_ID" "carol-pass" "$LEAD_DIR" "$WORK_DIR/carol.pub.apq"

# All members need the lead as contact (to verify sender on decrypt).
echo "lead-pass" | \
  aegispq --data-dir "$LEAD_DIR" identity export "$LEAD_ID" --output "$WORK_DIR/lead.pub.apq"
for dir in "$MEMBER1_DIR" "$MEMBER2_DIR" "$MEMBER3_DIR"; do
  aegispq --data-dir "$dir" contact import "$WORK_DIR/lead.pub.apq"
done

echo ""
echo "=== Create recipients file ==="
echo ""

cat > "$WORK_DIR/team-recipients.txt" <<EOF
# Project X team recipients
# Updated: $(date -u +%Y-%m-%d)
$M1_ID
$M2_ID
$M3_ID
EOF

echo "Recipients file:"
cat "$WORK_DIR/team-recipients.txt"

echo ""
echo "=== Encrypt document for the team ==="
echo ""

echo "Q4 revenue projections: confidential" > "$WORK_DIR/report.txt"

echo "lead-pass" | \
  aegispq --data-dir "$LEAD_DIR" encrypt \
    --file "$WORK_DIR/report.txt" \
    --recipients-file "$WORK_DIR/team-recipients.txt" \
    --identity "$LEAD_ID" \
    --output "$WORK_DIR/report.txt.apq"

echo ""
echo "=== Each member decrypts ==="
echo ""

for name_dir_id_pass in "Alice:$MEMBER1_DIR:$M1_ID:alice-pass" \
                         "Bob:$MEMBER2_DIR:$M2_ID:bob-pass" \
                         "Carol:$MEMBER3_DIR:$M3_ID:carol-pass"; do
  IFS=':' read -r name dir id pass <<< "$name_dir_id_pass"
  out="$WORK_DIR/${name}-decrypted.txt"
  echo "$pass" | \
    aegispq --data-dir "$dir" decrypt \
      --file "$WORK_DIR/report.txt.apq" \
      --identity "$id" \
      --output "$out"
  echo "  $name got: $(cat "$out")"
done

echo ""
echo "SUCCESS: All team members decrypted the document."
