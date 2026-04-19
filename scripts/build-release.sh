#!/usr/bin/env bash
# ============================================================================
# Build release binaries for AegisPQ
# ============================================================================
#
# Usage:
#   ./scripts/build-release.sh              # build for current platform
#   ./scripts/build-release.sh --install    # build and install to ~/.cargo/bin
#
# Output: target/release/aegispq
#
# The release profile is tuned for cryptographic correctness:
#   - opt-level 2 (avoid timing-variant aggressive optimizations)
#   - LTO enabled (cross-crate inlining of crypto operations)
#   - Single codegen unit (consistent optimization)
#   - Overflow checks enabled
#   - Debug symbols stripped

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "Building AegisPQ release binary..."
echo ""

if [[ "${1:-}" == "--install" ]]; then
    cargo install --path crates/aegispq-cli --force
    echo ""
    echo "Installed: $(which aegispq 2>/dev/null || echo '~/.cargo/bin/aegispq')"
    aegispq --version
else
    cargo build --release -p aegispq-cli
    BINARY="target/release/aegispq"
    SIZE=$(ls -lh "$BINARY" | awk '{print $5}')
    echo ""
    echo "Built: $BINARY ($SIZE)"
    echo ""
    echo "To install system-wide:"
    echo "  sudo cp $BINARY /usr/local/bin/"
    echo ""
    echo "Or install via cargo:"
    echo "  cargo install --path crates/aegispq-cli"
fi
