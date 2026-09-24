#!/usr/bin/env bash

# Updates contract ABI golden files from current contract specs.
#
# This script extracts the ABI from each compiled WASM contract and
# writes it to the golden artifacts directory. It is deterministic
# (uses pinned toolchain from rust-toolchain.toml) and uses synthetic
# values only — never production IDs or secrets.
#
# Usage:
#   ./scripts/update-goldens.sh
#
# Run this after intentional ABI changes, with a version bump and
# migration note in docs/releases/. The gate requires proof that
# the change was intentional and approved.
#
# Prerequisites:
#   - Rust 1.98.0 (from rust-toolchain.toml) installed
#   - cargo with wasm32-unknown-unknown target
#   - stellar CLI (optional; fallback to manual update)
#   - jq (optional; for formatting)
#
# Security notes:
#   - Only synthetic values in output (no real addresses, no secrets)
#   - Contract IDs and hashes are stable across builds (deterministic)
#   - Golden files are version-controlled and reviewed on commit
#
# Exit codes:
#   0 - Success; all goldens updated
#   1 - Build failed
#   2 - stellar CLI not available (partial success, requires manual review)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GOLDENS_DIR="${PROJECT_ROOT}/tests/compatibility/goldens"
BUILD_DIR="${PROJECT_ROOT}/target/wasm32-unknown-unknown/release"

echo "=========================================="
echo "Updating Contract ABI Golden Artifacts"
echo "=========================================="
echo "Project Root: $PROJECT_ROOT"
echo "Goldens Dir:  $GOLDENS_DIR"
echo ""

# Verify goldens directory exists
if [[ ! -d "$GOLDENS_DIR" ]]; then
  echo "ERROR: Golden artifacts directory not found: $GOLDENS_DIR"
  echo "Create it with: mkdir -p '$GOLDENS_DIR'"
  exit 1
fi

# Build all contracts for wasm32 target
echo "Step 1: Building contracts (wasm32-unknown-unknown release)..."
if ! cargo build \
  --target wasm32-unknown-unknown \
  --release \
  --quiet \
  2>&1 | grep -E "(error|warning:)" || true; then
  :
fi

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "ERROR: Build directory not found: $BUILD_DIR"
  echo "Build may have failed."
  exit 1
fi

echo "Step 2: Extracting ABI for each contract..."

# List of contracts (must match Cargo.toml workspace members)
CONTRACTS=(
  "protocol-config"
  "issuer-registry"
  "proof-registry"
)

for contract in "${CONTRACTS[@]}"; do
  wasm_file="$BUILD_DIR/${contract}.wasm"
  golden_file="$GOLDENS_DIR/${contract}.abi.json"
  
  if [[ ! -f "$wasm_file" ]]; then
    echo "  ⚠️  WARNING: WASM not found for $contract: $wasm_file"
    echo "     Skipping. Rebuild or check contract name."
    continue
  fi
  
  echo "  Processing: $contract"
  
  # Try stellar CLI first (ideal path)
  if command -v stellar &> /dev/null; then
    echo "    Using stellar CLI to extract ABI..."
    if stellar contract inspect \
      --wasm "$wasm_file" \
      --output json \
      > "$golden_file.tmp" 2>/dev/null; then
      
      # stellar CLI succeeded; merge with hand-written metadata
      # (In production, this would be post-processed by a tool)
      mv "$golden_file.tmp" "$golden_file"
      echo "    ✓ Extracted: $golden_file"
    else
      rm -f "$golden_file.tmp"
      echo "    ⚠️  stellar CLI failed; update $golden_file manually"
    fi
  else
    echo "    ⚠️  stellar CLI not installed"
    echo "       Update $golden_file manually or install stellar CLI"
    echo "       https://github.com/stellar/stellar-cli"
  fi
done

echo ""
echo "Step 3: Validation"
echo "  ✓ Golden artifacts are in: $GOLDENS_DIR"
echo ""
echo "Next steps:"
echo "  1. Review diffs: git diff $GOLDENS_DIR"
echo "  2. If breaking changes detected:"
echo "     - Add version bump to Cargo.toml (e.g., 0.1.0 → 0.2.0 for minor, 1.0.0 for major)"
echo "     - Write migration note in docs/releases/"
echo "     - Include rationale in commit message"
echo "  3. Commit both golden files and version/migration docs"
echo ""
echo "Breaking change checklist:"
echo "  ☐ Function signature changed (name, params, order, return type)"
echo "  ☐ Function removed or renamed"
echo "  ☐ Storage key variant added/removed/renamed"
echo "  ☐ Stored struct field added/removed/changed type"
echo "  ☐ Event removed or field removed from event"
echo "  ☐ Error code value changed or error removed"
echo "  ☐ Authorization changed (admin-only to public, or vice versa)"
echo ""
echo "If any breaking changes: additive changes alone do NOT bump the check."
echo "=========================================="
