#!/usr/bin/env bash
set -euo pipefail

echo "[lint-rust] Checking formatting and clippy warnings"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Install Rust toolchain (rustup)." >&2
  exit 127
fi

# Verify formatting
cargo fmt --all -- --check

# Lint with clippy and deny warnings
cargo clippy --all-targets --all-features -- -D warnings

