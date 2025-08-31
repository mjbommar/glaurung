#!/usr/bin/env bash
set -euo pipefail

echo "[format-rust] Running cargo fmt"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Install Rust toolchain (rustup)." >&2
  exit 127
fi

exec cargo fmt --all "$@"

