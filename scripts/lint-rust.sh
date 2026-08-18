#!/usr/bin/env bash
set -euo pipefail

echo "[lint-rust] Checking formatting and clippy warnings"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Install Rust toolchain (rustup)." >&2
  exit 127
fi

# Verify formatting
cargo fmt --all -- --check

# `--all-features` turns on `solver-bitwuzla`, whose build script used to panic
# whenever Bitwuzla was absent -- so this command died in the build script, on
# every machine without Bitwuzla installed, before clippy saw a single line.
# That is why it never caught the three solver backends that stopped compiling
# on 2026-07-31. `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1` makes build.rs skip the
# link setup; clippy, like `cargo check`, never links.
export GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1
# Lint with clippy and deny warnings
cargo clippy --all-targets --all-features -- -D warnings

