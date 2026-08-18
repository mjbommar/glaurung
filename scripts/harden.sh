#!/usr/bin/env bash
set -euo pipefail

echo "[harden] Formatting + linting Rust and Python, then type checking"

# Rust format + lint
if command -v cargo >/dev/null 2>&1; then
  echo "[harden] Rust: cargo fmt"
  cargo fmt --all
  # `--all-features` turns on `solver-bitwuzla`, whose build script used to panic
  # whenever Bitwuzla was absent -- so this command died in the build script, on
  # every machine without Bitwuzla installed, before clippy saw a single line.
  # That is why it never caught the three solver backends that stopped compiling
  # on 2026-07-31. `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1` makes build.rs skip the
  # link setup; clippy, like `cargo check`, never links.
  export GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1
  echo "[harden] Rust: cargo clippy (-D warnings)"
  cargo clippy --all-targets --all-features -- -D warnings
else
  echo "[harden] Skip Rust checks: cargo not found"
fi

# Python format + lint + types
if command -v uvx >/dev/null 2>&1; then
  echo "[harden] Python: ruff format"
  uvx ruff format python/
  echo "[harden] Python: ruff check --fix"
  uvx ruff check python/ --fix
  echo "[harden] Python: ty check"
  uvx ty check python/
else
  echo "[harden] Skip Python checks: uvx not found"
fi

echo "[harden] Completed."

