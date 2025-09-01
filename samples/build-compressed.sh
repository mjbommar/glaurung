#!/usr/bin/env bash
set -euo pipefail

# Build compressed and archived samples from existing sample binaries.
# This helps exercise container/compression detection without external downloads.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$ROOT_DIR/containers"
SRC_DIR="$ROOT_DIR/binaries/platforms/linux/amd64/export/native/gcc/O0"

mkdir -p "$OUT_DIR/zip" "$OUT_DIR/tar" "$OUT_DIR/gzip" "$OUT_DIR/xz" "$OUT_DIR/bzip2" "$OUT_DIR/zstd"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "Source binaries not found at $SRC_DIR; adjust SRC_DIR in this script to a valid sample folder." >&2
  exit 0
fi

# Pick a small representative binary
BIN="$(find "$SRC_DIR" -maxdepth 1 -type f | head -n1 || true)"
if [[ -z "$BIN" ]]; then
  echo "No binaries found in $SRC_DIR" >&2
  exit 0
fi

BASENAME="$(basename "$BIN")"
cp "$BIN" "$OUT_DIR/$BASENAME"

echo "Building containers from: $BIN"

# zip
if command -v zip >/dev/null 2>&1; then
  (cd "$OUT_DIR/zip" && cp "$BIN" . && zip -q "${BASENAME}.zip" "$BASENAME" && rm -f "$BASENAME") || true
else
  echo "zip not found; skipping zip sample" >&2
fi

# tar
if command -v tar >/dev/null 2>&1; then
  (cd "$OUT_DIR/tar" && cp "$BIN" . && tar -cf "${BASENAME}.tar" "$BASENAME" && rm -f "$BASENAME") || true
else
  echo "tar not found; skipping tar sample" >&2
fi

# gzip
if command -v gzip >/dev/null 2>&1; then
  cp "$BIN" "$OUT_DIR/gzip/${BASENAME}"
  (cd "$OUT_DIR/gzip" && gzip -f "$BASENAME") || true
else
  echo "gzip not found; skipping gzip sample" >&2
fi

# xz
if command -v xz >/dev/null 2>&1; then
  cp "$BIN" "$OUT_DIR/xz/${BASENAME}"
  (cd "$OUT_DIR/xz" && xz -f "$BASENAME") || true
else
  echo "xz not found; skipping xz sample" >&2
fi

# bzip2
if command -v bzip2 >/dev/null 2>&1; then
  cp "$BIN" "$OUT_DIR/bzip2/${BASENAME}"
  (cd "$OUT_DIR/bzip2" && bzip2 -f "$BASENAME") || true
else
  echo "bzip2 not found; skipping bzip2 sample" >&2
fi

# zstd
if command -v zstd >/dev/null 2>&1; then
  cp "$BIN" "$OUT_DIR/zstd/${BASENAME}"
  (cd "$OUT_DIR/zstd" && zstd -q -f "$BASENAME") || true
else
  echo "zstd not found; skipping zstd sample" >&2
fi

echo "Done. Output under $OUT_DIR"

