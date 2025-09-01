#!/usr/bin/env bash
set -euo pipefail

echo "🔨 Building packed binary samples..."

if ! command -v upx >/dev/null 2>&1; then
  echo "✗ upx not found on PATH. Please install UPX (https://upx.github.io)." >&2
  exit 1
fi

echo "✓ Found UPX version: $(upx --version | head -n1)"

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_BASE="$ROOT_DIR/binaries/platforms/linux/amd64/export"
OUT_DIR="$ROOT_DIR/packed"
mkdir -p "$OUT_DIR"

pack_one() {
  local src="$1"
  local base
  base="$(basename "$src")"
  local out="$OUT_DIR/${base}.upx9"
  echo -n "  Packing with UPX -9: $base -> $(basename "$out")... "
  if upx -9 -o "$out" "$src" >/dev/null 2>&1; then
    if [[ -f "$out" ]]; then
      local sz_in sz_out
      sz_in=$(stat -c %s "$src" 2>/dev/null || echo 0)
      sz_out=$(stat -c %s "$out" 2>/dev/null || echo 0)
      echo "✓"
      echo "    Size: $sz_in -> $sz_out bytes ($(( (10000 - (sz_out*10000/(sz_in>0?sz_in:1))) / 100 )).$(( (10000 - (sz_out*10000/(sz_in>0?sz_in:1))) % 100 ))% reduction)"
    else
      echo "✗ (no output produced)"
    fi
  else
    echo "✗ (unsupported or failed)"
  fi
}

echo
echo "📦 Packing Linux x86_64 binaries..."
if [[ -d "$SRC_BASE" ]]; then
  shopt -s nullglob
  while IFS= read -r -d '' f; do
    pack_one "$f"
  done < <(find "$SRC_BASE" -type f -perm -u+x -size +16k -print0 | head -z -n 10)
  shopt -u nullglob
else
  echo "  (No source directory at $SRC_BASE; skipping)"
fi

echo "Done. Output in $OUT_DIR"

