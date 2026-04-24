#!/usr/bin/env bash
# Build minimal Mach-O samples for testing the Mach-O stubs resolver.
# Requires: clang, ld64.lld, llvm-otool (for verification).
# Produces:
#   samples/binaries/platforms/darwin/amd64/export/native/multi_import-macho
#
# No macOS SDK is needed — we use `-nostdinc` and `-undefined dynamic_lookup`
# so undefined externals are resolved lazily by dyld at runtime.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/samples/binaries/platforms/darwin/amd64/export/native"
SRC_DIR="$ROOT/samples/source"

mkdir -p "$OUT_DIR" "$SRC_DIR"

build_macho() {
    local name="$1" src="$2"
    local obj="$ROOT/target/macho-obj-$name.o"
    mkdir -p "$(dirname "$obj")"
    clang -target x86_64-apple-darwin -nostdinc -c "$src" -o "$obj"
    ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 \
        -undefined dynamic_lookup -o "$OUT_DIR/$name" "$obj"
    rm -f "$obj"
    echo "built $OUT_DIR/$name"
}

build_macho "multi_import-macho" "$SRC_DIR/multi_import.c"

echo
echo "Verify stubs with:"
echo "  llvm-otool -Iv $OUT_DIR/multi_import-macho"
