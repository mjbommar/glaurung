#!/usr/bin/env bash
# Rebuild the Android packed-relocation test fixtures.
#
# Produces AArch64 shared objects whose dynamic relocations are compressed with
# bionic's packing schemes, plus an unpacked reference. Requires an aarch64
# cross toolchain and lld (ships with LLVM):
#
#   sudo apt install gcc-aarch64-linux-gnu lld clang
#
# The .so files are checked in so `cargo test` runs without a cross toolchain;
# re-run this only when regenerating them.
set -euo pipefail
cd "$(dirname "$0")"

CC=${CC:-aarch64-linux-gnu-gcc}
CFLAGS="-shared -fPIC -O2 -fuse-ld=lld"

# APS2-packed .rela.dyn (DT_ANDROID_RELA).
$CC $CFLAGS -Wl,--pack-dyn-relocs=android -o packed_android.so relocs.c
# RELR relative relocations (DT_RELR) + a plain .rela.dyn for the rest.
$CC $CFLAGS -Wl,--pack-dyn-relocs=relr -o packed_relr.so relocs.c
# Unpacked reference (plain DT_RELA), for comparison/debugging.
$CC $CFLAGS -Wl,--pack-dyn-relocs=none -o unpacked.so relocs.c

echo "built: packed_android.so packed_relr.so unpacked.so"
