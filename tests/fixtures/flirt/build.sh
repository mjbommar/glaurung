#!/usr/bin/env bash
# Build the two linked images that prove a masked signature survives relinking.
#
# Both link the SAME committed archive,
# `samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a`, and
# differ in every way a link can differ: PIE vs non-PIE, a different amount of
# driver code ahead of the archive's text, and a different subset of entry
# points called. The archive's `mathlib_*` functions therefore land at
# different addresses with different resolved displacements in the two images,
# which is exactly the condition an exact-byte signature cannot survive.
#
# The outputs are COMMITTED, not generated at test time: the test must be able
# to run on a machine with no compiler, and the two images must not silently
# change identity when someone's gcc is upgraded. Re-run this only when
# deliberately refreshing the fixture, and record the new toolchain in
# README.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
archive="$repo/samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
headers="$repo/samples/source/library"

if [[ ! -f "$archive" ]]; then
    echo "missing $archive" >&2
    exit 1
fi

# Deterministic-as-we-can-make-it: no build ID, no timestamps in the output.
common=(-O2 -g0 -I"$headers" -Wl,--build-id=none)

gcc "${common[@]}" -fPIE -pie \
    -o "$here/mathlib_link_a.x86_64.elf" "$here/driver_a.c" "$archive" -lm

gcc "${common[@]}" -fno-PIE -no-pie \
    -o "$here/mathlib_link_b.x86_64.elf" "$here/driver_b.c" "$archive" -lm

# A stripped copy of link A. The signature library's real job is naming
# functions in a binary with no symbol table, and that cannot be tested on a
# binary that has one.
cp "$here/mathlib_link_a.x86_64.elf" "$here/mathlib_link_a.stripped.x86_64.elf"
strip --strip-all "$here/mathlib_link_a.stripped.x86_64.elf"

echo "toolchain: $(gcc --version | head -1)"
echo "ld:        $(ld --version | head -1)"
for f in mathlib_link_a.x86_64.elf mathlib_link_b.x86_64.elf \
         mathlib_link_a.stripped.x86_64.elf; do
    echo "$f $(sha256sum "$here/$f" | cut -d' ' -f1)"
done
