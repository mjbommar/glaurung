#!/usr/bin/env bash
# Rebuild newlib_subset.thumb-v7e-m-fp-hard.a from the ARM GNU Toolchain.
#
# Run only when deliberately refreshing this fixture. Requires the toolchain
# at $GLAURUNG_ARMTC (see docs/development/corpora.md).
set -euo pipefail

: "${GLAURUNG_ARMTC:?set GLAURUNG_ARMTC to an arm-gnu-toolchain-*-arm-none-eabi root}"
AR="$GLAURUNG_ARMTC/bin/arm-none-eabi-ar"
LIBC="$GLAURUNG_ARMTC/arm-none-eabi/lib/thumb/v7e-m+fp/hard/libc.a"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"

"$AR" x "$LIBC" libc_a-tolower.o libc_a-toupper.o libc_a-memset.o

out="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/newlib_subset.thumb-v7e-m-fp-hard.a"
rm -f "$out"
"$AR" rcs "$out" libc_a-tolower.o libc_a-toupper.o libc_a-memset.o
sha256sum "$out"
