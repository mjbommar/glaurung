#!/usr/bin/env bash
# Build the two benchmark corpora and their list files.
#
#   build_corpus.sh <workdir>
#
# Tier A — ground truth. Nine Alpine 3.18 binaries (getconf/getent/iconv for
# x86-64, AArch64 and ARMv7) are the only samples in the tree that ship
# unstripped with DWARF. Each is copied and also stripped into a twin: stripping
# removes symbols but moves no code, so the original's DWARF still describes the
# stripped copy exactly. That pair is what separates *reading DWARF* from
# *inferring structure* — three of the four tools read it when it is there and
# score perfectly, so without the twin the benchmark measures almost nothing.
#
# Alpine 3.18 and not 3.19: `binaries-small/alpine3.19/linux-arm64/` is a
# byte-identical copy of its armv7 tree (same MD5, 32-bit ARM), so it contains
# no AArch64 binaries at all.
#
# Tier B — real-world at scale, scored against `.eh_frame` FDE starts.
set -u
BENCH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=${1:?usage: build_corpus.sh <workdir>}
SAMPLES=${EXTBENCH_SAMPLES:-/nas4/data/binary-analysis/glaurung/binaries-small}

if [ ! -d "$SAMPLES" ]; then
  echo "no sample tree at $SAMPLES (set EXTBENCH_SAMPLES)" >&2
  exit 1
fi

CORPUS="$WORK/corpus"
mkdir -p "$CORPUS"

# llvm-strip, not strip: the host binutils is x86-only and cannot strip the
# AArch64 or ARM binaries.
STRIP=${STRIP:-llvm-strip}
command -v "$STRIP" >/dev/null || { echo "need $STRIP on PATH" >&2; exit 1; }

echo "== Tier A: DWARF ground truth, sym/strip pairs =="
: > "$WORK/tierA.txt"
for arch in linux-amd64 linux-arm64 linux-arm-v7; do
  a=${arch#linux-}
  for prog in getconf getent iconv; do
    src="$SAMPLES/alpine3.18/$arch/usr-bin/$prog"
    [ -f "$src" ] || { echo "  missing $src"; continue; }
    cp "$src" "$CORPUS/sym_${prog}_${a}"
    cp "$src" "$CORPUS/strip_${prog}_${a}"
    "$STRIP" --strip-all "$CORPUS/strip_${prog}_${a}" 2>/dev/null \
      || { echo "  strip failed for $prog/$a"; continue; }
    echo "sym_${prog}_${a}|$CORPUS/sym_${prog}_${a}|dwarf|40|" >> "$WORK/tierA.txt"
    echo "strip_${prog}_${a}|$CORPUS/strip_${prog}_${a}|dwarf|40|$CORPUS/sym_${prog}_${a}" \
      >> "$WORK/tierA.txt"
    echo "  $prog/$a"
  done
done

echo "== Tier B: real-world stripped, .eh_frame ground truth =="
: > "$WORK/tierB.txt"
add_b() {  # tag  relative-path
  if [ -f "$SAMPLES/$2" ]; then
    echo "$1|$SAMPLES/$2|fde|40|" >> "$WORK/tierB.txt"
    echo "  $1"
  else
    echo "  missing $2"
  fi
}
add_b ub_cat        ubuntu24.04/linux-amd64/bin/cat
add_b ub_grep       ubuntu24.04/linux-amd64/bin/grep
add_b ub_find       ubuntu24.04/linux-amd64/bin/find
add_b ub_tar        ubuntu24.04/linux-amd64/bin/tar
add_b ub_bash       ubuntu24.04/linux-amd64/bin/bash
add_b deb_bash      debian-bookworm/linux-amd64/bin/bash
add_b ub_grep_arm64 ubuntu24.04/linux-arm64/bin/grep
# busybox and the ARMv7 grep carry no usable `.eh_frame` — busybox is built
# `-fno-asynchronous-unwind-tables` (4-byte section) and ARM uses `.ARM.exidx`
# instead. Both are listed so the skip is visible rather than silent; drive.py
# reports "no ground-truth functions" and moves on.
add_b alp_busybox   alpine3.19/linux-amd64/bin/busybox
add_b ub_grep_armv7 ubuntu24.04/linux-arm-v7/bin/grep

echo
echo "wrote $WORK/tierA.txt ($(wc -l < "$WORK/tierA.txt") entries)"
echo "wrote $WORK/tierB.txt ($(wc -l < "$WORK/tierB.txt") entries)"
echo
echo "next:  $BENCH/runall.sh $WORK/outA $WORK/tierA.txt"
echo "       $BENCH/runall.sh $WORK/outB $WORK/tierB.txt"
