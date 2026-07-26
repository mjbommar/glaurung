#!/usr/bin/env bash
# The heavy decompiler gates, in one place.
#
# Hosted CI runs the light lanes; these three are too slow or need tools the
# runners do not have, so they live here and are expected before a push that
# touches decompilation:
#
#   1. cargo test           — fast, and the only lane that gates the Rust logic
#   2. fixture matrix       — execution-differential, 4 lanes, ~3 min with jobs
#   3. decbench matrix      — per-cell metric ratchet; needs the DecBench fork
#
# Lane 3 is skipped with a clear message when DECBENCH_DIR is unset, because it
# cannot run without `decbench evaluate`. It is skipped LOUDLY: a silently absent
# gate is how a metric regression reaches a submission.
set -uo pipefail

cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:=$PWD/target}"
: "${GLAURUNG_FIXTURE_JOBS:=4}"
export CARGO_TARGET_DIR GLAURUNG_FIXTURE_JOBS NO_COLOR=1 TERM=dumb
unset FORCE_COLOR

fail=0
step() { printf '\n=== %s ===\n' "$1"; }
note() { printf '  %s\n' "$1"; }

step "1/3  cargo test"
if cargo test --lib --tests 2>&1 | tail -3; then
  note "ok"
else
  note "FAILED"; fail=1
fi

step "2/3  decompiler fixture matrix + structural ratchet"
if [ -z "${GLAURUNG_FIXTURE_TMPDIR:-}" ]; then
  note "GLAURUNG_FIXTURE_TMPDIR unset — the harness needs a writable exec tmpdir"
fi
if python -m pytest -p no:cacheprovider -m slow -q \
     python/tests/test_decompiler_fixture_matrix.py \
     python/tests/test_decompiler_fixture_structural.py 2>&1 | tail -6; then
  note "ok"
else
  note "FAILED"; fail=1
fi

step "3/3  decbench per-cell metric ratchet"
if [ -z "${DECBENCH_DIR:-}" ]; then
  note "SKIPPED: DECBENCH_DIR is not set."
  note "This lane compares all 56 (program, compiler, opt) cells against"
  note "tests/decbench_corpus/baseline.json and is the only gate that would catch"
  note "a metric regression. Set DECBENCH_DIR to a DecBench checkout to run it."
  note "Skipping is a gap, not a pass."
elif tools/decbench_matrix.py --check 2>&1 | tail -12; then
  note "ok"
else
  note "FAILED"; fail=1
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
  echo "HEAVY GATE: FAILED"
  exit 1
fi
echo "HEAVY GATE: passed (see any SKIPPED notes above)"
