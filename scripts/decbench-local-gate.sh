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
# The harness shells out to `glaurung`, so this script used to require an
# ACTIVATED venv and otherwise died with `FileNotFoundError: 'glaurung'` — an
# environment problem wearing a harness bug's clothes. Put the venv first
# ourselves; `tools/build_guard.py` resolves the same binary the same way for
# anything invoked outside this script.
if [ -x "$PWD/.venv/bin/glaurung" ]; then
  PATH="$PWD/.venv/bin:$PATH"
  export PATH
fi
# The execution differential needs a writable tmpdir it can exec from; some hosts
# mount /tmp noexec. Previously this only printed a note and then failed obscurely.
: "${GLAURUNG_FIXTURE_TMPDIR:=$PWD/target/fixture-tmp}"
mkdir -p "$GLAURUNG_FIXTURE_TMPDIR"
export GLAURUNG_FIXTURE_TMPDIR
# Nothing below means anything if the extension predates the Rust it is meant to
# be testing. One stat, and it has already cost a full gate cycle once.
if ! python tools/build_guard.py >/dev/null; then
  python tools/build_guard.py
  echo "HEAVY GATE: refusing to run against a stale build"
  exit 1
fi
# Default to the durable DecBench checkout. It previously lived in a per-session
# scratchpad, so DECBENCH_DIR came up unset, lane 3 skipped on every run, and ~25
# metric cells regressed unnoticed across a whole session. Defaulting it means the
# normal path needs no environment setup at all.
: "${DECBENCH_DIR:=/nas4/data/workspace-infosec/decbench}"
export CARGO_TARGET_DIR GLAURUNG_FIXTURE_JOBS DECBENCH_DIR NO_COLOR=1 TERM=dumb
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
note "exec tmpdir: $GLAURUNG_FIXTURE_TMPDIR"
if python -m pytest -p no:cacheprovider -m slow -q \
     python/tests/test_decompiler_fixture_matrix.py \
     python/tests/test_decompiler_fixture_structural.py 2>&1 | tail -6; then
  note "ok"
else
  note "FAILED"; fail=1
fi

# Lane 3 is the ONLY lane that scores GED / type_match / byte_match. It used to print
# "Skipping is a gap, not a pass" and then exit 0 — which is how a session's worth of
# semantic changes regressed ~25 of 56 cells with a green gate. A gate that can pass
# while its only metric lane is absent is not a gate, so absence is now a FAILURE.
#
# It costs ~37 minutes (56 cells, each spawning a Joern JVM to compute the graph edit
# distance), which is exactly why it is tempting to skip and exactly why the skip must
# not be silent. Set GLAURUNG_ALLOW_NO_METRICS=1 to waive it deliberately; the waiver
# is then reported in the FINAL line rather than mid-output where it scrolls past.
step "3/3  decbench per-cell metric ratchet"
waived=""
if [ ! -d "$DECBENCH_DIR" ]; then
  note "DECBENCH_DIR does not exist: $DECBENCH_DIR"
  note "This lane compares all 56 (program, compiler, opt) cells against"
  note "tests/decbench_corpus/baseline.json and is the only gate that catches a"
  note "metric regression. Without it, 'green' means 'no BEHAVIOURAL regression' only."
  if [ -n "${GLAURUNG_ALLOW_NO_METRICS:-}" ]; then
    note "WAIVED by GLAURUNG_ALLOW_NO_METRICS."
    waived="yes"
  else
    note "FAILING: a missing metric lane is a gap, not a pass."
    note "Set GLAURUNG_ALLOW_NO_METRICS=1 only if you accept shipping unmeasured."
    fail=1
  fi
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
if [ -n "$waived" ]; then
  echo "HEAVY GATE: passed WITHOUT METRICS (waived) — behavioural only, GED unverified"
  exit 0
fi
echo "HEAVY GATE: passed (all three lanes ran)"
