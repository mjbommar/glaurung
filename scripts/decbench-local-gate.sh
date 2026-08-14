#!/usr/bin/env bash
# The heavy decompiler gates, in one place.
#
# Hosted CI runs the light lanes; these are too slow or need tools the runners
# do not have, so they live here and are expected before a push that touches
# decompilation.
#
# DEFAULT — our own fixture corpus, and nothing else:
#
#   1. cargo test           — fast, and the only lane that gates the Rust logic
#   2. fixture matrix       — execution-differential, x86-64, 4 lanes, ~3 min
#   3. arch round trip      — the SAME differential for aarch64 / armv7 / i386
#
# OPT-IN — DecBench, only when explicitly asked for (see below):
#
#   4. behavior matrices    — legacy + curriculum round trips, run concurrently
#   5. decbench matrix      — per-cell metric ratchet; needs the DecBench fork
#
# Lane 3 exists because every lane of lane 2 — all 656 cases — is x86-64. Two of
# the three lifted architecture families, and the 32-bit half of the third, had
# no execution coverage at all: a change inverting a branch in every ARM binary
# left the whole gate green. A missing cross compiler there is a FAILURE.
#
# Why 4 and 5 are opt-in
# ----------------------
# They are an EVALUATION harness, not a correctness gate. They spawn a Joern JVM
# per cell, take tens of minutes, and their failures are frequently about the
# harness rather than the decompiler: a run of this script had 11 cells report
# "build failed" in lane 5 that had built and executed successfully in lane 4
# minutes earlier, and re-ran clean in isolation. That is resource contention
# being reported as a product defect, and paying tens of minutes to be told it
# is the wrong trade for ordinary work.
#
# Lanes 1-3 are the ones that can actually prove a decompiler change is sound:
# they execute real recompiled output and diff it against the original.
#
# Run the DecBench lanes with EITHER:
#     scripts/decbench-local-gate.sh --decbench
#     GLAURUNG_RUN_DECBENCH=1 scripts/decbench-local-gate.sh
#
# Do that when the change could move a published metric (type/name recovery,
# structuring, output shaping) or before preparing a submission artifact. When
# they are skipped, the FINAL line says so — an absent metric lane must never
# read as a green metric lane.
set -uo pipefail

cd "$(dirname "$0")/.."

# DecBench lanes are opt-in. Accept a flag as well as the environment variable so
# neither an interactive run nor a script has to remember the other spelling.
: "${GLAURUNG_RUN_DECBENCH:=}"
for argument in "$@"; do
  case "$argument" in
    --decbench) GLAURUNG_RUN_DECBENCH=1 ;;
    --no-decbench) GLAURUNG_RUN_DECBENCH= ;;
    -h|--help)
      sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $argument" >&2
      echo "usage: $0 [--decbench|--no-decbench]" >&2
      exit 2
      ;;
  esac
done
if [ -n "$GLAURUNG_RUN_DECBENCH" ]; then
  lanes=5
else
  lanes=3
fi
: "${CARGO_TARGET_DIR:=$PWD/target}"
# Scale to the host instead of a hardcoded 4. These lanes are overwhelmingly
# CONTAINER-STARTUP bound, not CPU bound: `tools/fixture_toolchain.py` runs each
# compile as its own `docker run --rm`, measured at ~1.07 s against ~0.085 s for
# `docker exec` into a live container. Lane 2 issues roughly 3,300 of them (728
# fixture compiles plus 2,568 recompiles of decompiled C), i.e. ~59 minutes of
# pure container spawn, which is essentially the whole lane.
#
# Concurrency changes wall-clock, not verdicts — lanes are independent binaries
# with per-function workers and stable per-function fuzz seeds. It is capped
# below `nproc` on purpose: `fixture_harness.default_jobs` notes that
# oversubscribing can push a slow-but-correct decompilation past its worker
# wall-clock timeout, which would turn a scheduling artifact into a fake verdict.
: "${GLAURUNG_FIXTURE_JOBS:=$(( $(nproc 2>/dev/null || echo 4) * 2 / 3 ))}"
: "${GLAURUNG_DECBENCH_JOBS:=4}"
[ "$GLAURUNG_FIXTURE_JOBS" -lt 1 ] && GLAURUNG_FIXTURE_JOBS=1
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
# scratchpad, so DECBENCH_DIR came up unset, the DecBench lanes skipped on every
# run, and ~25 metric cells regressed unnoticed across a whole session. Defaulting
# it means the normal path needs no environment setup at all.
: "${DECBENCH_DIR:=/nas4/data/workspace-infosec/decbench}"
export CARGO_TARGET_DIR GLAURUNG_FIXTURE_JOBS GLAURUNG_DECBENCH_JOBS DECBENCH_DIR NO_COLOR=1 TERM=dumb
unset FORCE_COLOR

fail=0
step() { printf '\n=== %s ===\n' "$1"; }
note() { printf '  %s\n' "$1"; }

step "1/$lanes  cargo test"
if cargo test --lib --tests 2>&1 | tail -3; then
  note "ok"
else
  note "FAILED"; fail=1
fi

step "2/$lanes  decompiler fixture matrix + structural ratchet (x86-64)"
note "exec tmpdir: $GLAURUNG_FIXTURE_TMPDIR"
if python -m pytest -p no:cacheprovider -m slow -q \
     python/tests/test_decompiler_fixture_matrix.py \
     python/tests/test_decompiler_fixture_structural.py 2>&1 | tail -6; then
  note "ok"
else
  note "FAILED"; fail=1
fi

# Lane 2 is x86-64 in EVERY lane. This one is the only thing that executes a
# single instruction lifted by src/ir/lift_arm64.rs, src/ir/lift_arm32.rs, or the
# 32-bit half of src/ir/lift_x86.rs. It cross-builds the same 30-fixture corpus
# for four architectures and decompiles it. The LP64 lanes rebuild and execute
# portable C on the host. Supported i386/ARMv7 signatures instead rebuild both
# sides for their real ILP32 ABI and execute a generated comparator under a
# version-fingerprinted qemu runner; richer signatures retain the explicit
# host-width audit fallback. Returns and mutated buffers are compared in either
# mode, and a runner change invalidates the ratchet rather than silently
# redefining it.
#
# A missing cross compiler FAILS rather than skips, exactly like lane 5's absent
# metrics. Provision with:
#   sudo apt install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf gcc-multilib
step "3/$lanes  cross-architecture round trip (aarch64 / armv7 / i386 + control)"
if tools/arch_roundtrip.py --check 2>&1 | tail -40; then
  note "ok"
else
  note "FAILED"; fail=1
fi

if [ -z "$GLAURUNG_RUN_DECBENCH" ]; then
  printf '\n'
  if [ "$fail" -ne 0 ]; then
    echo "GATE: FAILED (fixture lanes 1-3)"
    exit 1
  fi
  echo "GATE: passed (fixture lanes 1-3) — DecBench lanes 4-5 NOT RUN"
  echo "      GED / type_match / byte_match are UNMEASURED by this run."
  echo "      Run with --decbench when a change could move a published metric."
  exit 0
fi

# Behavior and metrics are intentionally separate. Run the two disjoint semantic
# corpora concurrently: they use isolated cell directories and comparing original
# vs rebuilt execution does not need Joern. A green metric matrix cannot substitute
# for either of these source -> binary -> C -> rebuilt-binary checks.
step "4/$lanes  legacy + curriculum executable round trips"
if [ ! -d "$DECBENCH_DIR" ]; then
  note "DECBENCH_DIR does not exist: $DECBENCH_DIR"
  note "FAILED: the executable matrices require the DecBench Python environment."
  fail=1
else
  behavior_legacy=0
  behavior_curriculum=0
  tools/decbench_matrix.py --corpus decbench --behavior-only --backend glaurung &
  legacy_pid=$!
  tools/decbench_matrix.py --corpus curriculum --behavior-only --backend glaurung &
  curriculum_pid=$!
  wait "$legacy_pid" || behavior_legacy=$?
  wait "$curriculum_pid" || behavior_curriculum=$?
  if [ "$behavior_legacy" -eq 0 ] && [ "$behavior_curriculum" -eq 0 ]; then
    note "ok"
  else
    note "FAILED (legacy=$behavior_legacy curriculum=$behavior_curriculum)"
    fail=1
  fi
fi

# Lane 5 is the ONLY lane that scores GED / type_match / byte_match. It used to print
# "Skipping is a gap, not a pass" and then exit 0 — which is how a session's worth of
# semantic changes regressed ~25 of 56 cells with a green gate. A gate that can pass
# while its only metric lane is absent is not a gate, so absence is now a FAILURE.
#
# It historically cost ~37 minutes serially (56 cells, each spawning a Joern JVM to
# compute the graph edit distance). The matrix now uses four isolated workers by
# default, configurable with GLAURUNG_DECBENCH_JOBS. It is still expensive enough that
# a skip must not be silent. Set GLAURUNG_ALLOW_NO_METRICS=1 to waive it deliberately;
# the waiver is then reported in the FINAL line rather than mid-output where it scrolls
# past.
step "5/$lanes  decbench per-cell metric ratchet"
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
echo "HEAVY GATE: passed (all five lanes ran, DecBench included)"
