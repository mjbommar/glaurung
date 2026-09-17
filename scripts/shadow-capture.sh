#!/usr/bin/env bash
# The shadow-split capture tier (solver-034): find the next Axeyum-vs-z3
# divergence the week it appears, not two months later.
#
# Until 2026-09-17 the shadow-split corpus was produced by a command in a
# README. It was run in July, nobody ran it again, and the improvement list of
# 2026-09-16 found 735 exporter-defect scripts being quoted as solver misses
# two months on. A capture that nobody schedules is a capture that happens
# once.
#
# This script runs, in order, and reports every stage's finding before it
# exits (a stage that fails does not hide the stages after it):
#
#   1. build   `--release --example ioctlance --features solver-z3,solver-axeyum`
#   2. capture tools/axeyum/shadow_capture.py over the named drivers with the
#              named per-function ceiling, publishing every exactly-one-backend-
#              decided query into tests/corpora/axeyum-qfbv/shadow-splits/<capture>/
#              through the in-process atomic, z3-parse-checked publisher.
#              FAILS on a both-decided disagreement (bytes under disagreements/)
#              and on a malformed export (solver-016's class: the exporter's
#              bug); a run that issues no checks is not evidence and FAILS.
#   3. gate 1  tools/axeyum/split_verdicts.py: z3 classifies every script under
#              the live root and adds the new ones to verdicts.tsv as
#              `unmeasured`. A new split is reported by NAME and is not a
#              failure -- a capability gap is a finding.
#   4. replay  tests/axeyum_shadow_split_verdicts.rs: every script through the
#              PINNED axeyum-solver's SMT-LIB front door. FAILS on a decided
#              disagreement, and on any script whose committed Axeyum column
#              was decided that the pinned solver no longer decides -- the
#              regression floor (the 107 of solver-032, plus whatever later
#              captures promoted).
#   5. gate 2  split_verdicts.py --axeyum-results: folds the replay's verdicts
#              into verdicts.tsv, prints NEW / PROMOTED rows by name, and FAILS
#              on the same regression and opposition classes.
#
# What to commit after a green run: the new `<capture>/` directories (scripts
# are Git LFS objects; the TSV/JSON sidecars are plain text) and
# `shadow-splits/verdicts.tsv`. A red run commits nothing; the finding is in
# the output and in <out>/report.json.
#
# Usage:
#   scripts/shadow-capture.sh                       # the four July drivers, 60 s ceiling
#   scripts/shadow-capture.sh --ceiling 60 --driver samples/.../foo.sys [--driver ...]
#   scripts/shadow-capture.sh --binary target/release/examples/ioctlance   # skip the build
#   scripts/shadow-capture.sh --out DIR             # report.json, logs, replay TSV (default target/shadow-capture)
#   scripts/shadow-capture.sh --skip-replay         # stages 1-3 only (no solver-axeyum-text build)
#
# Sizing (solver-034): one driver at a 60 s ceiling is about `ceiling x
# dispatch roots` of wall time -- 59.5 s for DptfDevGen -- because warm Axeyum
# at the 2026-09-16 pin puts the root function into the budget (solver-033).
# The four July drivers are minutes; the replay of the pinned corpus is
# ~2-3 min in a debug build. This is a weekly job (.github/workflows/
# shadow-capture-weekly.yml), not a per-push gate.
#
# System dependencies: libz3 (apt: libz3-dev) for the solver-z3 build, a `z3`
# binary for split_verdicts.py, and the drivers as real bytes (they are Git
# LFS objects: `git lfs pull`, or `lfs: true` in a checkout action).
set -uo pipefail

cd "$(dirname "$0")/.."

ceiling=60
drivers=()
binary=""
out=""
skip_replay=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --ceiling) ceiling=$2; shift 2 ;;
    --driver) drivers+=("$2"); shift 2 ;;
    --binary) binary=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --skip-replay) skip_replay=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

: "${CARGO_TARGET_DIR:=$PWD/target}"
export CARGO_TARGET_DIR NO_COLOR=1 TERM=dumb
out=${out:-$CARGO_TARGET_DIR/shadow-capture}
mkdir -p "$out"
root=tests/corpora/axeyum-qfbv/shadow-splits

if [ ${#drivers[@]} -eq 0 ]; then
  # ADR-0272's four drivers, the ones every timing campaign has used.
  drivers=(
    samples/binaries/platforms/windows/vendor/realworld/sqfs-intel-DptfDevGen.sys
    samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys
    samples/binaries/platforms/windows/vendor/realworld/windows-update-intel-audio-IntcSST.sys
    "surfacepen=samples/binaries/platforms/windows/vendor/realworld/windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"
  )
fi

if command -v uv >/dev/null 2>&1; then
  python=(uv run python)
else
  python=(python3)
fi

step() { printf '\n=== %s ===\n' "$1"; }
fail=0
findings=()
finding() { findings+=("$1"); fail=1; echo "shadow-capture: FAIL: $1" >&2; }

# A Git LFS pointer is ~130 bytes of text beginning with this line. Measuring
# one as a driver "succeeds" with zero checks; the capture tool would then
# fail on `queries=0`, but say why up front.
lfs_pointer() {
  case "$(head -c 40 "$1" 2>/dev/null)" in
    "version https://git-lfs"*) return 0 ;;
    *) return 1 ;;
  esac
}

step "0/5  preconditions"
if ! pkg-config --exists z3 2>/dev/null && [ "$(ldconfig -p 2>/dev/null | grep -c 'libz3\.so')" -eq 0 ]; then
  echo "libz3 not found (pkg-config z3 / ldconfig); the solver-z3 build cannot link. apt: libz3-dev" >&2
  exit 2
fi
if ! command -v z3 >/dev/null 2>&1; then
  echo "no z3 binary on PATH; split_verdicts.py classifies with it. apt: z3" >&2
  exit 2
fi
for spec in "${drivers[@]}"; do
  path=${spec#*=}
  if [ ! -f "$path" ]; then echo "driver not found: $path" >&2; exit 2; fi
  if lfs_pointer "$path"; then
    echo "$path is a Git LFS pointer, not a driver: git lfs pull" >&2; exit 2
  fi
done
first_pinned=$(find "$root" -maxdepth 2 -name '*.smt2' | head -n 1)
if [ -n "$first_pinned" ] && lfs_pointer "$first_pinned"; then
  echo "$first_pinned is a Git LFS pointer; the pinned corpus is not checked out: git lfs pull" >&2; exit 2
fi
echo "z3: $(z3 --version)"
echo "drivers: ${drivers[*]}"
echo "ceiling: $ceiling s; out: $out"

step "1/5  build ioctlance (solver-z3,solver-axeyum, release)"
if [ -z "$binary" ]; then
  if cargo build --release --example ioctlance --features solver-z3,solver-axeyum >"$out/build.log" 2>&1; then
    binary=$CARGO_TARGET_DIR/release/examples/ioctlance
    echo "built $binary"
  else
    tail -n 30 "$out/build.log"
    echo "shadow-capture: the solver-z3,solver-axeyum build failed" >&2
    exit 2
  fi
else
  echo "using $binary"
fi

step "2/5  capture"
capture_args=(--binary "$binary" --root "$root" --ceiling "$ceiling" --report "$out/report.json" --log-dir "$out/logs")
for spec in "${drivers[@]}"; do capture_args+=(--driver "$spec"); done
"${python[@]}" tools/axeyum/shadow_capture.py "${capture_args[@]}"
capture_status=$?
case "$capture_status" in
  0) ;;
  1) finding "capture: a disagreement, a malformed export, or a run that was not evidence (see above)" ;;
  *) echo "shadow-capture: capture tool exited $capture_status (usage/environment)" >&2; exit 2 ;;
esac

step "3/5  gate 1: z3 classifies the live root, new rows enter verdicts.tsv"
if ! "${python[@]}" tools/axeyum/split_verdicts.py "$root" | tee "$out/gate1.log"; then
  finding "gate 1: split_verdicts.py rejected the live root (malformed or z3-undecided script)"
fi

if [ "$skip_replay" -eq 1 ]; then
  step "4/5  replay SKIPPED (--skip-replay): the regression floor was NOT checked"
else
  step "4/5  replay every script through the pinned Axeyum (solver-axeyum-text, debug)"
  replay_out=$out/axeyum-results.tsv
  rm -f "$replay_out"
  if GLAURUNG_SHADOW_SPLIT_AXEYUM_OUT=$replay_out \
     cargo test --features solver-axeyum,solver-axeyum-text --test axeyum_shadow_split_verdicts -- --nocapture \
     >"$out/replay.log" 2>&1; then
    replay_status=0
  else
    replay_status=$?
  fi
  grep -E '^(shadow-split replay|open gap|now decided|test result)' "$out/replay.log"
  # A feature-gated suite compiles to nothing and exits 0: require the named
  # test to have run. (CLAUDE.md, the `--features full` trap.)
  if ! grep -q 'pinned_axeyum_decides_every_shadow_split_verdict_like_z3 \.\.\. ok' "$out/replay.log"; then
    if [ "$replay_status" -eq 0 ]; then
      finding "replay: the named test did not run (0 tests is not a pass); see $out/replay.log"
    else
      grep -E 'REGRESSION|DISAGREEMENT|panicked|error' "$out/replay.log" | head -n 20
      finding "replay: the pinned Axeyum regressed or disagreed; see $out/replay.log"
    fi
  fi
  if [ ! -s "$replay_out" ]; then
    finding "replay: no $replay_out was written"
  else
    step "5/5  gate 2: fold the replay into verdicts.tsv (floor, NEW, PROMOTED)"
    pin=$(sed -n 's/.*axeyum\.git?rev=\([0-9a-f]*\)#.*/\1/p' Cargo.lock | head -n 1)
    note="axeyum-solver ${pin:-unknown} via tests/axeyum_shadow_split_verdicts.rs (solve_smtlib, 30 s wall), $(date -u +%Y-%m-%d), debug build, scripts/shadow-capture.sh"
    if ! "${python[@]}" tools/axeyum/split_verdicts.py "$root" --axeyum-results "$replay_out" --axeyum-note "$note" | tee "$out/gate2.log"; then
      finding "gate 2: a floor regression or an Axeyum/z3 opposition (see above)"
    fi
  fi
fi

printf '\n'
# Gate 1 counts the NEW rows (they enter as `unmeasured`); gate 2 counts the
# ones the replay PROMOTED into the floor. Both lines, or the reason neither ran.
if [ -f "$out/gate1.log" ]; then
  echo "shadow-capture: gate 1: $(grep '^new rows:' "$out/gate1.log" | head -n 1)"
fi
if [ -f "$out/gate2.log" ]; then
  echo "shadow-capture: gate 2: $(grep '^new rows:' "$out/gate2.log" | head -n 1)"
fi
if [ "$fail" -ne 0 ]; then
  echo "SHADOW CAPTURE: FAILED (${#findings[@]} finding(s)); commit nothing"
  exit 1
fi
echo "SHADOW CAPTURE: passed. Commit the new $root/<capture>/ directories and $root/verdicts.tsv."
