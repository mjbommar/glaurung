#!/usr/bin/env bash
#
# Reproducible axeyum-vs-z3 benchmark for glaurung's QF_BV workload.
#
# Bottom-up: Tier 0 (solver primitives) -> Tier 1 (formula families) ->
# Tier 1b (width x count mechanism) -> Tier 2 (warm vs one-shot) ->
# Tier 3 (real ioctlance driver query streams). See README.md for the design.
#
# Usage:
#   docs/axeyum-integration/benchmark/run_benchmark.sh [--fast] [--full-drivers]
#
#   --fast          skip the large Tier-3 drivers (tcpip, dxgkrnl)
#   --full-drivers  additionally run the large drivers (minutes each)
#
# Every backend comparison uses GLAURUNG_SHADOW_DIFF=1 so Z3 stays the
# authoritative exploration path and axeyum is timed on the IDENTICAL query
# stream. Results (JSONL + tables + a provenance stamp) land in results/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"
BD="docs/axeyum-integration/benchmark"
RES="$BD/results"
mkdir -p "$RES"
REAL="samples/binaries/platforms/windows/vendor/realworld"
PDB="tests/fixtures/msvc-pdb"

FAST=0; FULL_DRIVERS=0
for a in "$@"; do
  case "$a" in
    --fast) FAST=1 ;;
    --full-drivers) FULL_DRIVERS=1 ;;
  esac
done

FEATURES="solver-z3,solver-axeyum"

echo "== provenance =="
{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "glaurung_rev: $(git rev-parse HEAD)"
  echo "glaurung_dirty: $(git status --porcelain | wc -l) files"
  echo "axeyum_rev: $(git -C /home/mjbommar/projects/personal/axeyum rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "host: $(uname -srm)"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
  echo "rustc: $(rustc --version)"
  echo "features: $FEATURES"
} | tee "$RES/provenance.txt"

echo "== build =="
cargo build --release --features "$FEATURES" \
  --example axeyum_bench_primitives \
  --example axeyum_diff --example axeyum_sweep --example axeyum_incremental \
  --example ioctlance

echo "== Tier 0: primitives =="
target/release/examples/axeyum_bench_primitives \
  >"$RES/tier0-primitives.jsonl" 2>"$RES/tier0-primitives.table.txt"

echo "== Tier 1: formula families =="
target/release/examples/axeyum_diff >"$RES/tier1-families.txt" 2>&1

echo "== Tier 1b: width x count mechanism =="
target/release/examples/axeyum_sweep >"$RES/tier1b-sweep.txt" 2>&1

echo "== Tier 2: warm vs one-shot =="
target/release/examples/axeyum_incremental >"$RES/tier2-incremental.txt" 2>&1

echo "== Tier 3: real driver query streams =="
export IOCTLANCE_SOLVE_SECS=60 IOCTLANCE_SOLVE_BUDGET=20000 IOCTLANCE_DEADLINE_SECS=300
FAST_DRIVERS=(
  "$REAL/win10-vwififlt.sys"
  "$REAL/sqfs-intel-DptfDevGen.sys"
  "$REAL/windows-update-intel-audio-IntcSST.sys"
  "$REAL/windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"
)
LARGE_DRIVERS=(
  "$PDB/tcpip.sys"
  "$PDB/dxgkrnl.sys"
)
: >"$RES/tier3-drivers.txt"
run_driver() {
  local drv="$1"
  echo "### $(basename "$drv") @ $(git rev-parse --short HEAD) ###" >>"$RES/tier3-drivers.txt"
  GLAURUNG_SHADOW_DIFF=1 target/release/examples/ioctlance "$drv" 2>&1 \
    | grep -E '^\[shadow-diff\]|^\[model-choice\]|^\[axeyum-warm\]' >>"$RES/tier3-drivers.txt"
  echo >>"$RES/tier3-drivers.txt"
}
for d in "${FAST_DRIVERS[@]}"; do run_driver "$d"; done
if [ "$FULL_DRIVERS" = 1 ] && [ "$FAST" = 0 ]; then
  for d in "${LARGE_DRIVERS[@]}"; do run_driver "$d"; done
fi

echo "== done. results in $RES/ =="
