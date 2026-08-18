#!/usr/bin/env bash
# Does every Cargo feature still COMPILE?
#
# Nothing in this repository used to ask. On 2026-08-17 three SMT solver
# backends had not compiled for seventeen days: b03d5057 (2026-07-31) added
# `BinOp::LogicalAnd` / `LogicalOr`, updated `src/symbolic/expr.rs`, and updated
# no backend, so z3_backend.rs, bitwuzla_backend.rs and
# axeyum_backend/translate.rs all failed E0004. `--features triage-parsers-extra`
# had not compiled since 2025-09-01. `examples/axeyum_bench_primitives.rs`
# carried a fourth copy of the same non-exhaustive match. Every gate in the
# repository was green throughout, because every gate in the repository builds
# exactly ONE configuration -- `--features python-ext`, in
# `scripts/decbench-local-gate.sh` lane 1 -- and no GitHub workflow runs cargo
# at all.
#
# `scripts/lint-rust.sh` and `scripts/harden.sh` DO run
# `cargo clippy --all-targets --all-features`, which would have caught all of
# it -- except `--all-features` turns on `solver-bitwuzla`, whose build script
# panicked whenever Bitwuzla was absent. Both scripts therefore died in the
# build script on any machine without Bitwuzla installed, and neither is called
# from anywhere. A check that cannot run is not a check.
#
# This is the same shape as the `python-ext` warning in CLAUDE.md: a green
# result over code that was never built.
#
# Cost: `cargo check`, not `cargo build`. Type checking is what catches this
# class of defect and it needs no linker, which is also what lets the Bitwuzla
# lane run without the C library. `--all-targets` is load bearing: the fourth
# E0004 above was in an example, and examples carrying `required-features` are
# invisible to cargo without it.
#
# Usage:
#   scripts/feature-build-gate.sh          # every lane
#   scripts/feature-build-gate.sh -h
#
# System dependencies, and what happens without them:
#   solver-z3        needs libz3 (apt: libz3-dev). Missing -> lane SKIPS, and
#                    the run FAILS unless GLAURUNG_ALLOW_MISSING_SOLVERS=1.
#   solver-bitwuzla  needs Bitwuzla 0.9.1 via BITWUZLA_LIB_DIR. Missing -> this
#                    script sets GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1 so build.rs
#                    skips the link setup. `cargo check` never links, so the
#                    lane is a REAL type check either way; only the runtime
#                    behaviour goes unverified.
set -uo pipefail

cd "$(dirname "$0")/.."

case "${1:-}" in
  -h|--help) sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

: "${CARGO_TARGET_DIR:=$PWD/target}"
export CARGO_TARGET_DIR NO_COLOR=1 TERM=dumb

# Lets `cargo check` cover bitwuzla_backend.rs without the C library present.
# Harmless when BITWUZLA_LIB_DIR is set -- build.rs prefers the real library.
export GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1

fail=0
skipped=0
step() { printf '\n=== %s ===\n' "$1"; }
note() { printf '  %s\n' "$1"; }

have_z3=0
if pkg-config --exists z3 2>/dev/null || ldconfig -p 2>/dev/null | grep -q 'libz3\.so'; then
  have_z3=1
fi

# Every lane below builds a configuration no other lane builds. A feature UNION
# is not a superset of its members: `#[cfg(not(feature = "..."))]` arms compile
# only when the feature is OFF, so `--all-features` cannot stand in for the
# single-feature lanes. `neutral_measurement_backend` in
# src/symbolic/ordered_trace.rs has exactly that shape.
#
# Fields: label | system dependency | cargo feature arguments
lanes=(
  "default (triage-core)|none|"
  "python-ext|none|--features python-ext"
  "exec|none|--features exec"
  "symbolic|none|--features symbolic"
  "solver-axeyum|none|--features solver-axeyum"
  "solver-axeyum-text|none|--features solver-axeyum-text"
  "solver-bitwuzla|none|--features solver-bitwuzla"
  "triage-parsers-extra|none|--features triage-parsers-extra"
  "solver-z3|z3|--features solver-z3"
  "solver-z3 + solver-axeyum (shadow/diff)|z3|--features solver-z3,solver-axeyum"
  "all-features|z3|--all-features"
)

total=${#lanes[@]}
index=0
# Keep the log inside the target directory, not /tmp. CLAUDE.md: ad-hoc /tmp
# scratch is never cleaned up, and a full /tmp surfaces as a plausible product
# defect rather than as a disk error.
mkdir -p "$CARGO_TARGET_DIR"
log="$CARGO_TARGET_DIR/feature-build-gate.log"
trap 'rm -f "$log"' EXIT

for lane in "${lanes[@]}"; do
  index=$((index + 1))
  label=${lane%%|*}
  rest=${lane#*|}
  needs=${rest%%|*}
  args=${rest#*|}

  step "$index/$total  $label"
  if [ "$needs" = "z3" ] && [ "$have_z3" -eq 0 ]; then
    note "SKIPPED: libz3 not found (pkg-config z3 / ldconfig)."
    note "Debian/Ubuntu: apt-get install libz3-dev"
    skipped=$((skipped + 1))
    continue
  fi

  # shellcheck disable=SC2086
  if cargo check --all-targets $args >"$log" 2>&1; then
    note "ok"
  else
    note "FAILED: cargo check --all-targets $args"
    grep -E '^error' -A 8 "$log" | head -40
    fail=1
  fi
done

printf '\n'
if [ "$fail" -ne 0 ]; then
  echo "FEATURE GATE: FAILED"
  exit 1
fi
if [ "$skipped" -ne 0 ]; then
  if [ -n "${GLAURUNG_ALLOW_MISSING_SOLVERS:-}" ]; then
    echo "FEATURE GATE: passed, $skipped lane(s) SKIPPED (waived) -- those features are UNVERIFIED"
    exit 0
  fi
  echo "FEATURE GATE: FAILED -- $skipped lane(s) could not run for want of a system library."
  echo "A skipped lane is a gap, not a pass. Install the library, or set"
  echo "GLAURUNG_ALLOW_MISSING_SOLVERS=1 to accept shipping that feature unbuilt."
  exit 1
fi
echo "FEATURE GATE: passed (all $total feature configurations type-check)"
