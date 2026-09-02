#!/usr/bin/env bash
# One discoverable entry point for decompiler evidence, with an honest scope.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: scripts/decompiler-gate.sh {fast|default|release} [--print-plan|--preflight]"
}

preflight() {
  local profile="$1"
  local command
  for command in git cargo uv uvx; do
    if ! command -v "$command" >/dev/null 2>&1; then
      echo "NOT EVIDENCE: required command is absent: $command" >&2
      return 3
    fi
  done
  if [ "$profile" != "fast" ] && [ ! -x scripts/decbench-local-gate.sh ]; then
    echo "NOT EVIDENCE: scripts/decbench-local-gate.sh is absent or not executable" >&2
    return 3
  fi
  if [ "$profile" = "release" ]; then
    local decbench_dir="${DECBENCH_DIR:-/nas4/data/workspace-infosec/decbench}"
    if [ ! -d "$decbench_dir" ]; then
      echo "NOT EVIDENCE: DecBench/Joern metric lane is absent: $decbench_dir" >&2
      return 3
    fi
  fi
  echo "PREFLIGHT: evidence prerequisites present for profile=$profile"
}

print_plan() {
  case "$1" in
    fast)
      echo "PROFILE: fast"
      echo "RUNS: uv run python tools/build_guard.py; cargo test --features python-ext; pytest python/tests/ -m \"core and not decbench\"; ruff check; ty check"
      echo "DOES NOT RUN: extended Python, fixture/architecture matrices, feature matrix, performance gate, stripped lane, or DecBench/Joern metrics"
      ;;
    default)
      echo "PROFILE: default"
      echo "RUNS: scripts/decbench-local-gate.sh --no-decbench; ruff check; ty check"
      echo "DOES NOT RUN: DecBench/Joern metrics; GED, type_match, and byte_match remain unmeasured"
      ;;
    release)
      echo "PROFILE: release"
      echo "RUNS: scripts/decbench-local-gate.sh --decbench; ruff check; ty check"
      echo "DOES NOT RUN: nothing in the declared release matrix"
      ;;
  esac
}

profile="${1:-}"
option="${2:-}"
case "$profile" in
  -h|--help)
    usage
    exit 0
    ;;
  fast|default|release) ;;
  "")
    usage >&2
    exit 2
    ;;
  *)
    echo "unknown profile: $profile" >&2
    usage >&2
    exit 2
    ;;
esac
case "$option" in
  ""|--print-plan|--preflight) ;;
  *)
    echo "unknown argument: $option" >&2
    usage >&2
    exit 2
    ;;
esac
if [ "$#" -gt 2 ]; then
  echo "too many arguments" >&2
  usage >&2
  exit 2
fi

print_plan "$profile"
if [ "$option" = "--print-plan" ]; then
  exit 0
fi
if [ "$option" = "--preflight" ]; then
  preflight "$profile"
  exit $?
fi

preflight "$profile"

revision=$(git rev-parse --short=12 HEAD)
started=$SECONDS
echo "REVISION: $revision"
uv run python tools/build_guard.py

case "$profile" in
  fast)
    cargo test --features python-ext --lib --tests
    uv run pytest python/tests/ -m "core and not decbench" -n auto
    uvx ruff check python/ tools/
    uvx ty check python/
    ;;
  default)
    scripts/decbench-local-gate.sh --no-decbench
    uvx ruff check python/ tools/
    uvx ty check python/
    ;;
  release)
    scripts/decbench-local-gate.sh --decbench
    uvx ruff check python/ tools/
    uvx ty check python/
    ;;
esac

elapsed=$((SECONDS - started))
echo "GATE: passed profile=$profile revision=$revision elapsed_seconds=$elapsed"
print_plan "$profile"
