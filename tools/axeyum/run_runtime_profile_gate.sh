#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

mkdir -p target/glaurung-tmp target/uv-cache target/runtime-axeyum-gates
run_dir=$(mktemp -d "$repo_root/target/runtime-axeyum-gates/release-XXXXXXXX")
cold_dir="$run_dir/cold"
warm_dir="$run_dir/warm"
host_observations="$run_dir/host-observations.jsonl"
mkdir -p "$cold_dir" "$warm_dir"

repetitions=${GLAURUNG_RUNTIME_PROFILE_REPETITIONS:-3}
if [[ ! "$repetitions" =~ ^[1-9][0-9]*$ || "$repetitions" -gt 20 ]]; then
  echo "GLAURUNG_RUNTIME_PROFILE_REPETITIONS must be in [1, 20]" >&2
  exit 2
fi
common_env=(
  "TMPDIR=$repo_root/target/glaurung-tmp"
  "UV_CACHE_DIR=$repo_root/target/uv-cache"
)
budget_args=()
if [[ -n "${GLAURUNG_RUNTIME_PROFILE_BUDGET:-}" ]]; then
  budget_path=$(realpath "$GLAURUNG_RUNTIME_PROFILE_BUDGET")
  if [[ ! -f "$budget_path" ]]; then
    echo "GLAURUNG_RUNTIME_PROFILE_BUDGET is not a file: $budget_path" >&2
    exit 2
  fi
  budget_args=(--budget "$budget_path")
fi

if [[ -n "${GLAURUNG_RUNTIME_PROFILE_CORPUS:-}" ]]; then
  corpus_path=$(realpath "$GLAURUNG_RUNTIME_PROFILE_CORPUS")
  if [[ ! -f "$corpus_path" ]]; then
    echo "GLAURUNG_RUNTIME_PROFILE_CORPUS is not a file: $corpus_path" >&2
    exit 2
  fi
  printf '%s\n' "$corpus_path" >"$run_dir/reused-corpus-path.txt"
else
  corpus_path="$run_dir/corpus/corpus.json"
  env "${common_env[@]}" uv run --offline --no-sync python \
    tools/axeyum/runtime_profile_corpus.py capture \
    --output "$run_dir/corpus" \
    --timeout "${GLAURUNG_RUNTIME_TEST_TRACE_TIMEOUT_SECONDS:-30}" \
    >"$run_dir/capture-summary.json"
fi

run_lane() {
  local iteration=$1
  local lane=$2
  local reuse profile_dir output_prefix rss_file
  if [[ "$lane" == cold ]]; then
    reuse=off
    profile_dir=$cold_dir
    output_prefix=cold
    rss_file="$run_dir/cold-peak-rss-kib.txt"
  else
    reuse=adaptive
    profile_dir=$warm_dir
    output_prefix=warm
    rss_file="$run_dir/warm-peak-rss-kib.txt"
  fi

  env "${common_env[@]}" uv run --offline --no-sync python \
    tools/axeyum/runtime_profile_host.py --output "$host_observations" \
    --iteration "$iteration" --lane "$lane" --stage before
  if env "${common_env[@]}" \
      GLAURUNG_AXEYUM_WARM_REUSE="$reuse" \
      GLAURUNG_AXEYUM_PROFILE_DIR="$profile_dir" \
      /usr/bin/time -a -f %M -o "$rss_file" \
      uv run --offline --no-sync python tools/axeyum/runtime_profile_corpus.py analyze \
      --corpus "$corpus_path" \
      --output "$run_dir/$output_prefix-analysis-$iteration.json" \
      >"$run_dir/$output_prefix-analysis-$iteration.stdout" \
      2>"$run_dir/$output_prefix-analysis-$iteration.stderr"; then
    :
  else
    local status=$?
    env "${common_env[@]}" uv run --offline --no-sync python \
      tools/axeyum/runtime_profile_host.py --output "$host_observations" \
      --iteration "$iteration" --lane "$lane" --stage after
    echo "runtime profile $lane lane failed at iteration $iteration; " \
      "see $run_dir/$output_prefix-analysis-$iteration.stderr" >&2
    return "$status"
  fi
  env "${common_env[@]}" uv run --offline --no-sync python \
    tools/axeyum/runtime_profile_host.py --output "$host_observations" \
    --iteration "$iteration" --lane "$lane" --stage after
}

for ((iteration = 1; iteration <= repetitions; iteration++)); do
  if ((iteration % 2 == 1)); then
    run_lane "$iteration" cold
    run_lane "$iteration" optimized
  else
    run_lane "$iteration" optimized
    run_lane "$iteration" cold
  fi
done

cold_profiles=("$cold_dir"/*.jsonl)
warm_profiles=("$warm_dir"/*.jsonl)
if [[ ! -f "${cold_profiles[0]}" || ! -f "${warm_profiles[0]}" ]]; then
  echo "runtime Axeyum gate did not produce both profile populations" >&2
  exit 1
fi

report_args=()
for profile in "${cold_profiles[@]}"; do
  report_args+=(--cold "$profile")
done
for profile in "${warm_profiles[@]}"; do
  report_args+=(--warm "$profile")
done
dirty_arg=()
if ! git diff --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  dirty_arg=(--dirty-worktree)
fi
source_state_sha256=$(
  git ls-files -co --exclude-standard -z -- '*.rs' '*.py' '*.toml' Cargo.lock \
    | sort -z \
    | xargs -0 sha256sum \
    | sha256sum \
    | cut -d ' ' -f 1
)

uv run --offline --no-sync python tools/axeyum/runtime_profile_report.py \
  "${report_args[@]}" \
  "${budget_args[@]}" \
  --cold-peak-rss-kib "$(sort -nr "$run_dir/cold-peak-rss-kib.txt" | head -n 1)" \
  --warm-peak-rss-kib "$(sort -nr "$run_dir/warm-peak-rss-kib.txt" | head -n 1)" \
  --glaurung-revision "$(git rev-parse HEAD)" \
  --axeyum-revision "$(git -C ../axeyum rev-parse HEAD)" \
  --source-state-sha256 "$source_state_sha256" \
  --measurement-metadata "$host_observations" \
  "${dirty_arg[@]}" \
  --output "$run_dir/report.json"

echo "$run_dir/report.json"
