#!/usr/bin/env bash
# Drive every decompiler over every binary in a corpus list.
#
# Sequential on purpose: the numbers collected include wall clock, and four
# decompilers fighting over the same cores would make that measurement
# meaningless.
#
#   runall.sh <outdir> <corpus-list>
#
# Corpus list is `tag|binary|dwarf-or-fde|limit|gt-binary`, one per line, `#`
# for comments. `gt-binary` is optional and names the file to read ground truth
# FROM when it differs from the file under test — used for stripped twins,
# whose DWARF lives in the unstripped original.
set -u
BENCH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT=${1:?usage: runall.sh <outdir> <corpus-list>}
LIST=${2:?usage: runall.sh <outdir> <corpus-list>}
mkdir -p "$OUT"

python3 "$BENCH/config.py" || true
echo

while IFS='|' read -r tag path gtsrc limit gtbin; do
  [ -z "${tag:-}" ] && continue
  case "$tag" in \#*) continue ;; esac
  if [ ! -f "$path" ]; then
    echo "### $tag  SKIP — no such binary: $path"
    continue
  fi
  echo "### $tag  ($gtsrc, limit $limit)  $path"
  extra=()
  [ -n "${gtbin:-}" ] && extra=(--gtbinary "$gtbin")
  python3 "$BENCH/drive.py" "$path" "$OUT" --gtsource "$gtsrc" --limit "$limit" \
      --tag "$tag" --timeout 1200 "${extra[@]}" 2>&1 \
      | grep -viE '^warning|deprecat|felix|unsafe' | tail -12
done < "$LIST"
echo "=== ALL DONE ==="
