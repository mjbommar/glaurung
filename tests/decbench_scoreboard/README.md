# Pinned DecBench submission ledger

This directory makes the 2026-08-08 Glaurung submission baseline independently
recomputable. It is deliberately separate from `tests/decbench_corpus/`: that
directory is the small 56-cell development matrix, while this one records the
official 250-function `sample-set` experiment.

The files have distinct roles:

- `manifest.json` is the fail-closed experiment contract: Glaurung, DecBench,
  dataset, and metric revisions; evaluator versions; the raw package checksum;
  all 250 ordered function identities; and overlapping stable canary sets.
- `glaurung-c1cfdc97.json` is the per-function score evidence materialized from
  the pinned result tree. It contains the PR #61 ARM `byte_match` correction.
- `baseline-ledger.json` is derived output. Its byte identity is tested so a
  code or schema change cannot silently redefine the baseline.

The two generated evidence files use canonical single-line JSON. This keeps
large machine data out of repository line-count and source-file-size reports;
use `jq . FILE` when inspecting them interactively.

The evaluation kit shipped prebuilt binaries without compiler version metadata.
The manifest records that fact instead of guessing versions. Future kits should
capture compiler identities before compilation; until then, the dataset revision
and function manifest hash are the reproducible binary identities.

## Reproduce the ledger

With the raw result package retained outside Git:

```bash
tools/decbench_score_ledger.py \
  tests/decbench_scoreboard/glaurung-c1cfdc97.json \
  --manifest tests/decbench_scoreboard/manifest.json \
  --raw-package /path/to/glaurung-c1cfdc97-results.zip \
  --check-baseline \
  --output /tmp/glaurung-decbench-ledger.json
cmp tests/decbench_scoreboard/baseline-ledger.json \
  /tmp/glaurung-decbench-ledger.json
```

`--check-baseline` must reproduce 59 GED perfects, 13 type perfects, seven
corrected byte perfects, and 67 union perfects. Omit it for a future Glaurung
revision: corpus and metric pins still fail closed, but Glaurung is intentionally
the independent variable.

The ledger reports overall coverage, missing values, perfects, means, medians,
zeros, and union; architecture, optimization, and CFG-size slices; all published
head-to-head comparisons; and current scores for each stable canary function.
