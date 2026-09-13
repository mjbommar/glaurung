# DecBench Joern-replacement differential, 2026-09-13

> **Kind:** measurement record · **Status:** running · **Upstream:** local evidence only

## Question

Can Glaurung replace the Java Joern/pyjoern source-CFG path used by DecBench
without losing useful reports or introducing noise?

The acceptance rule is deliberately asymmetric:

- when Joern reports a CFG, Glaurung must match the resulting GED or the
  difference must be investigated and explained;
- when Joern fails or returns no CFG, a Glaurung-only result is a gain only when
  its graph is supported by the source and passes structural invariants;
- producing a graph for parser garbage is noise, not coverage;
- a crash, missing artifact, or unscored function is reported separately and
  never converted into a passing value.

This record does not authorize an issue, comment, pull request, Discord post,
or any other autonomous DecBench interaction. It prepares evidence for a human
to review and share.

## Frozen inputs

| Input | Revision or identity |
|---|---|
| Glaurung code under test | `0892552157be6bd9267007231419ff6606a2dd38` |
| Differential runner | `bd18b47332e2135ce7abeb7508274e2ac79217a1` |
| Native extension SHA-256 | `12b095751310d866d4531e192df6e51699c39d73d7bf753fac76f48c0c666d28` |
| DecBench | `f76dae075d4d82004fb21132b3f15e43b680e179` |
| DecBench dataset | `e5eb576d66ee36793b800a4dd45e291e0add4472` (`full`) |
| Stored decompiler column | `glaurung-229fbb1-clean` |
| Java | OpenJDK 25.0.4 |
| pyjoern | 4.0.150.4 |
| Joern bundle | 4.0.150 |

The dataset manifest contains 803 binaries and 94,575 functions. The published
tree contains 800 source-CFG files. The strict apples-to-apples GED oracle is
therefore the 785 complete `(published source CFG, decompiled C, stored GED)`
binary triples containing 85,645 functions. The remaining 3,318 stored GED
cells are in 15 binaries whose source CFGs were not published and cannot be
recomputed from this dataset. They remain an explicit dataset gap rather than
being silently dropped from a claimed 94K denominator.

## Method

Both providers receive the same stored decompiled C and are compared with the
same published source CFG using DecBench's own `GEDMetric` policy:

1. is/verify isomorphism;
2. use the node/edge-count formula above `GED_MAX_NODES`;
3. otherwise run the Vujosevic-Janicic distance;
4. clamp a non-isomorphic result to at least 1.

`tools/source_cfg_parity.py` records every function as `exact`, `mismatched`,
`uncovered`, `no_source_cfg`, or `gained`. The Java run is divided into
ten-binary shards. Each shard stores a JSON summary, per-function JSONL,
stderr/progress, exit status, wall time, CPU percentage, and peak RSS. Completed
shards are resumable and are never recomputed automatically.

## Commands

The release build was made in a detached clean worktree. The first attempted
build accidentally used the concurrently dirty main checkout; it was rejected
before any corpus measurement and rebuilt correctly. This is recorded because
build provenance failures must not disappear from the narrative.

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv venv --python 3.12 --clear .venv
uv sync --locked --dev --python 3.12
CARGO_TARGET_DIR="$HOME/.cache/glaurung/target-decbench-joern-08925521" \
  uv run --python 3.12 maturin develop --release
```

Glaurung provider:

```bash
DECBENCH_DIR="$HOME/.cache/glaurung/decbench-full/decbench"
PYTHONPATH="$DECBENCH_DIR:$DECBENCH_DIR/.venv/lib/python3.12/site-packages" \
  .venv/bin/python tools/source_cfg_parity.py \
  "$HOME/.cache/glaurung/decbench-full/tree" \
  --provider glaurung --column glaurung-229fbb1-clean \
  --details-jsonl glaurung-details.jsonl --progress-every 100 --json
```

Java self-check uses the same command with `--provider joern`. The full run adds
`--start N --limit 10` for each shard from 0 through 780.

## Results so far

### Glaurung replacement: complete

| Measure | Result |
|---|---:|
| Binaries | 785/785 |
| Stored GED cells | 85,645 |
| Attempted | 85,645 |
| Exact agreement | 80,484 (93.9740%) |
| Mismatched | 5,161 |
| Uncovered | **0** |
| Additional functions found | 4,333 |
| Wall time | 64.06 seconds |
| Peak RSS | 338,092 KiB |

The replacement never voided a file or lost a Joern-covered function. The
5,161 differences are not yet classified as defects or justified divergences.
The 4,333 additional function names are candidates, not automatically wins;
they require false-positive review.

### Java Joern/pyjoern: smoke passed, full run active

The first three complete triples reproduced 2,525/2,525 stored values exactly,
with zero uncovered cells. They took 131.92 seconds and peaked at 5,507,272 KiB
RSS. This validates the stored-value oracle on that slice while also showing why
the full Java pass needs checkpoints.

## Required follow-up

- Aggregate all Java shards and prove that their ordinals cover 0..784 exactly
  once.
- Compare total cells with 85,645; reject overlaps, holes, malformed JSONL, and
  inconsistent repeated identities.
- Inventory every Joern provider exception and every uncovered function.
- Join Java and Glaurung per-function ledgers.
- Cluster the 5,161 Glaurung differences by graph delta and source construct.
- Review all large deltas and a deterministic sample of small deltas against
  source text and graph invariants.
- Review Glaurung-only functions for declarations, parser-recovery artifacts,
  duplicate names, and synthetic/decompiler helper names before calling them
  useful coverage.
- Produce a concise, human-written Discord handoff with exact commands,
  qualifications, and artifact hashes.

