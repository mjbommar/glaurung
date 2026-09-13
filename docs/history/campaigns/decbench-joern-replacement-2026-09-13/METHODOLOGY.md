# Methodology, provenance, and reproduction

> **Kind:** record · **Date:** 2026-09-13

## Frozen inputs

| Input | Identity |
|---|---|
| DecBench | `f76dae075d4d82004fb21132b3f15e43b680e179` |
| Dataset | `e5eb576d66ee36793b800a4dd45e291e0add4472`, configuration `full` |
| Stored C column | `glaurung-229fbb1-clean` |
| Baseline Glaurung | `0892552157be6bd9267007231419ff6606a2dd38` |
| Final compatibility implementation | `f9a5cbaa22022f4e2db9c775bc696b1c56deeaf8` |
| Scored runner | `3fd97f4608114dd2d5a9f20d74960ab7520b7fe4` |
| Aggregate runner | `828a41a98c8d45ea458ed589d45a12eda5d1269c` |
| Full-denominator runner | `a7a7bdcc5c7fc5baf6cc207b38e6c15f34625f11` |
| Java stack | OpenJDK 25.0.4; pyjoern 4.0.150.4; Joern 4.0.150 |
| GED large-graph threshold | 200 nodes |

## Acceptance policy

Both frontends received the same stored C. When Java reported a graph,
Glaurung either had to reproduce its stored GED or the graph difference had to
be investigated. A Glaurung-only result counted as useful coverage only when a
stored definition existed and the graph passed structural checks. Prototype or
declaration graphs were recorded separately and never promoted to executable
coverage. Missing files, provider exceptions, and uncovered functions failed
closed.

The metric followed DecBench's own policy: test graph isomorphism, use its
node/edge-count formula above `GED_MAX_NODES`, otherwise compute the configured
graph edit distance, and clamp non-isomorphic zero results to one.

## Build and provider commands

The release extension was built in the clean comparison worktree:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv venv --python 3.12 --clear .venv
uv sync --locked --dev --python 3.12
CARGO_TARGET_DIR="$HOME/.cache/glaurung/target-decbench-joern-08925521" \
  uv run --python 3.12 maturin develop --release
```

The scored Glaurung run used:

```bash
DECBENCH_DIR="$HOME/.cache/glaurung/decbench-full/decbench"
PYTHONPATH="$DECBENCH_DIR:$DECBENCH_DIR/.venv/lib/python3.12/site-packages" \
  .venv/bin/python tools/source_cfg_parity.py \
  "$HOME/.cache/glaurung/decbench-full/tree" \
  --provider glaurung --column glaurung-229fbb1-clean \
  --details-jsonl glaurung-ternary-loop-details.jsonl \
  --progress-every 100 --json
```

Java used the same runner with `--provider joern`, graph capture enabled, and
79 ten-binary shards (`--start N --limit 10`, starts 0 through 780):

```bash
export JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$TMPDIR"
```

The exact shard orchestration and the 18-file tail commands remain in the
chronological [README](README.md).

## Completeness controls

- The Java aggregate verifies shard ordinals 0 through 784 exactly once.
- Each of the 85,645 stored identities occurs exactly once.
- Shard summaries and their lossless JSONL records agree.
- Both scored providers attempted all 85,645 cells.
- The separate tail runner fails if any of 4,380 definition markers is missing
  or a provider call fails.
- The final joined audit reconciles 89,978 scored-file definitions plus 4,380
  tail definitions to 94,358 total definitions.
- The joined audit separately records all names lacking definition markers.

## Artifact location and final hashes

Lossless artifacts are retained outside Git at:

```text
$HOME/.cache/glaurung/decbench-full/joern-replacement-2026-09-13/
```

| Final artifact | SHA-256 |
|---|---|
| `glaurung-ternary-loop-report.json` | `71cadc70ca556bc532a411b47618415ef6e4533dbf9533bb5553f9d1cd14a1a2` |
| `glaurung-ternary-loop-details.jsonl` | `86831de11abb572335f6078edb8c9ca50582ec9b80e2692684ec20dfdd2ebe53` |
| `aggregate-ternary-loop.json` | `9e551540143ae282b0d383a86d410e0a5705d6bc57bf811fcc7e4f7810480654` |
| `aggregate-ternary-loop.md` | `0ca6315c0b8c5c9174ed999037fbe067cdc6a7f373f17a28aa47aff14523e837` |
| `unscored-glaurung-report.json` | `c18d1cc1a86bf421bc7c162695ab133e911550b602ea8f6db49a7f6d9e90ac50` |
| `unscored-joern-report.json` | `4da18430ecb488bc1495d285262fe601273f7528675ff54baf61cccca017fca5` |
| `full-corpus-coverage.json` | `81be937bced098dffa87a9ec84854f636c1a8393eaec5fa41ea8ba849f6171da` |

## Scope limits

This campaign measures source-CFG extraction from stored decompiler C. It does
not compare raw-binary decompilation quality, reconstructed types, byte match,
runtime equivalence, or downstream analyst usefulness. Published source CFGs
and Java CFGs share Joern provenance, so Java/source agreement is a
reproducibility result rather than independent semantic ground truth.

No agent may use this record to autonomously create a DecBench issue, comment,
pull request, or Discord post.
