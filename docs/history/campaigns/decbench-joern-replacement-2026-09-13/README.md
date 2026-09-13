# DecBench Joern-replacement differential, 2026-09-13

> **Kind:** measurement record · **Status:** full A/B complete; differences under review · **Upstream:** local evidence only

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
| Differential runner | `f67ef4d853cc0ff4a891a4dd605ad44e71a70814` |
| Baseline native extension SHA-256 | `12b095751310d866d4531e192df6e51699c39d73d7bf753fac76f48c0c666d28` |
| Parallel-edge correction extension SHA-256 | `baef2831611af06d23490bbfd44c96138873fb96c507b4d1dd9012259e048b35` |
| Constant-loop correction extension SHA-256 | `103b6f7522d67c985858ada6992b294eeeac7cf9554ed623f68dd4e118a6fe91` |
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
`uncovered`, `no_source_cfg`, or `gained`, together with the lossless
metric-visible graph (entry/exit roles and directed edges). The Java run is divided into
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
`--start N --limit 10 --capture-graphs` for each shard from 0 through 780 and
sets `JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=$TMPDIR`.

The first checkpointed attempt omitted that JVM property: pyjoern placed its C
input under `$TMPDIR`, but Joern still left `joern-predef*.sc` under `/tmp`.
That run was stopped, its scalar-only shards were rejected as final evidence,
and the graph-preserving run restarted with Java's temporary directory fixed.

## Results

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
| Wall time | 60.90 seconds |
| Peak RSS | 336,048 KiB |

The replacement never voided a file or lost a stored function. The 4,333
additional function names are candidates, not automatically wins; the joined
audit below separates declarations from executable definitions.

### Java Joern/pyjoern: complete

| Measure | Result |
|---|---:|
| Shards | 79/79 |
| Binaries | 785/785 |
| Stored GED cells | 85,645 |
| Exact reproduction | 85,645 |
| Mismatched / uncovered / provider failures | **0 / 0 / 0** |
| Summed shard wall time | 11,716.9 seconds |
| Peak shard RSS | 9,255,808 KiB |

The fail-closed aggregate verified ordinals 0 through 784 exactly once, all
85,645 stored identities exactly once, and agreement between every shard report
and its JSONL ledger. Thus the stored Java values are fully reproduced for the
published 785-binary comparison universe.

### Joined audit and declaration noise

The initial joined result was 80,484 equal and 5,161 different GED cells. Gain
sets require a more careful denominator:

- 4,309 names were reported by both providers beyond DecBench's function list;
- all 76,312 names reported only by Joern have the same one-node, zero-edge,
  entry-and-exit graph and lack DecBench's `// Function:` definition marker;
- there are **zero** nontrivial Joern-only graphs;
- Glaurung alone reports 24 one-node non-returning definitions: one
  `__idle_thread` and 23 `blocking_handler` instances. All have definition
  markers in the stored text.

The 76,312 Joern-only names are declaration/import prototypes, not executable
definition coverage. They are useful parser facts but would radically inflate
a naive coverage count. On executable definitions, Glaurung loses no unique
nontrivial Joern result and identifies 24 definitions omitted by Joern.

### First broad correction

Source review of the cases where Joern was source-isomorphic exposed a general
reference-semantics defect around empty branches. S2 correctly preserves
parallel true and false edges to the same continuation, while Joern places its
CFG in a NetworkX `DiGraph` and deduplicates those edges before chain
contraction. Glaurung's parity layer deduplicated only afterwards, stranding a
spurious condition block for any empty `if` or empty `if`/`else`.

`parity_chains` now computes contraction degree from unique successors without
changing the general CFG. A focused two-case regression passed. The complete
85,645-cell Glaurung rerun then finished in 59.97 seconds at 336,940 KiB RSS:

| Measure | Before | After | Change |
|---|---:|---:|---:|
| Exact agreement | 80,484 (93.9740%) | 81,274 (94.8964%) | **+790** |
| Different GED | 5,161 | 4,371 | **-790** |
| Uncovered | 0 | 0 | 0 |
| Joern-source-isomorphic differences | 77 | 40 | **-37** |
| Glaurung-source-isomorphic differences | 91 | 92 | +1 |
| Different graph size | 3,608 | 2,783 | **-825** |

The runner intentionally returned status 1 because 4,371 mismatches remain;
that is the benchmark's fail-closed result, not a provider crash. The joined
aggregate passed every completeness and identity check.

### Second broad correction: constant-true loops

The parity graph inherited S2's deliberately conservative false edge from
every loop header, including `while (1)` and `for (;;)`. The correction proves
only bare nonzero integer literals and missing `for` conditions, removes only
their impossible false edge, and retains the loop node, back edge, and every
reachable `break`. It therefore does not copy Joern's separate bug of reducing
a truly infinite loop to the same one-node entry/exit graph as an empty
function.

Twenty-one focused node-rewrite tests passed. The complete corpus rerun took
60.65 seconds at 335,800 KiB RSS:

| Measure | After parallel-edge fix | After constant-loop fix | Change |
|---|---:|---:|---:|
| Exact agreement | 81,274 (94.8964%) | 81,501 (95.1614%) | **+227** |
| Different GED | 4,371 | 4,144 | **-227** |
| Uncovered | 0 | 0 | 0 |
| Glaurung-source-isomorphic differences | 92 | 313 | **+221** |

The detailed [difference review](DIFFERENCE-REVIEW.md) classifies all 40
apparent Java-source-isomorphic wins, all 1,457 role-only differences, and
reduces the initially unexplained graph-size queue to 45 unaffected cases. Nine
of those are now traced to duplicated branching for a value-only ternary nested
in a loop condition, leaving 36 unclassified cells.

## Artifact integrity

The lossless artifacts are stored outside Git under
`$HOME/.cache/glaurung/decbench-full/joern-replacement-2026-09-13/`.

| Artifact | SHA-256 |
|---|---|
| `glaurung-dedup-report.json` | `267f2ca0eb81f52b5f707a77a66c3009b862f8ff8fd59fe59afddefbd746518f` |
| `glaurung-dedup-details.jsonl` | `65d672598a5cff89b4a8f9ded8a1c04608bcdd265a8591370a82b7ae59cd6936` |
| `aggregate-dedup.json` | `b96be68a2bccf019a63bddf3d7728aa8515fab681049663d21a609a68a5b1b39` |
| `aggregate-dedup.md` | `2544a02c7de583206cc58dd1961a46e378d53a6a3dc76a57a5ab04d19216fbc0` |
| `glaurung-constant-loop-report.json` | `630de103838f68ac75cb5029f6c58270ce13fa9c345156af801e578e315d7185` |
| `glaurung-constant-loop-details.jsonl` | `65fa1f96dd56c85d9286fcbf25a1edd88297e8cb223ab987fa740a072f9b2e98` |
| `aggregate-constant-loop.json` | `d15efc30e4eee44f1ebca97835be09b25a30b2cc849d6d363dc301087f71682e` |
| `aggregate-constant-loop.md` | `e1e68e7e4174dc440e8e5a15f19cc9261d3619f0f92761df41f36f3f848daef2` |

## Required follow-up

- Repair the nine duplicated-branch ternary-loop cells by retargeting entry and
  back edges to the real expression entry; do not land the rejected partial
  node-deletion approach recorded in the difference review.
- Root-cause the remaining 36 graph-size differences untouched by
  constant-loop correction, deduplicating repeated functions across builds
  first.
- Review all large deltas and a deterministic sample of small deltas against
  source text and graph invariants.
- Decide whether an explicitly compatibility-only entry-flag emulator is worth
  implementing; do not feed Joern's merge-order artefacts into the general CFG.
- Prepare a concise Discord handoff for human review. Do not post it
  autonomously.
