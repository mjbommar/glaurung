# DecBench full-score audit — 2026-08-30

## Verdict

The raw evaluation fragments consistently support this result for the
target-address route at the recorded Glaurung revision:

| metric | perfect | shared denominator | rate |
|---|---:|---:|---:|
| GED | 29,463 | 91,287 | 32.275% |
| type match | 18,905 | 86,671 | 21.812% |
| byte match | 5,563 | 94,405 | 5.893% |
| **Union** | **39,236** | **94,423** | **41.553%** |

This is not yet an exact replay of DecBench's current Glaurung adapter. The run
used target VAs for every binary, while the adapter switches to whole-binary
mode above 400 targets. Fifty-five of 803 binaries cross that threshold. The
score is defensible as a targeted-VA evaluation because DecBench supplies the
DWARF-derived target addresses, but it must not be labelled an exact adapter or
submission replay until that route is run corpus-wide.

There is also a retrospective provenance limit. The column says
`glaurung-229fbb1`, and repository history places that revision at the start of
the run, but the old runner accepted the label as an argument and did not store
the native extension's hash. The artifacts do not cryptographically prove that
the loaded extension was built from that commit. Future runs must record and
verify the executable and extension hashes before decompilation.

## Frozen inputs

- Dataset: `noelo-lab/decbench-dataset` revision
  `e5eb576d66ee36793b800a4dd45e291e0add4472`, full config.
- Dataset manifest: 803 binary/config cells and 94,575 function identities.
- Metric implementation: clean detached DecBench checkout at
  `f76dae075d4d82004fb21132b3f15e43b680e179`.
- Glaurung artifact column: `glaurung-229fbb1`.
- Metrics: GED, type match, and byte match. Type match uses DecBench's C-text
  fallback because materialized artifacts contain no structured variables.

The separate `/nas4/data/workspace-infosec/decbench` checkout was dirty, but it
was not the executable environment used by the run. The scorer resolves to the
clean pinned checkout under `~/.cache/glaurung/decbench-full/decbench`.

## Completeness and identity checks

The audit reads the raw fragments rather than trusting `final_score.json` or a
generated scoreboard.

- 803/803 decompiled C artifacts exist.
- 803/803 evaluated TOMLs exist and contain function metrics.
- C marker identities: 94,358 unique functions.
- Evaluated identities: the same 94,358 functions; no evaluated function lacks
  a stored C artifact, and none lies outside the 94,575-function manifest.
- Missing from decompiled output: 217 manifest functions. They remain misses
  whenever another column makes the metric measurable.
- Every metric total recomputed from individual flat TOML keys matches the
  saved ad-hoc totals exactly.

The independent audit is `tools/decbench_audit_full.py`; its synthetic tests
cover shared-denominator expansion, replacement of a same-named column,
manifest leakage, missing/empty binary results, stale evaluated functions, and
deterministic output.

## Why 94,423 is the denominator

DecBench does not divide each column by its own coverage. For each metric, its
shared denominator is the set of functions where any decompiler has a finite
value. Union uses the set measurable on at least one metric.

| universe | functions |
|---|---:|
| dataset manifest | 94,575 |
| published measurable Union | 94,267 |
| new Glaurung values | 94,358 |
| newly measurable only because of new Glaurung column | 156 |
| published-measurable but absent from new Glaurung column | 65 |
| **merged shared Union** | **94,423** |

The old comparison helper incorrectly reused 94,267. It now omits a fixed
denominator by default and directs comparable runs to the merged audit.

## Independent reproduction

Two implementations agree:

1. `decbench_audit_full.py` parses all 803 TOMLs, joins them to the manifest and
   published per-function dataset, and implements the documented finite-value
   shared-universe rule.
2. The pinned DecBench `FunctionData` model plus
   `build_scoreboard_from_function_data` was fed the same new values in memory.

They produced the same Union count and denominator, the same three per-metric
counts and denominators, and the same revised denominators for the existing
columns.

A clean sequential replay of `O0/base-passwd/update-passwd` produced a TOML
byte-identical to the fragment created by the sharded run. As a negative
control, changing `xmalloc(long)` to `xmalloc(void)` reduced its type-match value
from 1.0 to 0.5 and reduced the cell's Union percentage. The scorer therefore
responds in the expected direction rather than preserving a cached perfect.

## Remaining claim boundary

The evidence supports the metric arithmetic, artifact completeness, pinned
metric implementation, shared denominator, and one sequential-vs-sharded
replay. It does not prove exact-adapter equivalence for the 55 large-target
binaries or exact native-build provenance for the historical run. Those are
claim restrictions, not reasons to discard the measured targeted-VA result.
