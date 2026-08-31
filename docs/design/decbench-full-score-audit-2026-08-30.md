# DecBench full-score audit — 2026-08-30

## Verdict

The raw evaluation fragments and a clean, full-corpus reproduction support this
result for the target-address route at Glaurung revision
`229fbb1d373bdc7bfc3ff3e6f69b105723852225`:

| metric | perfect | shared denominator | rate |
|---|---:|---:|---:|
| GED | 29,463 | 91,287 | 32.275% |
| type match | 18,905 | 86,671 | 21.812% |
| byte match | 5,563 | 94,405 | 5.893% |
| **Union** | **39,236** | **94,423** | **41.553%** |

This is not an exact replay of DecBench's current Glaurung adapter. The run
used target VAs for every binary, while the adapter switches to whole-binary
mode above 400 targets. Fifty-five of 803 binaries cross that threshold. The
score is defensible as a targeted-VA evaluation because DecBench supplies the
DWARF-derived target addresses, but it must not be labelled an exact adapter or
submission replay.

There is a retrospective provenance limit on the original column. It says
`glaurung-229fbb1`, and repository history places that revision at the start of
the run, but the old runner accepted the label as an argument and did not store
the native extension's hash. The artifacts do not cryptographically prove that
the loaded extension was built from that commit. To resolve that uncertainty,
the reproduction used a clean detached worktree at the full commit, forced a
fresh build, and recorded both executable hashes before decompilation. Its
column is `glaurung-229fbb1-clean`.

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

The clean reproduction recorded:

- Glaurung full commit: `229fbb1d373bdc7bfc3ff3e6f69b105723852225`.
- Clean detached worktree and a `fresh` build-guard result.
- CLI SHA-256:
  `38dfcba48e9308b71b8f6c0985468e747b500379c8d85420ec141ceca667a13d`.
- Native-extension SHA-256:
  `0b4bcff631b4e9f9281887f0745e69a1f1f1282124e3f162a47af431c642680d`.
- Reproduction provenance file:
  `~/.cache/glaurung/decbench-full/clean-229fbb1-run-provenance.json`.

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

The clean exact-commit reproduction then decompiled all 803 binaries and wrote
803 C artifacts plus 803 metadata TOMLs. The pinned scorer completed all 116
optimization/project shards; all 803 evaluated TOMLs contain the clean column
and none is empty. The independent audit found 94,358 scored function
identities, all backed by stored C markers and all inside the 94,575-function
manifest. Its deterministic report is
`~/.cache/glaurung/decbench-full/audited-score-clean-229fbb1.json` (SHA-256
`7f73c045dd11209a6eb784aeb3bc995daa10c85bc546ecfbbcad19a91c84b2b8`).

Pinned DecBench's own `build_scoreboard_from_function_data` independently
recomputed the merged data and matched the audit for all 14 columns, all three
metric denominators, and Union. For the clean column it reported exactly
`39,236 / 94,423 = 41.553435074%`.

The clean and historical artifacts are not merely aliases. Of 803 generated C
files, 783 are byte-identical and 20 differ. Those differences changed 13
non-perfect type-match values and five non-perfect byte-match values; they
changed no GED values and produced zero perfect-score gains or losses. After
normalizing only the column name, 785 evaluated binary TOMLs are byte-identical
and 18 contain those non-perfect changes. This explains, rather than merely
observes, why the independently rebuilt column has the same perfect counts.

## Ground-truth and leakage boundary

The materialized protocol uses the unstripped binary's symbol table to map each
manifest function name to an address, strips a copy of the binary, and passes
only those addresses and the stripped bytes to Glaurung. Glaurung does not
receive source bodies, source CFGs, DWARF types, expected pseudocode, or metric
values. DecBench alone reads those ground-truth products after decompilation.

Glaurung names functions in a stripped binary `sub_<va>`. The runner therefore
uses the already-established name/address map to relabel each returned entry
for DecBench's name-keyed result join. This relabel changes the emitted function
identifier, not its recovered signature body, control flow, types, or machine
code. Without it, a result produced at the requested address cannot join to its
manifest function at all. It is benchmark bookkeeping, not decompilation input.

The anti-caching negative control provides a separate direction of evidence:
changing one recovered `xmalloc` parameter type changed type match from 1.0 to
0.5 and removed that function's perfect contribution. The scorer was therefore
reading the candidate C rather than replaying a cached score or accepting the
manifest identity as correctness.

A clean sequential replay of `O0/base-passwd/update-passwd` produced a TOML
byte-identical to the fragment created by the sharded run. As a negative
control, changing `xmalloc(long)` to `xmalloc(void)` reduced its type-match value
from 1.0 to 0.5 and reduced the cell's Union percentage. The scorer therefore
responds in the expected direction rather than preserving a cached perfect.

## Remaining claim boundary

The evidence supports the metric arithmetic, artifact completeness, pinned
metric implementation, shared denominator, exact-commit clean-build
reproduction, and one sequential-vs-sharded replay. It does not prove
exact-adapter equivalence for the 55 large-target binaries, and it cannot
retroactively add a binary hash to the historical run. The clean reproduction
removes the latter uncertainty from the reproduced score; the former remains a
route-specific claim restriction, not a reason to discard the measured
targeted-VA result.
