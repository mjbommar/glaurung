# DecBench leaderboard submission status

> **Kind:** record · **Date:** 2026-09-13

## Short answer

We have a complete, independently audited, full-corpus DecBench result that is
valuable for comparison and proves the end-to-end pipeline. It is not a result
from the 2026-09-13 Glaurung code, and it is not an exact replay of DecBench's
current Glaurung adapter. A human should therefore not label it "latest
Glaurung" or submit it without those qualifications.

Nothing has been sent to DecBench. This page is internal evidence for human
review and does not authorize an agent to create an upstream issue, comment, or
pull request.

## The audited leaderboard result

The clean reproduction at Glaurung
`229fbb1d373bdc7bfc3ff3e6f69b105723852225` produced:

| Metric | Perfect functions | Shared denominator | Rate |
|---|---:|---:|---:|
| GED | 29,463 | 91,287 | 32.275% |
| Type match | 18,905 | 86,671 | 21.812% |
| Byte match | 5,563 | 94,405 | 5.893% |
| **Union** | **39,236** | **94,423** | **41.553%** |

The result includes 803/803 generated C artifacts and 803/803 evaluated TOML
artifacts, representing 94,358 scored Glaurung function identities from a
94,575-function manifest. The raw fragments were independently recomputed and
also passed through pinned DecBench scoreboard code; both calculations agreed.

On the locally merged full-corpus comparison, the 41.553% Union rate is above
the recorded Kuna (38.495%), IDA (38.098%), angr (36.939%), Ghidra (27.075%),
and Binary Ninja (23.442%) columns. This is a reconstruction against pinned
local data, not a claim that DecBench has published that rank.

## Why this is not based on today's code

Two separate operations are easy to conflate:

1. **Decompiler leaderboard run, 2026-08-30.** Glaurung analyzed the stripped
   binaries and generated the stored C column `glaurung-229fbb1-clean`. DecBench
   then measured GED, type match, and byte match. This is the operation that
   produced the 39,236 Union-perfect functions.
2. **Source-CFG frontend comparison, 2026-09-13.** Java Joern and Glaurung both
   parsed that already-existing stored C column. This operation compared the
   two ways of constructing the source CFG used for GED evaluation. It did not
   decompile the 803 binaries again and therefore could not update the C text,
   recovered signatures, types, byte match, or leaderboard totals.

Reusing the stored column was intentional. The September experiment needed one
frozen input so that any graph difference could be attributed to the source-CFG
frontend rather than to changing decompiler output at the same time. It answers
"can Glaurung replace Joern on identical C?" It does not answer "what score does
the latest decompiler obtain?"

The final source-CFG compatibility implementation was
`f9a5cbaa22022f4e2db9c775bc696b1c56deeaf8`, 1,791 commits after the pinned
leaderboard revision along this branch's history. Those intervening changes
include decompiler work that can alter rendered code and therefore any of the
three leaderboard metrics. The old score cannot be projected forward by adding
known fixes; only a fresh evaluation can measure their combined effect.

## What remains valid

The following claims remain fully supported for the pinned August run:

- all 803 manifest binaries were processed;
- the exact Glaurung commit, CLI hash, native-extension hash, DecBench commit,
  and dataset commit are recorded;
- all 94,358 emitted function identities have stored C and evaluated metrics;
- the perfect counts were recomputed from raw per-function TOMLs;
- the merged shared-denominator policy was reproduced independently;
- one sequential replay matched its sharded result byte-for-byte;
- an anti-caching mutation changed the expected metric and Union contribution.

These controls make it a sound historical baseline and a useful regression
oracle. Age does not invalidate the measurement; it limits what revision the
measurement describes.

## The adapter-route qualification

The August run passed target addresses with `--vas` for every binary. The
current DecBench adapter uses `--vas` only for target sets of at most 400 and
switches larger sets to whole-binary `--all` mode before narrowing the output.
Fifty-five of 803 binaries cross that threshold, containing 65,742 of the
94,575 manifest functions.

The targeted-VA route is legitimate: DecBench supplies the DWARF-derived
addresses, and Glaurung receives stripped bytes rather than source or expected
answers. But it is not byte-for-byte the same execution route as the current
adapter for those 55 binaries. A small A/B probe found one output difference
among 58 overlapping functions, caused by whole-binary context recognizing a
tail jump. That is enough to require the qualification; it is not evidence that
the full score would materially rise or fall.

## Denominator interpretation

Four counts must not be substituted for one another:

| Count | Meaning |
|---|---|
| 94,575 | Functions in the full dataset manifest |
| 94,267 | Published measurable Union before adding this column |
| 94,358 | Functions for which this Glaurung run emitted scored artifacts |
| **94,423** | Recomputed shared Union universe after merging the new column |

DecBench's leaderboard denominator is shared: a function joins a metric's
denominator when any submitted decompiler has a finite value for that metric.
The new Glaurung column made 156 functions newly measurable while omitting 65
that another column measured. Therefore the comparable Union score is
`39,236 / 94,423`, not `39,236 / 94,358` and not `39,236 / 94,267`.

## Interpretation of the score

- **Union, 41.553%:** Glaurung achieves at least one perfect metric on 39,236
  functions. This is its strongest result and indicates broad deterministic
  coverage.
- **GED, 32.275%:** Control-flow shape is the largest contributor. It is not
  directly comparable to the September 95.1883% Joern-frontend parity rate:
  the former compares decompiled output to source; the latter compares two CFG
  extractors on identical decompiled C.
- **Type match, 21.812%:** Type recovery contributes substantially but remains
  well behind the Union total. The materialized protocol uses DecBench's C-text
  fallback because it does not carry structured variable records.
- **Byte match, 5.893%:** Exact recompilation-byte recovery is the weakest axis.
  It is a strict measure and should not be interpreted as the percentage of
  semantically correct functions.

The result supports a strong full-corpus ranking claim only for the pinned
dataset, evaluator, shared universe, Glaurung revision, and targeted-VA route.
It does not establish current-code quality or generalize to arbitrary binaries.

## What is needed for a current submission

A submission-quality refresh should:

1. choose and record the exact current Glaurung commit from a clean worktree;
2. build the release native extension and record both CLI and extension hashes;
3. pin the same dataset and DecBench revisions, unless a human deliberately
   chooses newer revisions and treats the result as a new comparison universe;
4. run all 803 binaries through the exact current DecBench adapter policy,
   including its `--vas`/`--all` threshold;
5. retain all generated C, metadata TOMLs, evaluated TOMLs, logs, exit states,
   and resource measurements;
6. fail closed on missing, empty, duplicate, or out-of-manifest identities;
7. recompute GED, type match, byte match, and Union from raw per-function data;
8. merge the new column into the shared measurable universe instead of reusing
   a historical denominator;
9. compare every changed perfect/non-perfect classification against the
   `229fbb1-clean` baseline and investigate unexpected regressions;
10. prepare a human-review packet, then stop at the upstream boundary.

The August result should remain preserved unchanged as the baseline. A current
run should use a new column name and new artifact directory rather than
overwriting it.

## Review artifacts

| Artifact | Purpose |
|---|---|
| `~/.cache/glaurung/decbench-full/audited-score-clean-229fbb1.json` | merged full-corpus scoreboard and shared denominators |
| `~/.cache/glaurung/decbench-full/final_score.json` | raw perfect counts using the run's own scored coverage |
| `~/.cache/glaurung/decbench-full/clean-229fbb1-run-provenance.json` | exact executable and revision identities |
| `~/.cache/glaurung/decbench-full/tree/decbench_dataset_provenance.json` | dataset identity and manifest counts |
| `~/.cache/glaurung/decbench-full/published_function_results.json` | published per-function comparison data used for the merge |

The earlier detailed audit is
[`docs/history/design/campaigns/decbench-full-score-audit-2026-08-30.md`](../../design/campaigns/decbench-full-score-audit-2026-08-30.md).
