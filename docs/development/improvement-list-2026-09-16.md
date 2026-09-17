# Improvement list from the Axeyum side, 2026-09-16

> **Kind:** plan · **Status:** maintained (the status section at the end is the ledger)

Measured today against Axeyum `defc4f806` and this checkout at `2fbf1af4`.
Every number below was produced this afternoon and can be re-run; nothing is
inherited from the July integration notes.

## What the measurements say

| question | answer |
|---|---|
| Axeyum pin | `c38a9515e`, 2026-07-20, **11,605 commits** behind Axeyum's head |
| Does head still fit the adapter? | Yes: `cargo check --features solver-axeyum` 0 errors; `cargo test --features solver-axeyum` **2,923 passed, 0 failed** (6 `ordered_trace` tests need a git repository, see item 8) |
| The shadow-split corpus (`tests/corpora/axeyum-qfbv/shadow-splits/`) | 842 files; **733 are malformed exports** z3 itself rejects (`invalid extract application`, the pre-solver-016 exporter); of the 107 valid ones Axeyum head decides **107 of 107**, median 0.41 s, max 1.31 s, every verdict matching z3 |
| The perf gate that keeps `solver-axeyum` opt-in | measured once, in July: 1.7–3.2× slower one-shot; warm regime 0.74× to 2.3× by driver; never re-run |
| Model choice | 79 % of both-sat queries returned different valid models in July; there is still no value-selection knob on the Axeyum side |

So the capability gap the July corpus recorded is closed on everything it
captured, and the integration has been running a two-month-old solver because
nobody re-checked. Dormant, not broken.

## Do first

1. **Bump the Axeyum pin to head** and re-run the tcpip lineage gate. A scratch
   copy of this checkout with a `[patch]` section pointing at the local Axeyum
   tree type-checked and tested clean; the same patch on a branch is the
   change.
2. **Prune and regenerate the shadow-split corpus.** Keep the 107 z3-valid
   files as a regression set with their verdicts; drop the 733 malformed ones
   or move them under a `malformed-exports/` name so no sweep counts them as
   solver misses again. Then re-capture with the fixed exporter at head, and
   add a z3-parses-it check to the capture path (solver-015) so an exporter
   bug cannot fill the corpus a second time.
3. **Re-run the six-cell timing campaign** (ADR-0272's preregistered harness,
   four drivers, z3 vs Axeyum vs Bitwuzla, warm and cold) at Axeyum head. Its
   result is the decision `solver-002` has been waiting on since July: whether
   Axeyum becomes the default backend. Nothing else on this list matters as
   much as that number.
   **Done 2026-09-17 as four cells** (Bitwuzla not buildable on the host):
   [`solver-033`](../decisions/solver-033-six-cell-rerun-at-the-2026-09-16-pin.md).
   Gate not met; every driver inconclusive under ADR-0272 because warm Axeyum
   at the new pin pushes each process into the 60 s solve budget. Cold Axeyum
   is at parity or faster; warm Axeyum's latency grows with session age.

## Then

4. **Consume a value-selection policy** once Axeyum exposes one (its list,
   item 4): least-unsigned or prefer-small models for concretization. The
   July measurement says the policy is worth having; the knob does not exist
   yet on either side.
5. **Canonical constraint-cache identity (ADR-0303)** in the Axeyum backend
   adapter: the sorted, duplicate-elided assertion set as the exact key, not
   the ordered query text. The v2 analyzer measured 62 % exact reuse across
   12,902 checks per four-driver pass.
6. **Align the adapter with the current Axeyum API** after the bump:
   `check_assuming_measured` is implemented locally
   (`src/symbolic/solver/axeyum_backend.rs:482`) while `IncrementalBvSolver`
   now exposes `stats()` with per-phase timing; one of the two is redundant.
7. **Make shadow-split capture continuous** in the gate (a weekly or per-push
   tier), so the next divergence is seen the week it appears rather than two
   months later.
8. **Tests that shell out to `git rev-parse HEAD`** (`src/symbolic/ordered_trace.rs:1349`
   and five siblings) fail in any non-repository checkout. Use a fixture
   repository or skip with the reason named.
9. **Label the July integration notes as frozen.** `docs/history/axeyum-integration-2026-07/`
   still says Axeyum is 1.7–3.2× slower on real driver formulas; that was true
   on 2026-07-19 and is unmeasured since. A dated banner beside the number,
   with a pointer to item 3's rerun, keeps it from being quoted as current.

## The decompiler self-check this enables

10. **Decompiled C → cindergraph → Axeyum.** The pipeline built today in
    Axeyum (`python/examples/cindergraph_defects/`) lifts cindergraph's typed
    AST into QF_BV and replays witnesses under a sanitizer. Glaurung's
    decompiled output is C; running that pipeline over it is a decompiler
    self-check that names a concrete input for every length, index, divisor,
    shift and overflow defect in the recovered code, and proves dead branches.
    It needs cindergraph's Milestone H (Glaurung on the cindergraph crate, not
    an embedded copy) and cindergraph's items 1–3 (operator, resolved type,
    typed operations export) to stop being a research script.

## Status, 2026-09-17

| item | status | where |
|---|---|---|
| 1 pin bump | **done, re-pinned** | `7d6f5f70` (pin `c38a9515e` → `8df853252`), merged in `11b68faf`; [`solver-032`](../decisions/solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md). Re-pinned 2026-09-17 to `11b895a35` (the warm-session fix, Axeyum ADR-2142): same 5,253 / 1 / 19 test counts, the 134-row shadow-split floor holds, DptfDevGen's capture sizing 59.5 s → 6.0 s with 0 splits; [`solver-035`](../decisions/solver-035-warm-fix-repin-and-model-preference.md). Re-pinned again to `43f1e0f90` (Axeyum ADR-2144 + ADR-2145, the kept trail): same test counts plus the five item-4 tests, floor 135 holds, sizing 5.6 s, warm Axeyum on DptfDevGen 1,516 → 517 ms, the four-driver tier 5 min 42 s with 0 splits; [`solver-036`](../decisions/solver-036-canonical-cache-consumed-and-the-kept-trail-measured.md) |
| 2 prune and regenerate the corpus | **done** | `0d07b09d`: 735 z3-rejected scripts moved to `malformed-exports-pre-solver-016/`, the 107 valid pinned in `shadow-splits/verdicts.tsv`, capture parses with the linked libz3 before indexing; [`solver-032`](../decisions/solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md) |
| 3 six-cell rerun | **done, gate not met** | `2931047d` / `da49fbc4`, merged in `3b3f2b4b`: four cells (no Bitwuzla on the host); every driver inconclusive under ADR-0272 because warm Axeyum at the new pin hits the 60 s budget; cold Axeyum at parity or faster; [`solver-033`](../decisions/solver-033-six-cell-rerun-at-the-2026-09-16-pin.md). At `11b895a35` DptfDevGen, vwififlt and IntcSST no longer hit the budget (`deadline=0`; SurfacePen still reports `deadline=1`, as it did at the old pin, [`solver-035`](../decisions/solver-035-warm-fix-repin-and-model-preference.md)); the campaign itself has not been re-registered at that pin |
| 4 value-selection policy | **done** | `GLAURUNG_AXEYUM_MODEL_PREFERENCE` (`any` \| `zero` \| `least-unsigned`) → `SolverConfig::model_preference` through `axeyum_backend/config.rs::build_config`, every Axeyum session this adapter creates; default unchanged (`any`); four tests in `axeyum_backend::tests` including the three-witness `zero` model that replays; [`solver-035`](../decisions/solver-035-warm-fix-repin-and-model-preference.md) |
| 5 canonical constraint-cache identity (ADR-0303) | **done** | Axeyum landed the identity as a library feature of `IncrementalBvSolver` (ADR-2144, keyed by the sorted deduplicated set of live assertion `TermId`s inside one arena); pinned at `43f1e0f90` and consumed as `GLAURUNG_AXEYUM_CANONICAL_CACHE` (`on` \| `off`) → `SolverConfig::canonical_constraint_cache` through `axeyum_backend/config.rs::build_config`, counters folded into `canonical_cache_stats()` and printed by `ioctlance`; default unchanged (off). Measured against Glaurung's own text/SHA cache on DptfDevGen and vwififlt: the library cache is faster in backend time AND wall (Glaurung's costs more wall than it saves, ADR-0304 reproduced), sees more repeats, 0 verdict disagreements; what it cannot do is the cross-path share (needs a structural term hash in `axeyum-ir`); [`solver-036`](../decisions/solver-036-canonical-cache-consumed-and-the-kept-trail-measured.md) |
| 6 adapter vs `stats()` | **done, no change** | `4544067f`: `check_assuming_measured` times the two adapter-side phases and `stats()` the six in-solver phases; the profile sums them as disjoint. Not redundant; documented in a doc comment |
| 7 continuous shadow-split capture | **done** | `17ff0387`: `scripts/shadow-capture.sh`, `tools/axeyum/shadow_capture.py`, `.github/workflows/shadow-capture-weekly.yml`, the regression floor in `split_verdicts.py` and the Rust replay; [`solver-034`](../decisions/solver-034-continuous-shadow-split-capture-tier.md) |
| 8 tests that shell out to `git rev-parse` | **done** | `3a95df4f`: a checkout without `.git` publishes a trace; the six git-bound tests skip with the reason named |
| 9 label the July notes as frozen | **done** | `4544067f`: dated banner on `PAPER-NOTES.md` and `FEEDBACK-LOG.md`, pointing at item 3's rerun; no number edited |
| 10 decompiled C → cindergraph → Axeyum | **Milestone H done; the pipeline not started** | Glaurung is on the cindergraph crate: `cindergraph = { git = "https://github.com/mjbommar/cindergraph.git", rev = "ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825" }`, the embedded `src/syntax/` and reusable `src/csource/` deleted (54 files, 32,872 lines, 583 unit tests that cindergraph carries), every consumer importing `cindergraph::`, and a no-drift-back test with four mutation-checked guards; [`source-001`](../decisions/source-001-depend-on-cindergraph-by-git-rev.md), sizing in [`cindergraph-migration-2026-09-17.md`](cindergraph-migration-2026-09-17.md). **Caveat:** four 2026-09-13 DecBench parity corrections (`828a41a9`, `0266715f`, `68b39f18`, `f9a5cbaa`) exist nowhere in cindergraph and cannot be shimmed over the crate; they need porting upstream (ten named tests), after which Glaurung re-pins. The pipeline itself still wants cindergraph's items 1–3 (`repr="ops"`, resolved types), which are in cindergraph's unpushed commits past `ed5e55e` |

Items 1–9 are done as of `solver-036`; item 10's Milestone H is done as of
`source-001`, with the parity port and the pipeline outstanding.
