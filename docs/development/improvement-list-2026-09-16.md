# Improvement list from the Axeyum side, 2026-09-16

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
