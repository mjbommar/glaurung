# Decompiler metrics: the staged plan

> **Kind:** plan · **Status:** proposed

Six increments, ordered by value per unit of work rather than by interest. Each
ships something usable on its own, ends at a gate that can be run without the
next increment existing, and carries a stop condition. The style and the
two-track rule are borrowed from
[`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md), and the
same caution applies: **nothing here is scheduled by appearing here.** The live
plan set is [`../../development/roadmap/README.md`](../../development/roadmap/README.md).

## 0. How this is judged

This is a **MEASUREMENT** programme, not a CORRECTNESS one. M0 through M3 will
move zero decompiler fixture cells. They succeed when a number that was
misleading stops being misleading, and when a claim that could not be checked
becomes checkable.

Two rules bind every increment:

* **A metric ships after its instrument, never before.** M1 is the mutation
  harness and it gates M2 onward. A metric proposed without a sensitivity and a
  specificity number is an opinion.
* **Every published number carries its null baseline.** GED's is 27.24%
  ([`what-ged-measures.md`](what-ged-measures.md) §2.2). A metric that cannot
  report its own is not ready.

## 1. At a glance

```
M0 report the data we already have ─┐
                                    ├─> M2 control-skeleton TED ──┐
M1 mutation harness ────────────────┘                             ├─> M4 behavioural
                                    └─> M3 graded CFG distance ───┘    agreement (S4)
                                                                          │
                                            R1/R2 research               M5 bounded
                                                                         equivalence (S5)
```

| id | deliverable | needs | gate | moves cells? |
|---|---|---|---|---|
| M0 | stratified reporting + the null and transplant baselines | nothing | reproduce 27.24% and 58.61% from a committed tool | no |
| M1 | `tools/metric_mutants.py`, both halves | S1 (landed) | every class has a measured sensitivity **and** specificity for GED | no |
| M2 | control-skeleton tree edit distance | S1, S2 (landed), M1 | beats GED on the structural classes; 100% specificity on rename/whitespace; null baseline under 5% | no |
| M3 | adjacency-aware graded CFG distance | M1 | separates the 4-cycle from two 2-cycles; monotone under progressive corruption | no |
| M4 | behavioural agreement (Tier 1) | **S4**, M1 | detects all six semantics-only classes | **the point** |
| M5 | bounded equivalence (Tier 2) | **S5**, M4 | separates known-good from known-bad with a witness; `unknown` rate published | yes |
| R1 | human-agreement study | M2 | none — it is a check, not a gate | no |
| R2 | the type-layout problem for semantic scoring | M4 | none | no |

## 2. M0 — Report the data we already have

**Deliverable.** Two things, both arithmetic over already-published data:

* a stratified GED report — perfect rate per source-CFG-size band, per column,
  never pooled — extending `tools/source_cfg_census.py`, which already has the
  bands (`1, 2-3, 4-7, 8-15, 16-31, 32-60, >60`);
* the **null baseline** and the **transplant baseline** of
  [`calibration.md`](calibration.md) §4, as committed, re-runnable numbers.

**Why first.** It is the largest single effect in the directory and it needs no
new capability at all. It changes what the existing scoreboard means: every one
of `dewolf`'s 2,808 perfect cells is a single-node function, so its 3.09% is zero
on any function with control flow; and a constant body scores 27.24%.

**Gate.** A committed tool reproduces, from `~/.cache/glaurung/decbench-full`,
the numbers in [`what-ged-measures.md`](what-ged-measures.md) §2.2, §3 and §4 —
specifically 24,243 / 89,014 = 27.24% for the null baseline and 52,167 / 89,014 =
58.61% for the twin rate — with no Joern and no DecBench pipeline run. Exit
non-zero when the tree is absent, so an unrunnable report never reads as a pass
(the convention `tools/source_cfg_parity.py` already uses).

**Stop condition.** None. This is a day.

**Adjacent, and worth doing here because it is one line of the same join:** fix
`tools/source_cfg_parity.py` to model the metric it is diffing against. It calls
bare `vj_ged` (line 238) where the stored cells came from a function with an
isomorphism fast path, a `max(1.0, raw)` clamp and a 200-node cap. Measured
impact on the `glaurung-229fbb1-clean` column: **at most 358 of 88,963 cells
(0.40%)** ([`what-ged-measures.md`](what-ged-measures.md) §0). It does not
explain the parity gap and it is not urgent — but a gate that models the wrong
function will mislead as soon as the front end is good enough for the residue to
matter, and the fix is small.

## 3. M1 — The mutation harness

**Deliverable.** `tools/metric_mutants.py`: a fixed-seed, versioned mutation
catalogue over a fixed function corpus, reporting per-class sensitivity and
specificity for any registered metric. Both halves of
[`calibration.md`](calibration.md) §2 — the pilot built only the first.

**Corpus.** Start with what the pilot used: the 300 `samples` records in
`published_function_results.json`, of which 285 parse, resolve and yield a
non-degenerate CFG. Extend to `tests/decompiler_fixtures/src/` (196 files), which
is single-construct by design and therefore gives a per-construct sensitivity
breakdown for free.

**Gate.** Every class in [`calibration.md`](calibration.md) §2.1 and §2.2 has a
measured number for GED, recorded as the baseline any later metric must beat.
The specificity half must reach **100% on whitespace and renaming for every
metric**; a metric that moves when a variable is renamed is reading text.

**Stop condition.** If the semantics-preserving half cannot be built without a
semantic oracle — that is, if we cannot assert a rewrite is behaviour-preserving
without running it — then M1 ships with sensitivity only, and **every specificity
claim in this directory is withdrawn** rather than assumed. Say so in the report.

**Degenerate cases needing their own generator** (the rule from
[`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §0 and §9 —
a corpus sweep is a gate for none of them):

| case | why a sweep will not produce it |
|---|---|
| a mutation inside a function with no branches | 27.24% of the corpus, and the class every metric is worst on |
| a mutation that is a no-op on some paths | `constant-bump` on a dead constant; the label "changes behaviour" is then false |
| two mutations that cancel | the catalogue applies one at a time and never checks |
| a mutant that does not parse | 6 of 279 in the pilot; must be an abstention, never a detection |

That last row is the trap: an unparseable mutant looks exactly like a detected
defect. The pilot counts them separately (`mutant-unparsed`) and any production
harness must too.

## 4. M2 — Control-skeleton tree edit distance

**Deliverable.** The metric recommended in
[`structural-metrics.md`](structural-metrics.md) §2.6 and §3: Zhang–Shasha over a
fixed 19-symbol control alphabet with two versioned canonicalizations, normalized
by the source skeleton's node count, reported graded and stratified.

**Why it is next.** It is the only structural candidate that splits the
24,243-function class every CFG metric collapses, and it is the only one that
sees structuring quality — which is what a decompiler is for, and which is
invisible to every CFG metric because a `while` loop and its goto-ified
equivalent have the same graph.

**Gate.** Four conditions, all from M1's instrument:

1. strictly higher sensitivity than GED on `goto-ify`, `while->if`, `drop-break`
   and `else->if(0)`, with `goto-ify` at or near 100% (GED is at 0% by
   construction);
2. 100% specificity on whitespace, comments, renaming, `for`↔`while` and
   `else if` chaining;
3. null baseline under 5%, and transplant baseline strictly below GED's 58.61%;
4. byte-identical output across two runs and across two machines.

**Stop condition.** If (2) cannot be met — if the canonicalizations cannot be
made to absorb legitimate rewrites without also absorbing real defects — the
metric is measuring the decompiler's stylistic distance from the source, not its
correctness. Stop, and keep GED's isomorphism verdict as the structural signal
while M4 is built.

## 5. M3 — Adjacency-aware graded CFG distance

**Deliverable.** A Riesen–Bunke local-edge-structure substitution cost feeding
the existing LSAP. It reuses `solve_assignment(cells: &[Cost], order: usize)` in
[`src/syntax/ged.rs`](../../../src/syntax/ged.rs) unchanged — that function is
the reuse seam, decoupled from the cost model and already carrying the
determinism contract.

**Positioning.** A **diagnostic**, not a published score. When M2 says a function
regressed, this is what says which edge.

**Gate.** Scores the 4-cycle against two 2-cycles as non-zero (the counterexample
in [`../static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md)
§2, where `vj_ged` returns 0); is monotone non-decreasing under a sequence of
progressive double-edge swaps on a real corpus function; agrees with `vj_ged` on
the degenerate cases where the two must agree.

**Stop condition.** If it does not beat GED's isomorphism verdict on any M1
class, it is only a diagnostic and must never be published as a score. That is an
acceptable outcome, not a failure.

## 6. M4 — Behavioural agreement

**Blocked on stage S4** (C → LLIR), which is not built. Specified in
[`semantic-metrics.md`](semantic-metrics.md) §2.

**Deliverable.** Tier 1: both sides lowered to LLIR, executed under
`Machine<Concrete>` on a branch-covering input set generated by
`Machine<Symbolic>` plus `symbolic::solve`, scored on the agreement of an
observable tuple that includes the call trace.

**Gate.** Detection of all six semantics-only mutation classes — the 795 injected
defects that every structural metric misses, of which GED detects 7. Anything
less and the semantic tier has not earned its cost. Plus: `paths_covered /
paths_found` reported with every score, and a `Budget`-tick bound rather than a
wall clock.

**Stop condition.** The one in [`semantic-metrics.md`](semantic-metrics.md) §5:
if hand-built known-good and known-bad pairs cannot be separated, this is not an
oracle and must not be quoted as one. Bank M0–M3 and stop.

## 7. M5 — Bounded equivalence

**Blocked on stage S5**, whose gate is already written in
[`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §7 and is
not restated here. Two additions from this directory:

* the `unknown` rate is published beside every score and never folded into either
  side;
* the bound is quoted with every number, and the budget is work rather than wall
  clock — `DEFAULT_CHECK_TIMEOUT_MS` is not a metric-grade bound
  ([`calibration.md`](calibration.md) §5).

## 8. R1 and R2 — research

**R1 — human agreement.** Fifty (source, decompiled) pairs from the 300 published
samples, ranked by a person on "would I trust this to understand the function",
against each candidate metric's Spearman correlation. **Underpowered by
construction**: fifty pairs can catch a metric that is badly wrong and cannot
separate two good ones. Run it as a sanity check, report it as one, and never let
it decide between M2 and M3.

**R2 — the type-layout problem.** [`semantic-metrics.md`](semantic-metrics.md)
§2.3 is the deepest unsolved issue in the programme: a semantic metric needs a
shared memory image, and the decompiled side's layout is exactly the thing
`type_match` says is usually wrong. The recommendation there — impose the
ground-truth layout on both sides — is a position, not a result. What fraction of
the corpus has scalar-only arguments could not be determined offline; it needs
DWARF the materialized tree does not carry.

## 9. What this plan deliberately does not do

* **It does not propose changing DecBench.** The upstream boundary in
  `CLAUDE.md` is absolute: no autonomous issues, comments or pull requests. This
  is a plan for what Glaurung measures, and any of it that would benefit DecBench
  is handed to a human as evidence.
* **It does not retire `type_match` or `byte_match`.** They measure different
  things badly rather than the same thing badly, and stage S6 already covers the
  first.
* **It does not put a semantic metric in the iteration loop.** M4 is a nightly
  oracle at the shape of cost sketched in
  [`semantic-metrics.md`](semantic-metrics.md) §2.4; the loop keeps a structural
  metric, and the structural metric is checked against the oracle rather than
  trusted on its own.
* **It does not bank M0 and stop.** That is the likeliest failure mode, exactly as
  [`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §10 warns
  about S3: M0 is the increment with the striking number attached, and it fixes
  reporting rather than measurement.
