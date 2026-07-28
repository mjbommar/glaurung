# Reviewer checklist: pre-submission todos for the axeyum/glaurung paper

> A self-review written from the perspective of a skeptical PC reviewer for a
> solver/security venue (CAV / TACAS / USENIX Security / OOPSLA tool track).
> Each item is a concern a reviewer will raise; each is broken into
> **(1) the problem**, **(2) the evidence or action required**, and
> **(3) concrete guidance on what to build or do** -- with pointers to the real
> harnesses so these become executable todos, not abstractions.
>
> Companion to `README.md` (the benchmark itself). The benchmark as it stands is
> strong on *correctness* and weak-to-over-claimed on *performance*; this list
> is ordered by how much each item would move a review score.

## Severity triage

| # | Concern | Severity | Blocks acceptance? |
|---|---|---|---|
| 1 | z3 baseline is one-shot-over-FFI (strawman) | critical | yes |
| 2 | Ratio-of-sums / single-run statistics | critical | yes |
| 3 | "Faster" confounded with "timed out less" | critical | yes |
| 4 | Finding-parity under axeyum-authoritative mode | critical | yes |
| 5 | Isolate axeyum's contribution from glaurung's scheduling | major | likely |
| 6 | Generality (one tool / arch / query shape) | major | likely |
| 7 | Cold-path gap + warm-hit rate under-reported | major | revision |
| 8 | Correctness TCB / oracle circularity | major | revision |
| 9 | Latent emission bugs -> numeric stability | major | revision |
| 10 | Deployability claims unmeasured | minor | polish |

The **lead contribution should be correctness** (strict typing as a differential
oracle that caught three real consumer soundness bugs z3 silently masked). The
performance story is publishable but only after 1-4 are addressed.

---

## 1. The z3 baseline is one-shot-over-FFI (critical)

**Problem.** Every speed number compares axeyum's *warm/incremental* path against
a *freshly constructed z3 solver per query, over libz3 FFI*
(`z3_backend.rs`: `Z3Solver::new().check(...)` per call). That conflates three
independent effects: (a) in-process vs FFI/context-construction overhead,
(b) one-shot vs incremental reuse, (c) the underlying decision procedures.
Tier 1b already shows the K=1 floor is 359-841 us of pure z3 setup. A reviewer
will read the headline 2.8-15.6x as "mostly the FFI tax the authors imposed on
the baseline," which is not a solver result.

**Evidence / action required.** A **warm z3 baseline**: a persistent
`z3::Context`/`Solver` driven with `push`/`assert`/`pop` that mirrors axeyum's
lineage reuse, on the identical query stream. Plus at least one **neutral
third-party solver** (bitwuzla and/or cvc5) so the comparison is not axeyum-vs-z3
alone. Report all backends on the same stream, warm and cold.

**What to build.**
- Add a warm z3 backend behind the existing incremental seam: implement the
  `IncrementalSolver` trait (already defined in `solver/mod.rs`) for z3 using
  its native `Solver::push/pop` and a persistent `Context`. Wire it into the
  shadow harness as a third timed column alongside axeyum-warm.
- Extend `examples/axeyum_diff.rs` and the Tier-3 `[shadow-diff]` footer to time
  **four cells** per query: {z3, axeyum} x {cold, warm}.
- Add bitwuzla/cvc5 via the existing `pipe::PipeSolver` SMT-LIB path
  (`$GLAURUNG_SMT_SOLVER`) for a cold third-party point; note they are
  subprocess-bridged (document the boundary cost).
- Deliverable: a 4-6 column table (per driver, per formula family) so the
  reader can separate FFI overhead from incremental reuse from raw solving.

## 2. Ratio-of-sums and single-run statistics (critical)

**Problem.** The artifacts report "median-sum ratio," per-cell speedups, and
summed z3/axeyum milliseconds (`README.md` Tier 0/3). A **ratio of summed times
is dominated by a few hard queries**; a single process run has no variance
estimate. This is the first thing a methods-literate reviewer rejects.

**Evidence / action required.** Per-query **paired** measurements; the
**geometric mean of per-query ratios** (not the ratio of sums); confidence
intervals; latency **CDFs per backend**; and multiple runs with reported
coefficient of variation.

**What to build.**
- Emit per-query timings (not just aggregates). The ordered-trace already
  records `z3_nanos`/`axeyum_nanos` per check
  (`ordered_trace.rs`) -- consume that as the raw paired dataset instead of the
  global `SHADOW_*_NANOS` accumulators.
- A small analysis script (`benchmark/analyze.py`) that computes: geomean of
  paired ratios, bootstrap 95% CIs, per-backend p50/p90/p95/p99, and writes a
  latency-CDF plot (matplotlib, one PNG per driver).
- Run each configuration N>=5 times (use the **fixed-work boundary** so the
  query set is identical across runs -- see #3); report mean +/- CV per cell.
- Replace every "X.Yx" scalar in README/paper with "geomean X.Yx [CI_lo, CI_hi]".

## 3. "Faster" is confounded with "timed out less often" (critical)

**Problem.** Under the shared 250 ms timeout the two backends decide *different
subsets* (tcpip: `z3-unknown=52` vs `axeyum-unknown=11`). Summed-time comparison
partly rewards whichever solver gives up more. Also 480 tcpip checks hit the
assertion cap and ran **one-shot, not warm** -- silently mixed into the "warm"
number.

**Evidence / action required.** **Solved-only** paired latency (restrict to
queries both backends decided); the timeout as an explicit swept variable; and a
clean partition of warm vs fallback-to-cold checks in any "warm" aggregate.

**What to build.**
- In the analysis script, join paired per-query records and bucket:
  {both-decided, z3-only, axeyum-only, neither}. Report timing on both-decided
  only, and report the unknown split as a separate correctness/robustness figure.
- Sweep the per-solve timeout (e.g. 50/100/250/1000 ms) and show the ratio's
  sensitivity to it. Use the existing `SOLVE_TIMEOUT` constant / config.
- Separate warm from fallback: the `[axeyum-warm]` footer already reports
  `path-cap-fallbacks` and `assertion-cap-fallbacks`; exclude those checks from
  the "warm" latency bucket and report them as their own line.
- Use `IOCTLANCE_SOLVE_BUDGET`/`IOCTLANCE_SOLVE_SECS` + the fixed-work boundary
  (`examples/ioctlance.rs`, the deterministic function-count bound) so runs are
  reproducible and the query set is invariant across the timeout sweep.

## 4. Does axeyum-driven analysis find the same bugs? (critical)

**Problem.** `different-model` is enormous (tcpip: 25,097 of 31,651 both-SAT).
Shadow mode pins the stream to z3's models, but in real *axeyum-authoritative*
use, divergent models change address concretization -> exploration -> the
**vulnerability findings themselves** (documented swing: vwififlt 55/19 with z3
vs 91/36 with axeyum). "0 verdict disagreements" is necessary but not sufficient:
if the tool's *output* depends on the solver, the paper must confront it.

**Evidence / action required.** **End-to-end finding-parity**: run glaurung for
real (each backend authoritative, not shadow) and compare the produced
vulnerability reports per driver. Either they match, or the paper characterizes
and bounds the divergence (and argues neither backend misses true positives).

**What to build.**
- Run `ioctlance` with each backend as the sole solver (drop
  `GLAURUNG_SHADOW_DIFF`), capture the `[by-kind]` finding sets and the detailed
  sink list, and diff them per driver.
- Root-cause divergences to `concretize_addr` model choice (already known). Then
  make concretization a **configurable model-selection policy** (a pluggable
  `ConcretizationPolicy` at `concretize_addr`/`eval_concrete`; the call site is
  already tagged `glaurung-any-address-v1`, and `glaurung-min-unsigned-v1` exists
  as a second policy per axeyum ADR-0236), then sweep it: a canonical policy
  (least-unsigned/lexicographic) makes backends concretize identically and
  removes the confound, while a `BoundarySet`/diverse policy can be *both*
  deterministic and higher-coverage. Show the finding-parity sweep across
  policies (design + rationale: axeyum repo
  `docs/research/08-planning/axeyum-glaurung-pareto-strategy.md`, Pillar A). This
  is the honest fix and turns the confound into a measured result.
- Report a finding-parity table: {driver, z3 findings, axeyum findings,
  symmetric difference, root cause}. This is arguably a *stronger* result than
  timing and belongs in the paper body.

## 5. Isolate axeyum's contribution from glaurung's scheduling (major)

**Problem.** The real-driver win comes from lineage + serial-sibling + adaptive
admission + replay-cache + owner-transfer (ADRs 010-020, ~40 commits) -- most of
which is *glaurung explorer* engineering co-designed with the solver. A reviewer
will ask what part is **axeyum's reusable contribution** vs a bespoke
integration another embedder could not replicate.

**Evidence / action required.** A clean decomposition of the speedup into
solver-side vs integration-side factors, and a statement of what a generic
consumer inherits for free vs must build.

**What to build.**
- An ablation ladder on one driver: {z3-cold} -> {axeyum-cold} ->
  {axeyum-warm-lineage} -> {+serial-sibling} -> {+replay-cache} ->
  {+owner-transfer} -> {+model-completion gate}. The `lineage_gate.py` policies
  already expose each as a flag/env -- run them and attribute the delta per
  layer. You have the artifacts (`lineage-adaptive-*.json`); assemble them into
  one ablation figure.
- Explicitly label each rung "axeyum-provided" (e.g. incremental CNF-root fusion,
  `assert_configured`, replay cache) vs "glaurung-provided" (path lineage,
  serial leasing, admission control). The paper's axeyum claim rests only on the
  former; the latter is the application's contribution.

## 6. Generality: one tool, one arch, one query shape (major)

**Problem.** All evidence is glaurung + x64 Windows IOCTLance + a small,
extract/concat-heavy, register-slice QF_BV distribution -- exactly axeyum's sweet
spot. The paper says "binary analysis"; the evidence supports "this workload."

**Evidence / action required.** axeyum's standing on a **neutral benchmark set
(SMT-COMP QF_BV)** vs z3/bitwuzla, and at least one **second axis** of the real
workload.

**What to build.**
- Run axeyum and z3 on the SMT-COMP QF_BV division (or a stratified sample) and
  report where axeyum wins/loses generally. If it is generally slower but faster
  here, state the scope precisely: "on the small-formula, high-reuse distribution
  of binary symbolic execution."
- Add a second real axis: either the AArch64 driver path (needs the
  detection-layer port -- out of scope for the solver but names the frontier), or
  a second consumer/tool issuing QF_BV, or a non-driver glaurung workload
  (overflow/UAF passes on Linux binaries). Even one more axis blunts "cherry-
  picked distribution."
- Characterize the distribution quantitatively (width histogram, op mix, formula
  size, prefix-reuse depth) so a reader can judge transferability. The capture
  corpus (`capture/`) already has much of this -- surface it as a figure.

## 7. Cold-path gap and warm-hit rate are under-reported (major)

**Problem.** On the deduped corpus axeyum is ~1.34x *slower* one-shot, with
bit_blast+cnf = 84% of cold time. The warm headline can hide that the core solver
still trails z3 on non-incremental queries, and that some real checks never get
warm reuse.

**Evidence / action required.** Honest cold-path reporting **and** the
**warm-hit rate**: fraction of real checks that actually reuse retained state vs
fall back to cold one-shot.

**What to build.**
- Report the cold corpus result (1.34x slower) in the paper body, not a footnote,
  with the phase attribution (CNF/bit_blast/SAT/model-lift) from the existing
  native profiler (`GLAURUNG_AXEYUM_PROFILE_DIR`).
- Instrument and report per-run: `warm checks` / `total checks`, and within warm,
  exact-reuse vs prefix-delta vs full-rebuild. The `[axeyum-warm]` footer has the
  raw counters; compute the rate and put it next to every speedup.
- State the implication plainly: the warm win applies to the (large) reusable
  fraction; the cold fraction is where the roadmap (CNF/bit_blast micro-opt) still
  matters.

## 8. Correctness TCB and oracle circularity (major)

**Problem.** Differential-vs-z3 cannot certify correctness, you *also* use z3 as
the speed baseline (circular), and the concat bug proved z3 silently returns
wrong answers on malformed input. DRAT certifies only the CNF layer; the
term->CNF reduction is trusted unless the end-to-end faithfulness miter runs.

**Evidence / action required.** A stated **trusted computing base**, the
**frequency the faithfulness miter is actually run**, and **multi-oracle**
differential validation rather than z3 alone.

**What to build.**
- Add bitwuzla and cvc5 as differential oracles (via the pipe path) so
  agreement is 3-way, not axeyum-vs-z3. Report any query where axeyum agrees with
  bitwuzla/cvc5 but not z3 (candidate z3-adapter bugs like the concat one).
- Quantify proof coverage: run `certify_qf_bv_unsat_end_to_end` (the miter) on a
  sample of UNSAT results and report the fraction end-to-end-certified vs
  CNF-only-DRAT. State the TCB explicitly (translator + CNF encoder trusted;
  SAT/DRAT checked).
- Add differential fuzzing: random well-typed QF_BV term generator ->
  {axeyum, z3, bitwuzla} -> assert 3-way verdict agreement. Report queries fuzzed
  and bugs found. This backs the correctness claim independently of the workload.

## 9. Latent emission bugs -> numeric stability (major)

**Problem.** Three soundness bugs (empty-model, extension-width, concat-width)
surfaced *during* the study; at least one made z3 silently wrong. A fair reviewer
worries the current numbers sit on a fourth undiscovered emission bug.

**Evidence / action required.** The assurance argument that today's results are
stable, and "strict typing found N bugs" promoted to a **first-class result with
methodology**, not an anecdote.

**What to build.**
- Turn the fuzzer from #8 into a standing gate: it is exactly what would have
  caught all three width-contract bugs pre-emptively. Report coverage (which IR
  constructs/widths are exercised) and run it to a fixpoint (no new
  disagreements for K rounds).
- Write the bug-find story up as a methods contribution: for each of the three,
  give the malformed shape, why z3 masked it, how axeyum's strict sort surfaced
  it, and the fix. This is the paper's most defensible novelty -- lead with it.
- Add a regression corpus (the archived `*-shadow-split` corpora already exist)
  and assert zero recurrence in CI.

## 10. Deployability claims must be measured (minor/polish)

**Problem.** "Pure-Rust / no-C / WASM / proof-carrying" are asserted as
advantages but not exercised. Memory is a hidden cost: lineage raises RSS 6-31%
-- the speed is bought with memory.

**Evidence / action required.** A measured instantiation of each claimed
capability.

**What to build.**
- **WASM:** build the solver to wasm32 and report a latency number on a sample of
  the corpus (even 2-5x slower than native is fine -- the point is it *runs*
  where libz3 cannot). axeyum is already wasm-buildable; capture one data point.
- **Memory:** publish the time/memory Pareto for the warm policies (the
  `lineage_gate.py` artifacts already record median RSS per policy). Show the
  speed is a deliberate memory trade, with the knee (9 paths / 512 assertions,
  ADR-0177) justified.
- **Proofs:** give one concrete downstream use -- e.g. a glaurung "infeasible
  path" verdict that attaches and re-checks a DRAT certificate -- so
  "proof-carrying" is a demonstrated capability, not a latent feature. If none
  exists yet, either build a minimal one or downgrade the claim to "supports".

---

## Suggested experiment order (fastest path to a defensible submission)

1. **#3 + #2 harness first** (per-query paired data + fixed-work runs) -- it is
   prerequisite plumbing for everything else and cheap.
2. **#1 warm-z3 baseline** -- the single biggest credibility fix.
3. **#4 finding-parity + canonical model policy** -- converts a threat into a
   result.
4. **#8/#9 multi-oracle fuzzer** -- backs correctness independently and future-
   proofs the numbers; promote the three bug-finds to the lead narrative.
5. **#5 ablation, #6 SMT-COMP + 2nd axis, #7 cold/warm-rate, #10 deployability**
   -- fill out generality and honesty.

Correctness is the paper's spine; performance is a supporting, carefully-scoped
result once the baseline and statistics are fixed.
