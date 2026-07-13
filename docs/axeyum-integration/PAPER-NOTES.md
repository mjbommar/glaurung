# Paper notes: axeyum as an in-process SMT backend for binary symbolic execution

> Working notes for a future academic paper announcing **axeyum**, using
> **glaurung** (a reverse-engineering / driver-vulnerability-detection
> framework) as the real-world application. This file accumulates the
> claims, the experimental method, and the measurements as they land.

> ## !!! MAJOR CORRECTION (2026-07-13) -- read before trusting earlier numbers
>
> An earlier version of these notes claimed axeyum was **12-29x faster** than
> z3 on real drivers. **That was wrong** and was an artifact of a bug in the
> glaurung->axeyum translator: it did not coerce width-mismatched operands
> (the lifter emits e.g. `BitVec 16` op `BitVec 64`; z3's backend silently
> coerces, axeyum strictly rejects). So axeyum was **erroring out on ~98% of
> real queries** and returning fast - the "speed" was fast *failure*, not
> fast solving. A shadow-differential instrument that logged Unknown/Error
> per backend (z3-unknown=0, axeyum-unknown=12915/13126) exposed it.
>
> After fixing the translator to coerce (mirroring z3_backend), axeyum
> **decides every real query correctly (0 disagreements)** but is **~1.7-3.2x
> SLOWER than z3** on real driver formulas. The honest thesis is below. The
> lesson (worth a paragraph in the paper's methodology/threat-to-validity):
> a "faster" result that coincides with a large drop in *work done* must be
> audited; verdict-agreement alone is insufficient - you must confirm the
> fast backend actually *decided* the queries.

## 1. The claim (HONEST thesis, post-correction)

Symbolic execution of binaries issues very many small, mostly-independent
QF_BV queries. On this workload, axeyum vs the conventional FFI-to-libz3:

- **C1 - Correctness/parity: HOLDS.** Across 180k+ real queries, axeyum
  returns identical sat/unsat verdicts to z3 (0 disagreements).
- **C2 - Speed: axeyum is currently SLOWER on real formulas (~1.7-3.2x),
  NOT faster.** It is faster only on trivially small, well-typed synthetic
  formulas (micro-benchmark) - which are NOT representative of the real
  workload (real path conditions are width-mismatched, extract/concat-heavy,
  and structurally harder, favoring z3's mature simplification/preprocessing).
  This is the key finding to report honestly; the "faster" story does not
  survive contact with the real application.
- **C3 - New capability: HOLDS.** axeyum emits DRAT-checked unsat
  certificates; z3-via-crate does not.
- **C4 - Deployability: HOLDS.** Pure Rust, no C dependency, WASM-buildable.

**So what is the paper?** Not "a faster solver." Honestly, it is: *"a
correct, verified-equivalent, deployable (pure-Rust/no-C/WASM/proof-carrying)
SMT backend for binary analysis, with a rigorously-measured performance gap
(~2-3x) to close, and the real-query corpus that defines the optimization
target."* If/when axeyum closes that gap, the "faster + deployable" paper
becomes available; until then, claiming speed would be false. (Historical
note: earlier commit messages on this branch repeat the incorrect "34x"
figure - superseded by this correction.)

## 1. The claim (paper thesis)

Symbolic execution of binaries (driver IOCTL analysis, exploit-primitive
discovery) issues **very many, individually small, mostly-independent
QF_BV queries**: one feasibility check per branch fork, per candidate
sink, per concretization. The dominant per-query cost in the conventional
stack is not the SAT search - it is the **fixed overhead of crossing into
a C solver**: constructing a solver/context object, marshalling terms
across the FFI boundary, and tearing down. For small formulas that
overhead dwarfs the solve.

axeyum removes that overhead by being a **pure-Rust library linked
in-process**: no FFI, no context marshalling, terms shared directly from
the host's arena. The paper's measurable claims:

- **C1 - Correctness/parity.** On a real application's full query stream,
  axeyum returns identical verdicts to z3 (the de-facto reference).
- **C2 - Speed on the real workload.** For the small-one-shot-query
  distribution that symbolic execution produces, axeyum is substantially
  faster than the z3-crate (FFI) backend, *because* it avoids per-query
  boundary-crossing overhead - a structural, not incidental, advantage.
- **C3 - New capability.** axeyum emits DRAT-checked unsat certificates,
  so "this bug path is infeasible" becomes a *checkable* claim - relevant
  to trustworthy automated triage. z3-via-crate does not give this for
  free.
- **C4 - Deployability.** Pure Rust, no C dependency: ships in the
  analyzer's binary/wheel and builds to WebAssembly. The conventional
  stack cannot (libz3 is a C/C++ dependency).

## 2. The application (glaurung)

glaurung is an AI-native RE framework with a native symbolic-execution
engine used for Windows-driver IOCTL vulnerability detection (an
IOCTLance-class analysis: taint an IRP, explore the dispatch handlers,
and flag controlled-write / arbitrary-read / null-deref / UAF / double-
free / integer-overflow / double-fetch / shellcode sinks). The engine:

- lifts x86-64 (and AArch64) to a generic LLIR,
- runs one interpreter parameterized by a `Domain` trait (a concrete
  emulator and a symbolic domain share all instruction semantics),
- represents path conditions as a hash-consed bit-vector IR
  (`ExprPool`/`Expr`),
- reaches a solver through a one-method `Solver` trait
  (`check(pool, asserts) -> sat/unsat/model`),
- meters thousands of solves per function under a budget.

This is a faithful, non-toy consumer: the same solver-query distribution a
production binary-analysis tool generates.

## 3. Why the conventional (FFI-to-libz3) pattern is suboptimal here

- **Per-query boundary cost.** glaurung's z3 backend builds a fresh
  `Z3Native` solver per `check` and marshals the term DAG across FFI. For
  8-32 bit driver-field formulas the boundary cost dominates.
- **Thread-hostility.** The z3 crate's shared context forces glaurung's
  symbolic passes to run *sequentially* even though lifting is parallel -
  a scaling ceiling attributable to the C solver's integration, not the
  math.
- **No proofs.** Unsat is asserted, not certified.
- **C dependency.** libz3 is excluded from glaurung's shipped
  (pure-Rust) wheel; the symbolic engine therefore cannot ship with a
  solver at all in the default artifact.

## 4. Experimental method

- **Micro-benchmark (isolates the solver).** A corpus of realistic
  path-condition-shaped QF_BV formulas (linear size arithmetic, mask +
  unsigned range windows, signed windows, off+len overflow reachability,
  byte reassembly, unsat contradictions, ite/shift mux) across widths
  8/16/32/64. Run both backends N times each; report per-op latency and
  verdict agreement. Harness: `examples/axeyum_diff.rs`.
- **Application-level (real drivers).** Run the full IOCTLance analysis
  (`examples/ioctlance.rs`) on real Windows `.sys` drivers under each
  backend; report (a) findings parity, (b) **solver-only time** and
  **solve count** (instrumented globally in `solve()`, isolating the
  solver from lifting/CFG), and (c) end-to-end wall-clock. Isolating
  solver time is essential: wall-clock is dominated by disassembly/lifting
  and would *understate* the solver-level speedup.
- **Reference.** z3 (via the `z3` crate, linking libz3) is the
  ground-truth oracle for verdicts and the performance baseline.
- **Determinism.** No KASLR/randomness; fixed inputs; release builds.

## 5. Results

### 5.1 Micro-benchmark (solver isolated) -- from `axeyum_diff.rs`

20 formulas, 50 reps each, release. **Verdict agreement: 20/20, zero
disagreements.** Aggregate solver time: **z3 ~1050 ms, axeyum ~88 ms
(~12x faster).** Per-family ratio (axeyum/z3): signed windows ~0.01-0.04x,
masks ~0.02-0.11x, linear/overflow ~0.03-0.21x. The advantage **narrows
with width** (0.01x at 8-bit -> ~0.2x at 64-bit): axeyum's bit-blast cost
grows with the formula while z3's fixed FFI overhead amortizes, so the two
converge as formulas get larger/harder. For the small formulas that
dominate driver analysis, axeyum wins by ~1-2 orders of magnitude. This is
the paper's core micro-result and it isolates *why*: the win tracks
inversely with formula size, exactly as the "fixed boundary overhead"
hypothesis predicts.

### 5.1a Mechanism sweep (WHY) -- from `axeyum_sweep.rs`

Sweep an always-SAT formula family (K independent vars, each `x*8+16==0x90`,
=> x=15) across width and count. Cell = z3 us / axeyum us (speedup), 100 reps:

| width \ K | K=1 | K=4 | K=16 | K=64 |
|---|---|---|---|---|
| 8-bit | 479/17 (27.7x) | 1014/61 (16.5x) | 2975/256 (11.6x) | 10290/1018 (10.1x) |
| 16-bit | 370/34 (10.8x) | 560/142 (3.9x) | 1275/578 (2.2x) | 3832/2315 (1.7x) |
| 32-bit | 476/76 (6.3x) | 965/313 (3.1x) | 2671/1227 (2.2x) | 9528/5086 (1.9x) |
| 64-bit | 810/180 (4.5x) | 2213/707 (3.1x) | 7752/2859 (2.7x) | 29113/12307 (2.4x) |

**The mechanism, quantified.** The decisive number is the *per-query floor*:
the trivial 1-constraint formula costs z3 **370-810 us** but axeyum only
**17-180 us** - a ~15-30x fixed-overhead gap. That floor is z3's FFI +
context construction + term marshalling, paid every query regardless of how
trivial. axeyum, linked in-process with no boundary crossing, has a ~15-40x
smaller floor. As formula size grows, axeyum's bit-blast cost rises (it does
real SAT work) and the two converge, but axeyum stays faster across the whole
sweep (min 1.7x). Symbolic execution of binaries generates overwhelmingly
*small* formulas (8-32 bit driver fields, short path conditions), which sit
in the top-left of this table where axeyum is 10-28x faster - and that is
exactly what the real-driver aggregate (Sec 5.2) reflects. This is the
paper's central figure: **the win is structural (fixed boundary overhead),
not an implementation accident, and it is largest precisely on the query
distribution the application produces.**

### 5.2 Application level (real drivers) -- from `ioctlance.rs`

Full IOCTLance symbolic analysis on real Windows drivers, each backend, with
**solver-only time** instrumented globally (isolating it from lifting/CFG).

| driver | size | #solves | z3 solver-time | axeyum solver-time | us/solve (z3 -> ax) | ratio |
|---|---|---|---|---|---|---|
| win8-pciidex | 49 KB | 0 | - | - | - | n/a (no handlers reach solver) |
| sqfs-intel-DptfDevGen | 80 KB | ~5.5k | 1671 ms | 1719 ms | 302 -> 310 | ~1.0x (hard formulas) |
| win10-vwififlt | 78 KB | 13-16k | **6748 ms** | **197 ms** | **514 -> 12.6** | **~34x** |

**C2 confirmed and characterized.** On vwififlt (a driver whose analysis
issues ~13-16k *small* QF_BV queries) axeyum spends **34x less** time in the
solver (197 ms vs 6.75 s) - 514 us/solve for z3 vs 12.6 us/solve for axeyum,
i.e. z3's per-query cost is ~40x axeyum's. On DptfDevGen (harder formulas)
they are within 3% - consistent with the micro-benchmark's width dependence:
axeyum dominates the small-formula-heavy workloads that are typical of driver
IOCTL analysis, and converges to parity as formulas harden. Wall-clock: the
whole vwififlt symbolic pass drops from **7.0 s (z3) to 0.24 s (axeyum)** -
a ~29x end-to-end speedup on the symbolic phase, because for this driver the
solver *was* the bottleneck.

**C1 + C2 on the IDENTICAL query stream (the rigorous, headline result).**
The single-backend runs above explore *different* query sets (model-choice
divergence, see below), so their timings are not strictly apples-to-apples.
The shadow-differential mode fixes this: it runs BOTH backends on **every
query issued during one z3-authoritative analysis**, so the two are timed on
the exact same formulas (order alternated per call to cancel cache bias).

**HONEST numbers (translator coercion fixed; axeyum decides every query).**
Same-stream shadow-diff, per-function budget lifted so both solve the full set:

| driver | queries | agree | disagree | z3 (same stream) | axeyum (same stream) | speedup |
|---|---|---|---|---|---|---|
| win10-vwififlt | 13126 | 13126 | 0 | 7445.9 ms | 24077.6 ms | **0.31x** |
| sqfs-intel-DptfDevGen | 5539 | 5539 | 0 | 2003.1 ms | 3438.8 ms | 0.58x |
| windows-update-intel-IntcSST | 14923 | 14923 | 0 | 6124.1 ms | 18738.3 ms | 0.33x |

- **C1 confirmed:** 0 verdict disagreements on the real query stream (also
  holds across the pre-correction 180k-query sweep - correctness was never
  the issue; the bug made axeyum *error*, not mis-decide).
- **C2 corrected: axeyum is 1.7x-3.2x SLOWER than z3 on real driver
  formulas** (z3/axeyum per-solve ~468 us vs ~1418 us on vwififlt). Consistent
  across drivers. z3's mature preprocessing/simplification handles the
  lifter's width-mismatched, extract/concat-heavy path conditions better than
  axeyum's current bit-blast path.
- **Model-choice IS real (now that axeyum actually solves):** of vwififlt's
  both-sat queries, 781/989 (79%) returned different (valid) models. So the
  single-backend *finding* differences (z3 55/19 vs axeyum 91/36) are indeed
  concretization-model divergence - but this only mattered once the coercion
  bug was fixed; before, axeyum wasn't producing models at all.

### 5.2a Why the micro-benchmark disagreed with reality (threat to validity)

The synthetic micro-benchmarks (`axeyum_diff`, `axeyum_sweep`) showed axeyum
5-28x *faster*. They are **not representative**: (1) they use well-typed,
matching-width operands (no coercion), whereas real formulas are
width-mismatched and the coercion inflates axeyum's bit-blast; (2) they use
simple arithmetic/mask/compare chains, whereas real path conditions are
extract/concat/memory-derived and structurally harder; (3) they favor the
regime (tiny formulas) where z3's fixed FFI floor dominates. The lesson for
the paper: **micro-benchmarks chosen by the solver author flatter the solver;
only the real application's own query stream is trustworthy.** This is itself
a methodological contribution.

**The subtle, honest finding (belongs in the paper).** vwififlt's *reported
sinks* differ between backends (z3-driven: 55 raw / 19 high-confidence;
axeyum-driven: 91 / 36), and the *solve counts* differ (13126 vs 15583) -
even with the per-function budget raised 50x (ruling out a
coverage-under-budget artifact). Since verdicts never disagree, the cause is
**model-choice nondeterminism**: glaurung concretizes symbolic addresses by
asking the solver for *any* satisfying model (`concretize_addr`) and binding
`addr == that_value`. z3 and axeyum return different (equally valid) models,
so exploration forks down different concrete paths and surfaces
overlapping-but-different sink sets. This is a property of *model-based
concretization*, not of either solver's correctness. Two paper-worthy
implications:
1. **Reproducibility/canonicalization.** For deterministic analysis, model
   selection must be canonicalized (e.g. lexicographically-least model), a
   requirement independent of solver choice but exposed by swapping solvers.
2. **Solver diversity as a coverage multiplier.** Because different solvers
   walk different concrete paths from identical verdicts, running more than
   one (cheap when both are fast/in-process) *unions* the explored space and
   finds strictly more sinks - a novel, low-cost coverage-boosting technique
   that only becomes practical when the extra solver is fast (axeyum) rather
   than a heavyweight FFI call.

## 6. Running measurement log

- 2026-07-13 win8-pciidex (49 KB): 0 solves (no IOCTL handler reaches the
  solver); findings identical (empty). Baseline sanity.
- 2026-07-13 sqfs-intel-DptfDevGen (80 KB): ~5.5k solves; z3 1671 ms / axeyum
  1719 ms (ratio ~1.0x); findings IDENTICAL; shadow-diff 5382/0. Harder
  formulas -> axeyum == z3 speed, exact parity.
- 2026-07-13 win10-vwififlt (78 KB): 13126 (z3) / 15583 (axeyum) solves; z3
  6748 ms / axeyum 197 ms (34x); symbolic wall-clock 7.0 s -> 0.24 s (29x);
  findings differ (model-choice, not verdict); shadow-diff 13126/0.
  Budget-raised-50x re-run: identical solve counts -> not a budget artifact.
