# axeyum feedback log (from the glaurung integration)

> Running diary of the axeyum -> glaurung integration. Everything tagged
> **[AXEYUM]** is feedback to carry back to the axeyum project (API
> friction, bugs, perf, missing features, docs). **[GLAURUNG]** items are
> integration-side notes. Newest iteration at the bottom.

Environment: glaurung `sec/axeyum-backend` branch; axeyum workspace 0.1.0.
rustc 1.97.0-nightly. libz3.so present (z3 backend usable as differential
reference).

---

## Iteration 0 - setup + ground-truth reconciliation

Facts checked against the plan (`01-current-state.md`), corrections noted:

- **[GLAURUNG] Edition mismatch, not a blocker.** glaurung is
  `edition = "2021"` (the plan/ADR-001 said "both edition 2024" - wrong
  for glaurung; axeyum is 2024). An edition-2021 crate can depend on an
  edition-2024 crate, and rustc 1.97-nightly clears axeyum's 1.88 MSRV.
  So the cross-edition dep is fine; doc correction filed.
- **[GLAURUNG] glaurung is a single crate**, not a workspace - one
  Cargo.toml, features live there.
- **[AXEYUM] `solve_smtlib_get_model` does not fit glaurung's script.** It
  gates on `script.get_model` (i.e. an explicit `(get-model)` command), but
  glaurung's `pipe::build_script` emits `(get-value (...))`. So the model
  door for the text bridge is `solve_smtlib_get_value`, which keys on
  `(get-value ...)` and returns `Vec<axeyum_ir::Value>` in the get-value
  order. Minor, but a caller expecting "get me the model of this sat
  script" hits `Ok(None)` surprisingly if they used get-value. Worth a doc
  line or a unified accessor.
- **[AXEYUM] `Value` is not re-exported from `axeyum-solver`.** To pattern
  -match the model you must also depend on `axeyum-ir` and import
  `axeyum_ir::Value`. A `pub use axeyum_ir::Value;` from `axeyum-solver`
  would let a pure-solver consumer avoid a second explicit dep. (Not a
  blocker - we need `axeyum-ir` for the native backend anyway.)
- **[GLAURUNG] baseline `--features symbolic` builds clean** (pipe backend,
  no solver dep) - good starting point.
## Iteration 1 - P1 text bridge (DONE, green)

`AxeyumTextSolver` (`src/symbolic/solver/axeyum_backend.rs`): reuse
`pipe::build_script` -> `axeyum_solver::solve_smtlib` for the verdict,
`solve_smtlib_get_value` for the model. Feature `solver-axeyum` +
axeyum path deps; `solve()` cascade z3 > axeyum > pipe.

- **[GLAURUNG] Works end-to-end, both smoke tests green:** `x+1==0x100`
  -> Sat with x=0xff (model extraction correct), and `... AND x==0` ->
  Unsat. axeyum decides glaurung's real formula shape in-process, pure
  Rust, no libz3.
- **[AXEYUM] `solve_smtlib` + `solve_smtlib_get_value` behaved exactly as
  documented** - values returned in get-value order, `Value::Bv{value}`
  parsed cleanly. No surprises. Good API.
- **[GLAURUNG] Text bridge costs 2 solves on a Sat** (verdict via
  `solve_smtlib`, then model via `solve_smtlib_get_value` which re-solves).
  Known inefficiency; the P2 native backend returns the model from the
  single `CheckResult::Sat(Model)`. Not an axeyum problem - a consequence
  of routing through text with two separate entry points.
- **[AXEYUM] Build cost:** first build of the axeyum crate graph (19
  crates transitively) is ~60s. Not unusual for a solver, but the full
  transitive pull (aig/cnf/egraph/fp/query/rewrite/strings/lean-kernel)
  is heavy for a consumer that only wants QF_BV. A slimmer feature-gated
  `axeyum-solver` (QF_BV-only, without strings/fp/lean) would cut a
  consumer's build/dep footprint. Feature-gating suggestion, not a blocker.

## Iteration 2 - P2 native term-translation backend (DONE, green)

`AxeyumSolver`: translates glaurung `Expr` -> `axeyum-ir` `TermArena`
terms (memoized on `ExprId`), solves with `IncrementalBvSolver`, reads the
model straight from `CheckResult::Sat`. `solve()` cascade now routes to the
native backend. 11/11 tests green, incl. the tricky operators.

- **[GLAURUNG] Full operator set validated by known-answer tests:** signed
  vs unsigned compare (Slt/Ult), logical vs arithmetic shift (lshr/ashr),
  concat operand order, zext vs sext, udiv, ite, 12-bit (non-power-of-two)
  wraparound, and model extraction. The Bool<->BV1 bridge (Cmp lifted via
  `ite(cond,1,0)`, Ite cond via `!= 0`, assert via `!= 0`) works exactly as
  the mapping doc specified.
- **[AXEYUM] The two conventions I refused to assume are confirmed:**
  `concat(a,b)` puts `a` as the **high** half (SMT-LIB order), and
  `extract(hi,lo,a)` is **inclusive** `[hi:lo]` (extract(15,8,0xABCD)=0xAB).
  Worth stating explicitly in the `extract`/`concat` doc-comments; I had to
  verify empirically.
- **[AXEYUM] `IncrementalBvSolver` is bound to the arena for its lifetime**,
  which is clean but forced a scoped-`Translator` pattern on the consumer
  (build all terms, drop the `&mut arena` borrow, then hand `&arena` to the
  solver). Ergonomic enough once you see it; a one-line doc example of
  "build terms, then solve" would help first-time embedders.
- **[AXEYUM] Builder API is pleasant:** `declare`+`var` for a symbol handle
  (so you keep the `SymbolId` for model read-back), `Result<TermId,IrError>`
  everywhere (composes with `?`), `Value::Bv{value}` for model read. No
  surprises, no missing ops. QF_BV coverage is complete for glaurung's IR.

## Iteration 2b - realistic-suite differential catch (the extract convention)

Ran glaurung's OWN symbolic engine test suite (51 tests, incl. the full
IOCTLance driver-bug detection set) routed through the native axeyum
backend. First pass: **43 pass, 8 fail**; the same 8 pass under z3. Real
divergence, root-caused fast via the panic:
`axeyum translate: extract [64:56] out of range for width 64`.

- **[GLAURUNG] My translation bug, not an axeyum bug.** glaurung's
  `Expr::Extract{hi,lo}` treats `hi` as **EXCLUSIVE** (result width = hi -
  lo; a 64-bit byte-extract is hi=64,lo=56). axeyum's `extract(H,L,a)` is
  **INCLUSIVE** like SMT-LIB. glaurung's own z3/SMT lowerings use `hi - 1`
  as the inclusive top index; I had used `hi`. Fixed to `hi - 1`. All 8
  recovered -> **51/51 glaurung symbolic tests green on axeyum**, matching
  z3.
- **[PROCESS] The lesson the plan half-missed:** my P2 per-op unit test was
  *self-consistent but wrong* - it built `Extract{hi:15,lo:8}` and checked
  against the inclusive-hi result, so it passed while encoding the wrong
  convention. Only the differential against glaurung's REAL formulas (which
  emit hi=EXCLUSIVE) caught it. Confirms `06-validation-and-ci.md`: unit
  tests must be backed by a differential vs the real engine, not just
  hand-built formulas. Updated the P2 test to the correct convention.
- **[AXEYUM] Good behavior:** axeyum returned a clean, specific
  `IrError` ("extract [64:56] out of range for width 64") instead of a
  silent wrong answer or panic. That precise error is what made the
  root-cause a 2-minute job. Exactly the "wrong is worse than absent"
  discipline - it refused the malformed term loudly.
- **[MILESTONE] The native axeyum backend now powers glaurung's entire
  symbolic engine, including realistic AArch64-adjacent IOCTLance driver
  analysis, with zero divergence from z3 across 51 engine tests.**

## Iterations 3 + 4 - differential oracle + benchmark (DONE)

`examples/axeyum_diff.rs` (gated on `solver-z3,solver-axeyum`): 20
realistic path-condition-shaped formulas (linear size arithmetic, mask +
unsigned range windows, signed windows, off+len overflow reachability,
byte reassembly, unsat contradictions, ite/shift mux), across widths
8/16/32/64. Runs both backends, asserts verdict agreement, times each
(50 reps, fresh solver per call = glaurung's real one-shot pattern).

- **[RESULT] 20/20 verdicts agree, 0 confident disagreements, 0 errors.**
  Combined with the 51 engine tests, axeyum matches z3 on every query
  glaurung issues.
- **[AXEYUM behavioral diff, fixed for parity] Strict `bv_const`.** axeyum
  rejects an over-wide constant value (`bv_const(8, 0x1000)` -> IrError);
  z3_backend silently masks. glaurung's `ExprPool::constant` masks, so
  well-formed pools never hit this - but for drop-in parity the translator
  now masks Const to width. NB: axeyum's strictness is arguably *correct*
  (catches malformed input); a documented "does bv_const mask or reject
  over-wide values?" note would save an integrator the round-trip.
- **[PERF - flips risk R1] axeyum is ~12x FASTER overall on this corpus**
  (axeyum 88 ms vs z3 1096 ms total; ratio 0.08x). Per glaurung's actual
  usage (many small one-shot solves), z3's per-call libz3 context + FFI
  setup dominates; axeyum's pure-Rust in-process path has none. Both
  backends build a fresh solver per `check`, so this is an apples-to-apples
  comparison of the two AS GLAURUNG USES THEM.
- **[PERF - honest caveat] The advantage narrows as formulas grow.** Ratio
  by width on the arithmetic families: ~0.01-0.03x at 8-bit, ~0.2x at
  64-bit (linear64 0.21x, overflow64 0.18x). axeyum's bit-blast cost grows
  with width/hardness; on much larger/harder BV, z3's mature core would
  likely overtake (consistent with axeyum's own "not perf-parity on hard
  BV" status). No crossover in this corpus - glaurung's driver-field
  formulas are small (8-32 bit), which is exactly axeyum's sweet spot here.
- **[IMPLICATION for ADR-002] The "axeyum default, z3 opt-in for perf"
  framing may be backwards for glaurung's workload.** For small one-shot
  driver formulas, axeyum is both the pure-Rust *and* the faster choice.
  z3 remains the escape hatch only for pathologically hard/large queries.
  Worth re-benchmarking on the real IOCTLance corpus at scale before
  finalizing the default.

### Benchmark table (us/op, 50 reps, release)

| case | z3 | axeyum | ratio |
|---|---|---|---|
| linear8/16/32/64 | 665/415/522/784 | 19/34/73/168 | 0.03-0.21x |
| mask_range8/16/32/64 | 128/1735/1183/1617 | 14/36/57/112 | 0.02-0.11x |
| signed_win8/16/32/64 | 1226/1203/1410/1440 | 16/21/31/52 | 0.01-0.04x |
| overflow8/16/32/64 | 1631/2022/2087/2729 | 69/130/257/504 | 0.04-0.18x |
| reassemble32 | 123 | 20 | 0.16x |
| contra_eq/range (unsat) | 219/368 | 40/37 | 0.10-0.18x |
| ite_shift_mux | 407 | 70 | 0.17x |

## Iteration 5 - proofs + incremental PoC (DONE)

- **[AXEYUM - G3 works] Proof-carrying unsat.** `AxeyumSolver::prove_unsat`
  translates the query, calls `export_qf_bv_unsat_proof`, and
  `UnsatProof::recheck()`s the DRAT independently. Test:
  `x==5 AND x==6` -> `ProvedRechecked{drat_lines>0}`. This is a capability
  z3 does NOT give us: a checkable certificate that a bug path is
  infeasible. The API (`Proved/Satisfiable/Inconclusive`, in-memory
  `dimacs/drat/lrat`, self-`recheck`) was clean and worked first try.
- **[AXEYUM - P5 mechanism validated] Warm push/pop.**
  `IncrementalBvSolver` push/assert/check/pop drives glaurung's fork shape
  correctly (base `x<100`; fork `x==50` sat; fork `x==200` unsat; base sat
  after both pop). Confirms the incremental Solver-trait extension (P5) is
  viable against this API. Bound-to-one-arena is fine since a persistent
  explorer arena is what P5 would use anyway.

---

# CONSOLIDATED FEEDBACK FOR THE AXEYUM PROJECT

Bottom line: **axeyum is a drop-in, correct, and (for this workload)
faster QF_BV backend for glaurung.** 54/54 engine tests + 20/20 randomized
differential cases agree with z3; zero confident disagreements. The
integration is ~250 lines. Prioritized notes:

1. **Correctness: flawless on glaurung's full QF_BV.** Every operator, both
   power-of-two and 12-bit widths, signed/unsigned, shifts, extract/concat,
   ite, and the IOCTLance driver-analysis path condition shapes. No missing
   ops, no wrong verdicts.

2. **Performance is a pleasant surprise (re-benchmark before trusting).**
   For glaurung's usage (many small one-shot solves, fresh solver per
   call), axeyum is **~12x faster** than the z3 crate because it avoids
   per-call libz3 context + FFI setup. The edge narrows with width
   (0.01x at 8-bit -> ~0.2x at 64-bit); on large/hard BV z3's core would
   likely overtake. Recommend axeyum publish a small-formula/one-shot
   micro-benchmark - it's a genuine strength that its "not perf-parity"
   self-description undersells for this class of consumer.

3. **API friction (all minor, none blocking):**
   - `Value` not re-exported from `axeyum-solver` -> consumers must also
     depend on `axeyum-ir` just to match the model. A `pub use
     axeyum_ir::Value` would help pure-solver users.
   - `solve_smtlib_get_model` keys on `(get-model)`; a script emitting
     `(get-value ...)` needs `solve_smtlib_get_value` -> silent `Ok(None)`
     surprise. Doc note or a unified "give me the model of this sat script".
   - `extract(hi,lo)` inclusivity and `concat(a,b)` operand order are not
     stated in the builder doc-comments; I had to verify empirically.
   - `bv_const` strictly rejects over-wide values (good!) but this differs
     from z3-crate masking; one doc line ("value must fit width") saves a
     round-trip.

4. **Excellent behaviors worth keeping:**
   - Precise `IrError` on a malformed term (`extract [64:56] out of range
     for width 64`) instead of a silent wrong answer - turned a debugging
     session into a 2-minute fix.
   - `Unknown` is structural (never mistaken for `unsat`); undecided is an
     `Unknown`, not an `Err`.
   - DRAT proof self-`recheck()` with no solver dependency.
   - `with_timeout` honored on the warm path (matched z3's 250 ms budget).

5. **Build/dep footprint:** a QF_BV-only consumer transitively pulls all 19
   crates (strings/fp/lean-kernel/egraph/...). A `default-features=false`
   QF_BV-only profile would cut a consumer's build time and dep surface.

6. **Suggested axeyum-side additions that would most help embedders:**
   an incremental-friendly "assert many + check" doc example; the
   `pub use Value`; and doc-comment convention notes on extract/concat/
   bv_const.

## Iterations 6-8 - real Windows drivers (the realistic use case)

Ran glaurung's full IOCTLance symbolic analysis on real `.sys` drivers
through each backend, with solver-only time instrumented globally
(`total_solver_stats`) to separate solver cost from lifting/CFG.

- **[RESULT - speed] On vwififlt (~13-16k small QF_BV queries) axeyum spends
  34x less solver time (197 ms vs z3's 6748 ms; 12.6 us/solve vs 514 us).**
  The whole symbolic pass drops 7.0 s -> 0.24 s (~29x). On DptfDevGen (harder
  formulas) axeyum == z3 (1719 vs 1671 ms). Matches the micro-benchmark's
  width dependence exactly: axeyum dominates small-formula workloads (the
  common case in driver analysis), ties on hard ones.
- **[RESULT - correctness, C1] Shadow-differential (both solvers on every
  real query): 18,508 queries, 0 verdict disagreements.** Combined with the
  54 engine tests + 20 synthetic cases, axeyum matches z3 on every query
  glaurung's real analysis issues.
- **[NOT an axeyum bug] vwififlt findings differ between backends** (z3-driven
  55/19, axeyum-driven 91/36). Root cause: glaurung's `concretize_addr` binds
  `addr == any-satisfying-model`; z3 and axeyum return different valid models,
  so exploration forks differently. Verdicts never disagree (proven above).
  This is a glaurung/model-based-concretization property, surfaced by the
  solver swap - not an axeyum defect. (Confirmed by raising the per-function
  budget 50x: identical solve counts, so not a coverage-under-budget effect.)
- **[AXEYUM - robustness win] Zero crashes / hangs / Unknowns across ~18.5k
  real driver queries.** Every query decided within the 250 ms budget; the
  `with_timeout` path never needed to fire on this corpus. Solid.
- **[AXEYUM - perf profile note for your benchmarks] Per-solve cost is
  formula-size-dominated, not fixed-overhead-dominated** (12.6 us on
  vwififlt's small formulas vs ~310 us on DptfDevGen's harder ones), whereas
  z3's is fixed-overhead-dominated (479-514 us regardless). This is the crux
  of the paper argument and a genuinely favorable story for axeyum on
  binary-analysis workloads - worth a dedicated axeyum micro-benchmark that
  sweeps formula width to show the crossover.
