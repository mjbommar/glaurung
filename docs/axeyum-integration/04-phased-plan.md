# 04 - Phased plan

Sequenced small-unit-first: a walking skeleton that proves the whole flow
before any code coupling, then the real native backend, then default, then
performance, then the Android use case. Each phase has explicit entry and
exit criteria; a phase is not "done" until its acceptance test is green.
No phase ships a solver that can return a confident wrong answer - a slow
or `Unknown` axeyum is acceptable; an *incorrect* sat/unsat is never.

## Dependency graph

```
P0 ground-truth -> P1 text-bridge MVP -> P2 native backend -> P3 diff-oracle+proofs -> P4 default -> P5 perf/incremental
                                                                                                 |
   (glaurung-internal, parallel) -- AArch64 lift->BV --------------------------------------------+--> P6 Android reachability
```
The AArch64-lift work (P6 prerequisite) is glaurung-internal and does NOT
depend on axeyum; start it in parallel any time. (P1 is now the in-process
text bridge, not a subprocess pipe - see the P1 section.)

---

## P0 - Ground truth + scaffolding  (this doc set)

- Entry: none.
- Work: capture exact interfaces (done: `01`, `02`); create the docs; get
  the crate dep mechanism decided (`03`, `07` ADR-001).
- Exit: `02-interface-mapping.md` has a total, reviewed op-by-op table and
  the confirmed axeyum crate/type names; `07` records the dep + default
  decisions.

## P1 - In-process SMT-LIB text bridge (walking skeleton)

Goal: prove axeyum can answer glaurung's real queries end to end with
**minimal, in-process code and no term translator**, and stand up the
differential baseline. (Correction vs a first instinct: axeyum has **no
stdin SMT-LIB CLI**, only the `axeyum-bench` harness - so the pipe
*subprocess* route would require building a shim binary. The cleaner MVP
reuses glaurung's existing SMT-LIB serializer and axeyum's text frontend
*in process*.)

- Entry: `axeyum-ir` + `axeyum-solver` path/git dep resolves in glaurung's
  build (ADR-001); confirm edition-2024/rustc-1.88 floor is satisfied.
- Work:
  - New `axeyum_backend::AxeyumTextSolver` implementing `Solver`: reuse
    glaurung's `pipe::build_script` to render the `(pool, asserts)` into an
    SMT-LIB2 QF_BV string, call `axeyum_solver::solve_smtlib(&script,
    &SolverConfig::new().with_timeout(250ms))`, map `SmtLibOutcome.result`
    (`CheckResult`) -> `SolveResult`, and read the model via
    `solve_smtlib_get_model`/`get_value`.
  - Gate behind `solver-axeyum` (feature added here); wire a third arm in
    `solve()`.
  - (Optional even-lighter probe: a ~20-line axeyum stdin->`solve_smtlib`
    shim binary + `GLAURUNG_SMT_SOLVER` pointed at it - a true zero-code
    glaurung change, at the cost of subprocess overhead. Use only if the
    in-process bridge is blocked for some reason.)
- Exit / acceptance:
  - On a fixed query set, axeyum returns the **same sat/unsat** as z3 for
    100% of queries; any model it returns satisfies the formula
    (re-evaluated in glaurung's `Concrete` domain).
  - Captures the first differential-corpus snapshot for P3, and the first
    real axeyum-vs-z3 latency numbers (the R1 probe).
- Value even if we stopped here: a working, in-process, pure-Rust solver
  path with no libz3 (slower than the native term backend due to text
  serialization, but already shippable).
- Rollback: feature-gated; off by default, cannot affect existing builds.

## P2 - Native in-process backend

Goal: the real deliverable - `axeyum_backend.rs` linking axeyum, behind
`solver-axeyum` (not yet default).

- Entry: P1 green (flow validated); `02` mapping reviewed.
- Work:
  - Implement the total translator `Expr -> axeyum term` (memoized on
    `ExprId`), width-safe `Assert` truthiness (`term != 0@width` for true,
    `term == 0@width` for false), and result
    mapping to `SolveResult`/`Model` (`03` data-flow).
  - Add `solver-axeyum` feature + axeyum deps to Cargo.toml.
  - Unit tests: one per `Expr` variant (Const/Sym/Bin{10}/Un{2}/Cmp{6}/
    ZExt/SExt/Trunc/Extract/Concat/Ite), each asserting axeyum agrees with
    z3 on a small hand-built formula exercising that op at multiple widths
    (incl. W1, W8, W64, and a non-power-of-two width).
- Exit / acceptance:
  - Every op-variant unit test green (axeyum == z3 verdict; model
    satisfies).
  - The P1 differential corpus passes in-process (no subprocess).
- Rollback: feature-gated; off by default, cannot affect existing builds.

## P3 - Differential oracle in CI + proof retrieval

Goal: continuous z3-vs-axeyum agreement, and proof-carrying unsat.

- Entry: P2 green.
- Work:
  - Stand up a differential harness modeled on the existing Unicorn
    emulator oracle (`dev-oracle`): for each query, run both backends,
    assert verdict agreement and mutual model-satisfaction; a mismatch
    fails CI with the reproducing formula. Corpus = SMT-LIB QF_BV set +
    the IOCTLance planted-bug queries + P1/P2 snapshots (`06`).
  - Wire optional DRAT proof retrieval on `Unsat` (concrete-type method or
    stashed-on-struct, not a trait change - `03`).
- Exit / acceptance:
  - Differential CI green across the corpus.
  - A representative `Unsat` query yields a DRAT proof that an independent
    checker accepts.
- Rollback: harness is dev/CI-only; does not affect the shipped artifact.

## P4 - Make axeyum the default backend

Goal: the shipped build/wheel gets a real in-process pure-Rust solver.

- Entry: P3 green (correctness continuously verified).
- Work:
  - Add `solver-axeyum` to default features and to the wheel build.
  - Keep `solver-z3` out of defaults (opt-in perf backend). Update the
    `solve()` cascade to the `03` priority order.
  - Run the FULL glaurung symbolic suite + the IOCTLance parity corpus on
    the default (axeyum) build.
- Exit / acceptance:
  - IOCTLance parity maintained on the default build (same planted bugs
    detected as with z3).
  - Any query where axeyum is materially slower or returns `Unknown` is
    logged with its formula into a "perf-watch" list for P5; none is a
    correctness regression.
  - Wheel now ships with symbolic analysis working out of the box.
- Rollback: revert the default-feature change; z3/pipe paths untouched.

## P5 - Performance: incremental trait + optional hybrid fallback

Goal: exploit axeyum's incremental API and give a runtime escape hatch.

- Entry: P4 shipped; perf-watch list from P4 shows where it hurts.
- Work (each independently optional):
  - **Contract tranche landed (ADR-011):** an object-safe incremental solver
    trait (push/pop/assert/check/assume) now exists alongside one-shot `check`,
    with a direct-delta `IncrementalAxeyumSolver` implementation. It translates
    only newly asserted roots and retains solver state across checks.
  - **Next:** wire explorer-owned path deltas into that session behind an opt-in
    control. Keep the accepted snapshot/adaptive path as the default and
    rollback control until the ordered real-driver gate shows equal semantics
    and lower translation/snapshot work.
  - Optional runtime hybrid: when both `solver-axeyum` and `solver-z3` are
    compiled in, try axeyum first and fall back to z3 on per-query
    timeout/`Unknown`.
- Exit / acceptance:
  - Measurable solve-time reduction on the benchmark corpus (report the
    number) with zero correctness regression on the P3 differential CI.
- Rollback: incremental trait is additive; hybrid is feature+config gated.

## P6 - AArch64 / Android IOCTL reachability (G4)

Goal: the concrete payoff - decide reachability of a driver bug from an
AArch64 `.ko`.

- Entry: the AArch64 lift->symbolic-BV path exists (glaurung-internal;
  see `05` - `lift_arm64.rs` must feed the `symbolic`/`exec` domain the
  way x86/iced does today); P2+ backend available.
- Work:
  - Feed `analysis::linux_ioctl`'s decoded `_IOC(dir,type,nr,size)` +
    input-buffer symbol as the symbolic inputs; build the path condition
    to the candidate bug site; solve with axeyum.
- Exit / acceptance:
  - On a test `.ko`: a known-**reachable** ioctl-guarded bug path resolves
    `Sat` with a concrete `_IOC`+input model; a known-**unreachable** path
    resolves `Unsat` and emits a DRAT proof.
- This is where axeyum + linux_ioctl + (later) the sepolicy oracle compose
  into a real Android reachability verdict.

---

## Estimating discipline

Deliberately no calendar estimates here - the units are small and
sequential by design (matching the operator's "small sequential units,
patient" habit). The gating unknowns that would move any estimate are all
in `05`: axeyum's QF_BV coverage/perf on glaurung's real formulas, and the
AArch64-lift effort. P1 exists precisely to measure the first cheaply
before committing to P2+.
