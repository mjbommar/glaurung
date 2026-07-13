# 00 - Motivation and goals

## The gap this closes

Glaurung's symbolic-execution engine (the IOCTLance-parity line of work:
`src/symbolic/`, `src/exec/`) reasons about bit-vector path conditions and
must ask a solver "is this satisfiable, and if so give me a model." It
reaches the solver through one small trait:

```rust
pub trait Solver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult;
}
```
(`src/symbolic/solver/mod.rs`).

Two backends exist:

- `z3_backend::Z3Solver` - in-process, but **links libz3 (C/C++)**, gated
  behind the `solver-z3` cargo feature, and **deliberately excluded from
  the shipped Python wheel** (the Cargo.toml comment: "engine / native
  solver stay opt-in ... Never shipped in the wheel").
- `pipe::PipeSolver` - shells out to an external solver process over
  SMT-LIB2. Works anywhere, but needs an external binary present and pays
  subprocess + text-serialization cost per solve.

Two facts compound here (both verified in `Cargo.toml`):
- The symbolic engine is gated behind the `symbolic` feature, which is
  **not** in `default` and **not** pulled by `python-ext` (the wheel pulls
  only `exec`, the pure-Rust emulator). So the shipped wheel has no
  symbolic engine at all today.
- The only *in-process* solver (`solver-z3`) links **libz3 (C/C++)**, so
  even turning `symbolic` on for the wheel would drag a C dependency into
  an otherwise pure-Rust artifact.

The gap, precisely: **there is no pure-Rust in-process solver, and that is
the blocker to ever shipping the symbolic engine in the pure-Rust wheel /
default build.** Axeyum removes exactly that blocker.

## Why axeyum specifically

Axeyum (`~/projects/personal/axeyum`, workspace version 0.1.0, edition
2024) is a pure-Rust SMT/SAT solver whose profile is a near-exact fit for
glaurung's stated architecture principles:

| glaurung principle | axeyum property |
|---|---|
| "pure Rust, no C/C++ in the default build" | axeyum default build is pure Rust, no C |
| WASM-buildable core | axeyum builds to WebAssembly |
| "checkable evidence" (models verified, unsat proof-backed) | axeyum `unsat` carries a **DRAT-checked proof** |
| hash-consed BV IR, explicit widths, total lowering to QF_BV | axeyum is QF_BV-complete (full scalar op set, widths to 2^16) |
| pluggable solver behind a trait | axeyum is a linkable crate; implements the trait in-process |

It also already exposes the incremental primitives glaurung's explorer
would benefit from (`IncrementalBvSolver`: push/pop/assume,
assumption-core pruning, all-SAT `block_model`, symbolic memory) - see
`02-interface-mapping.md` for how much of that we consume now vs later.

## Goals (in priority order)

1. **G1 - Pure-Rust in-process solver, wheel-shippable.** A pure-Rust
   `axeyum_backend` implementing `Solver`, so the symbolic engine can be
   compiled with a real in-process solver and **no C dependency** - making
   it feasible (separately, if desired) to add `symbolic` to the wheel
   build without libz3. Out of the box, no external process.
2. **G2 - Correctness parity with z3 on glaurung's queries.** For every
   query glaurung issues, axeyum returns the same sat/unsat verdict as z3
   (models may differ but must both satisfy). Enforced by a differential
   oracle (`06-validation-and-ci.md`), mirroring the existing Unicorn
   emulator oracle.
3. **G3 - Proof-carrying unsat.** When a reachability query is `Unsat`
   (a bug path is infeasible), surface axeyum's DRAT proof as optional
   evidence, so "path X cannot be reached" is checkable, not asserted.
4. **G4 - Android/AArch64 reachability.** Enable the IOCTL-constraint
   satisfiability use case on AArch64 driver objects (composes with
   `analysis::linux_ioctl`). Gated on the separate AArch64-lift work
   (`05-risks-and-open-questions.md`), not on the solver swap itself.

## Non-goals (explicit)

- **NG1 - Not replacing z3 wholesale.** z3 stays as an opt-in
  `solver-z3` performance backend. Axeyum becomes the *default*; z3 is the
  escape hatch for queries axeyum is slow/unknown on. (See `07` ADR-002.)
- **NG2 - Not merging the executors.** Axeyum has its own
  `SymbolicExecutor`/BMC/k-induction layer; glaurung has its own
  `explore.rs`. We integrate **only at the SMT-query seam** (glaurung
  builds path conditions, axeyum decides them). We do not adopt axeyum's
  executor, and glaurung does not expose axeyum's BMC layer. (ADR-003.)
- **NG3 - Not blocking on performance parity.** Axeyum's own docs are
  honest that it is not yet a perf-parity Z3 replacement. G1-G3 are about
  correctness, shippability, and evidence; perf is tracked as an open gate
  (`05`), not a launch blocker - the fallback policy (ADR-002) makes slow
  axeyum queries fall back to z3 when z3 is compiled in.
- **NG4 - Not changing the `Solver` trait contract in Phase 1.** The MVP
  honors the existing one-shot `check` contract. An *incremental* trait
  extension to exploit axeyum's push/pop is a later, opt-in phase (`04`
  Phase 5), not part of the initial landing.

## Success definition

The integration is "done for v1" when: axeyum is the default in-process
solver in the shipped build (G1); the differential-oracle CI is green
across the QF_BV corpus and the IOCTLance planted-bug set (G2); and unsat
reachability results can emit a checkable DRAT proof (G3). G4 lands when
the AArch64-lift gap closes and one real AArch64 driver query resolves
end-to-end.
