# 03 - Target architecture

## The seam (unchanged)

Integration happens at exactly one place: a new backend implementing the
existing trait.

```rust
// src/symbolic/solver/mod.rs  (existing)
pub trait Solver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult;
}
```

Nothing above the trait changes for v1. `explore.rs` and the rest of the
symbolic engine keep calling the free `solve(pool, asserts)` dispatcher;
we add a compile-time branch that selects axeyum.

## Module + crate layout

```
glaurung/
  src/symbolic/solver/
    mod.rs            # trait + solve() dispatcher (edited: add axeyum branch)
    z3_backend.rs     # unchanged (feature solver-z3)
    pipe.rs           # unchanged (SMT-LIB2 subprocess fallback)
    axeyum_backend.rs # NEW: impl Solver via linked axeyum crates
  Cargo.toml          # NEW feature `solver-axeyum`; axeyum path/git deps
```

`axeyum_backend.rs` owns:
1. a translator `ExprPool + &[Assert] -> axeyum QF_BV formula` (the total
   op mapping in `02-interface-mapping.md`);
2. the `Solver::check` impl that builds the formula, calls axeyum, and
   maps the result back to `SolveResult` / `Model`;
3. (Phase 3+) optional DRAT-proof retrieval on `Unsat`.

## Dependency wiring

Axeyum is another of the author's Rust workspaces. glaurung depends only
on the crates needed for QF_BV solving (confirmed set finalized in
`02`; expected: the solver entry crate + the term-IR crate, e.g.
`axeyum-solver`, `axeyum-ir`/`axeyum-bv`). Mechanism, in order of
preference:

- **Path dependency** during co-development (both repos are local under
  the same account): `axeyum-solver = { path = "../../axeyum/crates/axeyum-solver" }`.
  Simplest, no publish step, but couples the two checkouts' locations.
- **Git dependency pinned to a rev** once axeyum's API for this use is
  stable: reproducible, decoupled from local paths, still no crates.io.
- **crates.io** only if/when axeyum publishes; not required.

Edition/MSRV: both are edition 2024 (axeyum MSRV rust 1.88) - no toolchain
conflict. License: both MIT/Apache-2.0 dual - compatible, no notice
churn.

## Backend selection

Today `solve()` is a compile-time cascade:

```rust
#[cfg(feature = "solver-z3")]
let result = z3_backend::Z3Solver::new().check(pool, asserts);
#[cfg(not(feature = "solver-z3"))]
let result = pipe::PipeSolver::new().check(pool, asserts);
```

Target cascade (priority: an explicitly-requested perf backend, else the
default pure-Rust one, else the zero-dep fallback):

```
if solver-z3         -> Z3Solver        (opt-in perf backend)
else if solver-axeyum-> AxeyumSolver    (DEFAULT in the shipped build)
else                 -> PipeSolver      (zero-dep fallback)
```

`solver-axeyum` is added to the crate's **default features** (and to the
wheel build) so the shipped artifact gets a real in-process solver.
`solver-z3` stays out of defaults. See `07` ADR-002 for the fallback
policy (why not runtime auto-fallback in v1).

Optional later refinement (Phase 5): a runtime hybrid where axeyum is
tried first and a per-query timeout/`Unknown` falls back to z3 when both
are compiled in. Deferred because it needs both backends linked and a
runtime selection layer the current compile-time cascade does not have.

## Data-flow of one `check` call

```
explore.rs
  -> solve(pool, asserts)            # (ExprId, bool) predicates over ExprPool
    -> AxeyumSolver::check
       1. new axeyum context
       2. for each ExprId reachable from asserts:
            translate Expr node -> axeyum BV term   (02, total mapping)
            (memoize by ExprId, mirroring the pool's interning)
       3. for each (ExprId, expected) assert:
            assert  term(ExprId) == const(expected, width 1)
       4. axeyum check-sat
       5. map: Sat -> collect model over Sym ids -> Model{BTreeMap<u32,u128>}
               Unsat -> SolveResult::Unsat  (+ optional DRAT proof, Phase 3)
               Unknown/timeout -> SolveResult::Unknown
               translation/engine error -> SolveResult::Error(msg)
```

Notes:
- The translator memoizes on `ExprId` so glaurung's hash-consing is
  preserved into axeyum (no term blow-up on shared subexpressions).
- `Model.values` is keyed by `Sym.id` (u32) and valued as `u128`, so
  models faithfully carry widths <= 128. Wider symbolic vars are a known
  limitation (`05`); binary IOCTL inputs are <= 64-bit in practice.
- Every glaurung `Expr` variant has a standard QF_BV image
  (`Div->bvudiv`, `Shr->bvlshr`, `Sar->bvashr`, etc.), so translation is a
  total function with no "unsupported op" path - failures can only be
  engine-level (timeout/resource), which map to `Unknown`.

## Proof plumbing (Phase 3)

On `Unsat`, axeyum can produce a DRAT proof. We thread it as optional
side-evidence WITHOUT widening the `Solver` trait's return in v1: either
(a) `AxeyumSolver` stashes the last proof on the struct for a caller that
wants it, or (b) a separate `check_with_proof` method on the concrete type
(not the trait). The reachability/verdict layer that consumes it (and,
downstream, agentic-security-bot's citation requirement) can then attach
"infeasible - DRAT-checked" to a negative reachability claim. Trait-level
proof return is an ADR to revisit if more than one backend can produce
proofs.

## What explicitly does NOT change

- The `Solver` trait signature (v1).
- `explore.rs`, `symdomain.rs`, `ioctl.rs` call sites.
- `z3_backend.rs`, `pipe.rs`.
- The Python bindings' view of symbolic analysis (the backend is an
  internal detail; if the wheel previously shipped without a solver, it
  now ships with one - a capability gain, not an API change).
