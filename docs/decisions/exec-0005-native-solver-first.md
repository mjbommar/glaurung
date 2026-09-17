# ADR-0005 — Historical native-Z3/pipe policy (superseded)

> **Kind:** decision · **Status:** maintained

> **Superseded in part by
> [solver-037](solver-037-axeyum-is-always-authoritative.md).** Axeyum is now
> the sole authoritative SAT/SMT backend. Z3 and pipe selection language below
> records the historical design, not current policy.

**ADR status:** Accepted; reversed once (2026-06) and extended once (2026-07) · **Date:** 2026-06

> **Revision note.** This ADR was originally "pipe first, native optional", and
> the file kept that name long after the decision flipped. The original argument
> — avoid a C/C++ build dependency in the base wheel — is satisfied by
> **feature-gating**, not by refusing native bindings. A native Rust engine
> should not shell out to a binary on `PATH`.

## Context

Symbolic execution needs a QF_BV solver. Three ways to get one: link a native
solver through a Rust crate; spawn a solver binary and speak SMT-LIB2 over a
pipe; or depend on a Python package that bundles a binary. Everything else in
the engine — interpreter, register file, memory, `Domain`, the `Expr` IR — is
in-process Rust.

## Historical decision

The following four points describe the pre-`solver-037` state only:

1. **One seam.** `pub fn solve(pool: &ExprPool, asserts: &[Assert]) -> SolveResult`
   in `src/symbolic/solver/mod.rs`. Backends implement `Solver`
   (`fn check(&mut self, pool, asserts) -> SolveResult`), and retained sessions
   implement the separate `IncrementalSolver` (`assert`/`push`/`pop`/
   `scope_depth`/`check`/`check_assuming`) added when the warm path landed.
2. **Native z3 was the preferred backend** (`solver-z3`, the `z3` crate linking
   libz3), translating the `Expr` DAG straight to z3 AST in-process.
3. **The SMT-LIB2 pipe was the zero-dependency fallback** (`PipeSolver`), trying
   `$GLAURUNG_SMT_SOLVER`, then `bitwuzla`, `z3`, `cvc5` on `PATH`.
4. **The base build stays lean by feature-gating, not by avoiding native code.**
   `default = ["triage-core"]` has no solver; `symbolic` builds the `Expr` IR and
   the pipe fallback with no link; each `solver-*` feature adds one backend.

## What happened next: the pure-Rust backend was built

This ADR's "On pure-Rust solvers" section said there was no mature pure-Rust SMT
solver competitive on QF_BV, and that bit-blasting to a pure-Rust SAT solver was
"a worthwhile future `Solver` backend". That backend now exists. `solver-axeyum`
binds [axeyum](https://github.com/mjbommar/axeyum) — a pure-Rust QF_BV solver by
the same author — in-process with no C dependency, pinned in `Cargo.toml` by git
rev. It is roughly 5,100 lines of adapter across
`src/symbolic/solver/axeyum_backend.rs` and `axeyum_backend/{config, profile,
snapshot, translate, warm_paths, warm_stats}.rs`, and it carries the retained
session, warm-path, and direct-delta machinery the one-shot trait cannot express.

Before `solver-037`, `solve()`'s cascade among enabled backends was
**z3 > axeyum > pipe**;
a fourth backend, `solver-bitwuzla`, binds the Bitwuzla 0.9.1 C API directly and
is deliberately excluded from selection — it exists only as a
topology-equivalent measurement cell
([`solver-031`](solver-031-pinned-bitwuzla-measurement-cell.md)).

Axeyum was *not initially* made the default. See
[`solver-002`](solver-002-axeyum-as-default-backend.md), which proposed exactly
that and is superseded.

## Alternatives rejected

- **Pipe-first or pipe-only** (the original decision) — couples the engine to a
  binary on `PATH` or a Python package. Demoted to fallback, kept because it is
  genuinely useful in build-constrained environments.
- **A Python `z3-solver` dependency** — helps wheel consumers only, does nothing
  for cargo consumers, and is not Rust-native.
- **Bitwuzla as the production native backend** — fastest on QF_BV, but the
  binding is thin and the C dependency is exactly what the shippability goal is
  trying to avoid. It became a benchmark cell instead.

## Current wheel (superseded by solver-037)

The ordinary wheel now ships the pure-Rust Axeyum backend because
`default = ["triage-core", "solver-axeyum"]`. `solver-axeyum` implies
`symbolic`, which implies `exec`; `python-ext` adds the bindings. No external
solver process or C solver library is part of that production path. Explicit
`--no-default-features` builds may omit Axeyum and then fail closed with
`NoSolver`.

## Consequences

- (+) In-process, Rust-API solving; deterministic; consistent with the engine.
- (+) Caching and independence live in our code over the `Expr` IR
  (`solver/constraint_cache.rs`), independent of which backend answers.
- (−) `solver-z3` adds a libz3 link and build time — bounded by the gate.
- (−) z3's `Context` is `!Send + !Sync`, so one context per worker thread. The
  warm paths in the axeyum backend are thread-local for the same reason.
- (−) Optional comparison backends require separate build lanes.
  `scripts/feature-build-gate.sh` type-checks them, including the explicit
  `solver-pipe-oracle` subprocess transport; ordinary `python-ext` builds
  compile authoritative Axeyum through the default feature set.

→ [`architecture/solver-backends.md`](../architecture/solver-backends.md),
[`design/execution-engine-research/smt-backends.md`](../design/execution-engine-research/smt-backends.md)
