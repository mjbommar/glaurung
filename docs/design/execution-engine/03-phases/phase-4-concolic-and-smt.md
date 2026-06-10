# Phase 4 — Concolic Execution & SMT Layer

**Goal:** add the `Symbolic` `Domain` (hash-consed bitvector AST) and a `Solver`
layer, so the **same interpreter** now builds path constraints alongside concrete
values and can solve for inputs. Specs:
[`symbolic-engine.md`](../02-architecture/symbolic-engine.md),
[`../01-research/smt-backends.md`](../01-research/smt-backends.md).

**Feature gate:** `symbolic` (= `exec` + the pipe solver; still no compiled C dep).

## Tasks

- **4.1 `symbolic/expr.rs`** — hash-consed `Expr` pool (interner) for typed
  bitvector terms (`Const`/`Sym`/`BinOp`/ext/trunc/extract/concat/ite/cmp).
  *Test:* structural sharing (equal terms → same id); width invariants.
- **4.2 `symbolic/symdomain.rs`** — `Symbolic: Domain`, `Val=(ExprId, u128)`
  (concolic: symbolic term + concrete shadow). `as_branch` uses the concrete bit
  to pick direction and signals `Fork` when the condition is input-tainted;
  `concretize_addr` applies the concretization strategy + records the binding.
  *Test:* running a block produces the expected `Expr` for each output (compare to
  the prototype's known terms).
- **4.3 `Solver` trait + `symbolic/solver/pipe.rs`** — `easy-smt` SMT-LIB2 pipe;
  `assert`/`push`/`pop`/`check_assuming`/`get_model`/`fresh`; defaults to the
  Bitwuzla binary, Z3 fallback; emits `(set-option :random-seed N)` for
  determinism. *Test:* solve a known constraint, get the expected model. (Skips
  gracefully if no solver binary is present — see note.)
- **4.4 Expr → SMT-LIB2 lowering.** Map the `Expr` pool to QF_ABV. *Test:* the
  prototype's `(ite (= (bvadd rax_sym 1) 0x100) …)` constraint solves to
  `rax_sym = 0xff`.
- **4.5 `symbolic/cache.rs`** — constraint **independence partitioning** +
  **counterexample cache** (subset/superset inference) + **taint gating**.
  *Test:* a query whose constraints are independent is split; a cached UNSAT
  subset short-circuits a superset.
- **4.6 Optional native backends** — `symbolic/solver/{z3,bitwuzla}.rs` behind
  `solver-z3`/`solver-bitwuzla`. *Test:* same solver test-suite passes through
  each backend (run in CI only where the dep is available).
- **4.7 Single-path concolic driver** — execute one concrete path, collect its
  path constraint, negate one branch, solve → a new input. (SAGE generational
  step; full exploration is Phase 5.) *Test:* on a tiny `if (x*7+3==52) bug()`
  fixture, recover `x==7`.

## Deliverables

- `src/symbolic/{expr,symdomain,cache}.rs`, `src/symbolic/solver/{mod,pipe}.rs`,
  optional native backends.
- A `concolic_step(binary, va, seed, symbolize)` entry point returning the path
  constraint + any solved alternative inputs.

## Exit criteria

- The same `step()`/`run()` drives both Concrete and Symbolic domains (no
  interpreter fork) — verified by a test that runs one block under both and checks
  the concrete shadow of the symbolic run equals the pure-concrete run.
- The pipe solver solves the fixture constraints to the expected models.
- A real, self-contained string-decrypt **branch** (e.g. a length/key check)
  yields a satisfying input. (Full string-decrypt application is Phase 7.)
- Caching demonstrably reduces solver queries on a multi-branch fixture.
- `cargo test --features symbolic` green (solver-dependent tests skip cleanly when
  no solver binary is installed).

## Note on solver availability (updated 2026-06-10)

Implemented **native-first** ([ADR-0005](../05-decisions/adr-0005-smt-pipe-then-native-optional.md)):
the `solver-z3` feature links libz3 in-process and is the primary backend; the
SMT-LIB2 pipe is the fallback. On the dev box, z3 + libz3 were installed via
`apt-get install -y z3 libz3-dev`, and native solving is verified.

The **pipe** backend's tests still skip cleanly (`SolveResult::NoSolver`) when no
solver *binary* is on PATH — useful for minimal environments. CI should build
with `solver-z3` (linked z3) for the native path and may additionally provide a
solver binary to exercise the pipe. The shipped wheel should link z3 via the `z3`
crate's `bundled`/`gh-release` (reproducible) rather than a system lib.
