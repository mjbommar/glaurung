# Solver backends

> **Kind:** architecture · **Status:** maintained

The symbolic engine has exactly one place where a path condition becomes a
verdict, and four things that can answer it. This page describes that seam, the
four backends, what each one costs to build, and the two diagnostic modes that
exist to keep any performance claim honest.

Everything here was checked against the tree at `b8884687`; commands are in the
"verified with" notes.

## The seam

```rust
// src/symbolic/solver/mod.rs
pub type Assert = (ExprId, bool);          // arbitrary-width truthiness
pub fn solve(pool: &ExprPool, asserts: &[Assert]) -> SolveResult;
```

`SolveResult` is `Sat(Model) | Unsat | Unknown(SolveUnknownReason) | NoSolver |
Error(String)`. `NoSolver` is a graceful no-op, not a failure: a build with no
backend still runs the explorer, it just cannot prune.

`Assert` is a *bit-vector* truthiness pair, not a boolean: `expected = true`
requires a nonzero value at the expression's own width, `false` requires zero.
That is deliberate — branch predicates are 1-bit, but concretization and probe
callers assert wider terms, and collapsing everything to `Bool` at the seam would
lose the width a backend needs. See
[`solver-009`](../decisions/solver-009-arbitrary-width-assertion-truthiness.md).

Two traits sit under it:

| Trait | Shape | For |
|---|---|---|
| `Solver` | one method: `check(&mut self, pool, asserts) -> SolveResult` | stateless one-shot checking; every backend implements it |
| `IncrementalSolver` | `assert`, `push`, `pop`, `scope_depth`, `check`, `check_assuming` | a genuinely retained session driven by assertion *deltas* — it never receives the whole snapshot, and a session is exclusive to one explorer owner |

`IncrementalSolver` was added after the fact; [`solver-005`](../decisions/solver-005-one-shot-solver-trait-first.md)
deliberately shipped only the one-shot trait first.

Verified with `rg -n 'pub fn solve|pub trait (Solver|IncrementalSolver)|pub type Assert' src/symbolic/solver/mod.rs`.

## Backend priority

Among the backends a build actually enables, `solve()` picks **z3 > axeyum >
pipe**:

```rust
#[cfg(feature = "solver-z3")]                                  → Z3Solver
#[cfg(all(not(solver-z3), feature = "solver-axeyum"))]         → AxeyumSolver / warm path
#[cfg(all(not(solver-z3), not(solver-axeyum)))]                → PipeSolver
```

This is a compile-time cascade, not a runtime probe: enabling `solver-z3` means
z3 answers, full stop. `solver-bitwuzla` is **never** in the cascade at all.

`PipeSolver` is the only backend that resolves anything at runtime. It tries, in
order, `$GLAURUNG_SMT_SOLVER`, then `bitwuzla`, `z3`, `cvc5` on `PATH`, spawning
the first that starts and speaking SMT-LIB2 over its stdin/stdout. A candidate
that is not installed is skipped; when none starts, the result is `NoSolver`.

## The four backends

| Feature | Backend | Links | Build requirement |
|---|---|---|---|
| `solver-z3` | `z3_backend::Z3Solver` — translates the `Expr` DAG straight to z3 AST in-process | libz3, via the `z3` crate **0.12** | a system libz3 (`libz3-dev`) |
| `solver-axeyum` | `axeyum_backend::AxeyumSolver` — translates to `axeyum-ir` terms and solves with `IncrementalBvSolver`; DRAT-checked unsat proofs | nothing (pure Rust) | network access to the pinned git rev |
| `solver-axeyum-text` | `axeyum_backend::AxeyumTextSolver` — renders SMT-LIB2 via `pipe::build_script` and calls axeyum's `solve_smtlib`; kept as a cross-check | nothing | implies `solver-axeyum` plus `axeyum-solver/full` |
| `solver-bitwuzla` | `bitwuzla_backend::BitwuzlaSolver` — binds the official Bitwuzla **0.9.1** C API directly | libbitwuzla | `BITWUZLA_LIB_DIR` must point at the pinned 0.9.1 library, or `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1` for a link-free `cargo check`; `build.rs` fails closed and rejects any other linked version |
| *(none)* | `pipe::PipeSolver` | nothing | a solver binary on `PATH` at run time |

Every `solver-*` feature implies `symbolic`, which implies `exec`. None of them
is in `default` or in `python-ext`, so **the shipped wheel has no solver** — and
no symbolic engine at all.

axeyum is [`github.com/mjbommar/axeyum`](https://github.com/mjbommar/axeyum), a
pure-Rust QF_BV solver by the same author, consumed as two crates
(`axeyum-solver` with `default-features = false, features = ["qfbv"]`, and
`axeyum-ir`) pinned by git rev `c38a9515e68e7427b1a41a7598805cf60686bd58`.
Production stays on that minimal QF_BV surface deliberately — see
[`solver-025`](../decisions/solver-025-explicit-qfbv-profile.md); only the text
bridge opts into the full profile.

`solver-bitwuzla` deserves its explicit exclusion restated: it exists **only** as
a topology-equivalent neutral measurement cell, so that a warm-versus-cold regime
map can be tested against an in-process solver that is neither of the two project
participants. Making it authoritative would defeat its purpose, and its C
dependency is exactly what axeyum's deployability claim is trying to avoid
([`solver-031`](../decisions/solver-031-pinned-bitwuzla-measurement-cell.md)).

Verified with `sed -n '/^\[features\]/,/^\[/p' Cargo.toml`,
`rg -n 'z3 = |axeyum-(solver|ir) = ' Cargo.toml`, and
`rg -n 'BITWUZLA_LIB_DIR|PINNED_API_VERSION' build.rs src/symbolic/solver/bitwuzla_backend.rs`.

## Budgets

| Constant / var | Value | Meaning |
|---|---|---|
| `DEFAULT_SOLVER_BUDGET` | `(6_000, 24)` | per function: max solves, max timeouts. The explorer bails when either is exceeded. |
| `DEFAULT_CHECK_TIMEOUT_MS` | `250` | per-check wall clock shared by every in-process backend; override with `GLAURUNG_CHECK_TIMEOUT_MS` (1–60,000, validated, panics on a bad value rather than silently defaulting). |
| `GLAURUNG_Z3_RLIMIT`, `GLAURUNG_AXEYUM_PROGRESS_CHECK_LIMIT`, `GLAURUNG_BITWUZLA_TERMINATION_POLL_LIMIT` | unset | deterministic per-backend *work* limits, as opposed to wall clocks. |

The timeout count is the interesting half of the budget: a function whose
formulas keep timing out is an obfuscation signal, and abandoning it cheaply is
the intended behaviour rather than a failure.

## Diagnostic modes

Two env-gated modes exist because a solver comparison is very easy to get wrong.

**`GLAURUNG_SHADOW_DIFF=1`** (requires both `solver-z3` and `solver-axeyum`) runs
**both** backends on every query, alternating which goes first to cancel
warm-cache bias, counts agreements, disagreements and unknown-splits separately,
and returns **z3's** answer authoritatively so the query stream and path lineage
are identical to a z3-only run. Its stricter sibling `GLAURUNG_FAIR_SHADOW` runs
a four-cell rotation (z3 cold, z3 warm, axeyum cold, axeyum warm), extended to
six cells when `solver-bitwuzla` is also built
([`solver-023`](../decisions/solver-023-four-cell-solver-control.md),
[`solver-031`](../decisions/solver-031-pinned-bitwuzla-measurement-cell.md)).
Unknown and error counts are tracked per backend on purpose: a backend that gets
"faster" by *not deciding* must be visible as such.

**`GLAURUNG_DUMP_QUERIES=<dir>`** publishes every decided query as
`<sha256>.smt2` and appends `<sha256>\t<verdict>` to `index.tsv`. Bytes are
published collision-safely before the index observation, so a partially written
capture is detectable. The sibling `GLAURUNG_DUMP_SHADOW_SPLITS=<dir>` captures
only the occurrences where exactly one backend decided. This is how
`tests/corpora/axeyum-qfbv/` was built; the procedure is in
[`tests/corpora/axeyum-qfbv/README.md`](../../tests/corpora/axeyum-qfbv/README.md).

Verified with `rg -n 'GLAURUNG_SHADOW_DIFF|GLAURUNG_FAIR_SHADOW|GLAURUNG_DUMP_QUERIES|GLAURUNG_DUMP_SHADOW_SPLITS|DEFAULT_SOLVER_BUDGET|DEFAULT_CHECK_TIMEOUT_MS' src/symbolic/solver/mod.rs`.

## One sentence about performance

An earlier version of this work claimed axeyum was **12–29× faster than z3**;
that was wrong, and the cause was un-coerced width mismatches making axeyum
*error out* on roughly 98% of queries rather than solve them — the retraction and
its evidence are in
[`history/axeyum-integration-2026-07/PAPER-NOTES.md`](../history/axeyum-integration-2026-07/PAPER-NOTES.md).
Any performance claim from here on requires a 100%-decided, 100%-agreed gate,
original-model replay, and same-stream timing. The method that satisfies those is
in [`bench/axeyum/README.md`](../../bench/axeyum/README.md); the results are
files beside it, and they predate the current axeyum pin.

## Adjacent contracts

- **Term translation, operator by operator:**
  [`solver/interface-mapping.md`](solver/interface-mapping.md). This is a live
  contract, not a plan — `axeyum_backend/translate.rs:63` cites it from source.
- **Which model value becomes a concrete value:**
  [`solver/concretization-policy.md`](solver/concretization-policy.md), decided by
  [`solver-026`](../decisions/solver-026-concretization-as-a-policy.md) and
  selected by `GLAURUNG_CONCRETIZATION_POLICY`. The explorer, not the policy,
  keeps ownership of every checked solve and every trace record.
- **Why a raw symbolic sink is not a finding:**
  [`solver/taint-provenance.md`](solver/taint-provenance.md), and the
  confidence partition behind `IOCTLANCE_ANNOTATE_CONFIDENCE`
  ([`solver-027`](../decisions/solver-027-preserve-taint-provenance.md),
  [`solver-028`](../decisions/solver-028-finding-confidence-partition.md)).
- **The engine that produces the queries:**
  [`execution-engine.md`](execution-engine.md).
- **All 31 solver decisions with their rejected alternatives:**
  [`decisions/`](../decisions/README.md).

## Examples and gates

`Cargo.toml` declares nine examples with `required-features`; they are the only
way to run a backend end to end.

| Example | Requires |
|---|---|
| `ioctl_scan`, `ioctlance` | `symbolic` |
| `ordered_native_replay`, `linux_symbolic_cve`, `axeyum_infeasible_path_proof` | `solver-axeyum` |
| `axeyum_diff`, `axeyum_bench_primitives`, `axeyum_sweep`, `axeyum_incremental` | `solver-z3`, `solver-axeyum` |

`scripts/feature-build-gate.sh` type-checks `solver-z3`, `solver-axeyum`,
`solver-axeyum-text`, `solver-bitwuzla`, `solver-z3,solver-axeyum` and
`--all-features` with `cargo check --all-targets`. It exists because none of
those trees is compiled by `cargo test --features python-ext`, and three backends
once sat uncompilable for seventeen days before anyone noticed: `BinOp::LogicalAnd`
and `BinOp::LogicalOr` were added to the IR on 2026-07-31 and no backend's
exhaustive match was updated, which `114a5c4c` ("solver: fix all three backends,
and gate the 11 feature configurations nobody built", 2026-08-17) fixed together
with the gate. Run the gate before pushing anything that touches a backend.

## Landmark commits

The work described here is on `master`; the branches the design notes named
(`sec/axeyum-backend`, `axeyum-concretization-policy-a0`, `sec/ioctlance-parity`)
were merged and deleted, so cite these instead.

| Commit | Date | What landed |
|---|---|---|
| `b000ff15` | 2026-07-13 | the pure-Rust axeyum backend: native translator, text bridge, DRAT proofs |
| `4ae96cfd` | 2026-07-17 | the fair four-cell solver tracing, and the wide-constant fix in the z3 adapter |
| `9ace0640` | 2026-07-17 | bounded direct-delta timeout continuation on by default inside direct sessions |
| `e98c0902` | 2026-07-18 | the complementary site-hash model policies |
| `07ea0c16` | 2026-07-18 | the behaviour-preserving `ConcretizationPolicy` seam |
| `845239f0` | 2026-07-18 | taint provenance preserved through symbolic loads |
| `931d8a84` | 2026-07-18 | findings partitioned by confidence |
| `2961d7c1` | 2026-07-19 | the pinned Bitwuzla measurement cell |
| `114a5c4c` | 2026-08-17 | all three backends compile again; the 11-configuration feature gate |
