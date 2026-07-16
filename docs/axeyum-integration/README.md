# axeyum -> glaurung integration

> Plan for embedding **axeyum** (a pure-Rust SMT/SAT solver + prover) as a
> first-class solver backend for glaurung's symbolic-execution engine.
> This directory is the design record; it does not itself change code.

## One-paragraph summary

Glaurung's symbolic engine already talks to a solver through a small,
pluggable `Solver` trait (`src/symbolic/solver/mod.rs`). Today the only
in-process backend links **libz3** (C/C++, feature `solver-z3`) and is
out of default features and out of the wheel build (`python-ext` pulls
only the pure-Rust emulator); the fallback shells out over SMT-LIB2
(`pipe::PipeSolver`). Axeyum is a pure-Rust QF_BV solver with DRAT-checked
unsat proofs and a WASM-capable build. Adding an `axeyum_backend` that
implements the same `Solver` trait gives glaurung a **default,
always-available, pure-Rust (no-C), wheel-shippable, proof-carrying**
in-process solver, with z3 kept as an opt-in performance backend. The seam is tiny
(one trait method) and the operator mapping is total, so the risk is
concentrated in performance and QF_BV coverage, not in wiring.

## Why (the short version)

- **Shippability.** The symbolic engine has no solver in the default wheel
  today (z3 is opt-in + links C). Axeyum is pure Rust, so it ships.
- **Ethos match.** Both projects are "pure Rust, no C/C++ in the default
  build, WASM-buildable, checkable evidence." Axeyum's DRAT proofs feed
  glaurung's evidence culture (and the downstream agentic-security-bot
  rule "verdicts must cite").
- **Self-owned stack.** axeyum (reason) -> glaurung (RE + symbolic) ->
  agentic-security-bot (hunt orchestration) with no Z3 / Ghidra / IDA in
  the critical path.
- **Concrete driver.** The Android/AArch64 IOCTL-reachability use case:
  "is there an `_IOC(dir,type,nr,size)` + input buffer satisfying the path
  condition to reach the bug?" is a QF_BV satisfiability query. See
  `05-risks-and-open-questions.md` for the AArch64-lift gap that gates it.

## Reading order

| doc | what it answers |
|---|---|
| `00-motivation-and-goals.md` | Why do this, success criteria, non-goals |
| `01-current-state.md` | Exact ground truth: glaurung solver surface + axeyum public API (cited) |
| `02-interface-mapping.md` | glaurung `Expr` IR <-> axeyum term IR, op-by-op; trait <-> axeyum calls; model/proof mapping |
| `03-architecture.md` | Target design: crate boundary, feature flags, backend selection, proof plumbing |
| `04-phased-plan.md` | Sequenced build with per-phase entry/exit + acceptance tests |
| `05-risks-and-open-questions.md` | Perf gap, QF_BV coverage gaps, AArch64-lift gap, WASM, versioning, fallback policy |
| `06-validation-and-ci.md` | Differential oracle (reuse the Unicorn-oracle pattern), corpora, golden tests, proof checking |
| `07-decision-log.md` | ADR-style records of the load-bearing choices |

## Status

**Implemented and green (2026-07-16).** P1 (text bridge), P2 (native
term-translation backend), P3 (differential oracle), proofs (G3), and the P5
retained-session contract are landed on branch `sec/axeyum-backend`:

- `src/symbolic/solver/axeyum_backend.rs` - `AxeyumSolver` (native) +
  `AxeyumTextSolver` (bridge) + `prove_unsat` (DRAT). Feature
  `solver-axeyum`; `solve()` cascade z3 > axeyum > pipe.
- `examples/axeyum_diff.rs` - z3-vs-axeyum differential + benchmark.
- The native backend group is 41/41 green, including scopes, ephemeral
  assumptions, model lifting, proof replay, snapshot lineage, direct deltas,
  cache bounds, profiling, and fail-closed resource limits.
- The ordered real-driver controls establish the honest performance boundary:
  cold one-shot Axeyum remains slower than Z3 on lifter formulas, while retained
  path lineage can amortize lowering and beat Z3. The direct-delta explorer
  route is wired and measured behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. It wins
  against equivalent snapshot topology but fails the serial-snapshot production
  time/RSS gate, so ADR-012 keeps it opt-in.
- Findings + full feedback: `FEEDBACK-LOG.md`.

The earlier 12x one-shot claim was a fast-failure artifact caused by
width-invalid consumer terms; strict Axeyum checking exposed those soundness
bugs. Current performance claims therefore require a 100% decided/agreed gate,
original-model replay, and same-stream timing. Still pending: direct-delta P5
acceptance and safe automatic policy, broader driver/variance coverage, and the
AArch64/Android reachability endgame (P6).

Placement note: this lives in glaurung because glaurung is the integrator;
Axeyum supplies the additive retained-session contract, while ownership,
ordered capture, and production admission remain Glaurung responsibilities.
