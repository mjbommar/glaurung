# axeyum -> glaurung integration

> **Status: maintained integration index.** Axeyum is implemented as an opt-in,
> pure-Rust in-process backend behind `solver-axeyum`. It is not enabled by the
> default build or `python-ext`. Dated state, phase, benchmark, and paper pages
> retain historical evidence; current source and the latest decision-log entry
> take precedence.

## One-paragraph summary

Glaurung's symbolic engine routes solving through `Solver` and
`IncrementalSolver` contracts in `src/symbolic/solver/mod.rs`. The current
production-capable backends are native Z3 (`solver-z3`), native Axeyum
(`solver-axeyum`), and the subprocess SMT-LIB fallback. When both native
features are enabled, selection priority is Z3, then Axeyum, then the pipe
fallback. `src/symbolic/solver/axeyum_backend.rs` contains direct IR
translation, model lifting, proof support, retained sessions, and experimental
warm/direct-delta paths. Cargo pins the Axeyum Git revision.

Axeyum is wheel-shippable without a C solver dependency, but it remains opt-in.
The default feature set is `triage-core`; `python-ext` includes concrete
execution, not symbolic execution or a solver. Do not use the earlier target of
making Axeyum the default as a statement of shipped configuration.

## Current source gate: failing

On 2026-08-07 at Glaurung `fcca960b`, both current feature gates fail during
compilation:

```bash
cargo check --features solver-axeyum
cargo test --features solver-axeyum --lib symbolic::solver::axeyum_backend
```

`src/ir/types.rs` now defines `BinOp::LogicalAnd` and `BinOp::LogicalOr`, while
an exhaustive translator match in `src/symbolic/solver/axeyum_backend.rs` does
not cover them (`E0004`). This is a Glaurung integration/build blocker, not a
solver verdict. Default-feature and `python-ext` builds do not compile that
backend, so their focused gates can still pass independently. Rerun both
commands and update this section when the translator is brought back into sync.

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
| `08-concretization-policy.md` | A0 policy contract, configuration compatibility, trace IDs, and A3/A2 boundaries |
| `09-taint-provenance-and-finding-labels.md` | Why raw sinks are not finding ground truth; provenance correction and policy-sweep gates |

## Historical implementation and evidence status

**Implemented and green (2026-07-17).** P1 (text bridge), P2 (native
term-translation backend), P3 (differential oracle), proofs (G3), and the P5
retained-session contract are landed on branch `sec/axeyum-backend`:

- `src/symbolic/solver/axeyum_backend.rs` - `AxeyumSolver` (native) +
  `AxeyumTextSolver` (bridge) + `prove_unsat` (DRAT). Feature
  `solver-axeyum`; `solve()` cascade z3 > axeyum > pipe.
- `examples/axeyum_diff.rs` - z3-vs-axeyum differential + benchmark.
- The native backend group is 42/42 green, including scopes, ephemeral
  assumptions, model lifting, proof replay, snapshot lineage, direct deltas,
  cache bounds, profiling, and fail-closed resource limits.
- The ordered real-driver controls establish the honest performance boundary:
  cold one-shot Axeyum remains slower than Z3 on lifter formulas, while retained
  path lineage can amortize lowering and beat Z3. The direct-delta explorer
  route is wired and measured behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. It wins
  against equivalent snapshot topology but fails the serial-snapshot production
  time/RSS gate, so ADR-012 keeps it opt-in. ADR-013 adds exact copy-on-write
  source ancestry and safely restores serial sibling leasing; the new candidate
  passes the strict repeated two-driver production gate. The later exact tcpip
  gate admits one bounded timeout continuation only inside separately selected
  direct sessions. A complete `dxgkrnl` no-op replay is functionally exact but
  fails the standard timing-variance gate, so ADR-021 keeps direct delta
  opt-in. `win32k` is a system-service/callout frontend target, not zero-query
  IOCTL solver evidence.
- Findings + full feedback: `FEEDBACK-LOG.md`.

The earlier 12x one-shot claim was a fast-failure artifact caused by
width-invalid consumer terms; strict Axeyum checking exposed those soundness
bugs. Current performance claims therefore require a 100% decided/agreed gate,
original-model replay, and same-stream timing. Still pending: wider
direct-delta P5 acceptance, broader stable driver coverage, and the
AArch64/Android reachability endgame (P6).

Placement note: this lives in glaurung because glaurung is the integrator;
Axeyum supplies the additive retained-session contract, while ownership,
ordered capture, and production admission remain Glaurung responsibilities.

The A0 concretization refactor, provenance correction, and machine-readable
finding-confidence partition are isolated on branch
`axeyum-concretization-policy-a0` at `931d8a8`: `AnyModel` remains the default, all accepted
least/greatest/site-hash policies implement one `ConcretizationPolicy` seam,
and the preferred `GLAURUNG_CONCRETIZATION_POLICY` config coexists with the
legacy experiment variable. Boundary-set forking is A3 execution work;
deferred symbolic memory is the separate, conditional A2 architecture project.
Policy sweeps must report raw diagnostics separately from confidence-gated and
validated findings; the first-15 tcpip slice now has zero high-confidence rows
under both authorities after exact taint provenance is preserved. Opt-in
`IOCTLANCE_ANNOTATE_CONFIDENCE=1` supplies an exhaustive versioned partition
without changing legacy finding bytes.
