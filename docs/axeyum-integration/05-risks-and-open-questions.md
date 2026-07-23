# 05 - Risks and open questions

Ranked by how much each could move the plan. Each has a concrete
mitigation or a probe that resolves it cheaply (usually in P1).

## R1 - Performance gap (the main one)

Axeyum's own docs are explicit: it is **not yet a perf-parity Z3
replacement** ("decides a slice of real public QF_BV; performance is the
open gate"). Glaurung meters **thousands of solves per function**
(`DEFAULT_SOLVER_BUDGET = (6000, 24)`) with a 250 ms/solve z3 timeout, so
a slower solver directly shrinks coverage under the budget.

- Impact: lower coverage per function, more `Unknown` (counted as
  timeouts, which trip the budget sooner).
- **Sharpened by the one-shot trait.** axeyum's headline perf mitigation
  is *warm incrementality* (shared subterms bit-blasted once, learned
  clauses retained across related queries) - and glaurung's
  many-related-path-queries shape is exactly what that is built for. But
  the current `Solver::check` is one-shot: it re-passes the full path
  condition every call, so the v1 backend rebuilds a fresh arena+solver
  each time and gets **none** of the warm benefit. This makes P5 (the
  incremental trait, where glaurung push/pops as it forks) the real
  perf-viability lever, not a nice-to-have. On the one-shot path, expect
  axeyum to be at its worst relative to z3.
- Mitigation: (a) axeyum is the *default* for correctness/shippability,
  not the only option - `solver-z3` stays as the opt-in perf backend
  (ADR-002); (b) P5 hybrid fallback (axeyum-first, z3 on timeout) when both
  are linked; (c) P5 incremental API to reuse solver state across the
  many-solves-per-function pattern; (d) the engine already skips solves
  when a predicate shares no symbol with the path condition
  (`shares_symbols`) - axeyum inherits that for free.
- Probe: P1 measures real axeyum-vs-z3 latency on glaurung's actual
  formulas before any code coupling. This is the whole point of P1.

## R2 - QF_BV coverage on glaurung's real formulas

Glaurung emits a **narrow, well-characterized** QF_BV subset (`02`): 10
BinOps (unsigned div only, no rem/rotate), 2 UnOps, 6 CmpOps (lt/le only),
ZExt/SExt/Trunc/Extract/Concat/Ite, explicit widths, **no arrays, no UF,
no floats** (symbolic memory is *concretized*, never modeled as SMT
arrays). This is squarely inside axeyum's QF_BV wheelhouse - low risk on
*expressiveness*. The open question is width handling:

- Widths are arbitrary `u16` bit counts (not just powers of two). Extract
  can produce odd widths. Axeyum must accept arbitrary BV widths, not just
  8/16/32/64.
- Probe: P2's per-op unit tests deliberately include a non-power-of-two
  width (e.g. W1 and a W12/W48) for each operator.

## R3 - Width-coercion / well-typedness contract

The z3 backend **width-coerces** operands (`coerce`, `z3_backend.rs:98`)
because z3 rejects width mismatches; the pipe/`render_smtlib` path does
**not** coerce (it assumes the lifter produced width-consistent terms).

- Risk: if the lifter ever emits a subtly width-inconsistent term, z3
  silently coerces (hiding it) while axeyum might reject or mis-evaluate -
  a *divergence*, not necessarily a wrong answer, but it fails the
  differential oracle.
- Mitigation: the axeyum backend should mirror z3's `coerce` (normalize
  operands to each node's declared width) rather than assume
  well-typedness, so the two backends agree by construction. Documented as
  a translator requirement in `02`.
- Open question: is any lifter-emitted term actually width-inconsistent,
  or is `coerce` purely defensive? The differential oracle (P3) answers
  this empirically - any coercion that changes a result surfaces as a
  mismatch.

## R4 - Model width limitation (>64-bit symbols)

Both existing backends read models via `as_u64()`, silently dropping
symbol values wider than 64 bits; `Model.values` is `u128` so the *type*
is fine. Binary IOCTL inputs are <= 64-bit in practice, so this rarely
bites - but axeyum returning full-width u128 values would be a **strict
improvement**, not a regression.

- Action: axeyum backend returns full u128 model values (up to 128). For
  symbols wider than 128 bits (rare/none in this engine), document the
  truncation explicitly rather than silently.

## R5 - AArch64 detection-path gap (gates G4, NOT the solver swap)

Critical scoping point: **the solver sees arch-neutral QF_BV**, so the
axeyum swap is arch-independent. But the *callers that produce
constraints* are x86-64/Windows-specific:

- `lift_arm64.rs` DOES lift AArch64 to the same generic LLIR the symbolic
  domain consumes - so arm64 *can* flow through the symbolic domain and
  the solver in principle.
- BUT `explore.rs` and `ioctl.rs` hard-code the **MS x64 ABI** (arg regs
  `rcx/rdx/r8/r9`, `[rsp+0x20]` stack args, `rax` return, `wrmsr`/`rdmsr`
  x86 intrinsics) and x64 WDM IRP offsets. `Machine::new(Symbolic)`
  defaults to `RegArch::X86_64`.
- Consequence: there is no AArch64 *symbolic detection* path today. G4
  (Android ioctl reachability) requires building an AArch64/Linux driver
  seeding + ABI layer (AAPCS64 arg regs `x0..x7`, Linux `file_operations`
  ioctl ABI) analogous to the x64 WDM one.
- This is **glaurung-internal work, independent of axeyum**, and can
  proceed in parallel (P6 prerequisite). The plan deliberately does not
  couple G1-G3 to it.

## R6 - Thread-safety / parallelism (an opportunity, not just a risk)

The z3 crate uses a shared thread-local `Context`, which forces glaurung's
symbolic passes to run **sequentially** (`ioctl_scan.rs` lifts in parallel
via rayon but solves serially, with a comment that "the z3 backend is not
safe under [parallelism]").

- Opportunity: if axeyum's solver is `Send + Sync` (or cheap to
  instantiate per-thread), the axeyum backend could **unlock parallel
  symbolic scanning** that z3 currently blocks - a real throughput win
  that partially offsets R1.
- Open question: confirm axeyum's solver thread-safety / per-instance
  isolation (the axeyum API map answers this). Track as a P5 upside.

## R7 - Metering + budget contract

`solve()` increments per-thread solve/timeout counters and the explorer
enforces `(max_solves, max_timeouts)` + optional wall-clock budgets. A
native axeyum arm MUST live inside `solve()` (or replicate the metering)
so budgets still bound runtime; and axeyum needs a **per-solve timeout**
knob equivalent to z3's 250 ms, or the wall-clock budget must be able to
interrupt it.

- Resolved: axeyum **does** expose a per-check timeout -
  `SolverConfig::new().with_timeout(Duration)`, honored by
  `IncrementalBvSolver`'s warm path (and by `solve_smtlib`). The backend
  sets 250 ms to match z3; a timeout yields `CheckResult::Unknown` ->
  glaurung `Unknown` (metered as a timeout), which is exactly the existing
  contract. The wall-clock `TIME_BUDGET` remains a coarse backstop.
  Residual: confirm the timeout is checked frequently enough to interrupt
  a single very hard bit-blast (verify in P2 with a deliberately hard
  formula).

## R8 - Version / API drift between two live repos

Both are the author's, both edition 2024, actively developed. A path
dependency couples checkout locations; a git-rev dependency pins but needs
bumping.

- Mitigation: ADR-001 - path dep during P1-P3 co-development, pin to a git
  rev at P4 (default landing) so the shipped artifact is reproducible.
  Keep axeyum's consumed API surface small (just the QF_BV solve + term
  build) to minimize drift surface.

## R9 - WASM constraints

Axeyum is WASM-buildable; glaurung's default is not WASM-targeted, but the
pure-Rust axeyum backend keeps that door open. Risk is low unless a WASM
build is a near-term goal.

- Open question: does the axeyum backend need any std feature (threads,
  time) that WASM lacks? Only relevant if/when glaurung targets WASM;
  noted, not blocking.

## Open questions consolidated (resolved + still-open)

Resolved by the ground-truth pass (`01`, `02`):
- axeyum term-builder API + result/model/proof types - known (`02`).
- Full glaurung QF_BV op set is inside axeyum's warm path - confirmed.
- Per-check timeout - exists (`with_timeout`).
- MVP door - in-process `solve_smtlib` (no CLI needed).

Still open, to close within the named phase:
- [P2] axeyum `extract` bit-index inclusivity + `concat` operand order
  (pin with a unit test vs z3, do not assume).
- [P2] Does the timeout interrupt a single very hard bit-blast promptly
  (R7 residual)?
- [P2] Confirm arbitrary non-power-of-two widths round-trip (part of the
  per-op unit tests).
- [P5] Is axeyum's solver `Send`/cheaply per-thread-instantiable (unlocks
  parallel scanning, R6)?
- [P6] Who builds the AArch64/Linux driver seeding + ABI layer, and when
  (glaurung-internal, solver-independent)?
