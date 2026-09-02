# Decision records

> **Kind:** decision · **Status:** maintained

A decision record exists for one reason: the **alternatives that were rejected**
are not recoverable from source. Code shows what was built; only this directory
shows what was considered, why it lost, and — where the two diverged — what the
implementation did instead.

Every record opens with the same declaration line as any other live document,
followed by its own `**ADR status:**` line carrying the status and date the ADR
was written with. The `status` column below is the *index's* judgement, checked
against the code, and uses four values:

| value | means |
|---|---|
| **held** | the decision still describes the code |
| **amended** | the decision held, but the implementation extended or narrowed it; the record says how |
| **superseded** | a later decision replaced it; the record links forward |
| **never implemented** | the decision was taken and the mechanism was never built |

Two series share this directory and once shared a number. `exec-0002` (harden
the LLIR in place) and `solver-002` (axeyum as the default backend) are
unrelated decisions that were both called "ADR-002" in their own trees; the
`exec-` and `solver-` prefixes end that collision, and `Cargo.toml`'s comment on
the `solver-axeyum` feature points at `solver-002` explicitly.

## Execution engine

Six decisions from the 2026-06 design of `src/exec` and `src/symbolic`.
Subject: [`architecture/execution-engine.md`](../architecture/execution-engine.md).

| id | title | status | date |
|---|---|---|---|
| `exec-0001` | [One interpreter parameterized by a `Domain` trait](exec-0001-single-domain-core.md) | held | 2026-06-10 |
| `exec-0002` | [Harden the existing LLIR in place](exec-0002-harden-llir-in-place.md) | held | 2026-06-10 |
| `exec-0003` | [Cached IR interpreter for v1, not a JIT](exec-0003-interpreter-not-jit.md) | amended | 2026-06-10 |
| `exec-0004` | [Symbolic memory: concretization, and where the threshold went](exec-0004-symbolic-memory.md) | superseded (ITE threshold never implemented) | 2026-06-10 |
| `exec-0005` | [SMT backend: native-first, pipe as fallback, pure-Rust alongside](exec-0005-native-solver-first.md) | amended | 2026-06-10 |
| `exec-0006` | [Execution mode: symbolic DFS with folding and solver-pruned forking](exec-0006-execution-mode.md) | superseded (directed concolic never implemented) | 2026-06-10 |

Three of the six need reading with their "what the implementation changed"
sections, not their decision paragraphs alone:

- **`exec-0003`** decided a *cached* IR interpreter. The interpreter shipped; the
  cache did not, and there is no `src/exec/liftcache.rs`.
- **`exec-0004`** decided a 1024-byte ITE-tree threshold for symbolic reads. That
  path was never built; what ships is the `ConcretizationPolicy` seam decided by
  [`solver-026`](solver-026-concretization-as-a-policy.md).
- **`exec-0006`** originally decided *directed concolic* execution — a concrete
  shadow value, taint-gated forking, and ICFG-directed search. **None of the
  three was implemented.** The file now records the engine that exists (symbolic
  DFS, constant folding, solver-pruned forking) and marks the concolic intent as
  never implemented.

## Solver integration

Thirty-one decisions from the 2026-07 integration of the pure-Rust `axeyum`
solver, previously one 1,160-line log. Subject:
[`architecture/solver-backends.md`](../architecture/solver-backends.md) and
[`architecture/solver/`](../architecture/solver/).

| id | title | status | date |
|---|---|---|---|
| `solver-001` | [Depend on axeyum by path (dev) then git-rev (release)](solver-001-depend-on-axeyum-by-git-rev.md) | held | 2026-07-13 |
| `solver-002` | [Axeyum is the default backend; z3 stays an opt-in perf backend](solver-002-axeyum-as-default-backend.md) | superseded | 2026-07-13 |
| `solver-003` | [Integrate at the SMT-query seam only, not the executor](solver-003-integrate-at-the-query-seam.md) | held | 2026-07-13 |
| `solver-004` | [MVP is an in-process SMT-LIB text bridge, not a subprocess](solver-004-in-process-text-bridge-mvp.md) | amended | 2026-07-13 |
| `solver-005` | [Keep the one-shot `Solver` trait for v1; add incremental later](solver-005-one-shot-solver-trait-first.md) | amended | 2026-07-13 |
| `solver-006` | [Proofs threaded off-trait in v1 (no trait signature change)](solver-006-proofs-threaded-off-trait.md) | held | 2026-07-13 |
| `solver-007` | [Placement: this plan lives in glaurung](solver-007-decision-record-lives-in-glaurung.md) | held | 2026-07-13 |
| `solver-008` | [Auto warm reuse requires observed same-path reuse](solver-008-auto-warm-requires-same-path-reuse.md) | held | 2026-07-16 |
| `solver-009` | [Assertion exports preserve arbitrary-width truthiness](solver-009-arbitrary-width-assertion-truthiness.md) | held | 2026-07-16 |
| `solver-010` | [Adapt lineage capacity from sustained live-path pressure](solver-010-adaptive-lineage-capacity.md) | held | 2026-07-16 |
| `solver-011` | [First-class direct-delta solver session](solver-011-first-class-direct-delta-session.md) | held | 2026-07-16 |
| `solver-012` | [Keep first-class direct deltas opt-in after the dual-control gate](solver-012-direct-delta-stays-opt-in.md) | held | 2026-07-16 |
| `solver-013` | [Exact source ancestry for direct serial sibling reuse](solver-013-source-ancestry-sibling-reuse.md) | held | 2026-07-16 |
| `solver-014` | [Accept the source-prefix production win, keep direct opt-in for widening](solver-014-source-prefix-production-win.md) | held | 2026-07-16 |
| `solver-015` | [Exact shadow unknown-split corpus](solver-015-exact-shadow-unknown-split-corpus.md) | held | 2026-07-16 |
| `solver-016` | [Enforce declared concat operand widths at every solver boundary](solver-016-enforce-declared-concat-widths.md) | held | 2026-07-16 |
| `solver-017` | [Opt-in synchronized-warm timeout cold retry](solver-017-warm-timeout-cold-retry.md) | held | 2026-07-16 |
| `solver-018` | [Opt-in same-session warm timeout continuation](solver-018-warm-timeout-continuation.md) | held | 2026-07-16 |
| `solver-019` | [Exact native ordered replay in the production topology](solver-019-exact-native-ordered-replay.md) | held | 2026-07-17 |
| `solver-020` | [Default bounded continuation inside direct-delta sessions](solver-020-bounded-continuation-by-default.md) | held | 2026-07-17 |
| `solver-021` | [Defer wider direct-delta default after the dxgkrnl no-op gate](solver-021-defer-wider-direct-delta-default.md) | held | 2026-07-17 |
| `solver-022` | [Add publication-grade paired check measurements](solver-022-paired-check-measurements.md) | held | 2026-07-17 |
| `solver-023` | [Add a topology-equivalent four-cell solver control](solver-023-four-cell-solver-control.md) | held | 2026-07-17 |
| `solver-024` | [Preserve full-width values in the native Z3 adapter](solver-024-full-width-values-in-the-z3-adapter.md) | held | 2026-07-17 |
| `solver-025` | [Make the production Axeyum backend QF_BV-profile explicit](solver-025-explicit-qfbv-profile.md) | held | 2026-07-17 |
| `solver-026` | [Make concretization a first-class policy](solver-026-concretization-as-a-policy.md) | held | 2026-07-18 |
| `solver-027` | [Preserve taint provenance before scoring policy coverage](solver-027-preserve-taint-provenance.md) | held | 2026-07-18 |
| `solver-028` | [Emit an exhaustive finding-confidence partition](solver-028-finding-confidence-partition.md) | held | 2026-07-18 |
| `solver-029` | [Separate WDM SystemBuffer address ownership from content taint](solver-029-systembuffer-address-versus-content.md) | held | 2026-07-18 |
| `solver-030` | [Require structural stack origin before stack-overflow classification](solver-030-structural-stack-origin.md) | held | 2026-07-18 |
| `solver-031` | [Add a pinned in-process Bitwuzla neutral measurement cell](solver-031-pinned-bitwuzla-measurement-cell.md) | held | 2026-07-19 |

`solver-002` is the one superseded record: axeyum was never made a default
feature, and the shipped configuration is `default = ["triage-core"]` with every
solver opt-in. `solver-004` and `solver-005` are marked amended because the
SMT-LIB text bridge became the secondary path behind a native term translator
(`solver-axeyum-text` still builds it), and the one-shot `Solver` trait gained
the separate `IncrementalSolver` companion the ADR deferred.

## Cross-cutting

| id | title | status | date |
|---|---|---|---|
| `whole-binary-serialization` | [Whole-binary analysis: what to adopt, what to design](whole-binary-serialization.md) | proposed work; the analysis holds | 2026-08-20 |
