# Decompiler Review Implementation Plan

> **Kind:** record · **Date:** 2026-09-02

Status: detailed execution specification subordinate to the canonical roadmap

Created: 2026-09-02

Review basis: `README.md` and `01` through `06` in this directory

Scope: local Glaurung implementation, tests, measurements, and documentation

Current-state snapshot: reconciled 2026-09-05 through homogeneous-float
behavioral commits `db750dbc` and `197e6383`, baseline commit `1bee3fb1`, and
census commit `a0915220`. WP0 and
WP7A are complete; the bounded WP1 production trial is complete and rejected,
with selective substrate cleanup still open under WP10. WP4 now has a pinned
715-function structural comparison and a 334-candidate execution comparison
with zero unexplained structural regressions, zero execution regressions, and
nested post-tested branches preserved; it still lacks the remaining promotion
measurements. WP5, WP8, WP9, and WP10 have production or shadow vertical slices
but have not met their full exit criteria. WP6 has its first per-use signedness
slice and the O0 `classify` signed-result vertical slice, but not the general
solver. WP2, WP3,
and the general WP7B idiom framework remain the principal unstarted or
dependency-blocked packages. A bounded, pre-WP3 WP7B relational slice is
landed and proved at `9c9c607c`; it does not establish the general framework.
The full Rust gate is green at `41af392d`: its library target reports 4,065
passed, 0 failed, and 5 ignored, and every integration and documentation target
also passed. Its required whole Python gate completed red: 4,613 passed, 116
failed, 68 skipped, 896 xfailed, and 125 deselected in 2,493.96 seconds. That
run exposed the expected stale two-test census and improvement ratchets as well
as the repository's broad pre-existing failures; the census is refreshed in
the accompanying documentation commit, while behavioral baselines are not
blindly rewritten. This is not a current-tip green `release` claim. M3 through
M6 remain open.

## Authority and relationship to the roadmaps

`docs/development/roadmap/README.md` remains the canonical roadmap index, and
`docs/development/test-estate/EXECUTION.md` remains its landed-work status
tracker. This file does not create a third independent queue: it supplies the
implementation detail, ordering, tests, measurements, and stop conditions for
the recommendations accepted from this review. When work starts or its status
changes here, the corresponding roadmap item must be added or updated in the
same documentation increment and link back to the relevant work package.

`docs/development/roadmap/real-binary-decompiler.md` remains product sequencing
evidence for real-binary priorities; it is not a second checkbox authority.
Where its ordering conflicts with this plan, the canonical roadmap records the
explicit scheduling decision. The dated review files and this plan provide
evidence and implementation detail; the canonical roadmap answers what is
actually active.

## 1. Objective

Turn the review's ten recommendations into an ordered program that improves
semantic correctness, structural recovery, type fidelity, readability, and
pipeline maintainability without accepting unmeasured regressions.

This plan does not authorize an upstream DecBench issue, comment, or pull
request. DecBench work here is limited to local evaluation and internal
evidence, consistent with `AGENTS.md` and `CLAUDE.md`.

## 2. Non-negotiable rules

1. Follow RED, GREEN, REFACTOR, VERIFY for every behavior change.
2. Preserve a best-effort analyst rendering even when release evidence fails.
   Fail closed on claims and gates, not by hiding the function body.
3. Run correctness changes against execution evidence and structural/score
   evidence together. A lower goto count alone is not success.
4. Keep scored pseudocode deterministic. Diagnostics and provenance belong in
   structured metadata unless a render style explicitly requests annotations.
5. Treat an authoritative declaration and an inferred prototype as separate
   facts. Render the authoritative declaration while retaining any conflict.
6. At equal inputs, session facts, options, and analysis budget, every entry
   point must produce byte-identical pseudocode.
7. Rust remains measured but is reported as a separate language axis. Rust ABI
   implementation is not on the primary C roadmap.
8. Do not delete dormant subsystems until their exact callers, tests, and
   retained responsibilities have been recorded and the deletion has passed
   the full release profile.

## 3. Status vocabulary

- `[ ]` not started
- `[~]` in progress or partially landed
- `[x]` complete and verified
- `[r]` rejected after a recorded experiment
- `[b]` blocked by a named dependency

A work package becomes `[x]` only when its implementation, focused tests,
required corpus gates, documentation, and before/after measurements exist.

## 4. Existing baseline authority

Do not create a parallel baseline ledger. The committed baseline JSON files at
a pinned Git commit are the baseline authority:

- `tests/decompiler_fixtures/baseline.json`
- `tests/decompiler_fixtures/arch_baseline.json`
- `tests/decompiler_fixtures/structural_baseline.json`
- `tests/decompiler_fixtures/defuse_baseline.json`
- `tests/decompiler_fixtures/stripped_divergences.json`
- `tests/open_defects/known_failures.json`

Every result report records the Git revision, build fingerprint, exact command,
and which of these committed files it used. DecBench scores, elapsed time, and
RSS are recorded only in the increment that actually measures them; they are
not prerequisites for starting capability work.

## 5. Dependency order

```text
WP0 minimal measurement and gate integrity
 |
 +--> WP1 bounded MIR trial --> keep MIR or delete it
 +--> WP2 shared pipeline and explicit analysis budgets --> WP3 SSA/origins
 +--> WP4 shadow-mode total structurer <---- typed cases from WP5 when ready
 +--> WP5 typed indirect targets
 +--> WP7A immediate render-level idioms
 +--> WP8 declaration authority
 +--> WP9 machine model increments

WP3 --> WP6 constraint typing
WP3 --> WP7B SSA-expression idioms

WP10 consolidation and deletion follows each accepted replacement; final
release evidence follows the selected set, not the completion of every package.
```

WP1 must precede any competing SSA- or AST-based implementation of the skipped
goto-aware definedness check. Otherwise the MIR trial cannot demonstrate
unique value. WP4 and WP5 depend only on WP0 and should start while WP2/WP3 are
in flight; the current typed CFG and `Cfg::from(lf, ssa)` are sufficient for a
shadow structurer, and indirect-target analysis does not require the new value
identity model.

### Rough effort bands

These are sizing bands for scheduling, not delivery promises. Re-estimate after
the RED fixture or first vertical slice exposes the actual boundary.

| package | rough effort | first independently useful result |
|---|---:|---|
| WP0 | 1-2 days | deduplicated/language-split counts and one honest gate command |
| WP1 | 2 days, hard cap | MIR keep/delete evidence |
| WP2 | 2-4 weeks | two entry points sharing one request/result path |
| WP3 | 4-8 weeks, incremental | one SSA consumer migrated with conservative invalidation |
| WP4 | 3-6 weeks to promotion; shadow in week 2 | condition-DAG shadow result and coverage report |
| WP5 | 1-3 weeks for host jump tables | typed x86 case edges reaching shadow structuring |
| WP6 | 3-6 weeks, incremental | C signedness constraints on one fixture family |
| WP7A | 2-5 days | typed literal spelling and one range-check fusion |
| WP7B | 2-4 weeks, incremental | first SSA-native proved idiom |
| WP8 | 3-7 days | `tail_dispatch` declaration and names rendered correctly |
| WP9 | 4-8 weeks, incremental | one fact class moved behind `TargetSpec` queries |
| WP10 | 1-3 weeks total, spread across migrations | first superseded module removed with release evidence |

## 6. WP0 — Minimal inventory and gate integrity

Purpose: make subsequent changes comparable without delaying capability work.

### Production and tooling changes

- [x] Extend `tools/gen_known_failures.py` to derive a stable binary identity
  from build provenance and content hash.
- [x] Batch known-failure recovery once per binary, reuse rendered text for
  signature parsing, and use bounded binary-level workers. Add language and
  fixture filters, real `--help`, progress control, and resumable per-object
  checkpoints; keep output deterministically sorted across worker counts.
- [x] Preserve O2 and stripped-O2 as distinct observations, but count an
  identical pair once in the primary defect total.
- [x] Add only the generated identity/language fields required to reproduce
  deduplication and language totals; do not expand the schema pre-emptively.
- [x] Update `tools/gen_defuse_baseline.py` and `tools/defuse_ratchet.py` to
  emit and compare C and Rust subtotals separately.
- [x] Add new `scripts/decompiler-gate.sh` with `fast`, `default`, and
  `release` profiles. Reuse `scripts/feature-build-gate.sh` and
  `scripts/decbench-local-gate.sh`; do not duplicate their implementations.
- [x] Make every profile print its revision, build fingerprint, included
  lanes, excluded lanes, elapsed time, and final evidence denominator.
- [x] Reject unknown profiles and incomplete prerequisites.
- [x] Add the strict xfail for the constant-false Duff's-device latch in
  `102_duffs_device-gcc-O2.so::duff_copy` immediately.

### Tests

- [x] Extend `python/tests/test_known_decompiler_failures.py` with schema,
  language-total, and deduplication invariants.
- [x] Batch the strict-xfail consumer once per object and test conventional
  pointer-star spelling, serial/parallel equivalence, and checkpoint/resume
  against real fixture binaries.
- [x] Extend `python/tests/test_defuse_ratchet.py` for language-split totals and
  identical-vs-divergent stripped pairs.
- [x] Add `python/tests/test_decompiler_gate.py` using print-plan and preflight
  contracts to test profile composition and fail-closed behavior without
  executing the expensive profiles.
- [x] Keep `python/tests/test_perf_gate_fails_closed.py` green.

### Gate definitions

- `fast`: build guard, focused Rust tests, Python unit tests that do not build
  the full fixture matrix, Ruff, and `ty`.
- `default`: `fast`, host O0/O2 fixture matrix, all supported architecture
  lanes, structural census, def-use census, fitness and allowlist ratchets,
  and the full Python suite.
- `release`: `default`, feature-build gate, performance/determinism gate,
  stripped divergence lane, and explicitly requested local DecBench evidence.

### Exit criteria

- [x] Raw and deduplicated counts reconcile exactly.
- [x] C and Rust subtotals sum to every overall total.
- [x] The complete 1,676-object inventory regenerates in a bounded run: 203.97
  seconds with eight workers on 2026-09-04, versus the superseded serial run
  still incomplete after 4,213 seconds.
- [x] A deliberately missing lane makes `default` or `release` not-evidence.
- [x] The Duff's-device semantic hole is represented independently of its
  existing `unrecovered` failure.

## 7. WP1 — Two-day MIR production-consumer trial

Purpose: decide whether the roughly 8,700-line MIR/MemorySSA substrate earns a
production role before building a competing verifier.

### Trial question

Use `DefinitionOracle::all_paths_defined` to evaluate path-sensitive
used-before-definition on goto-bearing functions currently skipped by
`src/ir/verify_defs.rs`.

### Files

- modify: `src/ir/mir/mod.rs`
- modify as needed: `src/ir/mir/verify.rs`
- modify: `src/ir/verify_defs.rs`
- modify: `src/ir/health.rs`
- modify: `src/python_bindings/ir/pipeline.rs`
- tests: existing MIR tests under `src/ir/mir/`
- tests: `src/ir/health_tests.rs`
- tests: `python/tests/test_decompiler_defuse_census.py`
- measurements: `tools/gen_defuse_baseline.py`

### Implementation sequence

- [r] RED: a temporary small goto-bearing CFG with a definition on only one
  predecessor proved that MIR reports the missing path while the structured
  walk declines goto-bearing flow. The trial code was removed after rejection.
- [r] A temporary read-only MIR result was exposed through the health record
  without modifying pseudocode, then removed after rejection.
- [r] The temporary record carried `analysis=MIR`, queried value, use site,
  predecessor evidence, and completeness/decline reason.
- [r] Two real-binary probes produced complete clean proofs, but the population
  sweep was stopped after the hard performance criterion failed. The bounded
  A/B evidence and its explicitly limited denominator are recorded in
  `mir-trial-results.md`.
- [x] Do not implement the recommendation 9 AST-label-graph alternative
  during this trial.

### Decision rule

Keep MIR only if, within two working days and below 10% fixture-matrix wall
time overhead, it produces at least one verdict unavailable to the structured
walk or complete clean proofs for the applicable population, and that value is
not cheaper to obtain from the authoritative SSA work in WP3.

If rejected:

- [x] Record results in
  `docs/history/decompiler-review-2026-09-02/mir-trial-results.md`.
- [x] Inventory every production and test reference to `src/ir/mir/`,
  `src/ir/memory_ssa.rs`, and the MIR adapters in `src/ir/memory_objects/`.
- [~] Delete only after porting any independent LLIR invariant checks and
  demonstrating the `release` profile remains green.
- [x] Implement goto-aware definedness over the final AST label CFG; malformed
  label graphs decline the stronger flow-sensitive claim while preserving the
  always-safe whole-function finding.

If accepted:

- [ ] Define MIR as the sole owner of the query and remove the structured
  verifier's overlapping implementation rather than maintaining two answers.

## 8. WP2 — One pipeline, explicit budgets, and checked pass ordering

Purpose: remove semantic differences caused solely by the Python entry point
and make pass repetition/invalidation explicit.

### Production changes

- [ ] Introduce a pipeline-owned request and result model in
  `src/python_bindings/ir/pipeline.rs`:
  - `DecompileRequest { va, style, analysis_budget, render_options }`
  - `AnalysisBudget` with explicit callee, discovery, type, CFG, and size
    limits;
  - `DecompileResult` carrying pseudocode, health, completeness, provenance,
    and pipeline fingerprint.
- [ ] Move common orchestration out of `src/python_bindings/ir.rs` into one
  `decompile_function(session, request)` implementation.
- [ ] Convert `decompile_at`, `decompile_range_at`, `decompile_all`, and
  `decompile_many` into adapters that create requests and call the same path.
- [ ] Move shared callee-contract preparation through
  `src/python_bindings/ir/callee_contracts.rs`.
- [ ] Add checked `PipelineStage` and pass preconditions to
  `src/python_bindings/ir/pipeline.rs`; split into a new
  `src/python_bindings/ir/pass_manager.rs` only when the module-size ratchet
  requires it.
- [ ] Replace hand-repeated settle passes with a bounded fixpoint driver that
  records firing and termination reasons.
- [ ] Include analysis-budget identity and pass-version identity in the
  pipeline fingerprint.

### Tests

- [ ] Extend `python/tests/test_decompiler_session.py` for shared-session facts
  and explicit budgets.
- [ ] Add `python/tests/test_decompiler_entrypoint_equivalence.py` covering all
  four entry points at equal budgets.
- [ ] Extend `python/tests/test_decompiler_determinism.py` for fingerprints and
  function-order independence.
- [ ] Extend `python/tests/test_pipeline_profile_report.py` for pass order,
  firing counts, and bounded fixpoint termination.
- [ ] Test that a deliberately lower range budget differs only with an
  explicit completeness reason.

### Exit criteria

- [ ] Equal budget produces byte-identical pseudocode for the same function
  across all entry points.
- [ ] No entry point independently performs discovery, naming, or callee
  analysis.
- [ ] Invalid pass order fails in a focused test.
- [ ] Every repeated pass is justified by recorded invalidation or a declared
  fixpoint, not duplicated orchestration.

## 9. WP3 — Authoritative SSA, stable value identity, and origins

Purpose: move dataflow work off display names and preserve instruction
provenance through lowering.

### Core model

- [ ] Add a pipeline-owned, versioned `SsaInfo` near the existing SSA
  implementation under `src/ir/`.
- [ ] Define explicit invalidation classes: CFG changed, definitions changed,
  uses changed, types changed, and presentation-only change.
- [ ] Make an unclassified mutating pass conservatively return
  `Invalidate::All`. Migrate passes one at a time to narrower change sets; do
  not require roughly 100 passes to convert before the first consumer lands.
- [ ] Require every newly added mutating pass to declare a change set, and
  ratchet the count of legacy `Invalidate::All` passes downward.
- [ ] Recompute or repair SSA before the next consumer when invalidated.
- [ ] Preserve opaque SSA value identity through AST lowering.
- [ ] Add a compositional instruction-origin set to expressions/statements;
  unions must be deterministic and deduplicated.

### Migration targets

- [ ] Move copy propagation from `src/ir/copy_prop/` to authoritative SSA
  consumption before AST lowering.
- [ ] Move constant folding, dead-store elimination, and DCE in bounded
  increments, one pass at a time.
- [ ] Remove semantic parsing of `ret`, `argN`, `local_`, and `#version` only
  after each consumer has a typed identity replacement.
- [ ] Remove `tag_phys` from `src/ir/value_number/tagging.rs` after its last
  typed consumer lands.
- [ ] Remove `remap_type_map` callers in `src/python_bindings/ir.rs` and
  `src/python_bindings/ir/type_maps.rs` after value-keyed type maps are live.
- [ ] Keep naming as a render mapping, not a program rewrite.

### Origin and mapping surface

- [ ] Extend AST definitions in `src/ir/ast.rs` or the owning AST module with
  `OriginSet`.
- [ ] Thread origins through lowering, expression rewrites, structuring, tail
  duplication, and rendering.
- [ ] Expose line-to-address mappings from the Python binding as structured
  data; do not infer them by parsing rendered text.
- [ ] Define non-contiguous origin behavior for folded, hoisted, and duplicated
  nodes.

### Tests

- [ ] Unit tests for SSA invalidation and reconstruction.
- [ ] Unit tests for deterministic origin union and duplication.
- [ ] Extend `python/tests/test_dectest_equivalence.py` for byte neutrality
  during identity-only migrations.
- [ ] Add `python/tests/test_decompiler_line_mappings.py` for one-to-many and
  non-contiguous mappings.
- [ ] Run the 419-pair output identity sweep after each migrated pass.

### Exit criteria

- [ ] No product consumer parses display names to identify semantic values.
- [ ] SSA construction occurs only on initial demand or declared invalidation.
- [ ] Origins survive every enabled pass and produce deterministic mappings.
- [ ] The fixture matrix is byte-identical until an intentionally output-
  changing work package begins.

## 10. WP4 — Total, locally degrading structurer

Purpose: replace whole-function structural fallback with a total algorithm
that preserves honest local gotos when required.

### New implementation boundary

- [x] Create `src/ir/structure_v2/` rather than mutating the current structurer
  in place during development.
- [x] Before adding the directory, record its temporary, bounded architecture
  growth in `tools/fitness_baseline.json` and the relevant reviewed-large-module
  allowlist. The acceptance must name WP4, its expected removal/replacement
  target, and an expiry condition at v2 promotion; do not let the fitness gate
  fail merely because the approved shadow implementation exists.
  The approval now permits nine files capped at 4,400 total lines. The first
  increase to 4,000 kept the rendering adapter as an explicit `render.rs`
  boundary; the additional 400-line allowance is pre-registered for the first
  typed-switch recovery, independent verification, and rendering slice rather
  than allowing those concerns to leak into CFG discovery. The same promotion
  or abandonment expiry still applies.
- [~] Suggested modules:
  - `mod.rs`: feature flag, public contract, and shadow comparison;
  - `cfg.rs`: normalized typed CFG input;
  - `dominators.rs`: dominance/post-dominance and loop forest;
  - `conditions.rs`: reaching-condition representation and simplification;
  - `region.rs`: multi-exit region algebra with `Return`, `Break`, `Continue`,
    `Sequence`, `If`, `Loop`, `Switch`, and local labelled region;
  - `recover.rs`: deterministic region construction;
  - `verify.rs`: block and edge accounting;
  - `cleanup.rs`: bounded tail duplication and else-after-terminal flattening.
  The boundary now has `mod.rs`, `cleanup.rs`, `conditions.rs`,
  `dominators.rs`, `local.rs`, `recover.rs`, `region.rs`, and `verify.rs`, while
  reusing v1's typed `Cfg` directly. `render.rs` conservatively adapts verified
  acyclic trees into the existing AST lowerer and C-like printer. `recover.rs`
  now constructs a deterministic
  `Sequence`/`If`/`Block`/`Return` tree for acyclic single-entry candidates and
  `Loop`/`Break`/`Continue` nodes for reducible loops. The real `early_return`,
  `dowhile_atleastonce`, and multi-exit `loop_return_on_neg` binaries are green;
  the latter keeps distinct exit regions before their singly owned shared
  return. Irreducible SCCs now become separately owned local-labelled
  definitions with explicit entry gotos and structured exit paths; the real
  two-entry fixture and the nested irreducible fixture both produce verified
  trees, and the latter retains its surrounding natural loop. An independent
  verifier checks exact leaf ownership, retained typed transfers,
  branch-source identity, natural-loop identity, loop and local exit targets,
  local-region evidence, and every explicit loop-control or local-goto
  transfer. The real `early_return` tree now produces deterministic raw
  pre-pass pseudocode with a structured `if/else` and no goto. The real
  single-exit `dowhile_atleastonce` tree also renders as `do`/`while`, with its
  body exit recovered as `break` and no goto; the adapter requires a unique
  typed latch and exit before accepting that spelling. The top-level real
  `two_entry_loop` local-labelled tree now renders through the existing
  labelled-CFG fallback: every retained local goto resolves to an emitted
  label, exit paths and their verified terminal clones remain present, and no
  irreducible edge is hidden behind speculative structure. The real nested
  irreducible fixture now also renders its surrounding pre-tested loop while
  retaining the inner region's honest labelled transfers. The adapter accepts
  that spelling only when at least one typed loop break exists and every break
  reaches the lexical continuation; mismatched exits remain an explicit
  decline. A RED experiment on
  `loop_return_on_neg` confirmed that v1's one-distinguished-exit `While` could
  not encode its two exit-specific paths without reversing a branch or moving a
  verified terminal clone. The region/AST boundary now has an explicit
  `MultiExitLoop`: its body retains typed exit transfers, lowering materializes
  each independently verified exit region at that exact transfer, and the real
  fixture emits deterministic `while (1)` pseudocode with both return paths and
  no goto. The real gcc-O2 `duff_copy` tree now also renders its independently
  verified eight-way typed dispatch as `switch`/`case 0..7`, while locally
  degrading the suffix-entry irreducible loop to resolved labelled gotos; no
  indirect-jump placeholder survives. Repeated recovery produces the same tree
  and text. The 208-case gcc-O2 and 256-slot clang-O2
  `wide154_dense_effects` fixtures now prove the same typed-switch path scales
  beyond the small vertical slice without losing a case, and both emit
  deterministic parseable C. Multi-exit loops no longer
  require an invented common continuation: the gcc-O2
  `206_aarch64_wide_dispatch::dispatch_in_loop` shape independently owns its
  non-reconverging terminal exits. WP5 now preserves the guard's `al <= 6`
  proof through GCC's `movzbl al, eax`; the exact seven PIC-relative targets
  reach a switch nested inside that verified loop, including the case that
  exits to the shared return, with no indirect-jump placeholder. Every
  currently renderable real WP4 tree (`early_return`,
  `dowhile_atleastonce`, `loop_return_on_neg`, top-level `two_entry_loop`,
  nested `irreducible_inside_reducible`, `duff_copy`,
  `wide154_dense_effects`, and `dispatch_in_loop`)
  now also records deterministic parseable C derived from that same adapted AST
  by the shared source-level preparation pass; all eight texts pass a real host
  `cc -fsyntax-only` test. This is not yet the full production pass stack:
  pipeline-context comparison, execution, and a separately normalized CFG view
  remain open.
- [x] Keep `src/ir/structure/` as production authority until shadow evidence
  satisfies the promotion criteria.
- [~] Feed both structurers the same typed CFG and compare coverage, health,
  pseudocode, execution, GED, and runtime.
  `structure-v2-shadow` now feeds the existing `Cfg` directly into a
  deterministic condition-DAG observer and records exact block/edge coverage;
  verified flat regions and the first acyclic structured trees are also
  recorded, including reducible single- and multi-exit loops and locally
  labelled irreducible children. Verified acyclic trees additionally record
  deterministic raw pseudocode through the existing AST/printer pipeline;
  unsupported tree vocabularies retain `None` rather than speculative text.
  The first proven post-tested single-exit loop now renders through the same
  path. Verified top-level local-labelled trees now render honest, resolved
  gotos plus separately owned labelled definitions and exit paths. Verified
  multi-exit loops now render through the explicit region/AST node rather than
  selecting one distinguished exit. Each renderable RED fixture additionally
  records deterministic post-preparation parseable C and compiles under the host
  syntax gate. The nested-local fixture now renders a verified outer loop plus
  closed honest gotos for its inner irreducible region. Health, corpus-wide
  full-pipeline pseudocode, GED, and runtime comparisons remain. A current scoped
  production differential for
  `154_wide_switch:clang:O2:wide154_dense_effects` still reports the committed
  `fail`: v1 emits an unrecovered indirect jump even though the v2 shadow tree
  renders all 256 values. That committed v1 result remains the default-path
  baseline and is not v2 promotion evidence by itself.
  `prepare_llir_for_lowering_with_shadow` now closes the first pipeline-context
  gap without changing default selection: on explicit opt-in it adapts only an
  independently verified v2 tree into the same production `Region` boundary
  used by lowering. A real clang-O2 `wide154_dense_effects` test proves the
  production-prepared LLIR retains `case 0..255` and no indirect-jump
  placeholder. `decompile_many(..., style="decbench", shadow_v2=True)` now
  carries that verified region through the normal prototype, AST-pass, typed
  render, pre-render definedness, and execution-differential stages while the
  default remains v1. The first exact run exposed two real adapter/pipeline
  defects rather than being accepted as a crash: the guarded-switch owner block
  was lowered twice, and nested callee-save spills survived cleanup. Focused
  Rust tests now require the adapter to consume a separate switch-guard leaf
  exactly once. Machine-frame cleanup now exposes separate top-level and
  recursive scopes: every production caller retains the historical top-level
  proof, while only an independently selected shadow-v2 region opts into the
  recursive walk needed after structuring nests the prologue. The real clang-O2
  output has zero undefined reads and matches the original
  `wide154_dense_effects` on all 34 deterministic differential cases. This is
  one scoped execution cell, not the corpus-wide promotion comparison.
  The full def-use ratchet also exposed baseline drift predating this increment.
  Exact commit A/B testing showed `c7473267` soundly added two guarded
  `miniz_oxide::inflate::decompress` dispatch tables (25 and 4 arms), exposing
  40 latent reads in each Rust binary that embeds that runtime body; the new
  required `wide154_dense_effects` v1 cell separately contributes 32 reads.
  `defuse_baseline.json` now records those five guarded acceptances with their
  provenance. The six census assertions pass; none of those default-v1 debts is
  presented as a shadow-v2 improvement. A subsequent full-census run also
  caught a refactor error where the historical shallow candidate scan stopped
  seeing reads inside nested control flow; a focused Rust regression now pins
  that v1 liveness contract. After the repair, the census is green again.
  The host execution matrix additionally moved
  `42_rpn_evaluator:clang:O2:rpn_evaluate` from fail to pass. Its regenerated
  inventory removes two unrecovered rows (debug and stripped) but records the
  readability tradeoff honestly: each form grows from 3 to 12 gotos. This is a
  behavioural/coverage improvement, not evidence that v1 structuring improved.
  The first complete shadow coverage census now batches all 715 current
  structure rows across 436 objects. Shadow-v2 returned 247 candidates: 180
  reduced goto count, 38 tied, and 29 regressed; the remaining 468 declined
  locally without discarding supported siblings. Comparable goto totals fell
  from 2,166 to 1,570, while comparable rendered size grew 64.4%. This is
  rejection evidence rather than promotion evidence: the run used a native
  extension built alongside unrelated dirty shared-worktree changes, and the
  29 individual regressions plus 65.5% decline rate remain blockers. The exact
  command, provenance limit, timing, and next target families are recorded in
  `results/wp4-corpus-shadow-coverage.md`.
  The first regression-driven repair now preserves an immediate
  post-dominator when it equals the enclosing recovery boundary, preventing a
  nested arm from taking ownership of a shared continuation. Across previously
  comparable candidates this removed 100 aggregate gotos and 122,459 output
  bytes: 57 rows improved, 173 tied, and 17 worsened. It also made 21 declined
  rows renderable. Overall shadow coverage rose from 247 to 268 candidates,
  but 41 raw rows now regress, including repeated copies of one Rust runtime
  body. The repair is therefore landed evidence and improved output, not a
  promotion claim; clean pinned reruns and focused removal/refusal of the
  worsened cells remain open.
  The follow-up structured-fallthrough pass now removes only branch-final
  gotos whose exact lexical successor is their target label; loops, switches,
  exception regions, and intervening effects block the rewrite. Across all 268
  shadow candidates it made 41 rows better and none worse, removed 89 more
  gotos, and moved 22 regressions to ties plus two to improvements. The current
  exploratory census is therefore 219 improved / 32 unchanged / 17 regressed /
  447 declined. The report was still built from shared dirty native sources,
  so `results/wp4-corpus-shadow-coverage.md` retains the clean-pinned rerun as
  an explicit prerequisite rather than accepting these counts for promotion.
  Post-increment validation now has a complete green Rust gate (3,951 library
  tests plus every integration and doc-test target). The full Python gate is
  still red: it was stopped at 19% after 32 failures across current-master
  analyst, build-configuration, ARM32, and control-flow tests. Focused v2 tests
  and the no-worse corpus goto comparison are green, but they do not replace
  that broad red result.
  Switch suffix entries now have a faithful C spelling as stacked case and
  machine labels: a case whose entire body jumps into another arm's owned
  suffix no longer needs its entry `goto`, while ordinary branches to that
  same suffix retain the machine label. The 715-row exploratory census moved
  to 222 improved / 30 unchanged / 16 regressed / 447 declined, with aggregate
  shadow gotos falling from 1,434 to 1,006. The worst clang-O2 wide switch fell
  from 220 to 87 gotos, gcc-O0 fell from 219 to 63, and two defaultless
  fallthrough fixtures reached zero; all changed real outputs remain
  parseable. The run still used a shared dirty native build, so it is
  engineering evidence rather than promotion evidence. The remaining 16
  regressions, including the still-regressed clang-O2 and gcc-O2 wide-switch
  rows, remain explicit blockers.
  Duff's-device local regions are now placed inside their typed switch when at
  least two arms enter the same independently verified multi-entry region.
  The region remains single-owned and displaced fallthrough remains explicit.
  Both O0 rows moved from regressed to unchanged (clang 10 to 2 gotos, gcc 9
  to 1), and both gcc-O2 rows fell from 9 to 8 while remaining regressions. No
  other corpus row changed. The exploratory census is now 222 improved / 32
  unchanged / 14 regressed / 447 declined, with 988 comparable shadow gotos.
  Focused tests rule out the same-address self-loop found during development,
  retain exact tree verification, and compile the prepared real outputs.
  Bounded cleanup now also clones a short straight-line tail ending in return,
  rather than only one terminal block. The plan records every cloned block and
  independently verifies unique linear successors, terminal return identity,
  instruction counts, clone sites, and both per-tail and per-function budgets;
  local-labelled-region exits are excluded because they are separately owned
  definitions rather than tree-builder clone sites. The limits remain eight
  instructions and 64 total cloned instructions, with a new four-block cap.
  On the real gcc-O0 `hybrid_switch`, verified shadow output fell from four
  gotos to one, tying production while preserving the `20 + 5` path as an
  explicit labelled continuation. The 715-row exploratory release comparison
  moved to **230 improved / 30 unchanged / 12 regressed / 443 declined**, with
  980 comparable shadow gotos; no previously comparable row gained a goto.
  Four formerly declined rows also rendered, so totals and output bytes are not
  directly comparable with the preceding denominator. The native extension
  still included another lane's uncommitted parser changes, so these numbers
  remain engineering evidence, not promotion evidence.
  Switch recovery now stops every arm at a shared immediate post-dominator and
  owns that continuation once after the switch. Inside a natural loop, the
  join must remain within that same loop and cannot be its header; an enclosing
  loop exit remains owned by the loop. This converts case-final jumps into C
  `break` without moving or duplicating the shared effects. Real regressions
  cover both sides: clang-O0 `obfuscated_transform` proves a shared in-loop
  continuation moves after the switch, while clang-O2 `flattened_accumulate`
  proves an outer loop exit is not claimed as a switch join. The three clang-O0
  flattened functions and `obfuscated_transform` pass 34-case execution
  differentials. The complete exploratory comparison now reports **236
  improved / 30 unchanged / 6 regressed / 443 declined**, and comparable
  shadow gotos fell from 980 to 581. The two remaining clang-O2 wide rows fell
  from 87 to 54 gotos, and both gcc-O2 wide rows moved from regressed to
  improved (208 to 75 versus production's 203). No row declined or gained a
  goto relative to the preceding run. Shared dirty native provenance still
  prevents treating these totals as promotion evidence.
  Multi-exit materialization now also descends into recovered switch arms.
  Before this fix, both O0 `dispatch_in_loop` objects left their early-return
  case as a goto whose label repair placed an empty label after the function's
  final return; execution returned garbage for that path even though tree
  verification passed. A real GCC/Clang fixture regression now requires the
  case to contain its return path, and release execution differentials pass all
  34 deterministic cases for each compiler. The complete exploratory census
  is now **236 improved / 32 unchanged / 4 regressed / 443 declined** with 571
  comparable shadow gotos. Both O0 dispatch rows moved from regressed to
  unchanged, and no row declined or gained a goto.
  The four remaining regression rows are two debug/stripped pairs with
  different dispositions. GCC-O2 `duff_copy` recompiles and passes all 34
  execution cases; its eight shadow gotos are verified suffix entries into the
  recovered Duff body, while production reports four only by leaving the
  indirect dispatch unrecovered. An initial attempt to spell the 22
  clang-O2 `wide154_dense_effects` switch-join transfers as `break` ran before
  copy/fallthrough preparation and failed execution differential, so it was
  rejected. The accepted implementation performs the same adjacency-proved
  rewrite as the final semantic AST pass, after every consumer that could
  reinterpret `Break`. All 34 execution cases pass; clang-O2 falls from 54 to
  32 gotos and gcc-O0 falls from 22 to zero. Across the complete comparison,
  shadow gotos fall from 571 to **505**, with no new decline or status
  regression. The remaining wide gotos are suffix/shared-effect entries rather
  than transfers to the switch continuation.
  The comparison report now preserves those four raw `regressed` statuses and
  records a separate, fail-closed classification. Only the exact reviewed
  debug/stripped rows can match; each candidate must still contain a recovered
  switch, at least one direct goto, and a definition for every goto target.
  The pinned `ca91dc68` full run reports **4 accepted honest-goto rows / 0
  unexplained regressions**, alongside the unchanged raw **236 improved / 32
  unchanged / 4 regressed / 443 declined** counts. This closes classification,
  not WP4 promotion: execution, accounting, GED, structure-axis, and budget
  evidence below remain required.
  The ordinary execution-differential harness now accepts an explicit
  `shadow_v2` selection without changing its production default, including
  batched roots and recursively included local helpers. The pinned `6175d67d`
  comparison executes every one of the 272 rendered candidates from the same
  revision through identical fixture contracts and vectors. It reports **14
  improved / 175 stable pass / 23 stable non-pass / 21 regressed / 39 not
  executable**, with zero infrastructure findings. The 39 are internal/static
  functions absent from the dynamic ABI and remain visible rather than being
  mislabeled as missing. Eight function families account for all 21 semantic
  regressions: branch hints, flattened accumulation, returning switch arms,
  Base64, bitset selection, bisection square root, internal rate of return, and
  trie insertion. Seven families improve. This is the first corpus-wide
  execution result and is a promotion blocker, not an accepted trade-off.
  The first correctness repair at `0da8744d` stops treating a back-edge as an
  implicit loop continuation merely because it is final inside a nested
  conditional or switch arm. Only the true outermost final transfer may fall
  through; nested transfers remain explicit, resolved gotos. This removes 15
  of the 21 behavioral regressions: the pinned rerun reports **14 improved /
  190 stable pass / 23 stable non-pass / 6 regressed / 39 not executable**, with
  zero infrastructure findings. The remaining six cells are three families:
  clang-O2 branch hints, flattened accumulation, and Base64 (including their
  stripped twins where present). Correctness exposes a readability debt:
  shadow gotos rise from 505 to 773 and 13 raw structural rows become
  unexplained regressions. Source-level `continue` recovery or an equally
  proved spelling is required before those transfers can be called structurally
  closed.
  Source-level continuation recovery at `85a61693` removed those unexplained
  structural regressions while retaining zero execution regressions. The
  follow-up at `80f5d106` now preserves ordinary nested conditionals inside
  post-tested loops rather than flattening or declining them. Its release-built
  pinned comparison covers 715 functions: 262 improve, 68 tie, four exact
  reviewed honest-goto rows remain raw regressions, 381 decline, and no
  regression is unexplained. The corresponding 334-candidate execution
  comparison reports 14 improvements, 246 stable passes, 29 stable non-passes,
  45 explicitly non-executable candidates, zero regressions, and zero
  infrastructure findings. The complete Rust gate is green and the global
  Python gate terminated red. Exact commands, timing, RSS, denominator limits,
  and validation boundaries are in
  `results/wp4-nested-post-tested-rendering.md`.

### RED fixtures

- [x] `01_conditional_polarity.c::sc_mixed`: condition DAG. The checked-in
  gcc-O0 binary is discovered, lifted, converted to SSA, and observed with
  total block/edge coverage; the synthetic equivalent is also checked against
  all eight Boolean valuations of `(a && b) || c`.
- [x] `03_loop_shapes.c::dowhile_atleastonce`: rotated multi-exit loop. The
  real gcc-O0 fixture yields a post-tested natural loop with explicit latch,
  `Continue`, and exit `Break` facts.
- [x] `03_loop_shapes.c::loop_return_on_neg`: shared terminal tail. The real
  gcc-O0 fixture preserves distinct loop exits converging on one return block,
  which remains singly owned.
- [x] Existing irreducible/dispatch fixtures for honest local goto behavior.
  The real `211_irreducible_loops` `two_entry_loop` and nested-irreducible
  functions preserve verified local labelled transfers; the nested case also
  proves that the surrounding natural loop survives.
- [x] A synthetic irreducible CFG whose correct result necessarily retains a
  goto, recorded as `accepted_honest_goto`.
- [x] Extend `tools/gen_structural_baseline.py` and
  `python/tests/test_decompiler_fixture_structural.py` for that classification.
  Every accepted row must name a reproducible CFG property; free-form waivers
  are invalid. The closed manifest contract names
  `irreducible_scc_multiple_entries_no_dominating_header`, the Rust fixture test
  reproduces it, and the structural report records only lanes that actually
  contain a goto.

### Safety properties

- [x] Every emitted-candidate input block appears exactly once or has an explicit duplicated-tail
  provenance record.
- [x] Every emitted-candidate CFG edge is represented by structured control, a local goto, or a
  typed refusal.
  `verify.rs` independently compares candidate ownership, terminals, edge
  multiplicity, polarity, and `Break`/`Continue` classification with the typed
  CFG. Accepted irreducible SCCs become local labelled regions; unclassified
  residual cycles still return `CyclicGraph` with zero claimed coverage.
- [x] Local failure cannot collapse an otherwise structured function. The real
  nested-irreducible fixture retains its outer natural loop while only the
  inner multi-entry SCC degrades to local gotos.
- [~] Tail duplication is size-bounded and restricted to straight-line return
  tails. Shadow cleanup keeps one deterministic canonical predecessor and
  records the complete block chain, source/predecessor identities, and total
  instruction count. Independent verification rejects repeated blocks,
  non-linear edges, a non-return terminal, forged counts or clone sites, and
  any plan above four blocks, eight instructions per tail, or 64 cloned
  instructions per function. Clone sites inside separately owned local-labelled
  regions are excluded. Synthetic single- and two-block boundary tests,
  branching-tail refusal, forged non-linear provenance, the real
  `loop_return_on_neg` shared return, and the real gcc-O0 `hybrid_switch` are
  green. Each planned clone is materialized as an explicit `DuplicatedReturn`
  carrying its whole chain; the tree verifier rejects missing, altered, or
  invented materializations one-for-one against the checked plan. Promotion
  still requires clean-pinned corpus and execution evidence.
- [x] Condition simplification preserves machine-width predicate semantics.
  Each shadow condition atom now carries the SSA producer's exact `CmpOp`,
  recoverable operand width, and `CondJump` inversion; unavailable producer or
  width evidence remains explicit `None`. Boolean complement folding compares
  the complete typed atom. Boundary tests prove that exact complements fold,
  while 32/64-bit or signed/unsigned mismatches do not.

### Promotion criteria

- [~] No execution-differential regressions. The fail-closed corpus route is
  now implemented. The first pinned run at `6175d67d` exposed 21 regressions;
  `0da8744d` removed 15. `c3bbe2a6` repairs or locally declines the remaining
  unsafe shapes, and its pinned 250-candidate report records **zero
  regressions**, 12 improvements, and no infrastructure findings. Thirty-nine
  candidates remain explicitly non-executable, so broader coverage remains
  open. The expanded pinned `80f5d106` report remains at zero regressions over
  334 candidates after enabling nested post-tested branches; 45 candidates are
  explicitly non-executable. See `results/wp4-nested-control-safety.md` and
  `results/wp4-nested-post-tested-rendering.md`.
- [ ] No unexplained block/edge accounting findings.
- [ ] GED does not regress on the pinned sample.
- [ ] The structure axis improves after accepted honest gotos are separated.
- [ ] Runtime and output-size budgets are recorded and accepted.
- [ ] Only then make v2 default and selectively retire compensation passes.

## 11. WP5 — Typed indirect targets and switch recovery

Purpose: eliminate the 48 unrecovered dispatch rows and give the structurer
one authoritative set of case edges.

### Production changes

- [~] Extend indirect-target analysis with bounded value-set analysis for:
  comparison guards, masks, subtract-and-unsigned-compare ranges,
  PIC-relative tables, and absolute tables.
  The current implementation already lives primarily in
  `src/analysis/dispatch.rs`, `src/analysis/cfg/dispatch_resolution.rs`, and
  `src/analysis/jump_table.rs`, rather than the relocation-only
  `src/ir/indirect_targets.rs`. It carries comparison, stack/memory, mask, and
  rebased bounds into bounded PIC-relative and absolute decoders. The live
  gcc-O2 Duff fixture proves that `arg2 & 7` resolves exactly eight ordered
  targets. The remaining encodings and measured declines still need a fresh
  census.
- [~] Add target-specific decoding for ARM `tbb`/`tbh` and
  `ldr pc, [pc, r0, lsl #2]` through the relevant lifter/machine-model layer.
  Both forms already decode through `dispatch_resolution.rs`; the remaining
  work is to complete the architecture lanes and consolidate the evidence
  contract.
- [~] Represent resolved case values, targets, default edge, provenance,
  bounds, and completeness as typed evidence attached to `Op::IndirectJump`.
  `Op::IndirectJump.index`, typed CFG `SwitchCase`/`SwitchDefault` edges, and
  ordered `Cfg::case_labels` already carry the first production facts. WP4's
  independently verified `RegionCandidate` now receives explicit
  `SwitchEvidence` and `SwitchDefaultEvidence` without re-recognising output:
  the real `102_duffs_device-gcc-O2.so::duff_copy` fixture records one dispatch,
  eight ordered values `0..7`, and its linked bypass edge. The verified WP4
  tree now consumes that same evidence and renders an eight-arm switch with
  honest labelled transfers into the suffix-entry region. A forged-label test
  proves that block/edge coverage alone cannot validate this metadata.
- [ ] Make discovery, `src/ir/structure_accounting.rs`, both structurers, and
  rendering consume the same evidence object.
- [ ] Add `Op::Switch` only if it becomes the sole semantic owner of those
  targets and receives execution semantics.

### Tests

- [ ] Keep WP0's strict xfail for the constant-false Duff's-device latch RED
  until the semantic fix lands here.
- [~] Focused fixture coverage for `102`, `103`, `145`, `154`, `206`, and
  `215`, across applicable O0/O2 and architecture lanes.
  The real `102` gcc-O2 discovery-to-shadow vertical slice is green. The gcc-O2
  `154` side-effect switch preserves all 208 typed case values through verified
  deterministic C rendering. The clang-O2 `154::wide154_dense_effects` lane
  now treats `movzbl`'s 8-bit source width as an intrinsic `0..255` proof,
  resolves all 256 table slots at site `0x15d9`, and records no unresolved
  decline for that site. All 256 values reach the independently verified shadow
  tree and deterministic parseable C without an indirect-jump placeholder;
  scoped execution-differential coverage is now green for this clang-O2 cell,
  while the remaining fixture/compiler matrix remains open. The gcc-O2
  `206::dispatch_in_loop` lane now
  preserves a guarded byte selector through register zero-extension, decodes
  exact cases `0..6`, and renders that typed switch inside its verified loop.
  The pinned clang-14 `statemachine::fsm` lane now carries the already-resolved
  four-way dispatch through the ordinary structurer as a dense guarded switch
  inside `do ... while`. Its guard-only default goes to the proven latch, and
  its terminating case borrows the shared return epilogue without taking global
  ownership. The former strict xfail is green with no goto or indirect-jump
  placeholder.
  Other compiler/optimization and named fixture lanes remain.
- [x] Unit tests for malformed, out-of-range, overlapping, and truncated
  tables; analysis must decline safely.
- [~] Execution differential for every newly recovered switch. The explicit
  shadow-output path now runs the exact typed C returned by
  `decompile_many(..., shadow_v2=True)` through the ordinary fixture comparator.
  The clang-O2 `154::wide154_dense_effects` cell passes all 34 deterministic
  cases with zero pre-render undefined reads. The default v1 path remains its
  committed `fail`. Both GCC-O0 and clang-O0 `206::dispatch_in_loop` cells now
  also pass all 34 cases after a switch-arm loop-exit materialization regression
  was found and fixed; every other newly recovered switch cell still needs the
  same explicit execution evidence before WP5 can complete. The pinned
  clang-14 `statemachine::fsm` default-v1 path now also recompiles and matches
  the original across 64 deterministic fuzz inputs.
- [~] Structural census assertion that typed cases reach the structurer.
  One real per-function assertion now proves the exact ordered cases and
  default reach the shadow tree, its independent verifier, and deterministic
  parseable C rendering. Corpus-wide census coverage remains.

### Implementation evidence — 2026-09-03 malformed-table safety

The bounded relative decoder and whole-section scanner previously computed
`table_va + signed_offset` through wrapping integer arithmetic. At either edge
of the address space, malformed table bytes could therefore wrap into an
address accepted by the executable-region predicate and manufacture a switch
target. Two RED tests reproduced both directions: `u64::MAX - 7 + 16` was
accepted as target `8`, and `4 + (-16)` was accepted near `u64::MAX`.

`src/analysis/jump_table.rs` now uses checked signed address arithmetic. The
bounded decoder reports the existing typed
`TableDecline::TargetArithmeticOverflow { index }`; the heuristic scanner
terminates the candidate run. Explicit unit coverage now includes malformed
object bytes, a table extent truncated at both the section end and a non-zero
offset, a target overlapping the absolute table itself, a non-executable
relative target, adjacent tables, and both arithmetic boundaries.

Validation against the working tree and a fresh release extension:

- `cargo test --features python-ext analysis::jump_table::tests -- --nocapture`:
  18 passed, 0 failed;
- `cargo test --features python-ext`: all 3,089 library tests and every ordinary
  integration target passed; its final CFR doctest hit a transient duplicate
  `pyo3` artifact error, then
  `cargo test --features python-ext --doc identity::cfr` passed 1/1 in
  isolation;
- the six named WP5 fixture families selected 24 baseline lanes with no scoped
  regressions; one `206_aarch64_wide_dispatch:gcc:O2:dispatch_in_loop`
  improvement was visible but is not attributed to this address-boundary fix
  in the concurrent worktree; and
- `08_indirect_dispatch` across i386, ARMv7, AArch64, and x86-64 GCC 15 selected
  eight architecture lanes with no scoped regressions.

The def-use census passed its five safety checks and stopped at the improvement
ratchet because concurrent work removed many baseline violations; it requires
a separately reviewed baseline refresh. The corpus-wide structural command was
still running when this evidence was written and is not claimed green here.

### Exit criteria

- [ ] `unrecovered` switch/dispatch rows reach zero or have typed, triaged
  declines with a specific unsupported encoding.
- [ ] No target exists in discovery but disappears before structuring.
- [ ] The Duff's-device latch is semantically correct.

## 12. WP6 — Constraint-based C type recovery

Purpose: replace sticky, flow-insensitive type joins with explicit constraints
while keeping machine width as truth.

### Production changes

- [ ] Introduce a type-constraint layer under `src/ir/types_recover/`:
  - new `constraints.rs`: equality, width, signed-use, pointer, pointee,
    aggregate, ABI, load/store, and call constraints;
  - new `solver.rs`: deterministic solution and conflict reporting;
  - new `confidence.rs`: provenance and confidence ordering;
  - retain `TypeHint` adapters until all consumers migrate.
- [ ] Treat signedness as per-use evidence, not an irreversible value property.
- [ ] Treat unsigned range comparisons as range facts.
- [ ] Add recursive pointer and aggregate representations needed by `char **`,
  by-value structs, and hidden returns.
- [ ] Key type facts by stable value identity from WP3.
- [ ] Split generated type/return reports by C vs Rust before judging movement.

The first incremental constraint slice landed in
`src/ir/types_recover/constraints.rs` on 2026-09-04. It records signed and
unsigned interpretations against exact operand uses in deterministic order,
resolves only unanimous evidence, and keeps equality, address indexing, and
x86's implicit 32-to-64-bit register-write extension neutral. The compatibility
`TypeHint` adapter now consumes that result only at the ABI live-in boundary;
the flow-insensitive register map continues to provide class and machine width.
This starts, but does not complete, the production checkboxes above: pointer,
aggregate, call, confidence, and general solver constraints remain open.

### Required `classify` signed-loop vertical slice

The exact source shape below is a required WP6/WP7 cross-package regression,
not an illustrative snippet:

```c
int classify(int n) {
    if (n < 0) return -1;
    while (n > 100) { n -= 100; }
    return n;
}
```

It was compiled locally at `80f5d106` with GCC and Clang at O0 and O2. The
release decompiler recovers balanced, parseable `if`/`else` plus `while`
control at O0. With DWARF it now renders the authoritative
`int classify(int n)` declaration, but the body still leaks unsigned casts.
After `strip --strip-debug`, both O0 compilers regress the return declaration to
`unsigned int`, and the negative result renders as `0xffffffff` or an explicit
unsigned cast. This is a missing stripped-inference capability, not a WP8
declaration-authority defect.

Required WP6 features:

- [~] Record negative return constants and signed relational uses as exact,
  per-use return/value constraints without making signedness sticky globally.
- [x] Resolve a stripped 32-bit return as signed only when all width-bearing
  ABI evidence agrees and the signed evidence is unopposed; retain ambiguity
  when signed and unsigned uses conflict.
- [x] Propagate the selected return interpretation to return expressions so an
  authoritative signed declaration does not retain redundant unsigned casts.
- [~] Keep genuinely unsigned functions unchanged and preserve C/Rust-separated
  measurement totals.
- [x] Add the fixture as GCC/Clang O0 debug and stripped cells. Keep O2 as a
  separately reported observation: compiler strength reduction or unrolling
  may erase the source loop, so exact loop reconstruction is not an O2
  correctness requirement.

Implementation boundaries for the remaining return-type work:

- Extend `src/ir/types_recover/result_hint.rs` (and the incremental constraint
  layer under `src/ir/types_recover/`) to collect return-width, signed-use, and
  negative-constant evidence. ABI-mandated x86-64 zero-extension of a 32-bit
  result is transport evidence, not proof that the C result is unsigned.
- Make `src/ir/ast/return_ctype.rs` consume the resolved result interpretation
  when choosing the declaration and simplifying each return expression. It may
  remove an unsigned cast only when that cast is an ABI transport shell over a
  value proved signed at the same source width.
- Keep `src/ir/const_fold.rs` responsible only for the already-landed terminal
  predicate equivalence. Do not infer a function return type from the visual
  shape of that folded predicate or from rendered variable names.
- On conflicting or incomplete evidence, preserve the current unsigned or
  ambiguous spelling rather than guessing. This vertical slice must remain an
  incremental consumer of the future WP6 solver, not establish a second type
  system in the AST renderer.

#### `classify` issue-to-feature contract

This table is the authoritative scope for the reported example. It keeps the
visible defects tied to production capabilities and prevents a prettier single
render from being mistaken for completion.

| observed behavior | classification | required production feature | acceptance evidence |
|---|---|---|---|
| The recovered `if`/`else` and `while` match the source control shape. | Existing strength to preserve. | Keep the WP4 structured loop and branch result unchanged while expression and type passes improve it. | Structural fixture remains an `if` with a nested `while`; execution differential remains green. |
| `n > 100` renders as the expanded `((x == 100) \| (x <s 100)) == 0` flag formula. | Glaurung expression-normalization defect. | Add a width- and signedness-proved terminal comparison fusion for the exact shared value and constant; carry its signed result type and decline every ambiguous variant. | O0 GCC and Clang, debug and stripped, render `n > 100` or `100 < n`; expanded flag spelling is absent; proof and refusal tests below pass. |
| A stripped build renders `unsigned int classify(...)`. | Glaurung stripped type-inference limitation. | Combine negative return constants, signed relational uses, ABI width, and per-use constraints; select signed only with unopposed evidence. | Both stripped O0 compiler cells render a signed 32-bit return, while genuinely unsigned counterexamples remain unsigned. |
| The negative return renders as `0xffffffff` and signed bodies retain unsigned casts. | Consequence of missing signed return propagation and destination-typed cleanup. | Propagate the chosen signed return interpretation into return-expression rendering and remove only provably redundant casts. | Render `return -1;`; emitted C compiles and boundary execution agrees with the reference. |
| A pasted output appeared to contain an unmatched brace. | Not reproduced in the pinned local rendering; likely transcript truncation, not a confirmed product defect. | Do not create a speculative brace-repair pass. Retain parseability and delimiter balance as gates on every affected cell. | Host C syntax check succeeds for debug and stripped outputs from both compilers. |

Completion means all four GCC/Clang O0 debug/stripped cells satisfy the table
in one pinned release build. An isolated constant-fold unit test or one
debug-assisted signature is necessary evidence, but is not completion.

The bounded return-result implementation is now green in all four required
signed cells and all four genuinely unsigned control cells. It joins exact SSA
result definitions before rendering, treats all-ones as ambiguous without
independent evidence, and removes only declaration-consistent ABI transport
casts. This closes the concrete `classify` return issue, but not WP6's general
constraint solver or corpus-wide C/Rust measurement exit criteria. See
`results/wp6-classify-signed-return.md`.

The follow-on `2be036eb` typed-render increment removes the remaining
`(long)(n)` shells from both signed `classify` predicates. It consults the
selected declaration, accepts only value-preserving signed widening against a
representable literal, and retains wider-literal and unsigned cases. This
closes the concrete example's cast-heavy predicate spelling without claiming
the general WP6 constraint solver is complete.

Required regression coverage is equally part of completion:

- `python/tests/test_classify_signed_loop.py` must assert the signed declaration,
  simplified relational condition, `return -1;`, absence of the redundant
  unsigned return cast, balanced/parseable output, and boundary execution for
  every O0 compiler/debug cell.
- `tests/fixtures/classify_signed_loop.c` must include a genuinely unsigned
  control (unsigned parameter/result and unsigned relational use). Its stripped
  GCC and Clang outputs must remain unsigned.
- Focused `src/ir/ast/return_ctype.rs` tests must cover signed resolution,
  unsigned preservation, conflicting evidence, and same-width ABI-cast removal;
  mismatched widths and non-transport casts must be refusal cases.
- The scoped loops/polarity/switch/width corpus and the full required Rust and
  Python gates must be reported separately. Syntax success alone does not prove
  the return-type inference or execution behavior correct.

### Tests

- [x] RED `tail_dispatch` signedness and return-width case.
- [ ] Existing `python/tests/test_pdb_type_recovery.py` xfails.
- [~] Existing aggregate/return fixtures `195`, `197`, and `198`. Commit
  `ede20fb0` repairs three SysV AMD64 memory-class return lanes by combining
  adjacent hidden-result setup with proved caller live-ins and promoting the
  declared result extent as one stack aggregate. Commits `9fed7199` and
  `41af392d` then preserve register-resident INTEGER+SSE results and stop the
  differential oracle from comparing indeterminate aggregate padding. Fixtures
  `195` and `198` are now entirely pass or intentionally structural across the
  scoped host matrix. Commits `cf9160ba`, `fe50a360`, `3f4f12fe`, and
  `db750dbc` close all nine former O2 HFA failures in `197`: declared
  `xmm0:xmm1` results are materialized all-or-nothing, exact direct-call
  contracts permit clobber-free pair forwarding, bounded legacy packed-XMM
  instructions retain their lane semantics, packed dword concatenation widens
  before shifting, and proved aggregate materialization prevents cross-bank
  scratch identities from collapsing into one cosmetic return name. The full
  four-lane fixture now has every non-structural row passing. See
  `results/wp6-sysv-hidden-return-buffers.md` and
  `results/wp6-sysv-split-bank-returns.md` and
  `results/wp6-sysv-sse-pair-returns.md`.
- [x] `python/tests/test_decompiler_observable_parameter_width.py`.
- [x] Stripped-lane tests to prove improvements do not depend on debug types.
- [ ] Solver unit tests for conflicts, ambiguity, and deterministic ordering.

### Exit criteria

- [ ] C parameter and return axes improve without stripped regressions.
- [ ] Low-confidence signedness is rendered honestly rather than asserted.
- [ ] Rust numbers remain visible but do not block C milestones.

The checked test slice is bounded evidence, not WP6 completion. Both stripped
GCC and Clang `tail_dispatch` declarations changed from
`unsigned int, unsigned int, int` to `int, int, int`; the inferred debug
prototype now agrees with the authoritative DWARF declaration and no longer
emits a false conflict. The complete O0/O2 execution corpus remained at 824 of
838 passing lanes with no scoped regressions and 27 pre-existing baseline
improvements. See `results/wp6-per-use-signedness.md` for commands and limits.

## 13. WP7 — Width-proved expression idioms

Purpose: translate compiler idioms into source-like expressions only when the
machine-width equivalence is established.

### WP7A — Immediate render-level idioms (depends on WP0)

- [x] Implement destination-typed literal spelling at the existing typed
  render boundary so `-1` in `int32_t` does not render as `0xffffffff`.
- [x] Implement one width-preserving subtract-and-unsigned-compare range fusion
  beside the existing `cmp_fusion` boundary.
- [x] Keep both changes narrow, table-driven where practical, and independently
  revertible. Do not introduce a second value-identity system.

Implementation revision: `81ffe9ab`. The literal rule consumes the existing
destination type only and declines unknown, unsigned, pointer, boolean, and
64-bit-positive cases. The range rule consumes the existing `TypeMap` or an
explicit unsigned cast shell, preserves that exact 8/16/32/64-bit view on both
replacement comparisons, recognizes both `Sub(x, low)` and the folded
`Add(x, -low)` form, and declines wrapping intervals. No new value identity or
name-parsing convention was introduced.

### WP7B — SSA-expression idioms (depends on WP3)

- [ ] Add an SSA-expression idiom module, preferably `src/ir/ssa_idioms/`,
  after WP3 establishes the owning SSA boundary.
- [~] Land one rule per increment:
  1. [x] flag-derived relational normalization, beginning with the exact typed
     equivalence `!((x == k) || (x <s k)) == (x >s k)` seen in `classify`;
  2. [ ] strength-reduced constant multiplication;
  3. [ ] signed division/modulo by a power of two;
  4. [ ] compiler magic-number division;
  5. [ ] compound boolean-mask normalization;
- [ ] Each rule must declare operand width, signed interpretation,
  preconditions, output type, and origin composition.
- [ ] Never peel or narrow casts unless equivalence is proved at the original
  width.
- [ ] Permit the first relational rule at the existing typed comparison-fusion
  boundary before WP3 only if both comparisons already carry the same exact
  SSA value, constant, width, and signed relation. Otherwise decline until WP3
  supplies stable identity; do not compare display names.

### Tests

- [x] Exhaustive equivalence at 8 and 16 bits.
- [x] Boundary-complete plus seeded randomized equivalence at 32 and 64 bits.
- [x] Regression test for the earlier `cmp_fusion` 64-to-32 narrowing bug.
- [x] End-to-end fixtures from `03_loop_shapes` and `102_duffs_device`.
- [x] Execution differential and pinned byte/readability measurements.
- [x] Exhaustively prove the `classify` relational rule at 8 and 16 bits and
  use boundary-complete plus seeded randomized checks at 32 and 64 bits.
- [x] Require exact refusal for mixed widths, unsigned `<`, different values or
  constants, inverted polarity mismatch, and a comparison with missing
  producer evidence.
- [x] End-to-end `classify` tests must require `while (n > 100)` (allowing
  equivalent operand order), reject the expanded `ZF | (SF ^ OF)` spelling,
  compile the emitted C, and pass execution differentials on negative, 0, 100,
  101, repeated-subtraction, and integer-boundary inputs.

The first relational rule landed at `9c9c607c` in the existing terminal
constant-fold boundary under the pre-WP3 exception above. It requires the same
expression, constant, source width, outer width, signed `<`, unsigned equality
view, non-negative signed-representable constant, and equality-to-zero terminal
use. Ten focused proof/refusal tests pass. The release-built GCC/Clang O0 debug
and stripped fixture cells all emit `100 < n` through the preserved signed
view, compile as C, and pass 34 differential cases each. The 24-lane loops,
polarity, switch, and width corpus reports zero scoped regressions. This closes
the predicate subproblem only; stripped return inference and redundant return
casts remain WP6 work. See `results/wp7b-classify-signed-predicate.md`.

At `81ffe9ab`, `cargo test --features python-ext` passes, including 15 focused
comparison-fusion tests and 191 AST/render tests; the six def-use census tests
also pass. The required real-binary slice runs 72/72 `03_loop_shapes`
functions successfully across clang/gcc O0/O2, retains the four independently
known `102_duffs_device` failures, and reports zero scoped regressions. In the
real gcc-O2 Duff output, the 84-byte opaque predicate
`(unsigned)15 < (unsigned)(arg2 - 1)` becomes the 159-byte explicit predicate
`(unsigned)arg2 < 1 || 16 < (unsigned)arg2`: bytes increase by 75, but the
accepted interval and rejection reason are directly readable. This is a
readability improvement, not an execution or aggregate-score improvement; the
unrecovered Duff indirect jump remains the reason that cell fails.

### Exit criteria

- [x] Every enabled WP7A rule has a machine-width equivalence test. WP7B is not
  yet enabled.
- [x] No execution regression and no unexplained type-width change in the
  required WP7A fixture slice.
- [x] The pinned Duff measurement improves readability with an explicitly
  recorded 75-byte cost; neither rule is claimed as an aggregate score win.

## 14. WP8 — Declaration authority and conflict provenance

Purpose: ensure analyst, DWARF, and PDB declarations improve rendered output
without concealing inference disagreement.

### Production changes

- [x] Trace `tail_dispatch` through:
  `src/python_bindings/ir/dwarf_contracts.rs`,
  `src/python_bindings/ir/type_maps.rs`,
  `src/ir/ast/declaration_plan.rs`, and
  `src/ir/ast/decbench_render.rs`.
- [x] Define authority order once in the program/session fact layer: analyst,
  trusted debug declaration, inferred recovery.
- [x] Preserve all candidates with provenance and record a typed
  `PrototypeConflict` health finding when they disagree.
- [x] Render the authoritative declaration's types, names, and variadic tail
  when representable.
- [x] Keep conflict diagnostics out of scored pseudocode by default. Expose
  them through structured Python results and an explicitly annotated analyst
  render mode.
- [x] Apply the same contract to all four entry points and propagated call
  sites.

### Tests

- [x] RED `tail_dispatch` exact prototype and parameter names.
- [x] Analyst-over-DWARF and DWARF-over-inference authority tests.
- [x] Stale/conflicting DWARF and PDB fixtures with both facts retained.
- [x] Variadic and aggregate declaration cases.
- [x] Scored-style determinism test proving metadata does not change text.
- [x] Stripped-lane recovery tests remain independent of declarations.

### Implementation evidence — 2026-09-02 DWARF/analyst increment

Implemented locally in `src/debug/dwarf.rs`,
`src/python_bindings/ir/dwarf_contracts.rs`,
`src/ir/ast/declaration_plan.rs`, `src/ir/ast/decbench_render.rs`, and
`src/ir/health.rs`:

- addressless C/C++ declaration DIEs are joined only through a unique defined
  text-symbol identity; non-C source declarations and ambiguous Rust/C++ local
  symbol names are not promoted into C declaration authority;
- source function and parameter names, types, and variadic state reach the
  signature and every corresponding body use through the declaration plan;
- analyst prototype tuples accept an additive fourth parameter-name list while
  retaining the shipped three-item form, and the CLI now transports names the
  project database already stored;
- analyst, DWARF, and machine-recovered candidates are retained as independently
  sourced `PrototypeConflict` entries in deterministic order, while scored text
  stays unchanged; and
- authoritative and inferred candidates fork from one recovery result, so
  provenance does not add a second whole-function type-recovery walk.

The first census attempt exposed `rustc:O0` `7898 -> 7924` undefined reads and
`rustc:O2` `5093 -> 5105`. The regression came from treating addressless Rust
DWARF declarations as C contracts. The language/identity guard above removed
the regression; the final unmodified baseline gate passed all six tests.

Validation at this increment:

- `cargo test --features python-ext`: 2,837 passed, 3 ignored, plus all
  integration targets and doc tests;
- `python/tests/test_decompiler_declaration_authority.py`: 4 passed;
- `python/tests/test_analyst_prototype_reaches_decompile.py`: 11 passed against
  a real compiled fixture;
- `python/tests/test_decompiler_defuse_census.py`: 6 passed, no baseline edit;
- native stub freshness and focused Ruff/ty checks passed. Whole-tree `ty`
  remains independently red with 335 pre-existing diagnostics.

### Implementation evidence — 2026-09-02 PDB declaration increment

Implemented locally in `src/symbols/pdb.rs`,
`src/python_bindings/ir/dwarf_contracts.rs`,
`src/ir/ast/dwarf_render_types.rs`, and `src/python_bindings/ir.rs`:

- module `S_GPROC32`/`S_LPROC32` procedure records now join exact code RVAs to
  `LF_PROCEDURE`/`LF_MFUNCTION` type records by TypeIndex; ID-stream records
  that cannot be resolved against TPI are rejected rather than guessed;
- PE image-base rebasing and CodeView build provenance travel with each joined
  declaration, and DWARF retains priority if a binary unusually supplies both
  trusted debug formats at one address;
- PDB scalar spellings distinguish CodeView `int`/`unsigned int`, `long`, and
  64-bit integer families, while tagged aggregate spelling is retained;
- complete PDB layouts referenced by declarations enter the existing debug
  type environment, allowing a real by-value `struct Point` parameter to be
  rendered and defined rather than flattened to `long`; requested layouts are
  collected in one bulk TPI scan rather than rescanning a large PDB per type;
  and
- all four decompile entry points consume the same map. PDB-versus-inference
  disagreements are reported as structured `PrototypeConflict` records with
  `authoritative_source = "pdb"`, outside scored text.

`python/tests/test_pdb_type_recovery.py` now has no prototype xfails. Its real
PE32+/PDB fixture proves five source signatures: by-value aggregate,
pointer-to-aggregate, mixed double/float, unsigned 64-bit return, and narrow
integer parameters. It also proves four-entry-point parity, metadata
provenance, and no-cache best-effort fallback. During conversion, the old
expected strings were corrected against `tests/pdb_types/types.c`: three
functions return `int`, not `unsigned int`, and `scale_pair` declares `char`,
not `signed char`.

Validation at this increment:

- `cargo test --features python-ext`: 2,839 passed, 3 ignored, plus all
  integration targets and doc tests;
- 12 focused Rust PDB tests, including real module-procedure joining and bulk
  layout lookup: passed;
- `python/tests/test_pdb_type_recovery.py`: 11 passed;
- declaration-authority and def-use census gates: 10 passed, with no baseline
  edit;
- native stub freshness and focused Ruff checks: passed.

### Implementation evidence — 2026-09-02 ABI and call-value increment

Implemented locally in `src/ir/value_number/parameter_slots.rs`,
`src/ir/call_contracts.rs`, `src/ir/call_result_split.rs`,
`src/ir/dead_stores.rs`, `src/ir/ast/dec_render.rs`,
`src/python_bindings/ir.rs`, and
`src/python_bindings/ir/callee_contracts.rs`:

- parameter-slot inference now follows reachable CFG paths instead of block
  address/storage order, so a scratch definition in one switch arm cannot hide
  a genuine live-in read in a sibling arm;
- exceptional-control-flow calls retain a result whenever their call contract
  proves one, while ordinary dead call results can still be discarded;
- two-register aggregate-return evidence survives call-contract refinement and
  result splitting instead of collapsing to a scalar carrier;
- non-C source declarations cross an explicit machine-ABI boundary: scalar and
  pointer aliases are normalized to representable C carriers, non-C aggregates
  do not silently impose the platform C aggregate ABI, and a hidden result is
  accepted only when the recovered void result, leading pointer, and exact
  one-parameter arity difference agree; and
- a call whose selected prototype returns `float` or `double` is rendered as a
  numeric value, not reinterpreted as integer bits through a union.

The parameter-slot algorithm is shared, but its register inventories remain
explicitly ABI-bounded: SysV AMD64, Win64, cdecl32 stack arguments, AAPCS32
soft/hard-float, and AAPCS64. This increment is therefore not evidence for
unsupported decompiler architectures or arbitrary language ABIs.

Validation used a freshly rebuilt release extension:

- focused Rust tests covered CFG sibling paths and every supported
  register-argument ABI;
- the full `168_rust_enum_niche` family had no scoped regressions, including
  the repaired `rustc:O2:rust_enum_discriminant` cell;
- `10_cpp_runtime_shapes`, `129_struct_by_value`, `168_rust_enum_niche`,
  `195_by_value_aggregates`, and `198_aggregate_return_edges` passed their
  18-lane full matrix without scoped regressions;
- `tools/dectest.py @calls @returns @structs` passed 36 of 838 selected lanes
  without scoped regressions after the float-call repair; and
- the four-lane default smoke selection passed without scoped regressions.

Known baseline failures in those families remain open; these commands prove
the bounded increment did not add regressions, not that aggregate, return, or
Rust recovery is complete.

### Implementation evidence — 2026-09-03 program-owned declaration authority

`src/program/environment.rs` now owns the single total declaration order:
inferred recovery, trusted PDB, trusted DWARF, then an explicit analyst
decision. Stable source labels come from the same type. PDB-versus-DWARF
selection, analyst-versus-debug selection, and conflict metadata in all four
binding entry paths consume that order instead of independently encoding it as
vacant-map insertion, `Option::or_else`, and raw strings.

The focused Rust authority test passes, and a fresh debug extension passes all
four real-binary declaration-authority tests, including deterministic scored
text and analyst-over-DWARF conflict provenance. At that snapshot the PDB suite
passed 10 of 11 because `record_value` still rendered `void *` instead of
`Record *`; the following increment closes that independently. The def-use
census fails closed on broad shared-tip drift in both directions; no baseline
was refreshed and no corpus movement is claimed for this output-neutral
change.

### Implementation evidence — 2026-09-03 nominal PDB aggregate pointers

The debug-declaration adapter now preserves authoritative `struct` and `union`
pointer spellings instead of passing them through the inferred library-catalog
normalizer, whose intentionally conservative fallback is `void *`. The real
PE32+/PDB fixture consequently emits `typedef struct Record Record;` and
`int record_value(Record *arg0)` rather than discarding the nominal type. The
generated translation unit passes strict C11 syntax checking.

The focused Rust regression test and all 11 tests in
`python/tests/test_pdb_type_recovery.py` pass against a freshly rebuilt debug
extension. Exact commands and output evidence are recorded in
`results/wp8-pdb-nominal-pointer.md`.

### Implementation evidence — 2026-09-04 Win64 home-slot dead store

The separately reported `record_value` body violation is now closed. The
clang-cl prologue `push rax; mov [rsp], rcx` reserves a word and immediately
homes the first Win64 parameter; stack promotion had rendered the unobserved
push value as `long local_8 = ret`, manufacturing an undefined source read.
Dead-store handling now removes only an adjacent, equal-width promoted-slot
write whose source is non-observable and whose replacement does not read the
slot. It declines partial writes, effectful expressions, self-dependence, and
control-flow crossings.

All 36 focused Rust dead-store tests and all 12 real PDB tests pass after a
fresh extension build. `record_value` has no `local_8`, produces no render-
verification finding, and compiles under strict C11. The smoke matrix reports
no scoped regressions. An exact clean-master A/B run proves the 12 failures in
the broader 85-test definedness/render/emission slice are unchanged current-
master defects. Commands and output are recorded in
`results/wp8-win64-home-dead-store.md`; no baseline was changed. The full Rust
gate is green. The def-use census remains red on its new-finding and
improvement ratchets because of broad current-tip drift in both directions;
the PDB fixture is outside that census and no corpus movement is attributed to
this increment.

### Implementation evidence — 2026-09-04 declared-call pointer boundaries

Call rendering now keeps parameter selection independent from result
representation conversion. A trusted declaration is no longer replaced with a
whole function-pointer cast merely because the recovered destination carrier
spells its return differently; incompatible parameter lists still retain the
per-site cast. At the argument boundary, the renderer now consumes the
declaration plan's selected local type, so a recovered `char *` local is passed
as a pointer rather than being weakened back to `(long)`. One pointer-width
transport cast may be removed only when the inner expression is already proven
compatible with the declared pointer parameter.

The real nullable-locale fixture improved from uncompilable calls such as
`strdup((long)old_locale)`, `strlen((long)saved_locale)`, and
`free((long)saved_locale)` to direct typed calls. All three libc pointer
fixtures compile, recompile, and execute equivalently. The full Rust gate and
the four-lane smoke matrix are green. The structural gate did not start a test:
its fixture setup lost the decompiler subprocess and waited indefinitely in
`subprocess.communicate`, so it was interrupted after 276.89 seconds. The
def-use census remains red on the same broad current-tip drift recorded above;
this fixture is outside that census and no baseline was refreshed. Exact
commands and limitations are in
`results/wp8-declared-call-pointer-boundaries.md`.

### Implementation evidence — 2026-09-04 pointer-return boundaries

Pointer-typed return and assignment boundaries now consume the declaration
plan's selected source type. When a pointer value retains one pointer-width
integer transport cast in the AST, the renderer removes only that redundant
machine representation: it emits a direct value for compatible pointer types
and preserves an explicit pointer-to-pointer cast for incompatible concrete
pointee types.

The real optimized linked-list fixture improves from
`return (node *)((long)var0);` (or the Clang `ret` equivalent) to a direct
pointer return. Both GCC and Clang variants compile and execute equivalently,
the adjacent libc pointer fixtures remain green, all 156 Rust pointer tests
pass, and the four-lane smoke matrix reports no scoped regression. The full
Rust gate is green. The required whole Python suite completed but remains
broadly red on 441 current-tip failures, dominated by the known-decompiler
recovery ratchet; no broad baseline was refreshed. Exact commands and limits
are recorded in `results/wp8-pointer-return-boundaries.md`.

### Implementation evidence — 2026-09-04 annotated declaration conflicts

The CLI now exposes the structured `PrototypeConflict` ledger through an
explicit `decompile --style decbench --annotate-conflicts` analyst mode. Each
requested annotation is deterministic, C-comment-safe, and placed immediately
before the affected signature with both prototype shapes, provenance labels,
and disagreement fields. Default and scored output remain unannotated.

Single, range, `--vas`, and whole-image routes are covered against the real
`tail_dispatch` fixture. Annotated single-function requests bypass the text
cache because drained provenance cannot be reconstructed from cached C. The
focused declaration, cache, generated-reference, and census suite passes all
36 tests; the existing DecBench-style CLI contracts pass all four selected
tests. Broader current-master failures remain visible and no baseline was
refreshed. Exact commands and limitations are recorded in
`results/wp8-annotated-conflicts.md`.

### Implementation evidence — 2026-09-04 DWARF variadic declarations

The DWARF reader now retains a direct `DW_TAG_unspecified_parameters` child as
an authoritative variadic fact and follows the same bounded, same-unit
abstract-origin/specification chain used for inherited attributes. The fact is
carried through the program-owned debug contract into `CallPrototype`, so GCC
and Clang declarations render `f(fixed, ...)` instead of the false fixed-arity
`f(fixed)` claim. PDB contracts remain explicitly non-variadic until their own
format adapter can prove otherwise.

The real four-lane variadic fixture proves all 12 combinations of GCC/Clang,
O0/O2, and three functions render the ellipsis. It also keeps the distinct
machine-to-C limitation visible: two GCC O2 bodies have no undefined reads,
while ten strict xfails still track incomplete SysV register-save-area and
`al` vector-count reconstruction. This increment therefore improves trusted
source declaration fidelity but does not claim generic stripped-binary
variadic inference or complete `va_start` lowering. Exact commands and results
are recorded in `results/wp8-dwarf-variadic-declarations.md`.

### Exit criteria

- [ ] No rendered prototype is worse than an available trusted declaration.
- [x] Conflicts are queryable with provenance.
- [x] Scored output contains no incidental diagnostic comments.

## 15. WP9 — Shared machine model and capability census

Purpose: make ISA/ABI facts explicit and turn missing-instruction discovery
into a standing test.

### Production changes

- [x] Inventory current ownership in `src/target/`, `src/ir/regview.rs`,
  lifters, ABI modules, stack recovery, naming, and dead-store handling. The
  result is `results/wp9-machine-model-inventory.md`.
- [~] Extend the existing `src/target/TargetSpec` boundary one fact class at a
  time. Do not introduce a competing `src/ir/machine/` identity: target ID,
  format/OS ABI, pointer width, instruction mode, PC rule, and special-register
  roles already live under `src/target/` with an exhaustive conformance table.
  Register views, ABI storage/effects, frame rules, and capability reporting
  remain split across IR consumers.
- [ ] Suggested target-owned query modules: `register_views.rs`, expanded
  `abi.rs`, and `capabilities.rs`; retain compatibility facades while callers
  migrate, and keep opcode semantics in the per-target lifters.
- [~] Add ARM32 register views, including VFP/NEON overlap, before migrating
  ARM32-specific shared-pass conditionals. `TargetSpec::register_view` now owns
  ARM32 core aliases and the complete `s0..s31`/`d0..d31`/`q0..q15` storage
  hierarchy. MIR register-effect completeness is the first consumer: `s0` and
  `d0` writes are opaque because each defines only part of `q0`, while a `q0`
  write is complete. Production SSA definition canonicalization is the second
  consumer: complete ARM core aliases use the target-owned parent, while
  partial `s`/`d` definitions deliberately retain their spelling until the
  lifter models their read-modify-write semantics. Remaining shared consumers
  and full VFP SSA identity are open.
- [ ] Migrate one fact class at a time: register overlap, clobbers/live-ins,
  argument/return locations, flag semantics, then silent writers.
- [ ] Keep lifter instruction semantics target-specific; share the queried
  contract, not necessarily implementations.
- [~] Add mnemonic capability census tooling and a documented exemption file.
  The standing effect census now has non-empty real-binary denominators for all
  four lifted targets, including i386, and validates every opaque mnemonic
  against `tests/decompiler_fixtures/effect_census_exemptions.json`. The gate
  rejects unreviewed names, count growth, overlapping matches, empty rationale
  fields, unknown targets, and exemptions which no longer fire. A second
  address-correlated census independently decodes each accepted LLIR block and
  requires every decoded instruction to produce a non-opaque LLIR op or match
  `tests/decompiler_fixtures/decoded_lift_exemptions.json`. Target, dynamic
  instruction-mode, compiler, and optimisation keys now have committed
  per-lane denominator and opaque-count ratchets.

### Tests

- [ ] Byte-identical fixture sweep for each architecture-only migration.
- [ ] Extend architecture roundtrip and ARM32 semantic tests.
- [x] New census test: every decoded mnemonic is lifted or has a reviewed,
  reasoned exemption. Both the post-lift opaque-effect census and the raw
  decoded-mnemonic-to-LLIR correlation are now enforced across all four lifted
  targets.
- [~] Ratchet `SILENT_REGISTER_WRITERS` toward zero. The standing x86 test now
  gives every remaining mnemonic an exact observed ceiling and rejects both
  count growth and stale entries. Sixteen-bit `bsr`/`bsf` now preserve their
  full register parents through explicit partial-read/write lowering, removing
  all four observed `bsr` occurrences. `cpuid`, `rdtsc`, `rdtscp`, and `xgetbv`
  now expose their complete architectural input/output dataflow on both i386
  and x86-64, removing 12 more observed silent writes; 19 reviewed mnemonic
  classes remained at that point. The exact 128-bit VEX `vpxor` register and
  memory forms now preserve both explicit sources, destination lanes, and the
  whole XMM view, removing four more silent writes; 18 reviewed mnemonic
  classes remained at that point. `pushfq` now exposes all seven represented
  flag inputs while retaining an honest unknown full flags word, and `popfq`
  extracts those seven bits from the loaded word while preserving both stack
  effects; four more observed silent writes are gone and 16 reviewed mnemonic
  classes remained at that point. The fixed-width YMM `vmovdqu` register and
  memory forms now transport all 256 bits as eight exact dword lanes, removing
  92 measured unmodelled forms and the `vmovdqu` silent-writer class. This does
  not claim general AVX semantics or first-class 256-bit LLIR storage. Fifteen
  reviewed mnemonic classes remained at that point. Exact eight-lane `vpand`
  now covers both register and memory sources, and exact `vpbroadcastb` reads a
  single byte and replicates it across all 32 destination bytes. Those remove
  four more measured forms and two more silent-writer classes. Thirteen
  reviewed mnemonic classes remain; the watched YMM form map is now only
  `vpcmpeqb` and `vpmovmskb`. The
  isolated `d14748cf` WP9 overlay passed the complete Rust gate with 3,080
  library tests passing, 3 ignored, and every integration and doc-test target
  green after `vmovdqu`; after the `vpand`/`vpbroadcastb` increment it passed
  again with 3,084 library tests passing, 3 ignored, and all integration and
  doc-test targets green.
- [x] Ensure `Op::Unknown` and generic intrinsic totals cannot silently grow.
  The per-target/mode/compiler/optimisation lane baseline requires zero
  `Op::Unknown` and caps the combined opaque plus modelled-intrinsic total for
  every measured lane. The combined WP9 overlay passed the complete isolated
  Rust gate: 3,071 library tests passed, 3 were intentionally ignored, and
  every integration and doc-test target passed.

### Implementation evidence - 2026-09-03 target-aware register reads

The production SSA path now distinguishes definition identity from read
identity. This fixes x86-64 partial reads such as `ax` observing the current
`rax` value, carries the exact SSA base through value numbering and MIR storage
inventory, and improves `cpp_template_int16:gcc:O2` from fail to pass without a
scoped x86-64 regression.

The required i386 sweep rejected an attempted standalone IA-32 register-view
model with 241 regressions across 410 lanes. That experiment was removed and an
explicit compatibility boundary retains historical i386 identity until the
lifter and all downstream consumers migrate together. The attempt, focused and
full-gate results, artifact hash, concurrent-worktree limitations, and remaining
three unaccepted i386 baseline regressions are recorded in
`results/wp9-target-aware-register-reads.md`.

This is one bounded WP9 increment. It does not close the shared target-model
ARM32/VFP, capability-census, or whole-architecture exit criteria below.

### Implementation evidence - 2026-09-03 ARM32 scalar VFP views

The first slice from `results/wp9-machine-model-inventory.md` is implemented in
`src/target/register_views.rs`, exposed through `TargetSpec`, and consumed by
MIR register-effect completeness. The target-qualified model keeps ARM core
and VFP banks distinct, maps `s0` and `s1` onto the low/high halves of `d0`,
and declines the same spelling under another architecture. Soft- and
hard-float targets share architectural storage while retaining distinct
calling conventions.

TDD and focused validation on the live shared snapshot:

- RED: target conformance did not compile because `register_view` did not
  exist; the MIR behavior test also described the former false-complete `s0`
  effect;
- `cargo test --features python-ext arm32_ --no-fail-fast`: 35 passed;
- `cargo test --features python-ext target:: --lib`: 5 passed;
- `cargo test --features python-ext ir::mir::tests:: --lib`: 15 passed; and
- release extension rebuild completed.

The slice was then overlaid by itself onto a fresh clone at `d14748cf`, with
the committed fixture build mounted read-only. In that isolated tree,
`cargo test --features python-ext` produced 3,065 passes, 0 failures, and 3
ignored tests. The same 410-lane ARMv7 O0/O2 sweep was run both on the isolated
slice and on an untouched control clone at `d14748cf`; both reported exactly
184 baseline regressions and 5 improvements. Thus the pre-existing ARM
baseline is red, but this slice changes zero lane verdicts relative to its
control. MIR remains an on-demand/debug analysis and the slice does not change
scored C.

The follow-up NEON increment makes `q0..q15` the widest canonical storage
parents: `s0..s3` partition `q0`, and `d0:d1` partition it. Its RED tests
proved that `q0` was absent and MIR falsely called a `d0` write complete;
GREEN validation passed all 35 ARM32-filtered tests, all 5 target tests, and
all 15 MIR tests. A fresh isolated overlay at `d14748cf` passed the complete
Rust gate, including 3,065 library tests with 0 failures and 3 ignored tests,
all integration binaries, and doc tests. Its release-built 410-lane ARMv7
O0/O2 sweep again reported exactly the untouched control's 184 regressions and
5 improvements, proving zero fixture-verdict changes from both the scalar and
NEON register-view increments.

Promotion is intentionally not claimed. A full isolated Python-suite attempt
was already producing failures in pre-existing fixture/decompiler groups and
was interrupted after roughly 22 percent when its process stopped yielding a
usable final report. Under the repository rule requiring the whole Python
suite after a source commit, that is not a passing gate.

The next increment migrated the duplicated ARM core-alias table out of
production SSA. `TargetSpec::complete_register_write_parent` is now the
fail-closed definition query: `a1` returns `r0`, a full `q0` write returns
`q0`, and partial `s0`/`d0` writes return no parent. Its RED conformance test
failed because the target query did not exist; GREEN validation passed all 5
target tests, all 12 SSA tests, and all 36 ARM32-filtered tests. An exact-file
isolated overlay passed the complete Rust gate, including 3,066 library tests
with 0 failures and 3 ignored tests, every integration binary, and doc tests.
The release 410-lane ARMv7 O0/O2 sweep remained identical to the untouched
control and both preceding slices: 184 historical regressions and 5
improvements, hence zero fixture-verdict changes attributable to the SSA
migration.

The attempted next step—unifying ARM scalar/vector SSA storage—was explicitly
deferred after inspecting the actual IR boundary. `Value::Const` is an `i64`,
while the widest `q` parent is 128 bits, and existing x86/AArch64 vector
lifters intentionally scalarise lanes rather than synthesize a 128-bit
read-modify-write. Canonicalising `s0` or `d0` directly to `q0` would therefore
manufacture a complete definition with no representable preservation of the
untouched bits. Full VFP SSA identity now has an explicit prerequisite:
scalarised ARM vector lanes or first-class 128-bit LLIR values and operations,
followed by real-instruction execution tests.

The independent capability-census increment added an existing committed i386
PE sample to the standing census corpus. A RED test first failed because the
per-architecture
census helper did not exist; GREEN now proves non-empty file, function, and
instruction denominators for i386, x86-64, ARMv7, and AArch64. The measured
report covers 10 binaries, 432 lifted functions, and 53,488 instructions,
including 26,089 i386 instructions that were previously invisible.

The follow-up RED test failed because no reviewed exemption manifest existed.
The new manifest records target, exact mnemonic or family, measured ceiling,
reason, semantic risk, owner, and removal condition. Its live gate covers all
236 current opaque effects: 194 i386 x87-family operations, 16 x86-64
`hlt`/`pause`/`ud2` operations, and 26 ARM `svc` or guarded-control effects;
AArch64 currently has zero opaque effects but retains a required denominator.
All 5 enforcing census tests pass, with the histogram reporter intentionally
ignored by the ordinary gate. An exact-file isolated overlay at `d14748cf`
passed `cargo test --features python-ext`: 3,068 library tests passed with 0
failures and 3 ignored tests, followed by every integration target and doc
test. This gate covers the combined ARM32 register-view, SSA-query, and census
increments without relying on the concurrently modified live worktree.

The next RED census used an empty raw-decoder exemption manifest. After the
audit was restricted to the exact function-owned block ranges accepted by the
lifter, it proved that no decoded instruction disappears entirely. It then
failed on the 236 decoded instructions which reach only maximally opaque LLIR:
194 i386 x87 instructions, 16 x86-64 trap/hint instructions, and 26 ARMv7
system-call or predicated instructions. The reviewed raw manifest records the
actual machine mnemonics independently of the normalized intrinsic names. Its
gate rejects unreviewed mnemonics, overlapping patterns, stale entries, count
growth, unknown targets, and empty review fields. The raw denominators are
6,236 i386, 8,394 x86-64, 812 AArch64, and 228 ARMv7 decoded instructions;
AArch64 has no opaque decoded instruction in this corpus. An exact-file
isolated overlay at `d14748cf` passed the complete Rust gate with 3,069 library
tests passed, 0 failed, and 3 ignored, followed by every integration target
and doc test.

Lane attribution is now enforced from committed provenance rather than filename
guessing. Each of the 10 corpus entries carries an explicit compiler and
optimisation identity sourced from its metadata sidecar and output path;
cross-built artifacts with no recorded optimisation level remain `unknown`,
and assembler output is `not-applicable`. A standing invariant rejects empty
fields, duplicate paths, missing binaries, or an unreviewed inventory-size
change. `effect_census_lane_baseline.json` splits the corpus into 10 actual
target/mode/compiler/optimisation lanes—including separate A32 and Thumb rows
from the mixed ARM binary—and requires each lane to retain its file, function,
and decoded-instruction denominator while its opaque count may decrease but
cannot grow silently. The exact-file isolated `d14748cf` overlay passed the
complete Rust gate with 3,074 library tests passed, 0 failed, and 3 ignored,
followed by every integration target and doc test.

### Implementation evidence - 2026-09-03 store-width demand

The bit-demand oracle now treats a register-valued memory-store source as the
width actually written, while retaining whole-value demand for address and
predicate operands. This removes the false entry-`rax`/undefined-`ret` input
from both Clang `atomic_flag_round_trip` lanes without inventing an initializer
or adding an architecture special case. The definedness module's six tests
pass, a narrow definition-health census reports no O0 or O2 violation, and all
four host atomic lanes remain baseline-stable. Exact RED/GREEN and fixture
evidence is in `results/wp9-store-width-demand.md`.

### Implementation evidence - 2026-09-03 interprocedural INTEGER pair

Direct-callee recovery now upgrades a call to the existing double-word INTEGER
carrier only when the callee must-define analysis proves both ABI result halves
on every reachable return and the exact caller consumes both before overwrite.
This removes the undefined `rdx`/`var4` from Rust trait-object `rust_dyn_apply`
at O2 and keeps O0 clean. Five positive/negative and cross-ABI proof tests and 18 adjacent
call-result tests pass; both Rust fixture lanes remain baseline-stable. The
broader host sweep measured 824/838 lanes but remains red from one infrastructure
crash and three scalar C++ regressions in the concurrent snapshot, none of which
crossed this new carrier path. Exact evidence and limits are in
`results/wp9-interprocedural-integer-pair.md`.

### Implementation evidence - 2026-09-03 Rust vtable tail calls

Prototype-backed tail-call recovery now joins the proven two-word callee result
with the exact terminal Rust vtable-slot load before converting an indirect
jump. O2 `rust_dyn_apply` consequently emits the real virtual call and return
instead of an unrecovered terminal jump, while four negative proof shapes stay
fail-closed. The complete Rust trait-object O0/O2 slice remains baseline-stable;
its remaining score failure is return-width/type cleanup, not missing control
flow. Exact proof conditions and gate limits are in
`results/wp9-rust-vtable-tail-call.md`.

### Implementation evidence - 2026-09-03 Rust scalar source types

The DWARF-to-C rendering boundary now translates Rust's fixed-width scalar
spellings into representation-preserving standalone C types. The real O0 and
O2 `rust_dyn_apply` fixture lanes consequently render their exported boundary
as `int rust_dyn_apply(unsigned int sel, int x)` instead of widening the return
to `long`; the clean O2 snapshot retains the previously recovered virtual call.
The conversion is deliberately outside the generic C catalog normalizer, so it
does not reinterpret Rust pointers or aggregates. Exact RED/GREEN and isolated
snapshot evidence is in `results/wp9-rust-scalar-source-types.md`.

### Exit criteria

- [ ] Shared passes no longer branch on architecture for migrated fact classes.
- [ ] ARM32 has an explicit register-view model.
- [ ] The capability census is part of `default` or a clearly named required
  architecture profile.

## 16. WP10 — Verification, consolidation, and selective deletion

Purpose: finish the architectural migration, make release evidence fail
closed, and remove superseded code only after equivalence is demonstrated.

### Verification changes

- [x] Restore the independent LLIR invariants currently stranded in
  `src/ir/verify.rs` by compiling the module or porting each invariant to its
  correct owner.
- [x] Complete goto-aware used-before-definition using the WP1 winner.
- [ ] Promote `BlockDropped`, `EdgeUnaccounted`, `UsedBeforeDefinition`, and
  constant-false live latches to fixture/release failures.
- [ ] Preserve best-effort output with structured health/completeness metadata.
- [ ] Add lane-keyed O2 closure and effect expectations.

### Implementation evidence — 2026-09-02 LLIR verifier restoration

`src/ir/verify.rs` existed with production-grade checks for invalid width
changes, undefined temporaries, invalid memory access sizes, residual unknown
instructions, and explicit undefined values, but `src/ir/mod.rs` did not
compile the module. Restoring the module declaration turns those checks and
their real lifted-binary test back into maintained code.

Validation:

- before restoration,
  `cargo test --features python-ext ir::verify::tests -- --nocapture` selected
  zero verifier tests;
- `cargo check --features python-ext --lib` passed with the verifier compiled;
  and
- after restoration, the same focused test command ran all nine verifier
  tests, including `real_lifted_functions_have_no_fatal_errors`: 9 passed,
  0 failed.

This closes only the stranded-module item. The verifier is a query API, not yet
a release gate, and the remaining health promotion and lane-keyed expectations
below stay open.

### Implementation evidence - 2026-09-03 goto-aware definedness

`src/ir/verify_defs.rs` now builds a fixed-point CFG from the exact final AST
for functions containing labels and gotos. The graph includes nested
conditionals, loops, switches, breaks, exception arms, explicit labels, and
direct gotos. Missing or duplicate labels fail closed for the stronger
flow-sensitive claim; `NeverDefined` remains active, including for throw,
indirect-goto, and try/catch reads.

The focused suite passed 38 tests and the full
`cargo test --features python-ext` gate passed. A release-built, goto-heavy
fixture slice selected 20 of 838 lanes with no scoped behavior regressions.
The full def-use census correctly remained red: it surfaced newly visible real
undefined reads while concurrent work resolved many baseline findings, so this
increment did not rewrite the shared baseline. The structural test file also
remained red with the expected new exception-body finding plus unrelated
concurrent output/baseline drift. Commands, build fingerprint, scope, and the
detected repair targets are recorded in
`results/wp10-goto-aware-definedness.md`.

### Implementation evidence - 2026-09-04 performance-gate preflight

The post-`src/` full Python suite exposed a gate-ordering defect: the
incomparable-unit fail-closed test launched nine intentionally expensive
whole-binary decompilations before checking metadata that already proved the
run could not be compared. The same problem affected missing baselines and
impossible baseline references. The interrupted suite reached 71% in 1:51:36;
its 372 failures, 2,761 passes, and 892 expected failures are partial
accounting, not a completed gate result.

`ef24d729` moves those metadata-only exit-3 decisions ahead of measurement
while preserving real comparison, baseline-write, and runtime partial-result
paths. The four focused contract tests now complete in 0.62 seconds and assert
that rejected preflight states never enter measurement. Exact diagnosis,
commands, and limits are recorded in `results/wp10-perf-gate-preflight.md`.

### Selective deletion checklist

For each candidate module/pass:

- [ ] name the replacement owner;
- [ ] identify all production and test callers with `rg`;
- [ ] record firing/applicability evidence;
- [ ] remove one candidate per commit;
- [ ] run focused tests and `default` after each removal;
- [ ] run `release` after the deletion series;
- [ ] update the roadmap and this plan with the measured result.

Candidates include rejected MIR/MemorySSA code, old structurer compensation
passes subsumed by v2, `tag_phys`, `remap_type_map`, repeated orchestration,
and zero-fire loop-form passes whose applicability cannot be demonstrated.
The entire AST compensation layer is not a deletion unit.

## 17. Required validation by change class

### Documentation/tooling-only changes

```bash
uv run pytest python/tests/test_known_decompiler_failures.py -xvs
uv run pytest python/tests/test_defuse_ratchet.py -xvs
uv run pytest python/tests/test_decompiler_gate.py -xvs
uvx ruff check python/ tools/
uvx ty check python/
```

### Rust semantic changes

```bash
cargo test --features python-ext
uv run maturin develop
uv run pytest python/tests/test_decompiler_fixture_structural.py -xvs
uv run pytest python/tests/test_decompiler_defuse_census.py -xvs
```

### Pipeline/API changes

```bash
uv run pytest python/tests/test_decompiler_entrypoint_equivalence.py -xvs
uv run pytest python/tests/test_decompiler_determinism.py -xvs
uv run pytest python/tests/test_decompiler_session.py -xvs
```

### Full completion gate

```bash
scripts/decompiler-gate.sh release
```

Until that script exists, use the commands in `CLAUDE.md` and record exactly
which lanes ran. Never describe an unrun or partial lane as green.

## 18. Measurement report required for every output-changing increment

Store a Markdown report under:

- `docs/history/decompiler-review-2026-09-02/results/<work-package>-<slug>.md`

Each report must include:

- before and after Git revisions;
- exact command lines and build fingerprint;
- focused test RED/GREEN evidence;
- fixture cells improved, regressed, and unchanged;
- C and Rust counts separately;
- structural goto/switch/break changes;
- execution-differential result;
- GED, type, byte, and Union changes when evaluated;
- wall time and RSS;
- accepted trade-offs or reason for revert.

Do not refresh a baseline merely to make a regression green. Any accepted
regression needs a written semantic justification and an explicit entry in the
relevant ratchet's accepted-regression record.

## 19. Milestones

### M0 — Evidence is trustworthy

- [x] WP0 complete at `7aec4e842fa1`; the generated inventories and gate
  contracts were established in `eb6484ce` and the core-facet preflight was
  corrected in `7aec4e84`.
- [x] Existing committed baselines are cited at pinned revision
  `e55576bc4612` in the active-roadmap status entry.
- [x] Gate profiles identify their denominator and fail closed.

### M1 — Capability work is producing evidence

- [x] WP4 is running in shadow mode on the first three RED fixtures, with v1
  still the sole production authority.
- [x] WP5 has a host jump-table vertical slice: the real gcc-O2 Duff dispatch
  resolves eight ordered targets in discovery and carries values `0..7` plus
  its typed bypass edge through the independently verified WP4 tree and into
  deterministic parseable switch output. The v1 production path remains
  unchanged until WP4 promotion evidence is complete.
- [x] WP7A landed at `81ffe9ab` with width-aware equivalence, real-binary
  readability, execution, and def-use evidence.

### M2 — Dormant architecture decision made

- [x] WP1 experiment complete: the production definedness consumer was
  rejected on its hard performance criterion and removed; see
  `mir-trial-results.md`.
- [~] MIR is not a named production authority. Its production consumer was
  removed, while responsibility-by-responsibility substrate deletion remains
  a WP10 item because independent verifier/object/type tests are retained.

### M3 — One semantic pipeline

- [ ] WP2 and WP3 complete.
- [ ] Entry points agree at equal budget.
- [ ] Semantic consumers use stable values, not display names.
- [ ] Origin mappings are deterministic.

### M4 — Largest measured defect classes closed

- [ ] WP4 and WP5 complete.
- [ ] Whole-function structural fallback is no longer the default failure
  mode.
- [ ] Switch target evidence reaches structuring.

### M5 — Types and readability improve safely

- [ ] WP6, WP7A, WP7B, and WP8 complete.
- [ ] C type/return axes improve.
- [ ] Every idiom has width-aware equivalence evidence.
- [ ] Trusted declarations render authoritatively with out-of-band conflicts.

### M6 — Architecture and release closure

- [ ] WP9 and WP10 complete.
- [ ] Release profile is green at a pinned commit.
- [ ] Final local DecBench evidence is complete and internally archived.

## 20. Immediate next actions

1. [x] Recover nested post-tested rendering without flattening conditional
   arms. Commit `80f5d106` preserves ordinary internal conditionals and absorbs
   only the exact typed latch. A missing lexical continuation is materialized
   only when its LLIR block is an unconditional-return tail. The release-built
   pinned corpus reports zero regressions across 334 executable candidates;
   see `results/wp4-nested-post-tested-rendering.md`.
2. [x] Replace the preserved nested loop-header gotos with a proved
   source-level `continue` representation. Commit `85a61693` introduces an AST
   `Continue` only while lowering transfers to the current multi-exit loop
   header; traversal does not cross nested loops. The pinned 715-function
   comparison reduces comparable shadow gotos from 584 to 324, moves improved
   rows from 204 to 220, and reduces nine unexplained regressions to zero. The
   250-candidate execution comparison remains at zero regressions. See
   `results/wp4-source-level-continue.md`.
3. [x] Complete the required O0 `classify` WP6/WP7 vertical slice above.
   Commit `9c9c607c` adds real GCC/Clang debug and stripped fixtures and lands
   the width- and signedness-proved `> 100` predicate fusion with proof,
   refusal, syntax, differential, and scoped-corpus evidence. Commit `5fdd0c8f`
   adds stripped signed-return evidence and redundant-cast cleanup at the SSA
   result-fact and typed-AST boundaries, with a genuinely unsigned control.
   The clean exact-checkout Rust gate is green, and both `classify` tests pass
   within the whole Python run. That whole run remains broadly red (121
   failures at the prior slice, 115 at `2be036eb` before its mechanical census
   refresh), which is recorded rather than promoted to a release claim; see
   `results/wp6-classify-signed-return.md`.
   Report O2 separately rather than claiming source-loop recovery after
   strength reduction or unrolling.
4. Finish the other WP4 promotion evidence. The remaining Duff and clang-wide
   rows are classified at `ca91dc68` by exact, fail-closed
   suffix/shared-effect-entry contracts, and the clean pinned full comparison
   reports zero unexplained regressions without rewriting the four raw
   regression statuses. The corpus-wide execution route is now live; still
   complete unexplained block/edge accounting, pinned GED, structure-axis
   movement, and accepted runtime/output-size budgets.
5. Complete WP5's shared typed-case transport so discovery, accounting, both
   structurers, and rendering consume one case/default/provenance object; add
   the remaining fixture/compiler/architecture execution cells and classify
   every residual decline. Malformed, truncated, overlapping, and wrapping
   table safety tests are already present and must remain green.
6. Begin WP2/WP3 as an independent architecture lane, using conservative
   invalidate-everything fallback while passes migrate incrementally.
7. Continue WP6 from the landed stripped-C per-use signedness, SysV hidden
   result-buffer, split INTEGER+SSE, and homogeneous SSE-pair return slices.
   Fixture `197` is now closed across its four host lanes: all non-structural
   helpers and wrappers pass, with nine former O2 failures removed and no
   adjacent aggregate regression in fixtures `195` or `198`. Next, add the
   general equality, pointer, pointee, aggregate, call, confidence, and stable-
   value constraints rather than extending fixture-specific ABI adapters.
   Keep Rust totals separate and do not generalize the SysV/x86 evidence to
   unsupported architectures, vector forms, or language ABIs.
8. Close WP8's remaining corpus-wide exit evidence. Declaration authority,
   structured conflicts, and the explicitly requested analyst annotation mode
   are landed; scored text remains free of diagnostics by default.
9. Continue WP9 from the landed ARM32 register-view and capability-census
   slices: migrate one remaining shared consumer or fact class at a time,
   reduce the 13 reviewed silent-writer mnemonic classes, and wire the census
   into a named required architecture profile. Do not canonicalize partial
   VFP/NEON writes until LLIR can represent the untouched lanes.
10. Under WP10, triage the current red full-gate failures by exact base/overlay
   comparison, promote only independently justified health findings to release
   failures, and remove rejected MIR or compensation code one owned
   responsibility per commit. The metadata-only performance-gate hang is
   closed at `ef24d729`; the remaining full-suite failures and unbounded real
   measurement paths still require triage.
