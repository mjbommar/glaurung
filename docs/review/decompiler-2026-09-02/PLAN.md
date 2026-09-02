# Decompiler Review Implementation Plan

Status: detailed execution specification subordinate to the canonical roadmap

Created: 2026-09-02

Review basis: `README.md` and `01` through `06` in this directory

Scope: local Glaurung implementation, tests, measurements, and documentation

## Authority and relationship to the roadmaps

`docs/design/decompiler-roadmap.md` remains the single canonical status
tracker. This file does not create a third independent queue: it supplies the
implementation detail, ordering, tests, measurements, and stop conditions for
the recommendations accepted from this review. When work starts or its status
changes here, the corresponding roadmap item must be added or updated in the
same documentation increment and link back to the relevant work package.

`docs/development/real-binary-decompiler-roadmap-2026-08-31.md` remains product
sequencing evidence for real-binary priorities; it is not a second checkbox
authority. Where its R0-R8 order conflicts with this plan, the canonical
roadmap records the explicit scheduling decision. The dated review files and
this plan provide evidence and implementation detail; the canonical roadmap
answers what is actually active.

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
| WP9 | 4-8 weeks, incremental | one fact class moved behind `MachineModel` |
| WP10 | 1-3 weeks total, spread across migrations | first superseded module removed with release evidence |

## 6. WP0 — Minimal inventory and gate integrity

Purpose: make subsequent changes comparable without delaying capability work.

### Production and tooling changes

- [x] Extend `tools/gen_known_failures.py` to derive a stable binary identity
  from build provenance and content hash.
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

- [ ] RED: add a small goto-bearing fixture with a definition on only one
  predecessor and prove the current structured walk declines it.
- [ ] Expose a read-only MIR definedness result through the existing health
  record. Do not modify pseudocode.
- [ ] Record `analysis=MIR`, queried value, use site, predecessor evidence,
  and completeness/decline reason.
- [ ] Run over the deduplicated structure population and capture unique
  findings, clean proofs, declines, wall time, and RSS.
- [ ] Do not implement the recommendation 9 AST-label-graph alternative
  during this trial.

### Decision rule

Keep MIR only if, within two working days and below 10% fixture-matrix wall
time overhead, it produces at least one verdict unavailable to the structured
walk or complete clean proofs for the applicable population, and that value is
not cheaper to obtain from the authoritative SSA work in WP3.

If rejected:

- [ ] Record results in
  `docs/review/decompiler-2026-09-02/mir-trial-results.md`.
- [ ] Inventory every production and test reference to `src/ir/mir/`,
  `src/ir/memory_ssa.rs`, and the MIR adapters in `src/ir/memory_objects/`.
- [ ] Delete only after porting any independent LLIR invariant checks and
  demonstrating the `release` profile remains green.
- [ ] Implement goto-aware definedness later over authoritative SSA or the AST
  label CFG, choosing the cheaper complete representation.

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
  closed honest gotos for its inner irreducible region. Health, full-pipeline
  pseudocode, execution, GED, and runtime comparisons remain. A current scoped
  production differential for
  `154_wide_switch:clang:O2:wide154_dense_effects` still reports the committed
  `fail`: v1 emits an unrecovered indirect jump even though the v2 shadow tree
  renders all 256 values. The harness does not yet execute shadow output, so a
  baseline-stable v1 failure is not promotion evidence.

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
- [~] Tail duplication is size-bounded and terminal-block-only initially.
  Shadow cleanup now plans clones only for explicit shared return blocks, keeps
  one deterministic canonical predecessor, records source/predecessor/count
  provenance, and is independently verified against the typed CFG. The initial
  ceilings are eight lifted instructions per tail and 64 cloned instructions
  per function. Synthetic boundary tests, a forged-provenance rejection test,
  and the real `loop_return_on_neg` shared return are green. Each planned clone
  is now materialized as an explicit `DuplicatedReturn` in the recovered tree;
  the tree verifier rejects missing or invented materializations one-for-one
  against the independently checked plan. The real multi-exit rendering now
  consumes that materialization and retains both return paths; corpus-wide
  output measurement remains open.
- [x] Condition simplification preserves machine-width predicate semantics.
  Each shadow condition atom now carries the SSA producer's exact `CmpOp`,
  recoverable operand width, and `CondJump` inversion; unavailable producer or
  width evidence remains explicit `None`. Boolean complement folding compares
  the complete typed atom. Boundary tests prove that exact complements fold,
  while 32/64-bit or signed/unsigned mismatches do not.

### Promotion criteria

- [ ] No execution-differential regressions.
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
  execution-differential coverage remains open. The gcc-O2
  `206::dispatch_in_loop` lane now
  preserves a guarded byte selector through register zero-extension, decodes
  exact cases `0..6`, and renders that typed switch inside its verified loop.
  Other compiler/optimization and named fixture lanes remain.
- [ ] Unit tests for malformed, out-of-range, overlapping, and truncated
  tables; analysis must decline safely.
- [ ] Execution differential for every newly recovered switch. The scoped
  clang-O2 `154::wide154_dense_effects` production lane was rerun after the
  256-slot recovery and remains a known `fail`, because the fixture harness
  executes v1 output while the recovered switch is still shadow-only. Add an
  explicit shadow-output differential path before counting this cell green.
- [~] Structural census assertion that typed cases reach the structurer.
  One real per-function assertion now proves the exact ordered cases and
  default reach the shadow tree, its independent verifier, and deterministic
  parseable C rendering. Corpus-wide census coverage remains.

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

### Tests

- [ ] RED `tail_dispatch` signedness and return-width case.
- [ ] Existing `python/tests/test_pdb_type_recovery.py` xfails.
- [ ] Existing aggregate/return fixtures `195`, `197`, and `198`.
- [ ] `python/tests/test_decompiler_observable_parameter_width.py`.
- [ ] Stripped-lane tests to prove improvements do not depend on debug types.
- [ ] Solver unit tests for conflicts, ambiguity, and deterministic ordering.

### Exit criteria

- [ ] C parameter and return axes improve without stripped regressions.
- [ ] Low-confidence signedness is rendered honestly rather than asserted.
- [ ] Rust numbers remain visible but do not block C milestones.

## 13. WP7 — Width-proved expression idioms

Purpose: translate compiler idioms into source-like expressions only when the
machine-width equivalence is established.

### WP7A — Immediate render-level idioms (depends on WP0)

- [ ] Implement destination-typed literal spelling at the existing typed
  render boundary so `-1` in `int32_t` does not render as `0xffffffff`.
- [ ] Implement one width-preserving subtract-and-unsigned-compare range fusion
  beside the existing `cmp_fusion` boundary.
- [ ] Keep both changes narrow, table-driven where practical, and independently
  revertible. Do not introduce a second value-identity system.

### WP7B — SSA-expression idioms (depends on WP3)

- [ ] Add an SSA-expression idiom module, preferably `src/ir/ssa_idioms/`,
  after WP3 establishes the owning SSA boundary.
- [ ] Land one rule per increment:
  1. strength-reduced constant multiplication;
  2. signed division/modulo by a power of two;
  3. compiler magic-number division;
  4. compound boolean-mask normalization;
- [ ] Each rule must declare operand width, signed interpretation,
  preconditions, output type, and origin composition.
- [ ] Never peel or narrow casts unless equivalence is proved at the original
  width.

### Tests

- [ ] Exhaustive equivalence at 8 and 16 bits.
- [ ] Boundary-complete plus seeded randomized equivalence at 32 and 64 bits.
- [ ] Regression test for the earlier `cmp_fusion` 64-to-32 narrowing bug.
- [ ] End-to-end fixtures from `03_loop_shapes` and `102_duffs_device`.
- [ ] Execution differential and pinned byte/readability measurements.

### Exit criteria

- [ ] Every enabled WP7A or WP7B rule has a machine-width equivalence test.
- [ ] No execution regression and no unexplained type-width change.
- [ ] Byte/readability measurements improve or the rule is reverted.

## 14. WP8 — Declaration authority and conflict provenance

Purpose: ensure analyst, DWARF, and PDB declarations improve rendered output
without concealing inference disagreement.

### Production changes

- [ ] Trace `tail_dispatch` through:
  `src/python_bindings/ir/dwarf_contracts.rs`,
  `src/python_bindings/ir/type_maps.rs`,
  `src/ir/ast/declaration_plan.rs`, and
  `src/ir/ast/decbench_render.rs`.
- [ ] Define authority order once in the program/session fact layer: analyst,
  trusted debug declaration, inferred recovery.
- [ ] Preserve all candidates with provenance and record a typed
  `PrototypeConflict` health finding when they disagree.
- [ ] Render the authoritative declaration's types, names, and variadic tail
  when representable.
- [ ] Keep conflict diagnostics out of scored pseudocode by default. Expose
  them through structured Python results and an explicitly annotated analyst
  render mode.
- [ ] Apply the same contract to all four entry points and propagated call
  sites.

### Tests

- [ ] RED `tail_dispatch` exact prototype and parameter names.
- [ ] Analyst-over-DWARF and DWARF-over-inference authority tests.
- [ ] Stale/conflicting PDB or DWARF fixture with both facts retained.
- [ ] Variadic and aggregate declaration cases.
- [ ] Scored-style determinism test proving metadata does not change text.
- [ ] Stripped-lane recovery tests remain independent of declarations.

### Exit criteria

- [ ] No rendered prototype is worse than an available trusted declaration.
- [ ] Conflicts are queryable with provenance.
- [ ] Scored output contains no incidental diagnostic comments.

## 15. WP9 — Shared machine model and capability census

Purpose: make ISA/ABI facts explicit and turn missing-instruction discovery
into a standing test.

### Production changes

- [ ] Define `MachineModel` in a new `src/ir/machine/` boundary only after an
  inventory maps current ownership in `src/ir/regview.rs`, lifters, ABI
  modules, stack recovery, naming, and dead-store handling.
- [ ] Suggested modules: `mod.rs`, `registers.rs`, `flags.rs`, `abi.rs`,
  `writers.rs`, plus per-target implementations.
- [ ] Add ARM32 register views, including VFP overlap/pairing, before migrating
  ARM32-specific shared-pass conditionals.
- [ ] Migrate one fact class at a time: register overlap, clobbers/live-ins,
  argument/return locations, flag semantics, then silent writers.
- [ ] Keep lifter instruction semantics target-specific; share the queried
  contract, not necessarily implementations.
- [ ] Add mnemonic capability census tooling and a documented exemption file.

### Tests

- [ ] Byte-identical fixture sweep for each architecture-only migration.
- [ ] Extend architecture roundtrip and ARM32 semantic tests.
- [ ] New census test: every decoded mnemonic is lifted or has a reviewed,
  reasoned exemption.
- [ ] Ratchet `SILENT_REGISTER_WRITERS` toward zero.
- [ ] Ensure `Op::Unknown` and generic intrinsic totals cannot silently grow.

### Exit criteria

- [ ] Shared passes no longer branch on architecture for migrated fact classes.
- [ ] ARM32 has an explicit register-view model.
- [ ] The capability census is part of `default` or a clearly named required
  architecture profile.

## 16. WP10 — Verification, consolidation, and selective deletion

Purpose: finish the architectural migration, make release evidence fail
closed, and remove superseded code only after equivalence is demonstrated.

### Verification changes

- [ ] Restore the independent LLIR invariants currently stranded in
  `src/ir/verify.rs` by compiling the module or porting each invariant to its
  correct owner.
- [ ] Complete goto-aware used-before-definition using the WP1 winner.
- [ ] Promote `BlockDropped`, `EdgeUnaccounted`, `UsedBeforeDefinition`, and
  constant-false live latches to fixture/release failures.
- [ ] Preserve best-effort output with structured health/completeness metadata.
- [ ] Add lane-keyed O2 closure and effect expectations.

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

- `docs/review/decompiler-2026-09-02/results/<work-package>-<slug>.md`

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
- [ ] WP7A has landed or been rejected with width-aware evidence.

### M2 — Dormant architecture decision made

- [ ] WP1 complete.
- [ ] MIR is either a named production authority or removed with retained
  invariants ported.

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

1. Pin the latest intended code revision and record which existing committed
   baselines apply; do not mix them with an older extension build.
2. Implement the known-failure deduplication/language tests before changing the
   generator.
3. Add the Duff's-device `if (0)` strict xfail.
4. Add the three-profile gate wrapper and its fail-closed tests.
5. Start the WP4 shadow structurer and WP5 host jump-table vertical slice as
   soon as WP0 is complete; do not wait for WP2 or WP3.
6. Land or reject WP7A's typed literal and range-check increments independently.
7. Run the two-day MIR trial before implementing any alternative goto-aware
   definedness checker.
8. Begin WP2/WP3 as an independent architecture lane with the effort and
   conservative-invalidation rules above.

The first output-quality implementation is the shadow-mode total structurer,
with typed jump-table evidence developed alongside it in week two. Full
constraint typing and SSA-native idioms wait for stable SSA identity; the two
narrow WP7A render-level improvements do not.
