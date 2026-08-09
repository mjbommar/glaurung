# Glaurung decompiler remediation and redesign roadmap — 2026-08-08

**Status:** active, ranked execution plan; Phase 0 mechanisms and multiple
Phase 1 increments are implemented, but the redesign definition of done remains
open

**Evidence:** [decbench-gap-analysis-diary-2026-08-08.md](decbench-gap-analysis-diary-2026-08-08.md)
**Historical evidence baseline:** Glaurung `c1cfdc97`, DecBench main `0a4e85b`,
dataset `0a2d996`, with ARM `byte_match` recomputed using pending DecBench PR #61

**Current planning baseline:** Glaurung `9c25fcb`, frozen 250-function replay,
all three corrected metric overlays recomputed from revision-specific artifacts

## Outcome

Do not respond to the current scores with another unbounded sequence of local AST
passes. Preserve the real ARM and execution-correctness gains, but migrate toward
one semantic spine:

```text
ProgramSession { ProgramImage, TargetSpec, ProgramEnv }
              |
       complete lifted CFG
              |
   verified typed MIR + MemorySSA
              |
 calls / types / objects / references
              |
 verified region graph -> semantic HIR
              |
          pure renderers
```

The migration must produce useful score and reliability increments every phase.
It is not permission to pause user-visible repairs for a multi-year rewrite.
Compatibility adapters remain until a new layer proves parity; then the old owner
is deleted rather than wrapped forever.

## Baseline and top-level targets

### Quality baseline

| Measure | Baseline | First competitive target | Long target |
|---|---:|---:|---:|
| union perfect | 69 / 250, 27.6% | at least 75 / 250, 30% | at least 82 / 250, 32.8% |
| GED mean | 23.79 | at most 20 | at most 15 |
| O2-noinline GED mean | 34.61 | at most 28 | at most 22 |
| type mean | 0.174 | at least 0.231 | at least 0.30 |
| type perfect | 13 / 235 | at least 20 / scored | at least 30 / scored |
| byte mean, corrected metric | 0.238 | at least 0.30 | at least 0.40 |
| unique union perfects vs live board | not freshly recomputed | at least 1 | sustained growth |

These are engineering targets, not promises to game DecBench. A score change is
accepted only with behavioral or semantic evidence. On the live 2026-08-09
sample-set snapshot, the first union target passes the current 28.4% traditional
leaders; the long target establishes a wider margin rather than chasing a stale
denominator.

### Performance baseline and targets

| Measure | Baseline | Phase-1 ceiling | End target |
|---|---:|---:|---:|
| 224-binary wall, 12 workers | 64.04 s | no more than 67.2 s | below 45 s |
| per-binary median | 2.82 s | no more than 2.96 s | below 2.0 s |
| p95 | 5.10 s | no more than 5.35 s | below 4.0 s |
| slowest | 18.77 s | no new unbounded case | below 15 s |
| repeated object parse per session | not constrained | exactly one base parse | exactly one |
| warm identical-function query | no reusable session | measured | at least 5x faster |

No phase may buy mean speed by silently timing out more functions. Report
coverage, completeness, and tail latency with every performance result.

The function-query diagnostic baseline at clean revision `4b6838f` is checked in
at `tests/decompiler_profile/baseline-2026-08-08.json`. Times are one cold run
and the median of three same-process warm runs; RSS is process high-water mark.

| Case | Cold | Warm median | Cold RSS | Object parses/query |
|---|---:|---:|---:|---:|
| small x86-64 | 289.3 ms | 98.8 ms | 88.0 MiB | 3,679 |
| stripped x86-64 | 1,049.8 ms | 946.5 ms | 92.7 MiB | 16,225 |
| large stripped x86-64 | 901.2 ms | 707.7 ms | 119.2 MiB | 18,252 |
| ARM32 | 17.5 ms | 16.5 ms | 49.5 MiB | 188 |
| debug-heavy Rust | 1,395.3 ms | 1,205.4 ms | 108.8 MiB | 22,873 |

The production extension has no allocator counter, so the baseline records
allocation evidence as unavailable rather than substituting Python-only data.
Every warm output hash is stable. Parse counts are identical on all cold and
warm repetitions, proving the current API redoes image work instead of reusing a
session. On the four x86-64 cases, first-use WinAPI catalog initialization inside
`apply_known_call_contracts` costs 187–191 ms; target-aware catalog selection is
therefore a separate measured opportunity from `ProgramImage` parse reuse.

### Code-size fitness baseline and targets

| Measure | Baseline | End target |
|---|---:|---:|
| product-code mean | 552.9 LOC | below 450 |
| product-code median | 302 LOC | below 250 |
| product files above 1,000 LOC | 73 | at most 35 |
| product files above 2,000 LOC | 21 | at most 5 |
| LOC in files above 1,000 | 47.9% | below 25% |
| `src/ir` median | 997.5 LOC | below 500 |
| `src/ir` files above 1,000 | 29 | at most 5 |

Generated tables may have documented exemptions. Moving tests or cutting a module
into arbitrary `part1`/`part2` files does not satisfy the target. Each split must
leave a narrower API and one reason to change.

## Design invariants

1. Machine value, source interpretation, and display spelling are different
   layers.
2. Function, block, instruction, value, use, memory version, object, symbol, and
   type identities are explicit typed IDs.
3. Every artifact carries target, origin, dependencies, diagnostics, budgets, and
   monotone completeness.
4. Unknown call or instruction effects clobber conservatively; unknown never
   means “no effect.”
5. Every reachable use resolves to input, instruction definition, phi, undef,
   poison, unknown effect, or unreachable—never an ambiguous absence.
6. Manual, relocation, and authoritative debug facts cannot be overwritten by a
   heuristic. Conflicts remain data.
7. Graph-changing passes prove preconditions and verify postconditions. A failed
   proof keeps a lower-level form or honest goto.
8. Renderers format verified HIR. They do not parse images, discover facts, run
   fixed points, or read correctness-changing environment variables.
9. One session parses and indexes an image. Analysis passes consume its APIs.
10. All public entry-point shapes select functions and profiles over the same
    pipeline.
11. Serial and parallel analysis are deterministic.
12. Score improvements never replace execution, verifier, and canary gates.

## Rank-ordered work register

| Rank | Work item | Direct gap addressed | Dependency |
|---:|---|---|---|
| 1 | Freeze the corrected evaluation ledger and top-50 canaries | trustworthy decisions | none |
| 2 | One `ProgramImage`/`ProgramSession` and typed artifact envelope | DRY, repeated work, partial-result safety | 1 |
| 3 | Canonical `TargetSpec` and register/effect model, ARM32-complete | architecture parity, widths, ABI | 2 |
| 4 | Verified typed MIR with explicit definitions and all effects | phantom values, unsafe transforms | 3 |
| 5 | Region-aware MemorySSA and a shared reaching-definition oracle | stack, calls, aggregates, DCE | 4 |
| 6 | Value-keyed function/call prototype inference | type blocker, phantom arguments | 4–5 |
| 7 | CFG completeness plus total region/edge accounting | large-function GED cliff | 2, 4 |
| 8 | Canonical `ProgramEnv`, `SymbolStore`, and `TypeStore` | program facts and interprocedural reuse | 2–6 |
| 9 | Contextual reference resolver over operand uses | constant symbolization | 3–5, 8 |
| 10 | Memory objects, access paths, and aggregate solver | structs, arrays, ABI aggregates | 5–9 |
| 11 | Semantic HIR, shared visitors, and pure renderers | composition and output reliability | 6–10 |
| 12 | Split large files and delete migrated legacy paths | maintainability and reviewability | per-owner migration |
| 13 | Dependency-aware persistence and deterministic parallelism | warm/batch performance | 2, 8, 11 |
| 14 | Profile-led data-layout and algorithm tuning | tail latency and memory | 13 |

## Phase 0 — lock evidence and make regressions attributable

**Goal:** every later patch has a reproducible before/after record.

Tasks:

1. Add a checked-in evaluation manifest containing the three pinned revisions,
   compiler/tool versions, PR #61 metric revision, 250 function keys, and raw
   package checksum.
2. Add a score-ledger script that reports coverage, perfect count, mean, median,
   zeros, union, architecture, optimization, CFG-size bins, and head-to-head
   deltas from one result tree.
3. Materialize the top 40 GED, top 40 type, top 40 byte, and every current perfect
   as stable canary sets; include overlap rather than silently deduplicating causes.
4. Add output health counters per function: parameters, declarations, temporaries,
   raw physical registers, undefined uses, gotos, uncovered/invented CFG edges,
   unresolved transfers, and output/source-CFG size ratio.
5. Add focused canaries for `yyparse`, `copy_reg`, `console_getc`, `statdb_write`,
   `arith:gcc:O0`, `recursion:gcc:O2`, and the formerly regressing linked-list
   byte cell.
6. Record current cold/warm time, RSS, allocations where available, parse count,
   and pass time for small, large, ARM32, debug-heavy, and stripped binaries.
7. Label score data with metric schema/hash so stale cached ARM byte results cannot
   merge silently.

Acceptance:

- repeated runs produce byte-identical raw output and the same score ledger;
- a missing function, stale cache version, or changed denominator fails loudly;
- PR #61 versus main differences are explicitly visible;
- the canary report names which pass first changed each output; and
- no semantic output changes in this phase.

Stop if the current replay cannot reproduce 60 GED perfects, 13 type perfects,
seven corrected byte perfects, and 69 union perfects from the pinned inputs.

### Implementation status — 2026-08-08

- [x] Pinned manifest with all 250 function keys, repository and metric
  revisions, evaluator versions, kit identity, and raw-package checksum.
- [x] Deterministic score ledger with overall, architecture, optimization,
  CFG-size, and head-to-head summaries.
- [x] Stable overlapping top-40 GED/type/byte and current-perfect canary sets.
- [x] Per-function output-health counters and first-changing-pass attribution.
- [x] Focused output canaries spanning four official functions and three local
  regression cells (eleven real functions total).
- [x] Cold/warm time, RSS, allocation availability, parse-count, and pass-time
  baselines across small, large, ARM32, debug-heavy, and stripped cases.
- [x] Metric implementation revision and source hash in every ledger.

The historical checked-in score baseline reproduces its original four headline
counts and has byte-identical output across reordered or repeated inputs. The
fresh `9c25fcb` external replay supersedes its planning numbers with 60 GED, 13
type, seven byte, and 69 union perfects. Refreshing the checked-in ledger/canary
material to that candidate is now the remaining Phase-0 publication task; do not
call the old 59/67 fixture the current score. The other Phase-0 mechanisms are
complete.
The focused canary gate pins input/compiler provenance, output identity, and final
health for all seven named cases and reports exact function/field deltas. The health trace
now covers every requested AST/CFG counter, names final definition violations,
records verified-structuring fallback separately from emitted edge defects, and
proves diagnostic enablement leaves real decompiler stdout byte-identical.

## Phase 1 — install one session and one pipeline seam

**Goal:** improve composition and repeated-query performance without changing
semantics.

Target modules:

```text
src/program/image.rs
src/program/session.rs
src/program/artifact.rs
src/decompile/engine.rs
src/decompile/pipeline.rs
src/decompile/profile.rs
```

Tasks:

1. Introduce `Diagnostic`, `Completeness`, `IncompleteReason`, pass metrics, and
   `AnalysisArtifact<T>`.
2. Preserve discovery limits, timeouts, unmapped/clipped blocks, decode failures,
   unresolved transfers, and unsupported semantics through lifting and rendering.
3. Add `ProgramImage` as the single owner of bytes, object parse, segments,
   sections, VA translation, relocations, readonly ranges, and debug handles.
4. Add `ProgramSession` and route `decompile_at`, range, many, and all through one
   `DecompilerEngine::analyze_function`.
5. Move the current `prepare_llir_for_lowering` and `run_ast_passes` ordering into
   an explicit stage list with a deterministic fingerprint.
6. Add approved import adapters and an architecture check that rejects new direct
   object parses elsewhere.
7. Cache immutable image indices and function discovery within a session.
8. Keep compatibility Python functions by constructing a temporary session; add a
   reusable Python session for batch and interactive users.

Acceptance:

- all four entry-point shapes render byte-identical output for the same function
  and profile;
- one session performs one base object parse;
- incomplete discovery remains incomplete at the API and renderer boundary;
- cancellation returns typed partial results rather than `None`;
- score ledger and execution canaries are unchanged; and
- cold performance does not regress more than 5%, while a second same-function
  query is measurably faster.

Immediate safe repairs may land here only if they use the new pipeline seam and
include RED/GREEN/REFACTOR tests. Do not add another top-level pipeline copy.

### Implementation status — first Phase 1 increment

- [x] Added an owned `ProgramImage` with one base parse, checked file/VA
  mappings, executable ranges, target metadata, and defined-symbol indices.
- [x] Routed CFG discovery, targeted callee discovery, LLIR lifting, and all four
  Python decompilation entry points through the image while retaining compatible
  byte-oriented Rust adapters.
- [x] Added real ELF, PE, ARM32/Thumb, malformed-input, overflow, CFG-parity, and
  LLIR-parity tests.
- [x] Kept all eleven focused output canaries byte-identical and reduced the
  measured small-x86 query from 3,679 to 47 object parses (98.7%). The full
  five-shape rerun reduced parses from 188–22,873 to 22–55; cold time improved
  1.3–6.9%, warm median improved 2.0–16.5%, and output hashes remained stable.
- [x] Indexed validated file-backed sections once in `ProgramImage` and routed
  string-pool and read-only-data collection through borrowed image views,
  removing two more repeated whole-object parses from all four Python entry
  points. Real ELF, ARM32 ELF, PE, and Mach-O fixtures prove parser parity. The
  measured small-x86 query is now 45 parses with identical output; do not mark
  the one-parse acceptance criterion complete while the other 44 owners remain.
- [x] Added a conservative ARM alignment-save classifier at the LLIR
  input-definition seam: a proven balanced `push {r3, lr}` no longer invents a
  fourth source parameter, while a restored-and-consumed `r3` remains live-in
  evidence. A conditional-exit near miss is also rejected. The focused
  `arm_input_evidence` module is covered by a checked-in real ARM binary plus
  both controls and advances the value-keyed prototype work without adding an
  AST signature heuristic or another subsystem to `value_number`.
- [ ] Recover pass-through arguments at indirect calls from value-keyed target
  and prototype evidence. The alignment repair narrows real `serialWrite` from
  four parameters to one but leaves its second source argument unknown and its
  type score at zero; treating every untouched call register as an argument is
  explicitly rejected as unsound.
- [x] Turn the 29 official functions exactly one type edit from perfection into
  a typed defect corpus, grouped by missing evidence owner rather than project
  name. Prioritize fixes that close a repeated invariant cluster (prototype,
  stack coordinate, aggregate extent, or definedness) and reject one-function
  signature patches; this cohort is the shortest path to verified perfect-rate
  movement without scoreboard overfitting. The checked corpus pins the exact
  `9c25fcb` overlay checksum and classifies 20 pointer-category defects, six
  missing-local identities, two integer-width defects, and one missing
  parameter. Its first invariant repair qualifies direct LSR use of an exact
  AAPCS core-register live-in as unsigned-word prototype evidence; the official
  evaluator moves `nvicEnableVector` from `0.5`/distance one to `1.0`/distance
  zero without a function-name or signature patch. A fresh address-scoped replay
  at parent `58cf71d` found 11 of the historical 29 already perfect, rather than
  trusting stale row statuses. The value-keyed call-contract and opaque-tag
  alias repair advances the current count to 13 perfect / 16 open. Across the
  full 250-function corpus it moves TypeMatch perfects 27→30 and mean
  `0.32579001→0.35462582`, with 31 improvements and zero regressions; all 36
  changed outputs retain isomorphic CFGs and identical no-cache ByteMatch
  outcomes. The next program-level DWARF type-environment increment resolves
  typedef-to-tag relationships once for rendering, field recovery, and ABI
  prototype hints. It advances the cohort from 13 to 20 perfect / nine open and
  the full corpus from 30 to 41 TypeMatch perfects, with 32 improvements and
  zero regressions. All 67 changed outputs retain isomorphic CFGs and identical
  no-cache ByteMatch outcomes. Ordinary scalar typedefs remain deliberately
  fail-closed after a measured `console_read` byte regression; enable them only
  after body values preserve source typedef identity. Continue from the nine
  verified-open rows and refresh status through real-binary evaluation after
  every general repair.
- [x] Close the nine remaining historical type-distance-one rows through shared
  DWARF local contracts, lifetime-aware value identity, dead promoted-object
  stores, source-unit pointer arithmetic, and aggregate-name safety. Fresh v15
  evaluation scores all 29 rows: 27 are officially perfect and two emit the
  exact expected ordinary-typedef pointer declarations that TypeMatch v5 does
  not parse. The ledger records all 29 product repairs and keeps the two metric
  false negatives visible. Across the full replay, current TypeMatch has 68
  perfects and mean `0.56153998`, versus 41 and `0.40518645` at accepted parent
  `acc3e24`; 123 common rows improve and none regress. Coverage changes from 235
  to 233 scored rows because two x0r requests return no artifact and is not
  disguised by comparing unlike denominators.
- [x] Audit ByteMatch and CFG consequences rather than treating type-only work
  as output-neutral. Fresh ByteMatch rises from 10 to 11 perfect and mean
  `0.16168974→0.19063337`; 33 common rows improve and nine compiler-shape rows
  regress. The audit found and fixed incorrect native pointer scaling and an
  aggregate typedef/local-name compilation collision. A bounded CFG audit names
  seven lifetime-SSA control-skeleton canaries; declaration-only differences
  are contracted separately. These canaries remain required until execution or
  semantic equivalence evidence retires them.
- [x] Extract the cohesive DWARF contract importer from
  `python_bindings/ir.rs` into a 449-line owner, reducing the binding module to
  3,656 lines while keeping bindings thin and avoiding a forwarding-only split.
- [x] Add a reusable `ProgramSession` over one immutable `ProgramImage`, with a
  bounded exact-key discovery cache and a Python `DecompilerSession` whose
  rendered-artifact cache includes address, budgets, type mode, and style.
  Diagnostic requests bypass rendered reuse. Real compiled-ELF tests prove
  standalone/session output identity, cache partitioning and reset behavior,
  and invalid-image rejection. A checked-in hello query measures 13.438 ms for
  the standalone median, 12.884 ms for first session use, and 0.001136 ms for
  an exact rendered cache hit with one output digest. The 11,826.9x exact-hit
  speedup is not generalized to uncached analysis.
- [x] Land definition-safe immediate repairs through the intended owners:
  symmetric reaching checks for mutable parameter homes, preservation of
  indirect-store lvalue category, unique-winner DWARF roles and semantic local
  order, and a typed loop-carrier proof. Full verification reports 2,037 Rust
  tests, complete x86/legacy/curriculum execution, no architecture regression,
  and a real i386 `heap_push` improvement that advances the ratchet to 1,758
  pass / 42 known failures. Fresh isolated official metrics report no per-cell
  GED, TypeMatch, or ByteMatch regression across 56/56 cells.
- [ ] Make every evaluation cache key include the decompiled artifact digest,
  binary digest, metric version, and toolchain identity. The byte re-evaluator
  currently reuses any same-named checkpoint even after the C changes; the
  `9c25fcb` replay had to use a fresh revision-specific checkpoint directory to
  prevent silent reuse of `45b233cf` results. GED source extraction also needs
  per-translation-unit durable checkpoints rather than an all-or-nothing
  project write after 3,747 files. For manifest-scoped runs, use
  `DW_AT_decl_file`, but validate target CFG presence before accepting the
  selection. The owner-only estimate was 207 units; the completed conservative
  run expanded three under-covered projects and required 454/3,794 units, still
  an 88.0% reduction. The executed coverage check, not the estimate, is the
  planning baseline.
- [ ] Make external-overlay finalization populate `FunctionData.metrics` and
  `perfect_values`, retain every manifest metric row, and fail if the derived
  scoreboard is empty while overlay values exist. The completed `9c25fcb` replay
  found 250 raw byte rows but only 249 derived rows (`freertos:Default_Handler`
  was omitted), and generated an empty-metric `scoreboard.toml`; direct overlay
  joining remains the authoritative 69/250 result until this publisher seam is
  repaired upstream.
- [ ] Move relocation, read-only-range, debug, environment, and remaining
  object-backed facts behind the image/session boundary and reach one base parse.
- [ ] Extend `ProgramSession` beyond exact discovery/rendered artifacts to
  shared debug, relocation, call-contract, type, and lowered-function facts;
  then route range, many, and all queries through the reusable public session.
- [ ] Add typed partial artifacts, a single `DecompilerEngine` path, explicit
  stage fingerprinting, and the direct-object-parse architecture gate.

This is a measured additive seam, not Phase 1 completion. The acceptance target
remains exactly one base parse per session and identical behavior across all
entry-point shapes before the legacy owners can be removed.

## Phase 2 — canonical target and exact lifted semantics

**Goal:** make ARM32 a peer and remove architecture inference from strings.

Target modules:

```text
src/target/spec.rs
src/target/registers.rs
src/target/abi.rs
src/target/{x86,aarch64,arm32}.rs
src/lift/context.rs
src/lift/builder.rs
```

Tasks:

1. Replace internal uses of the three architecture enums with one `TargetId` and
   validated `TargetSpec`; leave public adapters temporarily.
2. Model ISA, A32/Thumb mode, endian, address/pointer bits, object format, OS ABI,
   calling convention, register banks, instruction alignment, and PC rules.
3. Generalize `regview` to x86-32, x86-64, AArch64, and ARM32 GPR/VFP aliases,
   including partial write, zero-extension, preservation, and discarded writes.
4. Make constants exact-width bitvectors and retain source operand/provenance.
5. Make calls and intrinsics declare every register/flag/memory read and output.
6. Add `LiftContext`/`LiftBuilder`; migrate instruction families incrementally
   from all three large lifters.
7. Move ABI argument/result/clobber/stack classification out of lifters and AST
   passes into target ABI owners.
8. Add generated register-view and write-semantics conformance tests plus real
   A32, Thumb, soft-float, hard-float, ILP32, and big-endian negative controls.

Acceptance:

- no SSA, execution, type, or renderer path infers register meaning from an
  unqualified name;
- ARM32 uses the same register/value contracts as x86-64 and AArch64;
- every lifted constant and temporary has exact machine width;
- unsupported instructions have conservative footprints and diagnostics;
- lifter/executor differential tests pass for every migrated family; and
- the existing 43 AArch64 verdict failures and ARM lane results are reported as
  explicit remaining cells, not hidden by the refactor.

Stop if an ARM32 feature requires a parallel definition, SSA, or ABI model.

## Phase 3 — verified MIR and the shared definition oracle

**Goal:** remove the main type and transform-safety root cause.

Target modules:

```text
src/ir/mir/{model,builder,editor,verify}.rs
src/analysis/dataflow/{dominance,ssa,definedness,memory_ssa}.rs
```

Tasks:

1. Add typed arenas/IDs for blocks, instructions, values, storage, uses, effects,
   and origins.
2. Lower current LLIR into MIR while retaining a parity path to the old lowering.
3. Represent `Input`, instruction output with index, `Phi`, `Undef`, `Poison`,
   `UnknownEffect`, and `Unreachable` explicitly.
4. Support all outputs of multi-output operations; retire the one-def assumption
   in `def_uses` for MIR consumers.
5. Build dominance, complete def-use/use-def, phi, sort, CFG, and effect verifiers.
6. Add conservative MemorySSA regions: stack object, known global, readonly image,
   heap/unknown, and fully unknown. Add memory defs, uses, phis, and a clobber
   walker before refining alias precision.
7. Expose one query service for `definition`, `value_at`, `all_paths_defined`,
   `dominates`, `clobbers_between`, and `memory_version`.
8. Add transactional graph editing with invalidation and post-verification.
9. Port copy propagation, DCE, call argument recovery, value splitting, expression
   reconstruction, and stack promotion one at a time.
10. Delete each pass's local backward scan or AST definition map after parity.

Acceptance:

- every reachable use has one explicit definition state and passes dominance;
- diamonds, loops, irreducible flow, exceptions, calls, intrinsics, partial
  registers, undef/poison, and memory clobbers have property tests;
- `console_getc(int wait)` cannot become pointer-typed from a different lifetime;
- top-40 canaries contain no new phantom parameters or undefined machine locals;
- execution and architecture roundtrip gates remain green; and
- no migrated pass scans structured HIR to answer a reaching-definition query.

Stop and roll back a graph transaction whenever verifier proof fails. Do not
render plausible C from an invalid MIR.

## Phase 4 — function contracts, CFG completeness, and large-function recovery

**Goal:** attack the measured type and GED blockers directly on the new semantic
foundation.

### 4A — calls and prototypes

1. Recover parameters and returns from MIR values, ABI storage, call effects,
   dominating definitions, and interprocedural call-site evidence.
2. Separate candidate storage inputs from source parameters; model saved values,
   scratch reuse, variadics, hidden aggregate returns, and split returns.
3. Apply authoritative DWARF/PDB/library contracts as locked facts and retain
   conflicts.
4. Propagate call facts monotonically over call-graph SCCs rather than relifting
   callees per root.
5. Make `void`, noreturn, direct value, and indirect/sret output kinds explicit.
6. Eliminate raw-name remapping between `TypeMap`, `TypeMapV`, role names, and
   rendered declarations as consumers migrate.

### 4B — complete CFG and verified regions

1. Carry resolved/unresolved indirect transfers and uncovered ranges into MIR.
2. Give every block terminator an explicit typed edge set; never lower an unknown
   indirect jump as a call.
3. Build dominator/postdominator trees, SCC/natural-loop forests, SESE candidates,
   and edge ownership.
4. Make structural accounting mandatory, not diagnostic-only: every input edge is
   represented once as structure or goto, and no output edge is invented.
5. Replace global consuming-tree ownership with a region graph and deterministic
   selection policy.
6. Prefer verified gotos over attractive but unproven loop/if transforms.
7. Add large-function budgets and cancellation checkpoints without losing partial
   diagnostics.

Acceptance:

- `copy_reg` has the source-level parameter count or an evidence-backed explicit
  uncertainty, never 24 inferred parameters;
- `statdb_write` is correctly `void` and preserves terminal control;
- type mean reaches at least `0.231` with no canary regression;
- GED mean reaches at most `20` in the first increment and `15` before phase
  closure;
- O2-noinline GED mean falls below `28` in the first increment and `22` before
  phase closure;
- union reaches at least 30%; and
- `yyparse`/other 250+ node functions show bounded declaration/output growth and
  zero missing/invented CFG edges, even if goto-heavy.

The metric goals are necessary but not sufficient. Failure of execution or region
verification blocks the phase regardless of score.

## Phase 5 — canonical program symbols, types, and references

**Goal:** complete EPIC 1 and deliver EPIC 2 without destructive literal guessing.

Target modules:

```text
src/program/env.rs
src/program/provenance.rs
src/program/symbols.rs
src/program/types/
src/program/references.rs
src/program/functions.rs
```

Tasks:

1. Add `SymbolId`, `TypeId`, `ObjectId`, `FunctionId`, fact revisions,
   provenance, authority, confidence, alternatives, and conflicts.
2. Implement a range-aware `SymbolStore` with aliases, binding, kind, imports,
   exports, thunks, relocation addends, and address-space-aware queries.
3. Implement an interned recursive `TypeStore` by adapting `core::DataType`; keep
   C spellings in language projection.
4. Import object, relocation, DWARF, PDB, string, readonly, function-table, and
   analyst/KB evidence exactly once.
5. Attach reference interpretations to MIR operand uses while retaining the raw
   bitvector and origin.
6. Resolve by relocation/loader semantics, decoded operand role and PC behavior,
   mapped region, MIR data flow, prototype/type constraints, and xref consistency.
7. Support symbol+addend, function, global, string, enum member, field offset,
   type-info, and exact-literal fallback.
8. Migrate name, string, readonly, and function-table resolvers into the reference
   index and then delete the old independent interpretations.
9. Expose selected facts, alternatives, and provenance through typed Python APIs.

Acceptance:

- the `d0e8` case uses one object identity in every load/store path;
- identical bits remain an integer in arithmetic but become a symbol under
  relocation/use evidence;
- conflicting interpretations are inspectable and deterministic;
- manual/debug/relocation facts cannot be silently overwritten;
- every entry point returns identical symbol/type selections at one revision;
- repeated batch decompilation does not rebuild image fact indices; and
- negative controls reject “mapped number implies pointer.”

## Phase 6 — memory objects and aggregate recovery

**Goal:** recover structures, arrays, unions, and aggregate ABI transfers through
one model.

Tasks:

1. Create `MemoryObject` identities for proven stack, global, TLS,
   parameter-pointee, heap-allocation, and unknown bases.
2. Collect MIR access paths with affine offset, width, alignment, read/write role,
   stride, lifetime, source instruction, and memory version.
3. Import DWARF, PDB, and analyst layouts as strong constraints in the same
   `TypeStore` used by inference.
4. Add conservative size, field-offset, array-stride, overlap/union, bitfield,
   pointee, and compatible-type constraints.
5. Solve candidates monotonically; retain conflicts and unknown byte regions.
6. Propagate object/pointee constraints across calls.
7. Model by-value aggregates, split register/stack arguments and results, and
   hidden sret according to `TargetSpec` ABI.
8. Project proven accesses into semantic `Field`, `Index`, `AddressOf`, and typed
   dereference HIR nodes.
9. Treat vtables/RTTI/function tables as global objects connected to relocations,
   types, and call facts.
10. Delete debug-format-specific AST variants/walkers once both formats project
    through the common model.

Acceptance:

- debug-backed and no-debug layouts use identical object/access/HIR structures;
- ARM current-SP/CFA, x86 frame/SP, and AArch64 frame records all resolve through
  target coordinates rather than format-specific AST patches;
- array, struct, union/overlap, bitfield, and near-miss controls prevent false
  layouts;
- sret and by-value aggregate fixtures execute correctly on all targets;
- every rendered field has object, layout, access, and provenance evidence; and
- aggregate gains improve type and byte behavior without relying on GED alone.

## Phase 7 — semantic HIR, pure rendering, and physical decomposition

**Goal:** turn the new ownership boundaries into smaller, composable code.

Target layout:

```text
src/ir/lifted/             exact machine effects and verifier
src/ir/mir/                graph, values, memory, editor, verifier
src/ir/hir/                model, builder, visitors, verifier
src/analysis/calls/        call facts and propagation
src/analysis/types/        constraints and solver
src/analysis/objects/      access paths and layouts
src/analysis/structure/    graph regions and proofs
src/render/{faithful,c,decbench}.rs
```

Concrete splits:

- `ast.rs` -> HIR model, LLIR/MIR projection, visitors, verifier, declaration
  planning, output-neutral cleanup, and separate renderers;
- `lift_{x86,arm32,arm64}.rs` -> shared builder plus instruction-family modules;
- `call_args.rs` -> target ABI classifier, call evidence, interprocedural solver,
  and HIR projection;
- `types_recover.rs` -> constraint vocabulary, collection, solving, prototype
  projection, and language spelling;
- `stack_locals.rs` -> frame state, object construction, access recovery, scalar
  promotion, and source naming;
- `structure.rs` -> dominators/loops, regions, selection, verification, and HIR
  projection; and
- `python_bindings/ir.rs` -> thin binding adapters over session/engine/results.

Tasks:

1. Complete semantic HIR and one generated/central visitor and rewriter surface.
2. Move semantic operations out of renderers and output-specific preparation.
3. Remove renderer thread-local type/name state.
4. Give every pass declared inputs, outputs, required/preserved analyses,
   invalidations, budget, verifier, and failure policy.
5. Split files only as their semantic owner migrates; move tests beside the new
   owner but measure product and test LOC separately.
6. Add dependency checks: HIR cannot parse images, renderer cannot import lifters,
   target cannot import renderers, and correctness cannot depend on environment
   variables.
7. Add a code-size ratchet: no new production module above 1,000 LOC without a
   reviewed exception; thresholds decrease as legacy owners shrink.
8. Delete compatibility layers promptly after output and behavior parity.

Acceptance:

- rendering one HIR twice is byte-identical and side-effect free;
- adding an HIR variant updates its model/visitor/verifier and relevant renderers,
  not dozens of unrelated walkers;
- every profile uses the same verified semantic artifact;
- dependency and size ratchets pass;
- the stated mean/median/>1,000/>2,000 targets are met without trivial fragments;
  and
- full score, execution, fixture, and canary gates remain green.

## Phase 8 — persistence, deterministic parallelism, and hardening

**Goal:** exploit stable sessions and facts for performance without weakening
safety.

Tasks:

1. Cache artifacts by image hash/revision, target, function, pipeline fingerprint,
   configuration, and exact dependency revisions.
2. Persist versioned `ProgramEnv` and typed artifacts with schema migration and
   corruption recovery.
3. Schedule functions in parallel over immutable environment snapshots; merge
   interprocedural facts deterministically at SCC phase barriers.
4. Replace whole-HIR fixed-point clones with pass change sets/epochs.
5. Make expensive type/object/reference passes demand-driven and cacheable.
6. Record per-pass time, allocations, graph size, iterations, cache hits, and
   invalidations.
7. Enforce cooperative cancellation and resource budgets in every graph walk and
   fixed point.
8. Fuzz object/debug importers, target register contracts, lifters, MIR editor and
   verifier, reference resolver, serialized KB/project input, and cache schemas.
9. Run serial/parallel and cold/warm differential suites.
10. Optimize arenas, indices, allocation, and parallel granularity only from
    profiles after the above avoided-work changes.

Acceptance:

- serial and parallel facts/output are identical;
- warm queries reuse only dependency-valid artifacts and report provenance;
- analyst edits invalidate the minimum correct dependency set;
- cancellation returns promptly with typed partial artifacts;
- crash recovery and schema migrations retain manual facts safely;
- batch wall is below 45 seconds, median below 2 seconds, and p95 below 4 seconds
  on the pinned host, with unchanged coverage; and
- no correctness metric or execution gate regresses.

## TDD and validation matrix

Every code increment follows RED -> GREEN -> REFACTOR -> VERIFY and includes a
real binary/toolchain fixture plus a near-miss control. IR-unit shapes supplement
real integration tests; they do not replace them.

### Required focused evidence

| Change | Required evidence |
|---|---|
| target/register | generated view contracts + lifter/executor differential + real A32/Thumb binary |
| definition/MIR | verifier property tests + diamond/loop/exception/call/memory fixtures |
| call/type | real optimized caller/callee + variadic/sret/return-width negatives |
| CFG/structure | edge-accounting proof + execution + large irreducible/switch fixtures |
| reference | relocation and same-bits/different-context controls |
| aggregate | debug/no-debug + array/struct/union/bitfield + ABI execution |
| cache/parallel | cold/warm and serial/parallel deterministic differential |

### Broad phase gate

Run from a clean build of the exact candidate revision:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
uvx pytest python/tests/
uvx ruff format --check python/
uvx ruff check python/
uvx ty check python/
scripts/decbench-local-gate.sh
```

Also run the 250-function external-eval replay, architecture roundtrip matrix,
top-50 canaries, output health report, and performance matrix. Report focused,
full-local, remote-CI, score, behavior, and performance states separately. A
running or unrelated-red gate is not “green.”

## Score-campaign policy during migration

Local correctness fixes are still welcome. They must satisfy all of these:

1. reproduce on a real binary and name the first wrong semantic stage;
2. add a failing test before implementation;
3. use or advance the intended owner rather than create a second heuristic path;
4. include negative controls and execution/definedness evidence where applicable;
5. rerun the affected metric cell and all current perfect/canary cells;
6. record mean, median, perfect, coverage, and regressions—not only union; and
7. delete obsolete workaround code when the foundational owner subsumes it.

Prioritize campaign cells in this order:

1. wrong function contracts shared by many functions (`console_getc`,
   `copy_reg`, wrong void/returns);
2. large O2-noinline CFG ownership and declaration explosion (`yyparse`,
   `print_list`, large `main`/`cmp` cases);
3. unresolved direct callees, call effects, and symbol-backed references;
4. object/aggregate access patterns with type and byte leverage;
5. architecture semantic holes with execution consequences; and
6. textual normalization only after semantic parity.

## Stop conditions

Stop the affected phase and repair the foundation when:

- a transform cannot prove definition, dominance, effect, or edge-preservation
  preconditions;
- incomplete input becomes apparently complete downstream;
- an unknown call/intrinsic is treated as preserving unproven state;
- ARM32 requires an incompatible register, definition, memory, or ABI path;
- a heuristic overwrites manual/debug/relocation evidence;
- a score gain breaks an execution, verifier, perfect-cell, or semantic canary;
- a file split leaves the same responsibilities coupled through private cross-
  module mutation;
- a cache result cannot name exact dependencies and revisions;
- parallel execution is nondeterministic; or
- performance improves by reducing coverage or silently timing out work.

## Definition of done

The redesign is complete when Glaurung has one reusable session and program fact
environment; one validated target model including ARM32; one verified value and
memory definition graph; contextual reference and aggregate recovery over stable
identities; total verified CFG-to-HIR projection; pure output profiles; measured
smaller owners; deterministic incremental analysis; and the full behavioral,
score, safety, and performance gates above.

Until then, each completed phase must be independently usable, tested, and
releasable. “Architecture work” is not a reason to leave the score or user-facing
output unchanged for months.
