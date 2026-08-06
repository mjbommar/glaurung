# Glaurung decompiler rearchitecture — ranked implementation plan

**Status:** proposed, evidence-backed  
**Reviewed snapshot:** `1fc76ab` plus the 2026-08-06 execution diary  
**Scope:** binary loading, function discovery, lifting, analysis, decompilation, and C
emission

## Decision

Do not rewrite Glaurung. Replace the decompiler's accidental middle-layer contracts in
dependency order, behind the existing APIs and behavioral ratchets.

The target is one program analysis session feeding one verified pipeline:

```text
ProgramImage + ProgramEnvironment + MachineModel
    -> discovered CFG with completeness evidence
    -> exact-width machine LLIR
    -> typed MIR/SSA with ValueId, PredicateId, StorageId, and MemoryEffect
    -> verified data-flow and recovered source objects
    -> total region graph or explicit goto fallback
    -> typed HIR
    -> pure renderers and structured DecBench metadata
```

The five proposed epics are not independent feature projects. EPIC 5 (definitions) and
EPIC 1 (program environment) are the load-bearing identities; EPIC 4 supplies their
machine semantics; EPIC 3 consumes them to recover storage-backed aggregates; EPIC 2
is then a normal symbolic-value projection instead of a printer special case.

## Current evidence

### Composition and size

At this snapshot, Rust sources under `src/` are 252 files / 196,535 lines: mean
779.9, median 365.5, and 50 files over 1,000 lines. Python under `python/glaurung` and
`tools` is 413 files / 164,669 lines: mean 398.7, median 276, and 23 files over 1,000
lines. File size is not itself the defect, but the concentration identifies mixed
ownership:

| file | lines | mixed responsibilities to separate |
|---|---:|---|
| `src/ir/ast.rs` | 15,739 | HIR model, lowering, semantic passes, type-aware C rendering, plain rendering, and 6,000+ lines of tests |
| `src/ir/lift_x86.rs` | 7,605 | decode dispatch, instruction-family semantics, flag behavior, addressing, and tests |
| `src/analysis/cfg.rs` | 6,870 | discovery, seed management, block construction, scoring, budgets, and several test modules |
| `src/ir/call_args.rs` | 6,489 | ABI policy, liveness, call-site recovery, tail calls, and tests |
| `src/ir/types_recover.rs` | 5,632 | machine width, source-type hypotheses, constraint propagation, conflict repair, and tests |
| `src/ir/stack_locals.rs` | 4,998 | stack coordinates, object discovery, promotion, parameter homes, and tests |
| `src/ir/structure.rs` | 4,894 | graph analyses, recognizers, region ownership, fallback, verification hooks, and tests |
| `src/python_bindings/ir.rs` | 3,221 | session construction, four front doors, pipeline orchestration, rendering, and PyO3 conversion |

The shared `run_ast_passes` function is a real improvement: four public entry points no
longer copy the AST pass list. The front doors still repeat most of the discovery,
lifting, SSA, prototype, field, and render assembly around it. The pipeline is shared by
convention at one stage rather than represented by a single typed service.

Five separate modules also carried identical `local_` / `stack_` classification until
`types::is_promoted_local_*` was introduced in this work. That is representative: a
presentation spelling has become an inter-pass protocol, so helpers get duplicated to
keep each pass compatible.

### Correctness and safety

Current failures repeatedly cross layer boundaries:

- raw physical-register names serve as value identity, ABI role, type key, and printed
  name at different points;
- SSA is a side analysis rather than the representation every later pass consumes;
- a last-writer/name query stands in for dominance-aware reaching definitions;
- a promoted stack name can mean storage or a pointer value, which caused
  `local_8 = arg0` to be rewritten as `local_8->next = arg0`;
- type recovery has exact DWARF facts but flat type strings cannot represent every C
  declarator or preserve partial contracts reliably;
- architecture behavior is split between per-ISA lifters and shared passes containing
  `cc == ...` gates;
- CFG recovery can verify a region only against the discovered CFG, without a first-class
  statement that discovery itself was complete;
- render configuration uses thread-local maps, hiding dependencies and complicating safe
  concurrency.

The stale-extension incident in the diary adds a release-safety concern: Rust source
tests can be green while the Python product executes an older native object. Output
comparisons must bind the extension build to a Git object and expose that identity.

### Performance

`decompile_at`, `decompile_many`, and `decompile_all` build overlapping whole-image facts.
Commit `a08ff66` avoids rendering unrequested DecBench functions, but a durable solution
needs a reusable program session. Symbol maps, DWARF/PDB types, readonly data, string
pools, function tables, exception sites, machine model, lifted callees, dominators, and
call prototypes should be immutable cached facts with explicit invalidation—not rebuilt
or threaded separately through long argument lists.

Optimization must remain evidence-led. The initial targets are eliminated duplicate
whole-image scans and allocations, not micro-optimizing lifters. Profiles must report
wall time, peak RSS, functions/second, cache hit rate, and timeout/unknown counts on the
same corpus and Git object.

## Target components

### `ProgramSession`

Own immutable `ProgramImage`, `ProgramEnvironment`, `MachineModel`, discovery indexes,
and analysis caches. Public APIs become thin queries:

```text
session.decompile(FunctionId, DecompileOptions) -> DecompileArtifact
session.decompile_many(&[FunctionId], DecompileOptions) -> iterator/artifacts
```

No public front door assembles passes. A session is safe to share across function jobs;
per-function mutable state lives in a `FunctionWorkspace`.

### `ProgramEnvironment` — EPIC 1 and EPIC 2 owner

One canonical symbol/type/relocation namespace:

- `SymbolId`, aliases, linkage, address/range, section, and provenance;
- structured `TypeId` graph for scalars, qualifiers, pointers, arrays, functions,
  structs/unions, enums, and typedefs;
- `FunctionPrototype` and per-call-site instantiated contract;
- symbolic constants as `AddressValue { target, addend, width, relocation, provenance }`;
- conflicts retained as competing evidence, never overwritten silently.

ELF, PE/PDB, DWARF, exports, relocations, library catalogs, and heuristic recovery are
adapters into this environment. Printers consume `TypeId`/`SymbolId`; they do not parse
or invent C type strings.

### `MachineModel` — EPIC 4 owner

Replace shared-pass architecture gates with data and traits:

- register banks, views, aliases, and write-extension behavior;
- calling convention roles and preserved/clobbered sets;
- stack growth/alignment, CFA rules, entry-SP/frame coordinates, and return-address
  placement;
- flag effects and condition materialization;
- instruction helper/SIMD semantics and address-width modular arithmetic;
- explicit ARM modes (`A32`, `Thumb`, `AArch64`) rather than “ARM plus exceptions.”

The current AAPCS stack-coordinate widening shows the migration pattern: a shared
semantic operation parameterized by the model, protected by pinned x86 and A32/Thumb
controls.

### Typed MIR/SSA and `DefinitionOracle` — EPIC 5 owner

Make identity and definedness structural:

- stable `BlockId`, `InstId`, `ValueId`, `PredicateId`, and `StorageId` arena keys;
- mandatory machine sort (`Bool` or `BitVec(width)`) on every value;
- explicit `Phi`, call inputs/results, memory reads/writes, and undefined values;
- dominance-aware `definitions_at(use)` and `value_at(location)` queries;
- may/must alias results for storage, plus proof/provenance on each answer;
- no bare-name or traversal-order “last writer” fallback in correctness passes.

The oracle returns `Unique`, `Multiple`, `Undefined`, or `Unknown`; consumers must handle
all four. Verification rejects a generated C read from `Undefined` and prevents an
unproven choice from being presented as fact.

### `StorageGraph` — EPIC 3 owner

Unify current-SP, entry-SP, CFA, frame pointer, globals, and escaped addresses into
storage identities:

```text
StorageObject { id, space, base, extent, alignment, lifetime, provenance }
AccessPath { object, byte_offset, width, index, field }
```

Promotion changes representation from memory traffic to a source variable; it never
changes whether an expression denotes the object, its address, its stored pointer
value, or a pointee field. Aggregate recovery merges access paths and authoritative
layout evidence, with overlap/conflict detection and bounded extents.

### Pass manager and verified stage types

Use explicit stages rather than one giant function over mutable `ast::Function`:

```text
LiftedFunction -> SsaFunction -> NormalizedFunction -> RecoveredFunction
               -> RegionFunction -> HirFunction -> DecompileArtifact
```

Each pass declares required analyses, preserved analyses, produced facts, mutation
scope, and verifier. Analysis caches invalidate automatically when a pass changes the
relevant graph/value/storage property. Dumps and timings are pass-manager observers,
not environment-variable branches embedded in business logic.

### Typed HIR and pure emitters

HIR owns source variables, declarations, address-of/deref, access paths, calls,
structured regions, labels/gotos, and source `TypeId`s. C emission accepts an immutable
`RenderContext`; remove renderer thread locals. Structured DecBench variables and C text
are two projections of the same HIR, preventing partial metadata from disagreeing with
parsed declarations.

## Module decomposition and size policy

Split by ownership after behavior is locked, not by arbitrary line count:

```text
src/decompile/
  session.rs, options.rs, artifact.rs, pipeline.rs, pass_manager.rs
src/program/
  image.rs, environment/{symbols,types,relocations,merge}.rs
src/machine/
  model.rs, x86_64.rs, i386.rs, aarch64.rs, arm32/{a32,thumb}.rs
src/mir/
  ir.rs, builder.rs, ssa.rs, definitions.rs, memory.rs, verify.rs
src/recovery/
  calls.rs, variables.rs, storage.rs, aggregates.rs, types.rs
src/control/
  cfg.rs, dominance.rs, loops.rs, regions.rs, fallback.rs, verify.rs
src/hir/
  ir.rs, lower.rs, verify.rs
src/render/
  c/{decl,expr,stmt,types,context}.rs, plain.rs, decbench.rs
```

Move unit tests beside their owner or into `tests/ir_*`; do not leave 6,000 test lines in
`ast.rs`. During migration, old modules are facades that re-export new owners. Avoid a
flag day.

Enforce a soft production-file budget of 800 lines and a review gate at 1,000 lines.
Exceptions need a module-level ownership statement and follow-up issue. The objective is
not merely a lower median—it is zero decompiler production files combining model,
analysis, transformation, rendering, and tests. Phase 1 should reduce `ast.rs` below
4,000 lines without changing output; the final target is no decompiler production file
over 1,000 lines and repository-wide counts ratcheted downward.

## Rank-ordered phases

### P0 — Make evidence reproducible and fail closed

1. Persist the corrected DecBench evaluator/rebuild changes and freeze a new manifest.
   Retain an unstripped debug companion for every scored binary so source-function and
   type ground truth survive project install/strip steps.
2. Embed Git SHA/native-extension build ID/toolchain IDs in every artifact and cache key.
3. Gate behavior, compile success, exact target cells, architecture ratchets, GED,
   type-match, and byte-match separately.
4. Make CFG completeness, unknown instructions, undefined reads, and verification
   failures machine-readable artifact fields.
5. Add LOC/module-responsibility and duplicate-pass checks as non-blocking reports, then
   ratchet.

**Exit:** a clean checkout can reproduce the corpus and scores; stale native code or
missing metric inputs fails explicitly; no score is silently dropped.

### P1 — Extract composition boundaries with zero semantic change

1. Introduce `ProgramSession`, `FunctionWorkspace`, `DecompileOptions`, and
   `DecompileArtifact` behind existing PyO3 APIs.
2. Move the complete front-to-back sequence from four bindings into one pipeline.
3. Convert `run_ast_passes` into pass descriptors with timings and preserved-analysis
   declarations.
4. Split AST model, preparation passes, C renderer, plain renderer, and tests into owner
   modules; split instruction-family lifters and CFG discovery similarly.
5. Replace long parameter lists with immutable contexts; keep outputs byte-for-byte
   identical.

**Exit:** one pipeline call site, no stage list in bindings, `ast.rs < 4,000` lines, no
metric/behavior/architecture delta, and measurable session reuse on `decompile_many`.

### P2 — Land program identities and machine model

1. Build `ProgramEnvironment` merge/provenance rules and structured type graph.
2. Convert direct call targets, then all code/data constants, to `SymbolId` /
   `AddressValue` before lifting loses relocation context.
3. Introduce `MachineModel`; migrate ABI/register/stack/flag queries one family at a
   time, with no architecture-name tests in shared passes.
4. Make A32, Thumb, AArch64, i386, pinned x86-64 GCC 11, and x86-64 GCC 15 required
   lanes.

**Exit:** every direct call uses a canonical prototype when known; symbolic constants
retain width/relocation provenance; shared passes depend on model queries; all six lanes
remain ratcheted.

### P3 — Replace name-based data flow with typed MIR and the definition oracle

1. Introduce exact-width `ValueId`/`PredicateId` MIR and explicit phi/call/memory
   effects.
2. Implement dominators, reaching definitions, def-use chains, and `Unique/Multiple/
   Undefined/Unknown` answers once.
3. Migrate call-result recovery, parameter roles, return recovery, copy propagation,
   phi recovery, and verifier queries; delete each old name/last-writer implementation
   after parity.
4. Make undefined/unknown states survive to HIR or explicit failure—never fabricate a
   C initializer.

**Exit:** no correctness pass queries a value by rendered name; the call-result collision
canaries and width/phi failures improve; pinned controls do not regress; verifier output
is empty for emitted C.

### P4 — Recover storage and aggregates on the sound value layer

1. Build `StorageGraph` and unify CFA/current-SP/frame/global identities.
2. Model parameter homes and promoted locals as storage/value relationships, not
   renames.
3. Infer extents and access paths; merge authoritative DWARF/PDB layouts and reject
   conflicting overlaps.
4. Publish complete structured variables from HIR and use that same graph for C
   declarations.

**Exit:** ARM constructors/destructors share one object, linked-list storage has no fake
array, aggregate/pointer-depth type canaries improve, and structured DecBench metadata
is complete enough that enabling it never lowers the score by hiding parsed locals.

### P5 — Total control recovery and pure HIR emission

1. Give CFG discovery an explicit completeness result and indirect-jump terminator.
2. Recover loops/regions from dominators, postdominators, SCCs, and edge ownership.
3. Require every edge to be owned by a region or emitted as a goto; verify before HIR.
4. Remove semantic transforms from renderers and thread-local render state.

**Exit:** no invented/dropped edge, unresolved transfers remain explicit, every HIR
value is defined or marked unknown, and direct GED improves without behavior loss.

### P6 — Performance, robustness, and deletion

1. Cache immutable whole-program analyses by input hash/options/build ID; use arena IDs,
   compact bitsets, and bounded worklists in hot graph/data-flow analyses.
2. Analyze functions in parallel through shared immutable session facts and isolated
   workspaces; preserve deterministic ordering and diagnostics.
3. Add memory/time budgets and cancellation at discovery, lifting, analysis, structuring,
   and rendering boundaries.
4. Profile before/after on small, large, and adversarial binaries; optimize only measured
   owners.
5. Delete compatibility facades, duplicate helpers, legacy name-remap passes, and old
   renderer configuration after all consumers migrate.

**Exit:** lower wall time and peak RSS on the frozen corpus, deterministic results across
worker counts, bounded failure on malformed/adversarial inputs, no decompiler production
file above 1,000 lines, and no legacy pipeline path remains callable.

## Stop conditions

Stop a slice and root-cause it before proceeding when any of these occurs:

- a previously passing behavioral cell fails or disappears;
- the pinned x86 control changes unexpectedly;
- a metric improves only because functions or ground truth are missing;
- an architecture-specific fixture patch is proposed without a machine-model invariant;
- a pass chooses among multiple/undefined definitions without proof;
- structured metadata and emitted C disagree on declarations;
- a performance claim lacks identical inputs, Git/build identities, and retained raw data.

This ordering permits useful incremental shipping. It also prevents the current failure
mode: adding another downstream heuristic because the upstream identity, machine model,
or reaching definition was unavailable.
