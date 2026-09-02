# Glaurung decompilation architecture redesign — 2026-08-05

> **Kind:** record · **Date:** 2026-08-13

**Status:** proposed architecture and dependency-ordered implementation plan

**Evidence log:** [glaurung-architecture-review-diary-2026-08-05.md](../diaries/glaurung-architecture-review-diary-2026-08-05.md)

**Scope:** decompilation, lifting and IR, symbols/types, aggregate recovery,
machine semantics, data flow, binary-analysis composition, performance, and
failure safety

## Executive verdict

Glaurung does not primarily need more isolated decompiler passes. It needs one
semantic spine connecting facts about the program to verified facts about each
function.

The current implementation has capable pieces—bounded CFG discovery, four
lifters, SSA, structuring, rich source-type definitions, debug importers, call and
stack recovery, and multiple output modes—but the pieces exchange lossy maps,
register-name conventions, C type strings, and late AST annotations. That causes
three systemic problems:

1. the same image and facts are rebuilt by several entry points and passes;
2. architecture, type, definition, and completeness assumptions are implicit; and
3. increasingly large files compensate for missing ownership boundaries by doing
   several stages at once.

The recommended redesign is a staged migration to this spine:

```text
                       ProgramSession
                            |
            +---------------+----------------+
            |                                |
        ProgramImage                      TargetSpec
     bytes/segments/relocs          ISA/mode/registers/ABI
            |                                |
            +-----------> ProgramEnv <-------+
                         symbols/types/
                       objects/references
                              |
                    Function analysis pipeline
                              |
       Lifted IR -> verified MIR/SSA -> semantic HIR -> renderer
                         |                 |
                definedness/effects    source constructs
```

The first correctness priority is a sound definition/effect graph on a typed MIR.
The first composition priority is a reusable `ProgramSession` and one pipeline.
The first architecture priority is a canonical `TargetSpec`, using ARM32 as the
conformance test. The active constant-symbolization work should then become the
first consumer of a minimal `ProgramEnv`, not another AST-only resolver.

## Current-state diagnosis

### What should be retained

- CFG discovery already records budgets, cancellation, unresolved indirect
  transfers, and other completeness telemetry.
- `regview` has correctly centralized x86-64/AArch64 register-view behavior and
  demonstrated why one source of register semantics matters.
- `decompiler-middle-architecture.md` correctly separates machine sort,
  operation interpretation, and recovered source type.
- `run_ast_passes` is a useful first step toward a shared pipeline.
- The existing core `Symbol` and `DataType` models contain much of the vocabulary
  needed by a program environment.
- The Python knowledge-base rule that explicit analyst knowledge outranks
  heuristic recovery is the right product behavior.
- Real fixtures and the DecBench behavioral lanes provide a migration safety net.

### What must change

- Completeness must travel with every artifact; downstream code must not turn a
  partial graph into an apparently complete decompilation.
- Architecture cannot be inferred from register strings.
- Machine constants need exact width and operand provenance.
- Stable IDs must replace implicit identity by address, string, register name, or
  AST shape.
- Reaching definitions must be a query over verified CFG-based values and effects,
  not a collection of local AST scans.
- Symbols, types, relocations, strings, globals, function tables, and analyst
  knowledge must live in one revisioned `ProgramEnv`.
- HIR should express semantic source operations; renderers should format them
  without running analysis or consulting thread-local semantic state.
- Public decompilation entry points should choose inputs and output profiles, not
  assemble different pipelines.

## Design rules

These rules are intended to prevent the new architecture from reproducing the
same problems with new names.

1. **Machine truth and source interpretation remain separate.** A 32-bit constant
   stays exact 32-bit machine data even when evidence interprets it as an enum or
   pointer.
2. **Identity is explicit.** Functions, blocks, instructions, values, memory
   versions, objects, symbols, types, call sites, and targets use typed IDs.
3. **Evidence is retained, not overwritten.** Manual, debug, relocation, symbol,
   ABI, and heuristic facts can conflict. Selection is policy; conflict is data.
4. **Completeness and confidence are different.** An analysis can be complete but
   uncertain, or incomplete but contain a high-confidence relocation.
5. **Incomplete is monotone.** A downstream stage may add reasons for partiality;
   it cannot erase them.
6. **Passes declare contracts.** Each stage states inputs, required analyses,
   preserved facts, invalidations, budgets, and verification.
7. **Graph transforms fail closed.** Preconditions and post-verification surround
   every value/CFG-changing transform.
8. **Rendering is pure.** No fact discovery, global environment reads, implicit
   fixed points, or semantic rewrites happen in a renderer.
9. **One owner parses the image.** Format-specific modules populate indices through
   `ProgramImage`; ordinary passes never reopen the object.
10. **File size follows ownership.** Splitting a file counts only when it creates a
    narrow API and removes a reason to change from the former owner.

## Target architecture

### 1. `ProgramSession`: lifetime and composition root

`ProgramSession` owns one analyzed binary revision and is the only composition
root for decompilation:

```rust
pub struct ProgramSession {
    image: Arc<ProgramImage>,
    target: Arc<TargetSpec>,
    env: ProgramEnv,
    functions: FunctionIndex,
    pipeline: DecompilerPipeline,
    cache: AnalysisCache,
    revision: ProgramRevision,
}
```

It should:

- parse bytes, object metadata, segments, sections, symbols, relocations, debug
  data, imports, exports, strings, and read-only regions once;
- expose `decompile_one`, `decompile_many`, `decompile_range`, and
  `decompile_all` as views of the same function-analysis operation;
- maintain content-addressed analysis artifacts and explicit invalidation;
- give function-parallel work an immutable environment snapshot;
- merge interprocedural facts deterministically; and
- expose budget, cancellation, diagnostics, and completeness through every API.

The Python object should wrap this session. Convenience functions may construct a
temporary session for compatibility, but batch and interactive workflows should
reuse one.

### 2. Typed artifact envelope

The existing JSON-oriented `core::Artifact` is useful at serialization boundaries,
but internal analysis needs a typed envelope:

```rust
pub struct AnalysisArtifact<T> {
    pub value: T,
    pub revision: ProgramRevision,
    pub target: TargetId,
    pub dependencies: SmallVec<[ArtifactId; 4]>,
    pub completeness: Completeness,
    pub diagnostics: Vec<Diagnostic>,
    pub metrics: PassMetrics,
}

pub enum IncompleteReason {
    Budget(BudgetKind),
    Cancelled,
    UnmappedBytes(AddressRange),
    DecodeFailure(InstructionId),
    UnsupportedSemantic(OpcodeId),
    UnresolvedControlFlow(InstructionId),
    UnknownCallEffects(CallSiteId),
    InvalidatedDependency(ArtifactId),
}
```

`Completeness` should be a set of reasons, not a single optimistic boolean. A
separate `FactConfidence`/`Authority` belongs on inferred facts. Rendering policy
can then be explicit: reject partial artifacts, emit annotated partial output, or
allow a best-effort view.

### 3. Canonical `TargetSpec` and `MachineModel`

Unify the current architecture enums at the analysis boundary:

```rust
pub struct TargetSpec {
    pub isa: Isa,
    pub mode: IsaMode,
    pub endian: Endian,
    pub address_bits: u16,
    pub pointer_bits: u16,
    pub object_format: ObjectFormat,
    pub os_abi: OsAbi,
    pub default_calling_convention: CallingConventionId,
    pub registers: RegisterBank,
}
```

The model must answer, from validated data rather than register-name guesses:

- canonical storage and all register views;
- read/write width, bit offset, zero-extension, preservation, and poison rules;
- flag/predicate effects;
- PC and stack/frame roles;
- instruction alignment and endian rules;
- ABI argument, result, aggregate, clobber, and stack classification; and
- architecture-specific intrinsics and indirect-control-flow patterns.

The decoder/lifter remains ISA-specific, but it receives a `LiftContext` backed by
the same target model as SSA, execution, calling convention, and verification.
Hot paths may use enum dispatch and immutable tables; target abstraction does not
require virtual calls for every operand.

ARM32 is the acceptance architecture. Its model must cover A32 versus Thumb, PC
bias and literal pools, r0-r15/CPSR, condition execution, VFP s/d/q overlap,
soft-float and hard-float ABI selection, endian, alignment, and explicit unsupported
cases. A design that only fits x86-64 and AArch64 is not complete.

### 4. Three IR layers with explicit responsibilities

#### Lifted IR: exact machine effects

Lifted IR should remain close to instruction semantics, but values become
width-exact and the function carries target/provenance/completeness:

```rust
pub struct BitVector {
    pub width: NonZeroU16,
    pub bits: APInt,
}

pub enum LiftedValue {
    Storage(StorageRef),
    Constant(BitVector),
    Address(Address),
}

pub struct LiftedFunction {
    pub id: FunctionId,
    pub target: TargetId,
    pub entry: Address,
    pub blocks: BlockGraph<LiftedInst>,
    pub origins: OriginTable,
}
```

An instruction has all outputs and effects, including flags and memory. Unsupported
semantics become a declared intrinsic with exact read/write footprint or an
incomplete diagnostic. Lifting returns `Result<AnalysisArtifact<LiftedFunction>>`,
never an uninformative `Option`.

#### MIR: typed values, SSA, and effects

MIR is the authoritative analysis graph:

```rust
pub struct ValueData {
    pub sort: MachineSort,
    pub def: Definition,
    pub uses: SmallVec<[UseSite; 4]>,
    pub origin: OriginId,
}

pub enum Definition {
    Input(FunctionInputId),
    Instruction(InstructionId, OutputIndex),
    Phi(BlockId),
    Undef(UndefReason),
    Poison(PoisonReason),
    Unknown(UnknownEffectId),
}
```

`MachineSort` describes bits, integer/float/vector interpretation, and predicate
shape. Recovered source types are constraints referencing `TypeId`; they do not
replace machine sorts.

The MIR owns dominance, value definitions/uses, control edges, and memory effects.
All mutation goes through a graph editor that updates mappings and invalidates
analyses. Values and instructions live in typed arenas or slot maps so identity
survives local rewrites without raw pointer hazards.

#### Semantic HIR: recovered source operations

HIR should stop exposing every machine convention directly. It needs semantic
nodes such as:

- variables and object addresses by stable ID;
- `Field`, `Index`, `AddressOf`, and typed dereference;
- direct/indirect calls with `CallSiteId` and resolved signature candidates;
- casts with explicit reason;
- structured control regions with preserved CFG provenance; and
- fallback machine expressions when source recovery is not proven.

`PdbFieldAddr` should disappear. PDB/DWARF/manual/inferred evidence all resolve to
the same `Field` operation plus provenance. A HIR verifier checks that source-level
rewrites preserve value, object, and control mappings.

### 5. Sound definedness and reaching-definitions service

The shared oracle is built on MIR, not AST syntax. Its minimum API is:

```rust
definition(value: ValueId) -> &Definition
uses(value: ValueId) -> &[UseSite]
dominates(def: DefinitionSite, use_: UseSite) -> bool
value_at(storage: StorageRef, point: ProgramPoint) -> ReachingValue
all_paths_defined(value: ValueId, point: ProgramPoint) -> ProofResult
clobbers_between(value: ValueId, from: ProgramPoint, to: ProgramPoint) -> ClobberSet
memory_version(region: MemoryRegionId, point: ProgramPoint) -> MemoryVersionId
```

`ReachingValue` must distinguish a single definition, phi/set of definitions,
explicit input, undef, poison, unknown effect, and unreachable. Version zero is not
a substitute for these states.

Memory starts with conservative regions—stack object, known global object,
read-only image, heap/unknown, and fully unknown alias—and can refine from there.
Calls and intrinsics carry complete register and memory effect summaries. Unknown
effects clobber conservatively.

Every transformation that can remove, duplicate, move, or merge definitions uses
this sequence:

1. prove a precondition through the oracle;
2. apply a graph transaction;
3. rebuild invalidated analyses;
4. verify dominance, use ownership, phi arity, CFG edges, sorts, and effects; and
5. commit or fail closed.

The current AST verifier remains useful as a final emitted-C regression check, but
it is not the semantic oracle.

### 6. `ProgramEnv`: symbols, types, objects, and references

`ProgramEnv` is an evidence store, not a single guessed answer:

```rust
pub struct Fact<T> {
    pub subject: SubjectId,
    pub value: T,
    pub provenance: Provenance,
    pub authority: Authority,
    pub confidence: Confidence,
    pub scope: FactScope,
    pub revision: FactRevision,
}

pub struct ProgramEnv {
    pub symbols: SymbolStore,
    pub types: TypeStore,
    pub objects: ObjectStore,
    pub references: ReferenceIndex,
    pub functions: FunctionFacts,
    pub calls: CallFactStore,
}
```

The stores use `SymbolId`, `TypeId`, `ObjectId`, and `FunctionId`, not string IDs.
Addresses include address space and width. A symbol may have multiple names,
aliases, ranges, and import/thunk/target relationships. Recursive types are
interned and canonicalized through `TypeStore`; C spellings belong in language
renderers.

Import adapters populate facts from object symbols, relocations, imports/exports,
DWARF, PDB, FLIRT, string discovery, readonly regions, function tables, analyst
knowledge, and decompiler inference. Manual and authoritative debug facts rank
above heuristics for selection, but conflicting facts remain queryable and visible.

Interprocedural prototype and type propagation should be monotone and deterministic:
process strongly connected call-graph components to a fixed point, widen rather
than oscillate, and cache by dependency revision. A call-site query returns both
the selected view and alternatives/evidence.

### 7. Contextual operand references (EPIC 2)

Do not replace every numeric value with a symbol. Attach a contextual interpretation
to an operand/use:

```rust
pub enum ReferenceInterpretation {
    Relocation { symbol: SymbolId, addend: i64 },
    Address { address: Address, symbol: Option<SymbolId> },
    String { object: ObjectId, encoding: StringEncoding },
    Function { function: FunctionId },
    EnumMember { type_id: TypeId, member: EnumMemberId },
    FieldOffset { type_id: TypeId, field: FieldId },
    TypeInfo { type_id: TypeId },
}
```

Resolution order is evidence-driven:

1. relocation and loader semantics;
2. decoded operand role, PC-relative calculation, and target mode;
3. mapped region and section permissions;
4. MIR use and data-flow provenance;
5. call prototype and recovered type constraints;
6. xref/reference consistency; and
7. conservative heuristics.

A renderer may choose `symbol + addend`, `&global.field`, an enum member, a string,
or the original literal. The raw `BitVector`, source instruction, evidence, and
alternatives remain intact. Negative controls are mandatory: the same numeric bits
in arithmetic must remain an integer when reference evidence is absent.

The old name, string, readonly, and function-table resolvers should migrate into
one `ReferenceIndex` and then be deleted, not wrapped indefinitely.

### 8. Aggregate and memory-object recovery (EPIC 3)

Aggregate recovery is a constraint problem over objects and access paths:

```rust
pub struct MemoryObject {
    pub id: ObjectId,
    pub kind: ObjectKind,
    pub address_space: AddressSpaceId,
    pub extent: Extent,
    pub lifetime: Lifetime,
}

pub struct AccessPath {
    pub base: ObjectId,
    pub offset: AffineExpr,
    pub width: NonZeroU16,
    pub access: AccessKind,
    pub instruction: InstructionId,
}
```

Constraints include size-at-least, alignment, field-at-offset, compatible type,
array stride, repeated access, overlap/union, bitfield slice, pointer target, and
ABI layout. Sources retain provenance. The solver produces candidates with proofs
or unresolved conflicts; it never invents field names merely because an offset
matches a popular structure.

Recovery order:

1. create stack/global/TLS/parameter-pointee objects from proven bases;
2. import authoritative debug/manual layouts;
3. collect MIR loads/stores and affine access paths;
4. propagate call/prototype constraints across object boundaries;
5. classify structure versus array versus union conservatively;
6. solve field types and extents to a fixed point; and
7. project proven paths into semantic HIR.

ABI classification must model by-value aggregates, split register/stack values,
hidden structure returns, and aggregate result storage before rendering. Vtables
and RTTI are global aggregate objects tied to relocation and call facts, not a
separate pretty-print heuristic.

### 9. Pass manager and pure output profiles

The pass manager need not be a dynamic plugin framework. It does need an explicit,
testable stage graph:

```text
discover -> lift -> verify-lifted -> build-MIR -> verify-MIR
         -> recover-calls/types/objects -> structure -> build-HIR -> verify-HIR
         -> source-cleanup -> render(profile)
```

Each stage declares:

- artifact type and version;
- required analyses/facts;
- preserved and invalidated analyses;
- budget and cancellation checks;
- verifier and failure policy; and
- metrics/change summary.

`faithful`, `c`, and `decbench` become output profiles over the same verified
semantic artifact. A profile can enable explicit pre-render normalization passes,
but the renderer itself only formats. Pipeline fingerprints make entry-point drift
detectable in tests.

## Module and file decomposition

The following is a target ownership map, not a requirement to rename everything in
one patch:

```text
src/
  program/
    image.rs              one parse, segments/sections/address translation
    session.rs            composition root and public analysis lifetime
    env.rs                store facade and revision snapshots
    provenance.rs         facts, authority, confidence, conflicts
    symbol.rs             SymbolStore and queries
    types/                TypeStore, interning, constraints, language projection
    objects.rs            memory-object identities and access paths
    references.rs         relocations/xrefs/contextual interpretations
    cache.rs              dependency-aware artifact cache
  target/
    spec.rs               canonical target identity
    registers.rs          views and write semantics
    abi.rs                shared ABI classifier interface
    x86.rs
    aarch64.rs
    arm32.rs
  lift/
    context.rs
    builder.rs            shared effect/value construction
    x86/                  integer, control, memory, flags, vector
    aarch64/
    arm32/
  ir/
    lifted/               model and verifier
    mir/                  graph, value, effects, memory, verifier, editor
    hir/                  model, builder, visitor, verifier
  analysis/
    dataflow/             dominance, SSA, definedness, MemorySSA, liveness
    calls/                call-site facts and interprocedural propagation
    types/                constraint collection and solving
    aggregates/           objects, access paths, layout solving
    structure/            regions, proof checks, HIR projection
  decompile/
    pipeline.rs
    profiles.rs
    engine.rs
  render/
    faithful.rs
    c.rs
    decbench.rs
```

Specific splits should follow these semantic seams:

- `ast.rs`: `hir/model`, `hir/build`, `hir/visit`, `hir/verify`, output-neutral
  cleanup passes, and three renderer modules. Move tests beside their owner.
- `lift_x86.rs`, `lift_arm64.rs`, `lift_arm32.rs`: shared `LiftBuilder`, then
  architecture instruction families. Register and ABI semantics leave the lifter.
- `call_args.rs`: ABI classification, MIR call-site evidence, interprocedural facts,
  and HIR projection become separate owners. Local AST reaching-def scans disappear.
- `types_recover.rs`: evidence collection, constraint lattice/solver, prototype
  recovery, and language projection separate. ARM/VFP rules move to target ABI.
- `stack_locals.rs`: frame analysis, object construction, scalar promotion, and HIR
  naming separate.
- `structure.rs`: graph algorithms, region selection, verification, and HIR
  lowering separate.
- `analysis/cfg.rs`: decode walk, seed providers, dispatch completion, format seed
  sources, and orchestration separate while retaining one result contract.

Generate or hand-maintain one shared HIR visitor/rewriter surface so a new expression
or statement variant does not require dozens of independent recursive walkers.

### Size fitness targets

Measure production and test code separately. By completion of the migration:

- no new production module exceeds 1,000 LOC without a documented exception;
- normal implementation modules target 200–700 LOC;
- `src/ir` median falls from 1,014 to below 600 LOC;
- `src/ir` files above 1,000 LOC fall from 27 to at most 5;
- product-code mean falls from 552 to below 450 LOC;
- product files above 1,000 LOC fall from 71 to at most 35; and
- less than 25% of product LOC lives in files above 1,000 LOC, versus 47.4% now.

Generated tables and data declarations may be exempt, but mixed-responsibility
logic is not. These are architecture fitness checks, not incentives to create
hundreds of trivial wrapper files.

## Performance design

Performance should improve first through avoided work, then through measured local
optimization.

1. Parse the object and debug data once per `ProgramSession`.
2. Cache artifacts by image revision, target, function, pipeline version,
   configuration, and exact dependency revisions.
3. Use immutable environment snapshots for function-parallel analysis; merge facts
   deterministically at phase barriers.
4. Analyze call-graph SCCs for interprocedural fixed points rather than repeatedly
   relifting direct callees from roots.
5. Store MIR in arenas and use change epochs/change sets instead of cloning a whole
   HIR to detect fixed points.
6. Share walkers and indices; do not rescan whole ASTs for each local query.
7. Make expensive passes demand-driven and cacheable, with declared invalidation.
8. Record time, allocations, graph sizes, cache hits, and iteration counts per pass.
9. Enforce per-function and whole-session budgets plus cooperative cancellation.
10. Profile before changing representations or adding parallelism.

Required benchmarks should include cold one-function, warm repeated one-function,
cold batch, warm batch, debug-heavy binary, stripped binary, large CFG, and ARM32.
Report median and tail latency, peak RSS, parse count, and output/correctness parity.

## Safety and reliability design

- Replace semantic `Option` returns with typed errors or partial artifacts carrying
  reasons and affected ranges.
- Attach source address and operand origin to every lifted instruction/value.
- Carry unresolved CFG edges and skipped bytes to rendered diagnostics.
- Validate `TargetSpec` once and reject unsupported target/mode/ABI combinations
  before lifting.
- Require declared effects for calls and intrinsics; unknown means conservative
  clobber, never no clobber.
- Verify at every IR boundary and after every graph-changing pass.
- Remove environment-variable control over correctness checks. Environment flags
  may enable diagnostics, not semantic validity.
- Keep analyst/debug facts immutable by default; inferred facts cannot overwrite
  them.
- Make parallel results deterministic and stable under pass reordering where the
  dependency graph permits it.
- Fuzz decoders, target register-view contracts, MIR verifiers, reference
  resolution, and serialized knowledge-base inputs.

## Dependency-ordered implementation plan

### Phase 0 — lock behavior and install the composition seam

**Goal:** one observable pipeline and one typed result boundary without changing
decompiler semantics.

Tasks, in order:

1. Capture current exact-output and behavioral baselines for representative x86,
   x86-64, AArch64, and ARM32 fixtures; record cold/warm performance.
2. Introduce `Diagnostic`, `Completeness`, and `AnalysisArtifact<T>` adapters around
   discovery and lifting. Preserve all existing discovery stats.
3. Change lifting internals to report skipped/clipped/unmapped blocks and unsupported
   semantics, while compatibility APIs may still map the result to `Option`.
4. Add `ProgramImage` and prove with instrumentation that a session parses one
   image once.
5. Add `DecompilerEngine`/`ProgramSession` wrappers and route all four entry-point
   shapes through one internal function pipeline.
6. Make pipeline configuration explicit and give every run a deterministic
   fingerprint.
7. Add an architecture fitness check preventing new object parsing outside approved
   image/import modules.

Exit criteria:

- existing outputs and behavior gates are unchanged;
- every entry point uses the same pipeline fingerprint for the same profile;
- an incomplete discovery/lift remains marked incomplete through rendering; and
- batch analysis shows one object parse per session.

Stop if a compatibility wrapper drops a diagnostic without an explicit policy, or
if entry-point consolidation changes output without a focused regression and a
reviewed semantic explanation.

### Phase 1 — canonical target and exact lifted semantics

**Goal:** make target, width, register, ABI, and lift failure explicit.

Tasks:

1. Add `TargetSpec`, adapters from current public enums, and one canonical internal
   `TargetId`.
2. Generalize `regview` into `RegisterBank` with read/write semantics for x86,
   x86-64, AArch64, and ARM32.
3. Move register width/canonicalization out of name-only `phys_reg_width` and SSA
   helpers.
4. Add exact-width `BitVector` constants and operand/source provenance.
5. Introduce `LiftContext` and `LiftBuilder`; migrate one instruction family per
   architecture before broad file splitting.
6. Move calling-convention selection and register clobbers behind target ABI
   classifiers.
7. Build generated conformance tests for every register view and write behavior.
8. Complete the ARM32 matrix for A32/Thumb, conditions, PC, VFP aliases, and
   soft/hard-float ABI.

Exit criteria:

- no IR/SSA/execution code determines register semantics from an unqualified name;
- every lifted constant has exact width;
- all four target conformance suites pass; and
- unsupported target operations fail explicitly with footprints/diagnostics.

### Phase 2 — verified MIR and the definedness oracle

**Goal:** establish the correctness foundation before adding more destructive
source recovery.

Tasks:

1. Add typed IDs/arenas for blocks, instructions, values, storage, and effects.
2. Lower existing LLIR into MIR while retaining an output-parity compatibility
   path.
3. Represent explicit function inputs, undef, poison, unknown effects, and all
   outputs of multi-output operations.
4. Build dominance, SSA construction, complete def-use, and verifier services.
5. Add region-based memory versions for stack, globals, readonly image, and unknown
   memory; then refine aliases incrementally.
6. Model complete call/intrinsic register and memory effects.
7. Implement the shared definedness/reaching-definition query API.
8. Add transactional graph editing and invalidation.
9. Port the highest-risk consumers—call arguments, copy propagation, dead-store
   elimination, stack promotion, and expression reconstruction—to oracle proofs.
10. Delete their local reaching-definition approximations after parity is proven.

Exit criteria:

- every MIR use has one valid definition state and every reachable use is
  dominance-correct;
- mutation/property tests cover diamonds, loops, irreducible flow, calls,
  multi-output intrinsics, undef/poison, and memory clobbers;
- final AST verification still passes as an independent backstop; and
- no migrated pass scans backward through HIR to answer a reaching-def query.

### Phase 3 — canonical program environment

**Goal:** give every cross-function fact stable identity, provenance, and conflict
semantics.

Tasks:

1. Define typed IDs, `Fact<T>`, provenance, authority, confidence, revision, and
   conflict records.
2. Implement `SymbolStore`, including aliases, ranges, imports, thunks, bindings,
   and contextual address queries.
3. Implement recursive, interned `TypeStore`; adapt `core::DataType` rather than
   creating another source-type model.
4. Import object symbols, relocations, imports/exports, DWARF, PDB, FLIRT, strings,
   readonly objects, and current function-table evidence.
5. Implement `FunctionFacts` and `CallFactStore` with SCC-based monotone prototype
   propagation.
6. Adapt the Python knowledge base as a persistence/analyst-override backend.
7. Expose selected facts, alternatives, conflicts, and provenance through Python.
8. Remove `HashMap<u64, String>` and C-type-string exchanges from internal
   decompiler APIs as consumers migrate.

Exit criteria:

- one program query returns consistent symbol/type/call facts across all entry
  points;
- manual/debug facts cannot be silently replaced by inference;
- recursive types retain identity across functions and sessions; and
- repeated batch decompilation does not relift callees merely to recover facts that
  are already at the current environment revision.

### Phase 4 — generalized constant/reference symbolization

**Goal:** deliver EPIC 2 on the program/MIR foundation.

Tasks:

1. Add operand/use-site reference annotations without replacing raw bitvectors.
2. Resolve relocation and PC-relative evidence first.
3. Add contextual address, symbol+addend, string, global, function, enum, field
   offset, and type-info interpretations.
4. Index references once and expose them to decompilation, xrefs, UI, call graph,
   readonly folding, and function-table analysis.
5. Project selected interpretations into semantic HIR.
6. Make rendering policy choose a readable interpretation while preserving an
   exact-literal fallback.
7. Migrate and delete the separate name/string/readonly/function-table constant
   recognizers.

Exit criteria:

- the same bits can correctly render as an integer in arithmetic and as a symbol
  under relocation/type evidence;
- symbol+addend, enum, string, global, and function-pointer fixtures pass;
- conflicting interpretations are inspectable; and
- no generic "mapped number means pointer" rule exists.

### Phase 5 — aggregate and object recovery

**Goal:** recover layouts semantically, with or without debug data.

Tasks:

1. Create `MemoryObject` and `AccessPath` from proven stack/global/TLS/parameter
   bases.
2. Collect exact load/store/affine-offset/stride constraints from MIR.
3. Import DWARF, PDB, and analyst layouts into the same `TypeStore` constraint
   system.
4. Implement conservative structure/array/union/bitfield classification and
   conflict reporting.
5. Propagate object and pointee constraints through calls.
6. Implement target ABI rules for by-value aggregates, split values, and hidden
   structure returns.
7. Add semantic HIR field/index/address-of operations.
8. Model vtables/RTTI as global objects connected to relocations, types, and method
   prototypes.
9. Remove PDB-only AST variants and late debug-specific walkers.

Exit criteria:

- exact debug-backed layouts and no-debug inferred layouts use the same HIR nodes;
- overlap/union and repeated-stride/array negative controls prevent false structs;
- hidden-return and by-value ABI fixtures execute correctly; and
- every rendered field has object, type/layout, access, and provenance evidence.

### Phase 6 — finish HIR, pass, renderer, and file decomposition

**Goal:** make semantic ownership visible in code and eliminate output-specific
analysis.

Tasks:

1. Complete semantic HIR and shared visitors/rewriters.
2. Move every AST semantic transform into an explicit pass with requirements and
   verification.
3. Make faithful, C, and DecBench renderers pure projections.
4. Remove renderer thread-local type/name state and renderer-time fixed points.
5. Split the large files along the module plan, moving tests beside the new owners.
6. Add architecture dependency checks: renderer cannot import lifters; HIR cannot
   parse images; passes cannot query environment variables for correctness.
7. Delete compatibility paths as their callers reach parity.
8. Enforce the file-size fitness targets in a reporting/ratchet script.

Exit criteria:

- rendering the same HIR twice is deterministic and side-effect free;
- new HIR variants require changes in the model/visitor and relevant owners, not
  dozens of ad hoc recursive matches;
- all entry points and profiles use the declared stage graph; and
- the size metrics meet the stated targets without trivial file fragmentation.

### Phase 7 — persistence, parallelism, and hardening

**Goal:** capitalize on the new boundaries with measured performance and robust
long-running analysis.

Tasks:

1. Persist versioned ProgramEnv and cache artifacts with dependency fingerprints.
2. Add deterministic function-parallel scheduling and SCC phase barriers.
3. Add incremental invalidation for analyst edits, new debug facts, and pass
   upgrades.
4. Stabilize typed Python result objects and keep JSON only at storage/RPC edges.
5. Profile cold/warm/batch paths; optimize allocation/layout only from evidence.
6. Add cancellation and resource budgets to every expensive/fixed-point pass.
7. Fuzz importers, target contracts, lifters, MIR editors/verifiers, and persistence.
8. Add crash-recovery and schema-migration tests for the project knowledge base.

Exit criteria:

- warm analysis reuses only valid artifacts and reports cache provenance;
- parallel and serial runs produce identical facts and output;
- cancellation returns typed partial artifacts promptly; and
- the benchmark matrix shows no correctness regression and a documented improvement
  in mean/median batch cost and repeated-query latency.

## Rank-ordered backlog

This is the execution order within and across phases. A lower-ranked feature should
not bypass an unmet dependency merely because its output is visible sooner.

| Rank | Task | Why it is here | Depends on |
|---:|---|---|---|
| 1 | Carry completeness/diagnostics through typed artifacts | Prevents partial graphs from becoming trusted output | Current discovery telemetry |
| 2 | One `ProgramImage`/`ProgramSession` and one pipeline | Removes repeated work and entry-point drift; creates all later seams | 1 |
| 3 | Canonical `TargetSpec` | Removes architecture ambiguity from every semantic layer | 2 |
| 4 | Exact-width lifted values and explicit lift results | Makes constants, ARM32, and failure semantics reliable | 1, 3 |
| 5 | Typed MIR IDs, effects, and verifier | Creates stable semantic identity | 3, 4 |
| 6 | Sound register definedness/SSA oracle | Blocks unsafe transformations | 5 |
| 7 | Memory effects and MemorySSA regions | Makes calls, stores, stack, and aggregates sound | 5, 6 |
| 8 | `ProgramEnv` fact/provenance model | Gives program-wide knowledge one owner | 2, 3 |
| 9 | Canonical `SymbolStore` and `TypeStore` | Reuses existing rich models without lossy maps/strings | 8 |
| 10 | Interprocedural call/prototype fixed point | Replaces per-root callee relifting | 6–9 |
| 11 | Contextual reference resolver | Delivers generalized constant symbolization safely | 4, 8–10 |
| 12 | Memory objects and access paths | Establishes identity for aggregate recovery | 7–9 |
| 13 | Aggregate constraint solver and ABI projection | Delivers structs/arrays/unions/sret | 10–12 |
| 14 | Semantic HIR and shared visitors | Gives proven facts a source-level representation | 5–13 |
| 15 | Pure renderers and profile cleanup | Removes semantic work from output code | 14 |
| 16 | Large-file splits and legacy deletion | Makes the new ownership boundaries physical | Each owner as migrated |
| 17 | Persistent cache and deterministic parallelism | Exploits stable revisions and dependencies safely | 2, 8, 10, 14 |
| 18 | Representation-level performance tuning | Should follow profiling of the composed system | 17 |

## Validation strategy

### Focused gates per increment

Each increment follows the repository's TDD rule and must include:

- a real binary/fixture or generated real toolchain artifact, not a mocked IR shape
  alone;
- a negative or near-miss control;
- the narrow Rust/Python unit and integration tests for the owner;
- a verifier/property test when graph semantics change; and
- output plus behavioral comparison where decompilation changes.

Architecture work adds register-view and lifter/executor differential tests.
Reference work adds relocation and same-bits/different-context controls. Aggregate
work adds debug/no-debug, overlap, array, and ABI controls. Data-flow work adds
diamonds, loops, irreducible flow, calls, and memory clobbers.

### Broad gates before a phase closes

Use the repository-standard commands and report their evidence states separately:

```bash
cargo test
uvx pytest python/tests/
uvx ruff check python/
uvx ty check python/
scripts/decbench-local-gate.sh
```

Add format/lint commands appropriate to the touched Rust paths. Do not call a phase
green while the three-lane DecBench gate or any invoked command is still running.
Retain exact fixture cells and broad behavioral gates; generated-text/GED movement
alone is not semantic proof.

### Architecture fitness checks

Automate checks for:

- object parsing outside `program/image` and import adapters;
- name-only register-width/canonicalization calls;
- renderer imports of lift/analysis modules;
- semantic environment variables in passes;
- new production modules above 1,000 LOC;
- HIR variants missing visitor/verifier coverage;
- passes without declared invalidation/verifier policy; and
- compatibility APIs that discard incomplete reasons.

## Stop conditions and non-goals

Stop and repair the foundation when:

- a transform cannot prove definition/dominance/effect preconditions;
- ARM32 requires a second, incompatible register or ABI path;
- a heuristic overwrites manual/debug/relocation evidence;
- incomplete bytes, CFG edges, or semantics lose their diagnostic;
- a new resolver infers pointers solely because integers fall in mapped ranges;
- performance work lacks a profile and behavioral control; or
- a file split changes paths but not ownership/API boundaries.

This redesign does **not** aim to:

- force machine IR and source HIR into one universal representation;
- promise complete source-type recovery from stripped binaries;
- remove best-effort decompilation, only make its uncertainty explicit;
- make every architecture implement every instruction before joining the model;
- introduce a runtime plugin framework for passes; or
- optimize for a line-count score at the expense of cohesion.

## Recommended first implementation slice

Start with a narrow vertical slice that advances the active symbolization work
without creating another legacy path:

1. wrap `decompile_at` and `decompile_many` in one temporary `ProgramSession`;
2. add typed completeness to discovery/lifting and preserve it to the returned
   result;
3. add the minimal `TargetSpec` and exact-width constant/origin representation;
4. create a minimal `ProgramEnv` containing object symbols and relocations with
   provenance;
5. resolve one relocation-backed data operand as `symbol + addend`, retaining the
   raw bits;
6. test the same numeric bits in an arithmetic operand remain numeric;
7. exercise the slice on x86-64, AArch64, and ARM32; and
8. route both entry points through the same reference query and renderer behavior.

That slice proves the session, target, artifact, evidence, and contextual-reference
interfaces before attempting strings, enums, debug fields, or inferred pointers.
It also creates a safe foothold for EPIC 2 while the MIR/definedness work proceeds
on the critical correctness path.
