# Glaurung decompiler and binary-analysis roadmap

**Status:** canonical consolidated roadmap  
**Last updated:** 2026-08-13  
**Planning baseline:** Glaurung `fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4`

This file consolidates the architecture review, DecBench gap analysis, repair
campaign, branch audit, IR redesign, ARM work, type and aggregate work, code-size
goals, performance plan, and benchmark-submission checklist into one ordered
plan. The dated diaries remain the evidence log; this is the place to decide
what comes next.

The central conclusion is unchanged:

> Glaurung does not primarily need more isolated AST heuristics. It needs one
> semantic spine connecting program-wide evidence to verified per-function
> values, memory effects, objects, types, control flow, and source rendering.

The migration must remain incremental. Each phase must deliver a usable,
tested improvement; “architecture work” is not permission to stop fixing real
decompiler defects.

## How to use this roadmap

Status markers:

- `[x]` is implemented and has specific evidence.
- `[~]` is partially implemented or implemented only as a diagnostic sidecar.
- `[ ]` is open.
- `[!]` is blocked by a prerequisite or known unsafe approach.
- `[r]` is a measured, rejected approach that must not be revived unchanged.

When an old score or revision appears in an evidence document, treat it as
historical unless this file calls it current. Product correctness, local metric
results, the PR branch, and the public leaderboard are separate states.

## Current state

### Product and submission snapshot

- Glaurung `master` and `origin/master` are at `fb4ee6b`.
- The fresh deterministic DecBench package was produced from that exact commit:
  224/224 binaries, 250/250 requested functions, zero extraction failures.
- The package SHA-256 is
  `dac9d8382828a43f918739e79be61f98935f200287886b4e5548b3ae594cd69b`.
- DecBench PR #56 points its default Docker build at the exact evaluated commit.
  The image was built with Python 3.12 and Rust 1.97.1, reports Glaurung 0.1.0,
  and records `fb4ee6ba` in `/opt/glaurung.rev`.
- PR #56 is open and merge-clean at DecBench branch commit `f4fbd607`.
- No public result or leaderboard update is implied by the artifact or PR state.
- The current package differs from the preceding `60271f2` package in one
  generated C file, so its score must be evaluated rather than copied forward.

### Architecture already landed

- [x] Reusable `ProgramImage` and `ProgramSession` seams exist.
- [x] All four public decompilation entry shapes share session-owned image and
  environment data.
- [x] Canonical target identity exists and is shared with the newer analysis
  boundaries.
- [x] Stable typed MIR identities exist for blocks, instructions, storages,
  values, uses, memory values, effects, objects, accesses, and cursor lifetimes.
- [x] MIR represents inputs, phis, undef, opaque effects, and unreachable
  definitions explicitly.
- [x] A conservative, region-aware MemorySSA sidecar covers stack, known globals,
  readonly image data, heap/unknown, and fully unknown aliases.
- [x] MIR and MemorySSA have independent ownership, CFG, dominance, effect,
  region, phi, and cross-reference verification.
- [x] A canonical recursive `TypeStore` has stable `TypeId` identities,
  provenance, authority ordering, conflict retention, and object bindings.
- [x] Stable MIR objects can be joined to program types without source spelling.
- [x] A session-owned DWARF type graph has been implemented in the current
  working lane, including recursive nominal identities and referenced-member
  width resolution. It is not part of the `fb4ee6b` submission artifact until
  committed and verified.

### Foundations still incomplete

- [ ] Typed completeness and diagnostics do not yet travel through every stage.
- [ ] `ProgramSession` is not yet the sole owner of every parse and cache.
- [ ] The canonical target and ABI model is not ARM32-complete.
- [ ] The verified MIR/MemorySSA boundary is not yet the production authority
  for all definition-sensitive transformations.
- [ ] The production aggregate/type consumers still depend on AST-era adapters.
- [ ] PDB and inferred type facts do not yet populate the same canonical store.
- [ ] Semantic HIR and pure renderers are not complete.
- [ ] File-size and ownership targets remain substantially open.

## Non-negotiable design rules

1. Machine value, source interpretation, and rendered spelling are distinct.
2. Stable typed IDs identify every program, function, block, instruction, value,
   memory version, object, symbol, type, call site, reference, and target.
3. Evidence is retained with provenance, authority, confidence, scope, and
   revision. Selection policy never destroys conflicts.
4. Completeness and confidence are different. Incompleteness is monotone:
   downstream stages may add reasons, never erase them.
5. Unknown calls and instructions clobber conservatively. Unknown never means
   “no effect.”
6. Every reachable use resolves to a precise definition state: input,
   instruction, phi, undef, poison, unknown effect, unreachable, or a proved set.
7. Graph-changing passes prove preconditions, update through a controlled editor,
   invalidate dependent analyses, and verify postconditions.
8. A failed proof keeps a lower-level expression, explicit unknown, or honest
   goto. It does not guess.
9. One session parses and indexes one image. Passes consume session APIs and do
   not reopen the object independently.
10. Renderers are pure formatting projections over verified semantic artifacts.
11. ARM32 is a conformance architecture, not an optional afterthought.
12. Serial and parallel analysis must produce identical facts and output.
13. Metric gains do not override execution, verifier, completeness, regression,
    and canary evidence.
14. A file split counts only if it creates a narrower API and one reason to
    change; arbitrary fragmentation is not architecture.

## Target architecture

```text
                              ProgramSession
                   image / target / revision / budgets
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
     ProgramImage                TargetSpec                ProgramEnv
 bytes/segments/relocs     ISA/mode/registers/ABI     symbols/types/objects/
 debug/imports/strings       and effect contracts      references/call facts
          |                         |                         |
          +-------------------------+-------------------------+
                                    |
                         function analysis pipeline
                                    |
                 complete lifted IR with exact effects
                                    |
                    verified typed MIR + MemorySSA
                                    |
             calls / types / objects / references / regions
                                    |
                         verified semantic HIR
                                    |
                  pure faithful / C / DecBench renderers
```

### Stage contracts

Every stage declares:

- typed input and output artifact versions;
- exact target and program revision;
- dependencies and required analyses;
- facts preserved and invalidated;
- budgets and cancellation behavior;
- verifier and failure policy;
- completeness reasons and diagnostics; and
- timing, allocation, graph-size, iteration, and change metrics.

The intended stage graph is:

```text
discover -> lift -> verify-lifted -> build-MIR -> verify-MIR
         -> recover calls/types/objects/references
         -> complete CFG -> recover verified regions
         -> build-HIR -> verify-HIR -> source cleanup -> render(profile)
```

## The five primary epics

### EPIC 1 — Program-level symbol and type environment

**Goal:** one revisioned evidence store for all cross-function knowledge.

The environment owns `SymbolStore`, `TypeStore`, `ObjectStore`,
`ReferenceIndex`, `FunctionFacts`, and `CallFactStore`. It imports object symbols,
relocations, imports/exports, DWARF, PDB, FLIRT, strings, readonly objects,
function tables, analyst knowledge, and inference without collapsing them into
lossy `HashMap<u64, String>` or C type strings.

- [x] Establish `ProgramEnvironment` behind the reusable session.
- [x] Add stable recursive `TypeStore` identities and conflict-preserving facts.
- [x] Bind stable MIR objects to type facts.
- [~] Import DWARF once per session into the canonical store; finish, commit, and
  verify the current working slice.
- [ ] Implement a canonical `SymbolStore`: aliases, ranges, imports, exports,
  thunks, bindings, demangled names, and contextual address queries.
- [ ] Import PDB facts into `TypeStore` and `ObjectStore`; remove the separate
  PDB-only field-map authority.
- [ ] Import FLIRT/library catalog facts with explicit provenance.
- [ ] Add `FunctionFacts` and `CallFactStore` keyed by stable function/call IDs.
- [ ] Solve interprocedural prototypes and type constraints monotonically over
  call-graph SCCs.
- [ ] Expose selected facts, alternatives, conflicts, and provenance through
  Python and the project database.
- [ ] Delete legacy string-keyed and per-entry-point fact exchange after parity.

#### Name-based knowledge: permitted, bounded, and never silent

Names are useful evidence, not proof of behavior. Carefully integrating them is
moderate work once the program environment is the owner; sprinkling name checks
through decompiler passes is cheap but creates an unsafe maintenance trap.

Allowed uses:

- exact imported/dynamic symbol plus a versioned known-library prototype;
- demangled C++/Rust names as candidate signature or type evidence;
- standard allocator/string/memory APIs as declared call-effect summaries;
- suffix/prefix conventions only as low-authority hints; and
- analyst-approved names as highest-authority local facts.

Required safeguards:

- preserve symbol source, binding, version, module, and demangling provenance;
- distinguish exact catalog match from heuristic name resemblance;
- validate candidate contracts against ABI, call sites, value widths, and
  observed uses;
- retain conflicting alternatives instead of forcing a signature;
- never key a product fix to a DecBench project or target-function name;
- include stripped, renamed, misleading-name, and same-name/different-signature
  negative controls; and
- use the selected contract before liveness/DCE so argument evidence is not
  deleted and reconstructed later from stale register names.

### EPIC 2 — Symbolize constant operands, not only call targets

**Goal:** attach contextual interpretations to operand uses while preserving raw
machine bits.

A constant may represent an integer, relocation, address, string, function,
symbol plus addend, enum member, field offset, RTTI/typeinfo record, or vtable.
The same bits may validly mean different things at different use sites.

- [x] Recover direct and address-taken function symbols in several existing
  paths without emitting conflicting `extern void name(void)` declarations.
- [ ] Add an operand/use-site `ReferenceInterpretation` with source instruction,
  exact width, provenance, alternatives, and confidence.
- [ ] Resolve evidence in order: relocation/loader semantics, decoded operand
  role and PC calculation, mapped region, MIR provenance, call/type constraints,
  xref consistency, then conservative heuristics.
- [ ] Index references once for decompilation, xrefs, call graph, readonly
  folding, function tables, and UI consumers.
- [ ] Project selected interpretations as semantic HIR operations.
- [ ] Render `symbol + addend`, strings, enum members, globals, field offsets,
  and function pointers with an exact-literal fallback.
- [ ] Migrate and delete separate name, string, readonly, and function-table
  constant recognizers.
- [ ] Prove with negative controls that a mapped numeric value used in arithmetic
  remains numeric.

### EPIC 3 — Aggregate and memory-object recovery

**Goal:** recover stack/global/TLS/parameter-pointee objects and solve structures,
arrays, unions, bitfields, and ABI aggregate transfers from proven accesses.

- [x] Add source-spelling-independent `MemoryObject`, affine access paths,
  extent, alignment, role, stride, lifetime, provenance, and conflicts.
- [x] Carry stable objects/accesses and cursor lifetimes into typed MIR.
- [x] Join MIR objects to canonical program types.
- [~] Retain the AST compatibility adapter as production authority while the MIR
  model is diagnostic; do not create a second production heuristic path.
- [ ] Migrate the first production aggregate consumer to verified MIR evidence.
- [ ] Import authoritative DWARF/PDB/manual layouts into the same constraint
  system.
- [ ] Collect exact load/store, affine-offset, repeated-stride, overlap, pointer,
  and call-boundary constraints.
- [ ] Classify struct versus array versus union versus bitfield conservatively.
- [ ] Propagate pointee and object constraints across calls.
- [ ] Model by-value aggregates, split register/stack values, hidden structure
  returns, and aggregate result storage for each ABI.
- [ ] Project proven accesses as HIR `Field`, `Index`, `AddressOf`, and typed
  dereference nodes.
- [ ] Model vtables and RTTI as global objects connected to relocations, types,
  and method contracts.
- [ ] Remove PDB-only AST operations and debug-specific late walkers.

Near-term retained work:

- Port only the version-stable affine-index analysis from the retired
  `agent/stack-bias` snapshot against current master.
- Keep the guards that reject self-rooted read-modify-write facts and unstable
  definition endpoints.
- Add a real end-to-end fixture for an array indexed with a constant bias before
  integrating it.
- Do not merge the retired branch or restore its pervasive `StackAddressDefs`
  threading wholesale.

### EPIC 4 — Architecture-parametric machine model

**Goal:** one validated model for target identity, register views, instruction
mode, ABI classification, call effects, stack/frame rules, and exact widths.

- [x] Introduce canonical target identity at the program and MIR boundaries.
- [x] Centralize substantial x86-64/AArch64 register-view behavior.
- [ ] Finish `TargetSpec`: ISA, mode, endian, address width, pointer width,
  object format, OS ABI, default calling convention, and register bank.
- [ ] Remove remaining register-name inference from SSA, widths, execution,
  lifting, and recovery.
- [ ] Represent constants as exact-width bitvectors with operand provenance.
- [ ] Make all call and intrinsic read/write/clobber effects target-owned.
- [ ] Unify ABI argument/result/aggregate classification behind the target.
- [ ] Generate conformance tests for every register view and partial-write rule.

ARM32 acceptance work:

- [x] Preserve the real armv7 fixes recovered during branch integration.
- [x] Reject ARM alignment saves as parameter evidence when balanced and unused.
- [ ] Widen the dual current-SP/CFA entry-stack coordinate machinery from its
  AArch64 gate to ARM32, with real A32/Thumb controls.
- [ ] Cover A32 versus Thumb, PC bias, literal pools, condition execution,
  r0-r15/CPSR, instruction alignment, and endian behavior.
- [ ] Cover VFP s/d/q overlap and hard-float versus soft-float ABI selection.
- [x] Add a real `-marm` A32 fixture lane; Thumb-only ARM coverage is inadequate.
  `tools/arch_roundtrip.py` lists `armv7_a32` in `REQUIRED_ARCHES` and
  `tests/decompiler_fixtures/arch_baseline.json` carries 350 ratcheted
  `armv7_a32` lanes.
- [ ] Verify ARM32 frame promotion, stack aggregate extents, and argument homes
  through the shared coordinate model.
- [ ] Treat unsupported architecture/ABI combinations as typed incompleteness,
  not a silent fallback to x86/AArch64 assumptions.

### EPIC 5 — Sound definedness and reaching definitions

**Goal:** make verified MIR the single answer to “what value reaches this use?”
for registers and memory.

Minimum query surface:

```text
definition(value)
uses(value)
dominates(definition, use)
value_at(storage, point)
all_paths_defined(value, point)
clobbers_between(value, from, to)
memory_version(region, point)
```

- [x] Add stable MIR values, definitions, uses, phis, and dominance verification.
- [x] Add all-paths-defined fixed-point queries that preserve valid loop cycles
  and fail closed through poisoned dependencies.
- [x] Add conservative region-aware MemorySSA with explicit call/unknown clobbers.
- [x] Verify memory ownership, region consistency, phi predecessors, effects,
  backreferences, and dominance independently.
- [ ] Complete `value_at`, reaching-set, and `clobbers_between` queries needed by
  production consumers.
- [ ] Add transactional graph editing and precise analysis invalidation.
- [ ] Port call argument recovery, copy propagation, DCE, stack promotion,
  return recovery, expression reconstruction, and aggregate recovery to oracle
  proofs.
- [ ] Delete local backward scans and AST reaching-definition approximations as
  each consumer reaches parity.
- [ ] Cover diamonds, loops, irreducible flow, conditional definitions,
  exceptions, multi-output intrinsics, undef/poison, calls, and memory aliases in
  verifier and property tests.

## Cross-cutting decompiler workstreams

### Function contracts and indirect calls

- [x] Recover several direct, address-taken, format-sink, callback, and library
  contracts from reusable evidence.
- [ ] Recover function-pointer-table entry contracts before liveness/DCE.
- [ ] Preserve ABI may-use argument registers for proven indirect-table calls in
  the safe over-approximation direction.
- [ ] Reconstruct actual reaching values at the call site, not architectural
  register names that may now denote different caller arguments.
- [ ] Re-test the `dispatch_operation` table-call fixture and the full corpus.
- [r] Do not restore the reverted late table-layout patch: it emitted plausible,
  well-typed, but wrong arguments.

### Complete CFG and semantic structuring

- [ ] Carry unresolved transfers, skipped bytes, clipped blocks, budgets, and
  edge completeness through every artifact.
- [ ] Represent direct, conditional, switch, indirect, exceptional, call,
  return, tail-call, and unknown terminal edges explicitly.
- [ ] Build graph-complete region recovery with total edge accounting.
- [ ] Preserve irreducible and unresolved flow with explicit goto/indirect
  fallback rather than inventing structure.
- [ ] Separate dominance/loop discovery, region selection, verification, and HIR
  projection from the current large structuring owner.
- [ ] Diagnose the 43 historically AArch64-only DecBench failures by first wrong
  semantic stage, not verdict alone.
- [ ] Attack large O2-noinline GED failures directly after CFG completeness and
  definition ownership are trustworthy.

Measured cautions:

- [r] Do not restore always-hoist loop recovery. It recovered substantial GED
  but produced wrong answers in four functions across six cells.
- [r] Do not restore goto sinking merely to reduce goto count. It removed 11%
  of gotos but regressed `statemachine:gcc:O0` GED from 10 to 35 and lost five
  ByteMatch cells.
- [ ] Define a readability metric before trading source-like structure or
  execution safety for lower goto density.
- [ ] Add a linked-structure argument kind to the differential harness before
  changing the nearly dormant sentinel-list recovery pass.
- [ ] Keep pass-fire instrumentation and either add standing real coverage for
  extremely rare transforms or retire them deliberately.

### Semantic HIR and pure rendering

- [ ] Complete semantic HIR with stable variables, object paths, calls, casts,
  predicates, regions, and preserved CFG provenance.
- [ ] Generate or centralize one visitor/rewriter surface.
- [ ] Move copy-chain folding and every semantic renderer rewrite into named,
  verified pre-render passes.
- [ ] Verify def-before-use after the final semantic transform, before rendering.
- [ ] Make faithful, C, and DecBench output profiles pure projections of the same
  verified HIR.
- [ ] Remove renderer thread-local type/name state and renderer-time fixed points.
- [ ] Require deterministic pipeline fingerprints for every entry point/profile.

## Code quality, composition, and file-size program

### Ownership map

```text
src/program/       image, session, artifacts, environment, provenance, stores
src/target/        target identity, register banks, ABI and effect contracts
src/lift/          shared lift context/builders plus ISA instruction families
src/ir/lifted/     exact machine effects and verifier
src/ir/mir/        values, memory, graph editor, analyses and verifier
src/ir/hir/        semantic source model, builder, visitors and verifier
src/analysis/      dataflow, calls, types, objects, references and structure
src/render/        faithful, C and DecBench formatting-only projections
src/decompile/     pipeline, profiles, orchestration and result boundary
```

Priority splits, performed only as ownership migrates:

- `ast.rs`: HIR model, projection, visitors, verifier, declaration planning,
  cleanup, and renderers.
- `lift_x86.rs`, `lift_arm32.rs`, `lift_arm64.rs`: shared builder plus
  instruction-family modules.
- `call_args.rs`: ABI classification, evidence, solver, and HIR projection.
- `types_recover.rs`: constraints, collection, solving, prototypes, and language
  spelling.
- `stack_locals.rs`: frame analysis, object construction, access recovery,
  promotion, and naming.
- `structure.rs`: graph algorithms, regions, selection, verification, and HIR.
- `python_bindings/ir.rs`: thin adapters over session, engine, and typed results.

End-state fitness targets:

| Measure | Target |
|---|---:|
| Product-code mean | below 450 LOC |
| Product-code median | below 250 LOC |
| Product files above 1,000 LOC | at most 35 |
| Product files above 2,000 LOC | at most 5 |
| Product LOC in files above 1,000 | below 25% |
| `src/ir` median | below 500 LOC |
| `src/ir` files above 1,000 LOC | at most 5 |

- [ ] Add a reporting and ratchet check for these measurements.
- [ ] Reject new production modules over 1,000 LOC without a documented review.
- [ ] Exempt generated tables/data only; mixed-responsibility logic is not an
  exemption.
- [ ] Add dependency checks: renderers cannot import lifters, HIR cannot parse
  images, targets cannot import renderers, and correctness cannot depend on
  environment variables.
- [ ] Delete compatibility owners promptly after their consumers reach parity.

## Performance plan

Improve performance through avoided work first, then profile-led local tuning.

- [~] Parse object and debug data once per session; continue removing remaining
  independent parsers.
- [ ] Cache artifacts by image revision/hash, target, function, pipeline version,
  configuration, and exact dependency revisions.
- [ ] Analyze call-graph SCCs to fixed point instead of repeatedly relifting
  callees from each root.
- [ ] Use immutable environment snapshots for function-parallel work and
  deterministic phase-barrier merges.
- [ ] Replace whole-HIR clones used for fixed points with change sets/epochs.
- [ ] Make expensive type/object/reference passes demand-driven and cacheable.
- [ ] Record per-pass time, allocations, graph sizes, iterations, cache hits, and
  invalidations.
- [ ] Enforce per-function and per-session budgets plus cooperative cancellation.
- [ ] Profile before changing arenas, layouts, allocation, or parallel granularity.

Performance acceptance on the pinned host:

| Measure | End target |
|---|---:|
| 224-binary wall, 12 workers | below 45 s |
| Per-binary median | below 2.0 s |
| p95 | below 4.0 s |
| Slowest bounded case | below 15 s |
| Base object parses/session | exactly one |
| Warm identical-function query | at least 5x faster |

Coverage, completeness, errors, and tail latency must accompany every speed
claim. Timing out more work is not an optimization.

## Safety and reliability plan

- [ ] Replace semantically ambiguous `Option` results with typed errors or
  partial artifacts carrying exact reasons and affected ranges.
- [ ] Attach address, instruction, operand, and source origin to every lifted
  instruction and value.
- [ ] Preserve skipped bytes and unresolved CFG edges to API diagnostics.
- [ ] Validate target/mode/ABI combinations before lifting.
- [ ] Require declared register and memory effects for every call/intrinsic.
- [ ] Verify every IR boundary and every graph-changing pass.
- [ ] Keep manual/debug facts immutable by default; inference cannot overwrite
  them.
- [ ] Fuzz decoders, register contracts, lifters, importers, reference resolution,
  MIR editors/verifiers, project input, and persistence schemas.
- [ ] Add crash recovery and schema migration tests for persisted projects.
- [ ] Make cancellation prompt and return a typed partial artifact.

## DecBench and evaluation roadmap

Benchmark work exists to measure product quality. It must not become a second
product architecture or a source of target-specific patches.

### Benchmark correctness and reproducibility

- [x] Merge the verified additive orphan branch and preserve its real ARM fixes.
- [x] Audit and retire stale branches/worktrees, documenting the one stack-bias
  idea that requires a clean re-port.
- [x] Rebuild a local DecBench tree with preprocessed sources so GED and
  TypeMatch can be evaluated rather than asserted.
- [x] Submit the clear empty-disassembly ByteMatch correctness fix as DecBench
  PR #61.
- [x] Submit the reproducibility/efficiency follow-up as DecBench PR #62; no
  further work is planned unless upstream requests it.
- [x] Pin PR #56's deterministic Glaurung backend to the exact evaluated commit
  and publish the fresh artifact.
- [ ] Obtain a fresh official/current-evaluator score for the exact `fb4ee6b`
  artifact; do not infer it from the preceding package.
- [ ] Keep raw outputs, package hashes, evaluator revision, metric schema,
  compiler versions, target triples, and exact function joins in every ledger.
- [ ] Keep public publication separate from local evaluation and require explicit
  authorization for result/site changes.

### Metric attack order

1. TypeMatch and GED are the direct quality workstreams.
2. Function contracts and stable source types have the best near-term TypeMatch
   leverage.
3. CFG completeness, value ownership, and region recovery address GED without
   unsafe text shaping.
4. Aggregate/object recovery can improve TypeMatch and ByteMatch together.
5. Architecture fixes must be justified by execution/semantic evidence even when
   they also improve metrics.
6. Textual normalization comes last.

Open benchmark investigations:

- [ ] Score the exact current artifact and compute union from exact row-level
  joins.
- [ ] Explain the historical `linkedlist:clang:O0` ByteMatch drop from 0.47 to
  0.10. GED was already 0.0, so “structurally closer” is not supporting evidence.
- [x] Add and evaluate the A32 `-marm` lane. 350 ratcheted `armv7_a32` lanes in
  `arch_baseline.json`.
- [x] Rebuild the x86-64 control with GCC 15 to separate compiler-shape effects
  from architecture effects. `x86_64_gcc15` is in `REQUIRED_ARCHES` with 350
  ratcheted lanes.
- [ ] Diagnose the 43 AArch64-only failures at the first wrong stage.
- [ ] Preserve the ILP32-versus-ARM distinction, missing-lane caveat,
  control-compiler caveat, and metric-soundness findings in the canonical
  evidence register.
- [ ] Continue TypeMatch work from owner-grouped defects; do not patch function
  names or expected signatures.
- [ ] Prioritize large O2-noinline GED cases after control/data-flow correctness.

### Score-campaign acceptance policy

Every candidate must:

1. reproduce on a real binary and name the first wrong semantic stage;
2. add a failing test before implementation;
3. advance the intended owner rather than create a duplicate heuristic path;
4. include near-miss controls and execution/definedness evidence where relevant;
5. rerun affected cells plus all current perfect/canary cells;
6. report coverage, mean, median, perfect count, union, and regressions;
7. compare exact function identities, not adjusted aggregate arithmetic;
8. use fresh no-cache evaluation where cache identity is in doubt; and
9. delete superseded workaround code when the foundational owner replaces it.

## Dependency-ordered execution phases

### Phase 0 — Evidence and attribution

**Outcome:** a change cannot hide behind stale caches, denominators, toolchains,
or aggregate scores.

- [x] Deterministic score ledger and exact function-key joins.
- [x] Stable metric/canary sets and output-health counters.
- [x] Pass-attributed output traces and pass-fire instrumentation.
- [x] Cold/warm/resource and pipeline baselines.
- [ ] Refresh the canonical ledger for each exact release artifact.
- [ ] Add the A32 and GCC 15 control lanes.
- [ ] Close the linked-list ByteMatch investigation and AArch64-only diagnosis.

### Phase 1 — One session, image, pipeline, and artifact boundary

**Outcome:** remove repeated parsing and entry-point drift while preserving
behavior.

- [x] Land `ProgramImage` and `ProgramSession` foundations.
- [x] Route public entry-point shapes through shared session data.
- [~] Continue moving debug, symbol, relocation, string, unwind, and format data
  behind the session.
- [ ] Carry typed diagnostics/completeness through discovery, lifting, recovery,
  HIR, and rendering.
- [ ] Establish one explicit pipeline stage list and deterministic fingerprint.
- [ ] Prove exactly one base object parse per reusable session.
- [ ] Expose stable reusable Python session/result APIs.

### Phase 2 — Canonical target and exact lifted semantics

**Outcome:** widths, register views, ABI, effects, and target mode have one owner.

- [~] Finish canonical `TargetSpec` and migrate all consumers.
- [ ] Finish exact-width constants and operand provenance.
- [ ] Complete shared register banks and generated view/write conformance tests.
- [ ] Complete ARM32 A32/Thumb/PC/condition/VFP/ABI semantics.
- [ ] Widen the entry-stack coordinate model to ARM32.
- [ ] Add the real A32 lane and differential execution coverage.

### Phase 3 — Verified MIR and definedness authority

**Outcome:** every definition-sensitive transform asks one verified service.

- [x] Land typed MIR identities and baseline verifier.
- [x] Land region-aware MemorySSA and object identities.
- [ ] Complete value-at, clobber, reaching-set, and mutation APIs.
- [ ] Model complete call/intrinsic effects.
- [ ] Migrate high-risk consumers in order: call arguments, copy propagation,
  DCE, stack promotion, return recovery, expression reconstruction, aggregates.
- [ ] Delete migrated local approximations.

### Phase 4 — Function contracts and graph completeness

**Outcome:** values survive calls correctly and the structurer accounts for all
machine control flow.

- [ ] Implement stable `FunctionFacts`/`CallFactStore` and SCC propagation.
- [ ] Repair indirect-table call arity before DCE using reaching values.
- [ ] Complete terminal/indirect/switch/exception edge representation.
- [ ] Verify total region ownership and edge accounting.
- [ ] Attack large-function GED and AArch64-only failures from the first wrong
  stage.

### Phase 5 — Canonical program environment and references

**Outcome:** program-wide names, types, objects, calls, and operand meanings share
identity and provenance.

- [~] Finish and commit the session-owned DWARF `TypeStore` producer.
- [ ] Implement `SymbolStore`, PDB import, call facts, and analyst persistence.
- [ ] Add contextual operand reference interpretations.
- [ ] Migrate symbols, strings, globals, enums, function tables, RTTI, and vtables.
- [ ] Integrate bounded name-based library knowledge through evidence policy.
- [ ] Delete legacy maps and scattered recognizers after parity.

### Phase 6 — Aggregate recovery

**Outcome:** verified memory accesses become source-level objects and layouts.

- [x] Land the common object/access model and MIR identities.
- [ ] Port the safe affine-index slice with real end-to-end coverage.
- [ ] Migrate the first production aggregate consumer from AST to MIR.
- [ ] Solve arrays, structs, unions, bitfields, extents, and pointees.
- [ ] Implement aggregate ABI transfers and real execution fixtures.
- [ ] Project solved access paths to semantic HIR.

### Phase 7 — Semantic HIR, pure rendering, and physical decomposition

**Outcome:** semantic ownership becomes visible in APIs and file structure.

- [ ] Finish HIR and shared visitors/rewriters.
- [ ] Move all semantic renderer behavior into declared verified passes.
- [ ] Make all output profiles pure and deterministic.
- [ ] Split large owners only along migrated responsibility boundaries.
- [ ] Add dependency and file-size ratchets.
- [ ] Remove compatibility layers as parity is proven.

### Phase 8 — Persistence, deterministic parallelism, and hardening

**Outcome:** stable boundaries produce faster, safer long-running analysis.

- [ ] Persist versioned environment and artifacts with dependency fingerprints.
- [ ] Add deterministic function-parallel scheduling and SCC phase barriers.
- [ ] Add incremental invalidation for analyst edits, new facts, and pass changes.
- [ ] Replace global rescans/clones with indices and change epochs.
- [ ] Add cancellation, resource budgets, fuzzing, crash recovery, and schema
  migration coverage.
- [ ] Meet the performance targets without correctness or coverage regression.

## Immediate rank-ordered plan

This is the practical next-work queue as of the planning baseline.

1. Finish the current session-owned DWARF/`TypeStore` slice: make the existing
   RED alignment expectation pass conservatively, run focused Rust tests, then
   full Rust/Python/lint/type gates before commit.
2. Migrate one real aggregate/type consumer from the AST compatibility adapter
   to verified MIR object, memory, and type evidence. Use a real stripped and a
   real debug fixture plus a conflict/near-miss control.
3. Complete the MIR queries that consumer needs (`value_at`, clobbers, reaching
   sets) instead of adding local scans.
4. Extend the dual current-SP/CFA entry-stack coordinate model to ARM32 and prove
   it in both Thumb and A32 modes.
5. Add the `-marm` A32 fixture lane and rebuild the x86-64 GCC 15 control.
6. Implement indirect function-table call may-uses/contracts before DCE and
   reconstruct actual reaching call arguments.
7. Build the canonical `SymbolStore` and contextual operand-reference index;
   migrate exact symbols/relocations first, then bounded library-name knowledge.
8. Investigate the linked-list ByteMatch regression and the 43 AArch64-only
   failures with pass-attributed traces.
9. Finish CFG completeness and verified region ownership, then target the large
   O2-noinline GED cohort.
10. Complete aggregate constraints and ABI handling, then project them to HIR.
11. Finish semantic HIR and pure renderers, splitting the large legacy owners as
    each responsibility migrates.
12. Add dependency-aware persistence, deterministic parallelism, cancellation,
    fuzzing, and profile-led optimization.

## Required validation

Every implementation increment follows RED -> GREEN -> REFACTOR -> VERIFY with a
real compiled fixture and at least one negative control.

Focused evidence by change type:

| Change | Minimum evidence |
|---|---|
| Target/register | generated view contracts, lifter/executor differential, real A32 and Thumb binaries |
| MIR/definitions | verifier/property tests, diamonds, loops, calls, memory and corruption controls |
| Call/type | optimized real caller/callee, variadic/sret/width negatives |
| CFG/structure | edge accounting, execution, irreducible/switch/large fixtures |
| Reference | relocation and same-bits/different-context controls |
| Aggregate | debug/no-debug, array/struct/union/bitfield, ABI execution |
| Cache/parallel | cold/warm and serial/parallel deterministic differential |

Broad gate before closing a phase:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
uv run pytest python/tests/
uvx ruff format --check python/
uvx ruff check python/
uvx ty check python/
scripts/decbench-local-gate.sh
```

Also run the 250-function external-eval replay, architecture roundtrip matrix,
perfect/canary cells, output-health report, and performance matrix when relevant.
Report focused tests, full local gates, remote CI, score, behavior, and performance
separately. A running, skipped, environment-missing, or unrelated-red gate is not
green.

## Stop conditions

Stop the affected change and repair the foundation when:

- a transform cannot prove definition, dominance, effect, alias, or edge
  preconditions;
- incomplete input becomes apparently complete downstream;
- an unknown call/intrinsic is treated as preserving unproven state;
- ARM32 needs a second incompatible semantic or ABI path;
- inference overwrites manual, relocation, or authoritative debug facts;
- a mapped integer becomes a pointer without contextual evidence;
- a metric gain breaks execution, verification, a perfect cell, or a semantic
  canary;
- a file split leaves the same responsibilities coupled by private mutation;
- a cache entry cannot name exact dependencies and revisions;
- serial and parallel output differ; or
- performance improves by reducing coverage or silently timing out work.

## Definition of done

The redesign is complete when Glaurung has:

- one reusable session, image, pipeline, and typed artifact boundary;
- one validated target/machine/ABI model with full ARM32 conformance;
- one verified register and memory definition graph used by production passes;
- one provenance-bearing program environment for symbols, types, objects,
  references, and call facts;
- contextual operand symbolization over exact machine values;
- aggregate recovery over stable memory objects and ABI-aware layouts;
- total verified CFG-to-HIR projection with honest fallbacks;
- pure output profiles;
- substantially smaller, single-owner modules meeting the fitness targets;
- deterministic incremental and parallel analysis;
- prompt cancellation, typed partial results, persistence safety, and fuzzed
  boundaries; and
- green execution, verifier, fixture, score, architecture, performance, and
  reliability gates on exact reproducible revisions.

Until then, each completed phase must remain independently usable, tested, and
releasable.

## Evidence and decision records

This roadmap supersedes the ordering in the older plans but not their evidence:

- [Architecture redesign](glaurung-architecture-redesign-2026-08-05.md)
- [Architecture review diary](glaurung-architecture-review-diary-2026-08-05.md)
- [DecBench remediation roadmap](decbench-remediation-roadmap-2026-08-08.md)
- [DecBench gap-analysis diary](decbench-gap-analysis-diary-2026-08-08.md)
- [Decompiler middle architecture](decompiler-middle-architecture.md)
- [Value-model root cause and plan](value-model-root-cause-and-plan.md)
- [Register views and verifier boundary](register-views-and-the-verifier-boundary.md)
- [Semantic structuring](semantics-preserving-structuring.md)
- [Typed SSA and HIR](typed-ssa-hlir.md)
- [ARMv7 real defects](armv7-real-defects-2026-08-05.md)
- [Table-dispatch arguments](table-dispatch-arguments-2026-08-12.md)
- [Stack-bias affine-index record](stack-bias-affine-index-2026-08-13.md)
- [Dormant transform measurements](dormant-transforms-2026-08-12.md)
- [Goto-density measurement](goto-density-measurement-2026-08-12.md)
- [Measured GED trade](ged-recovery-measured-trade.md)
- [Master integration record](master-integration-2026-08-12.md)
- [Branch retirement manifest](branch-retirement-2026-08-13.md)
- [DecBench submission readiness](decbench-submission-readiness.md)

