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
- **All three submitted DecBench PRs are now MERGED upstream** into
  `Noelo-Lab/decbench` (verified 2026-08-14 via `gh pr view`):

  | PR | title | merge commit |
  |---|---|---|
  | #56 | Add Glaurung deterministic decompiler backend | `08f891581e6b` |
  | #61 | fix(metrics): honor ARM function encoding in byte_match | `af02672db6dd` |
  | #62 | build(corpus): make persistent rebuild reproducible | `3db5d557a6ae` |

  This supersedes the earlier "PR #56 is open and merge-clean at branch commit
  `f4fbd607`" state. Glaurung is now an upstream backend rather than a pending
  submission, which changes what "obtain a fresh official score" requires.
- No public result or leaderboard update is implied by the artifact or the
  merges. Merging a backend is not a published score, and publication still
  requires explicit authorization.
- The current package differs from the preceding `60271f2` package in one
  generated C file, so its score must be evaluated rather than copied forward.

### Local product state ahead of the planning baseline

Committed to `master` after `fb4ee6b` (see
[the 2026-08-13 execution diary](decompiler-roadmap-diary-2026-08-13.md)):

- `4549aee` DWARF type import retains conflicting cross-unit layouts instead of
  a first-wins dedup that destroyed them, and stops inventing alignment.
- `c4a6c9d` the local gate runs the fixture lanes by default; DecBench and Joern
  are opt-in behind `--decbench`.
- `558a012` the CLI loads only the invoked subcommand, cutting ~2.9 s of
  `pydantic_ai` import off every `glaurung decompile`.
- `4caa607` function lowering runs on its own 256 MB stack. A 442-deep region
  ladder from a 256-case switch built by gcc 15 for aarch64 overflowed the
  default stack and killed the process with a silent SIGSEGV, which had made
  `arch_roundtrip.py --write-baseline` unrunnable on this host for any change.
- `8f661ff`/`d3578ad` fixture `187_constant_bias_index` plus its three
  regenerated baselines, closing the roadmap's required constant-bias lane.
- `561e08f` fixture parallelism stays at the harness default; raising it
  recorded a fake regression in a baseline.

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
- [~] `ProgramSession` is not yet the sole owner of every parse and cache.
  Substantially closed 2026-08-15: object parses per session went from
  `O(functions + branches + callees)` — 58 on a small C binary, 40,865 on
  `hello-rust-musl` at the default limit, and varying run to run on the SAME
  binary — to a constant 19. `ProgramImage` now indexes PLT stub ranges in its
  existing single parse and lazily owns `noreturn_import_targets`,
  `exception_call_sites` and `dwarf_functions`. The residue is 19 distinct
  one-shot analyses; reaching exactly one needs a relocation/symbol index on
  `ProgramImage`. Note two production sites had been bypassing the
  `profile::parse_object` adapter entirely, so the instrument was under-reporting
  its own subject.
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
- [x] Implement a canonical `SymbolStore`: aliases, ranges, imports, exports,
  thunks, bindings, demangled names, and contextual address queries.
  **Built, and until 2026-08-15 it had ZERO production consumers** — every caller
  of `ProgramSession::symbol_store()` lived in `session_tests.rs`. It retained
  alternatives, conflicts, incompleteness and relocation sites by place the whole
  time; nothing asked. `program/references.rs` is now the first production
  consumer. "Implemented" and "connected" are different claims and this box only
  ever justified the first.
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
- [x] Add an operand/use-site `ReferenceInterpretation` with source instruction,
  exact width, provenance, alternatives, and confidence.
- [~] Resolve evidence in order: relocation/loader semantics, decoded operand
  role and PC calculation, mapped region, MIR provenance, call/type constraints,
  xref consistency, then conservative heuristics.
  **Tiers 1-3 resolved; 4-6 cannot be queried from this layer.** A resolver that
  reached MIR provenance, call/type constraints or xref consistency would have to
  live downstream of MIR construction, and `readonly_fold` calls this from
  upstream. They are accepted as validated caller input instead, and a caller
  claiming a tier the resolver owns is dropped rather than outranked. The
  implementation is also two RULES rather than a priority list — role admission
  (a relocation is admitted everywhere, anything weaker needs the role to already
  say "reference") and fail-closed supply.
- [ ] Index references once for decompilation, xrefs, call graph, readonly
  folding, function tables, and UI consumers.
- [ ] Project selected interpretations as semantic HIR operations.
- [ ] Render `symbol + addend`, strings, enum members, globals, field offsets,
  and function pointers with an exact-literal fallback.
- [ ] Migrate and delete separate name, string, readonly, and function-table
  constant recognizers.
- [x] Prove with negative controls that a mapped numeric value used in arithmetic
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
- [~] Collect exact load/store, affine-offset, repeated-stride, overlap, pointer,
  and call-boundary constraints. Load/store footprints, affine offsets and
  overlap were already carried by `MemoryObject` and its partition. Scaled-index
  addresses are now retained as `MemoryObject::indexed_accesses` instead of
  being discarded at the point of refusal — the refusal itself is unchanged.
  Pointer and call-boundary constraints are still only refusals
  (`EscapedRoot`), not facts.
- [~] Classify struct versus array versus union versus bitfield conservatively.
  `src/ir/memory_objects/shape.rs`, reached through
  `MirFunction::object_shapes`. **Two of those four are not decidable from
  access evidence and the module says so rather than guessing.** Arrays are
  claimed only from a scaled-index address, which is the one signal no
  aggregate spelling imitates; their element COUNT is never claimed. Struct
  versus array is not claimed at all — `int32_t[4]`, a four-field homogeneous
  struct, and four packed locals are the same bytes and the same instructions,
  so the model reports the proven cells and declines the noun. Union versus
  punned struct is refused with a measured justification: a real union, a real
  byte array read through a wider load, and a real bitfield container all
  produce the identical verdict on real fixtures (diary entry 38). Bitfields
  carry no evidence here at all, because their field edges live in value
  arithmetic and never appear as a memory footprint. The ignored `shape_census`
  test measures the whole corpus: 40 arrays recovered across 32 of the 173 C
  fixtures, 910 cell decompositions, 14 overlapping cells, and zero index
  refusals. Diagnostic only; no production consumer, per the `[~]` item above.
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
- [x] Widen the dual current-SP/CFA entry-stack coordinate machinery from its
  AArch64 gate to ARM32, with real A32/Thumb controls. **The gate was not what
  this item described.** The coordinate re-expression machinery was already
  widened to ARM32 at `401ac4f`; the gate actually remaining was an
  A32-versus-Thumb split *inside* ARM32. `STACK_BASES` carried AArch64's `x29`
  and A32's `fp`, but not Thumb-2's `r7` — which GCC anchors Thumb frames on
  because 16-bit encodings cannot reach high registers — and the
  `is_arm_frame_pointer` guard that already listed `"r7"` was nested inside the
  `is_active_stack_base` branch, so that arm was unreachable. Thumb frames
  therefore promoted NOTHING: `07_packet_parser` recovered 1 distinct local
  against A32's 25, `163_wire_header_parser` 1 against 12. Seven of eight Thumb
  lanes now match their A32 control exactly, with every A32 number unchanged.
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
- [~] `value_at`, `clobbers_between`, the reaching-definition set, and
  `memory_version` are implemented and tested in `src/ir/mir/query.rs`; the whole
  EPIC 5 minimum surface now exists. No production consumer has been migrated to
  it yet, and every call still poisons every unnamed machine storage because no
  target-owned clobber contract exists (EPIC 4). See diary entry 10.
- [ ] Add transactional graph editing and precise analysis invalidation.
- [ ] Port call argument recovery, copy propagation, DCE, stack promotion,
  return recovery, expression reconstruction, and aggregate recovery to oracle
  proofs.
- [ ] Delete local backward scans and AST reaching-definition approximations as
  each consumer reaches parity.
- [~] Diamonds, loops, irreducible flow, conditional definitions, multi-output
  intrinsics, undef/poison, calls, and memory aliases are covered by
  `src/ir/mir/query_tests.rs`, including a real x86-64/ARM32 property test that
  a query may refuse to answer but may never contradict the verified SSA edge.
  Exceptions are not covered: LLIR has no exceptional-edge representation yet.

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

- [~] Carry unresolved transfers, skipped bytes, clipped blocks, budgets, and
  edge completeness through every artifact.
  **Done: unresolved transfers, clipped blocks, clipped targets, edge
  completeness.** Undecodable blocks survive as an explicit `undecoded_bytes`
  intrinsic instead of vanishing (`38d6591`); terminal edges are typed and the
  unexplained ones counted (`01f0b23`). **Not carried: budgets, and skipped bytes
  on the discovery side.**
- [x] Represent direct, conditional, switch, indirect, exceptional, call,
  return, tail-call, and unknown terminal edges explicitly.
- [~] Build graph-complete region recovery with total edge accounting.
  **Measured 2026-08-15 and the successor-edge half already holds.** Census over
  60 gcc-O2 fixture objects (15576 health events; the absolute sums double-count
  because health is emitted at several pipeline points per function, but the
  zeros and the ratios do not depend on that):

      terminal_edges             24046
      unresolved_indirect_edges   2706     11% of terminals
      undefined_uses               761
      structure_fallbacks          594
      uncovered_cfg_edges            0
      invented_cfg_edges             0
      unknown_cfg_edges              0
      unknown_terminal_edges         0

  Zero uncovered and zero invented edges means the region tree already expresses
  exactly the successor graph — `structure_accounting::account` is not merely a
  diagnostic, it gates region selection through `structure_accounting_is_unsound`.
  What is NOT total is terminal ownership: there is no `Return` region node, so
  terminals are classified and counted but not owned by the tree.

  **The 2706 turned out to be ~99% mis-attribution, not unknown control flow.**
  Classified against `objdump`/`readelf` ground truth over 182 objects: 43.2%
  `crtstuff` `jmp *%rax` after a GOT load, 34.0% `.plt.got`/`.plt.sec` stubs,
  21.6% the `.plt[0]` lazy-binding header — 98.8% boilerplate whose destination a
  relocation states outright — and 1.2% real table dispatch. Resolving them from
  the relocation rather than the stored bytes took the corpus from 32838 to 351
  unresolved (23.2% to 0.25%), re-attributing every one and inventing none.

  Two things that census exposed are worth more than the number. The count is
  taken at the WRONG POINT: `cfg_health` is frozen at LLIR structure time, before
  `function_tables` runs, then re-stamped at ~39 later boundaries, so five of the
  nine residual functions already decompile perfectly — the honest floor is four,
  all fixtures written to be unresolvable. And "why the decoder declined" is
  already computed and thrown away: `analysis::dispatch::Unresolved` records
  `UnknownBase`/`NoTableAt`/`NoBound` and nothing serializes it, while ~14
  distinct decline points in `jump_table.rs` collapse to a bare `None`.

  What remains to chase here is the 594 structure fallbacks.
- [ ] Preserve irreducible and unresolved flow with explicit goto/indirect
  fallback rather than inventing structure.
- [ ] Separate dominance/loop discovery, region selection, verification, and HIR
  projection from the current large structuring owner.
- [x] Diagnose the 43 historically AArch64-only DecBench failures by first wrong
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
- [~] Move copy-chain folding and every semantic renderer rewrite into named,
  verified pre-render passes. Copy-chain folding was already out. 17 anonymous
  passes between `prepare_for_decbench` and `ready_to_render` now have names,
  which matters because `pass_health_report.py` blames the FIRST pass at which a
  counter moves — every new undefined read in that tail was being attributed to
  `ready_to_render`, the boundary that observes the damage rather than the pass
  that caused it. Still at render time, with blockers named:
  `renderable_dwarf_structs` (no blocker), `recover_named_call_prototypes`,
  `infer_return_ctype` (runs both pre-render AND in the renderer), and the
  `DEC_DECLARED_CTYPES` keystone — which is NOT circular, so the declaration plan
  is extractable. `DEC_SEMANTIC_WIDE_CAST` is genuinely unmovable and wants a
  parameter, not a pass.
- [x] Verify def-before-use after the final semantic transform, before rendering.
  The check already RAN at that boundary — `decbench_text` called
  `verify_defs::check` right after `ready_to_render` — but the answer was
  computed, found non-empty, logged at debug level and dropped. It now returns a
  `#[must_use] RenderVerification`, so discarding the proof is a compile error,
  and the verdict leaves by a channel that is not the C: stderr on every
  `glaurung decompile`, plus `take_render_verification()` programmatically. It is
  deliberately NOT a comment in the rendered output — that output is scored by an
  external benchmark, and a note announcing our own bug does not belong inside
  the code being scored.
- [ ] Make faithful, C, and DecBench output profiles pure projections of the same
  verified HIR.
- [ ] Remove renderer thread-local type/name state. (The bullet also said
  "renderer-time fixed points"; measured 2026-08-15, there are none — every
  bounded-iteration loop reachable from a DecBench render is inside
  `prepare_for_decbench` or `refine_decbench_abi_widths_with_value_widths`, both
  pre-render. The 16 `DEC_*` thread-local cells are real and remain.)
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

- [x] Add a reporting and ratchet check for these measurements. `tools/fitness_report.py`
  measures them over `src/` (test files/modules and generated tables excluded) and
  prints each current value against its target; `tools/fitness_baseline.json` is
  the committed baseline and `python/tests/test_fitness_report.py` fails the
  suite if a fresh measurement is worse than that baseline. The targets
  themselves are not met yet (see Entry 19 in the diary for current numbers) --
  this box is only the measurement and ratchet infrastructure, not the fitness.
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
- [~] Make expensive type/object/reference passes demand-driven and cacheable.
  `DecompilerSession` already caches artifacts and discovery per image, and the
  warm-query row is met through it (3081x on `hello-gcc-O2`, 271180x on
  `hello-rust-musl`). What is NOT demand-driven is the cold path itself.
- [~] Record per-pass time, allocations, graph sizes, iterations, cache hits, and
  invalidations.
  **Per-pass time is recorded** (`GLAURUNG_PIPELINE_PROFILE`) and was used for the
  first time on 2026-08-15. Allocations, graph sizes, iterations, cache hits and
  invalidations are not. Caution recorded with the measurement: instrumented
  stages account for only ~100 ms of a 285 ms run, so the timings are not yet
  complete enough to choose optimisation targets from.
- [ ] Enforce per-function and per-session budgets plus cooperative cancellation.
- [x] Profile before changing arenas, layouts, allocation, or parallel granularity.

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

**Measured for the first time, 2026-08-15.** Over the 138 real binaries in
`samples/binaries` (of 400 files attempted; the other 262 are not object files
and fail with `Unknown file magic`), via `g.ir.decompile_all(..., limit=250)`:

| Measure | Target | Measured | |
|---|---:|---:|---|
| Per-binary median | below 2.0 s | **0.022 s** | met |
| p95 | below 4.0 s | **2.15 s** | met |
| Slowest bounded case | below 15 s | **5.19 s** (`hello-go-static`) | met |
| 224-binary wall, 12 workers | below 45 s | 41.7 s for 138, **sequential** | met |
| Base object parses/session | exactly one | 58 -> **19** | closer; see below |
| Warm identical-function query | at least 5x | **3081x** | met |

Restricted to the 50 binaries with 50 or more functions, the median is 0.192 s,
p95 2.65 s, and the median cost is 1.67 ms per function.

So speed is not the problem, and optimising it would be work aimed at targets
already met.

The warm-query row must be measured through `DecompilerSession` — "reusable
decompiler state for repeated queries against one immutable image" — which is
the API the row is about. Measuring repeated `decompile_many` calls instead
rebuilds the session every time and reports 1.98x, which is the cost of NOT
having a cache rather than the benefit of having one. Through the session it is a
straight cache hit: 2.524 ms cold to 0.001 ms warm on `hello-gcc-O2`, and 163 ms
to 0.001 ms on `hello-rust-musl`.

The remaining gap is architectural, and it is the one this section's own plan
predicts. `object_parse_count` was **58** for 49 functions on `hello-gcc-O2`, and
**40,865** for `hello-rust-musl` at the default limit — the count scaled as
`O(functions) + O(branches) + O(callees)` and varied run to run on the same
binary. It is now **19 and constant**, the same 19 for both binaries at any
limit. The residue is 19 distinct one-shot analyses; reaching exactly one needs a
relocation/symbol index on `ProgramImage`.

Worth recording for the next person who optimises here: re-parsing was NOT worth
the time it appeared to be. An ELF `File::parse` reads a header and a section
table, about 12 us, so removing 40,848 parses from the `hello-rust-musl` run
moved wall time not at all. The gap between instrumented stages (~100 ms) and the
285 ms run is still unexplained, and it is not this.

The accounting also does not close: instrumented stages sum to roughly 100 ms of
that 285 ms run, so most of the wall time is outside any named stage. Until that
gap is explained, per-stage timings should not be used to choose what to
optimise.

## Safety and reliability plan

- [~] Replace semantically ambiguous `Option` results with typed errors or
  partial artifacts carrying exact reasons and affected ranges. **The lifter
  boundary is done** (entry 35): `lift_function_from_bytes`/`_from_image` return
  `Result<LlirFunction, LiftError>` with three distinguishable reasons, and
  `LiftError::NoLiftableBlocks` carries the exact disowned VA ranges. Two
  analyst-visible Python messages that guessed at the reason were replaced with
  the real one. Other ambiguous `Option`s remain; the ranking is in entry 35.
- [ ] Attach address, instruction, operand, and source origin to every lifted
  instruction and value.
- [ ] Preserve skipped bytes and unresolved CFG edges to API diagnostics.
- [x] Validate target/mode/ABI combinations before lifting. `validate_code_mode`
  and `validate_target_mode` resolve one `CodeMode` before any byte is decoded,
  and `lift_window` now matches on that mode exhaustively instead of on
  `(arch, thumb)` with a silent `_ => Vec::new()` arm. A Thumb marker on a
  non-ARM target is a typed rejection naming the function (entry 35).
- [~] Require declared register and memory effects for every call/intrinsic.
  Censused, not asserted (entry 35): `ir::effect_census` measures the corpus, the
  last `Op::Unknown` escape into a public API is closed, and two invariant tests
  hold the line. `Op::Unknown` still exists as the per-arch lifters' internal
  marker, deliberately — entry 35 records why it cannot be deleted yet.
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
  PR #61. **Merged upstream** as `af02672db6dd`.
- [x] Submit the reproducibility/efficiency follow-up as DecBench PR #62; no
  further work is planned unless upstream requests it. **Merged upstream** as
  `3db5d557a6ae`.
- [x] Pin PR #56's deterministic Glaurung backend to the exact evaluated commit
  and publish the fresh artifact. **Merged upstream** as `08f891581e6b`, so the
  backend is now part of DecBench rather than a pending submission.
- [ ] Obtain a fresh official/current-evaluator score for the exact `fb4ee6b`
  artifact; do not infer it from the preceding package. Now that #56 is merged
  this is a question of running the current upstream evaluator against the
  pinned image, not of getting a backend accepted. Note the artifact pins
  `fb4ee6ba`, and `master` has since moved past it, so decide deliberately
  whether the next score should describe the pinned commit or a fresh package.
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
- [~] Value-at, clobber, reaching-set, and memory-version queries are complete;
  the transactional mutation/invalidation API is still open.
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
- [~] Verify total region ownership and edge accounting. Successor-edge
  accounting is verified and enforced (0 uncovered, 0 invented across the
  measured corpus); terminal ownership is not, because the region algebra has no
  `Return` node.
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
2. **[UNBLOCKED — the prerequisite landed; the note below is kept for the
   reasoning, but its "see below" ordering claim is now history]** Migrate one
   real aggregate/type consumer from the AST compatibility adapter to verified
   MIR object, memory, and type evidence. Use a real stripped and a real debug
   fixture plus a conflict/near-miss control.

   The frame partition landed in `a45c1ae` and the join was completed in the
   `MergedPointer`/`base_offsets` work: on real gcc `-O0` `ua162_store_be32`,
   MIR — which never saw a promoted local — bounds all seven `frame_coordinates`
   entries at exactly their source widths, and both base spellings agree.

   **The roadmap names the wrong consumer.** `high_variables::refine_object_cursor_values`
   asks `has_conflict_free_extent`, which is a STRIDE question, not an extent
   question; its MIR analogue needs no partition at all, and the partition
   explicitly REFUSES stride-walked objects via `UnboundedCursor`. What actually
   blocks a migration is a name-to-value correspondence across pipeline stages:
   the AST adapter receives a frame that `stack_locals` has ALREADY SPLIT — a
   store to a promoted local is a definition there, not an access — so the AST
   model contains no frame object to migrate. Pick a different consumer, or
   state the correspondence first.

   The two models **partition memory differently**, so there is no join to
   write. `src/ir/memory_objects/mir.rs` keys every stack access by
   `ObjectIdentity::MirValue(root)` where `root` is the SP/FP `Input` value, and
   folds the displacement into each access's `offset` — one object per ROOT
   POINTER. Verified on a real two-array function: a single stack object
   carrying offsets -8, -16, -28, -40, -44, -56, -60, -76. The AST adapter
   instead builds one object per PROMOTED LOCAL, which is what
   `high_variables::refine_object_cursor_values` asks about.

   Migrating any aggregate consumer therefore requires first partitioning the
   MIR frame object into per-variable extents — which is item 10. **Item 10 is a
   prerequisite of item 2, not a follow-on.** Prerequisites already landed:
   `StackLocalFacts.frame_coordinates` (`d1ffbec`), MIR reachable outside the
   debug dump (`5ab8e7d`), and the EPIC 5 query surface (`a2fcd6f`).
3. Complete the MIR queries that consumer needs (`value_at`, clobbers, reaching
   sets) instead of adding local scans.
4. **[done]** Extend the dual current-SP/CFA entry-stack coordinate model to
   ARM32 and prove it in both Thumb and A32 modes. Thumb-2's `r7` anchor was the
   missing piece; Thumb had been promoting no frame storage at all. Still open in
   EPIC 4: VFP s/d/q overlap, hard/soft-float ABI selection, PC bias, literal
   pools, condition execution. Also unfixed: `153_many_live_locals` on Thumb
   reuses `r3` as both an address cursor and a constant register, which the
   register-keyed alias map cannot represent — that needs value numbering on
   that path, not a wider coordinate model.
5. Add the `-marm` A32 fixture lane and rebuild the x86-64 GCC 15 control.
6. **[done]** Implement indirect function-table call may-uses/contracts before
   DCE and reconstruct actual reaching call arguments.

   Both halves landed. The DIRECT half (`f72851e`) taught argument recovery to
   see past returning branch arms, answer live-in spellings from the enclosing
   scope, and prove entry-constant slots across a labelled join; it repaired six
   cells, four of them in fixtures unrelated to the one that found it.

   The INDIRECT half (`191_indirect_table_args`) rests on the observation that a
   call through a RELOCATION-PROVEN table has no single callee but a complete,
   proven callee SET, so the may-use set is the union over its entries. Union is
   the safe direction; refusing is the silent-wrong-code one.

   In both halves DCE turned out NOT to be the first wrong stage. The setup is
   alive after `reconstruct_args`, `eliminate_dead_stores` and `apply_role_names`,
   and is removed by `copy_prop::remove_dead` BECAUSE the call carries no
   arguments — consequence, not cause. The sharp form: a may-use set that is not
   MATERIALISED AS ARGUMENTS is cosmetic, since at the C boundary the recompiled
   indirect call passes nothing either way.

   Still open, and worse than what this item fixed: `lift_x86` lifts
   `call *(%rcx,%rax,8)` to `call @0x0`, destroying table identity before any AST
   pass runs. That is why the `95_function_pointer_table` O2 `fold_operations`
   cells and most `191` O2 lanes still fail, and why `dispatch_operation`
   improves at all — gcc happens to emit that one as `jmp *(...)`.
7. **[done]** Build the canonical `SymbolStore` and contextual
   operand-reference index; migrate exact symbols/relocations first, then bounded
   library-name knowledge. Landed in `9d4d0e0`/`16b`-era work: `src/program/symbols.rs`,
   `symbols/object_import.rs`, `symbols/verify.rs`.
8. **[restated — no DecBench required]** Investigate the linked-list correctness
   defect and the architecture-only failures with pass-attributed traces.

   This item was written against DecBench metrics, and it does not need them.
   Our own corpus answers the same questions with EXECUTION ground truth rather
   than a similarity score, which is strictly more actionable: DecBench says the
   output looks less like the original, the fixture corpus says it computes the
   wrong answer.

   Architecture-only failures, computed directly from `arch_baseline.json` as
   "passes on x86-64, fails here". Recomputed 2026-08-15 after the AArch64 scalar
   float, SysV SSE parameter, indirect-call and dual-width fixes landed and the
   corpus grew by four fixtures:

   | architecture | 2026-08-14 | 2026-08-15 | absolute failure rate |
   |---|---:|---:|---:|
   | armv7_a32 | 153 | **164** | 320/1288 = 24.8% |
   | armv7 | 144 | **159** | 312/1288 = 24.2% |
   | i386 | 102 | **116** | 280/1290 = 21.7% |
   | aarch64 | 94 | **93** | 243/1346 = 18.1% |
   | x86_64_gcc15 | 22 | **25** | 184/1346 = 13.7% |
   | x86_64 (reference) | — | — | 173/1345 = 12.9% |

   The differential grew even though the decompiler improved, because most of
   this week's fixes were x86-64-side: every cell they moved from fail to pass on
   x86-64 that is still failing elsewhere ENLARGES this column. It is a
   differential, not a defect count, and reading a rise in it as a regression
   would be a mistake. AArch64 is the one that fell, which is where the float
   lifting landed.

   Read the absolute rate alongside it: **ARM32 is the worst architecture in the
   corpus at roughly one function in four, nearly double x86-64** — on the
   architecture design rule 11 designates a conformance target, not an optional
   afterthought. A contributing measurement: ARM32 renders 6.6% of its lifted
   instructions as an OPAQUE intrinsic, all of them the single mnemonic `add`,
   against 0.18% for x86-64 and 0% for AArch64. An opaque declares a maximal
   memory footprint, so a pure register `add` modelled that way poisons dataflow
   for everything downstream.

   **i386 has no x87 lifting at all** — found 2026-08-15, and it is the same shape
   as the AArch64 scalar-float gap that `039c7d6` closed. Grepping `lift_x86.rs`
   for `fld`, `fstp`, `fadd`, `fmul`, `fdiv`, `fild`, `fistp`, `fucomi`, `faddp`
   returns ZERO for every one. i386 does all floating point on x87, so every float
   function on that lane lifts its arithmetic to nothing. Compiling
   `173_float_int_conversions.c` with `gcc -m32 -O2` gives 16 `fstp`, 12 `flds`,
   10 `fldcw`, 5 `fnstcw`, 3 `fistpl`, 2 each of `fxch`/`fldz`/`fistpll`/`fildl`,
   and the recovered C is:

       __attribute__((no_stack_protector)) int truncate_toward_zero(void) {
           long rsp;
           cf_2 = ((unsigned long)((unsigned int)(rsp)) < (unsigned long)(8));
           /* asm: fld */
           /* asm: fld */

   A function taking a float recovered as `(void)`, its arithmetic dropped to
   comments, and `rsp` read before definition. i386-only failures cluster
   accordingly: `173_float_int_conversions` 7, `175_float_matrix_kernel` 6,
   `181_compensated_summation` 5 — 18 of 116 from this one gap.

   The other i386 cluster is `193_mapped_constant_roles` at 8, the fixture added
   for EPIC 2 the day before. Its reference resolver is exercised only on x86-64;
   32-bit PIE resolves GOT-relative addresses through a different idiom, so that
   is a coverage gap in new code rather than an old one.

   The reverse differential is also worth keeping, because it shows this is not a
   one-sided deficit: 23 functions pass on aarch64 and fail on x86-64, 20 on
   armv7, 17 on armv7_a32, 14 on x86_64_gcc15, 9 on i386.

   That is 94 AArch64-only failures against the item's 43, and they cluster:
   `141_atomics` (7), `173_float_int_conversions` (6), `175_float_matrix_kernel`
   (5), `181_compensated_summation` (5) — a float and atomics cluster. Note ARM32
   is worse than AArch64 and was never the item's subject.

   **Resolved for the float cluster (`039c7d6`), and the clustering above is
   partly wrong.** Root cause: `lift_arm64.rs` had NO SCALAR FLOAT LIFTING AT
   ALL — grepping `src/ir/` for `fadd|fsub|fmul|fdiv|scvtf|fcvtz|fcmp|fneg|fsqrt`
   returned nothing outside `lift_arm32.rs` and `lift_x86.rs`. `return (float)value;`
   decompiled to `*(float*)&value`, and the first pass dump already read
   `[] = intrinsic scvtf()` with no output, no input and no footprint, so every
   later pass was faithfully processing garbage. Two ABI holes sat behind it:
   `return_registers(Aarch64)` was `["x0","w0"]` with no `v0`/`d0`/`s0`, and
   `float_argument_bank_slot` returned `None`. 12 functions fail → pass, 0
   regressions.

   The correction worth keeping: clustering by DISASSEMBLY rather than by fixture
   name shows `71_compound_interest`, `72_loan_amortization` and `64_root_finding`
   are FIXED-POINT INTEGER fixtures containing no float instruction whatsoever.
   The attributable float cluster is 20 of the 94, not the ~38 a name-based
   reading suggests; 7 more are `141_atomics`, whose cause is entirely different
   (`ldar`/`stlrb` are simply not decoded, and these are plain acquire/release
   accessors, not exclusive-monitor loops). The remaining 65 have no float
   instruction and no single identified cause. Also worth keeping: 19 functions
   PASS on aarch64 and FAIL on x86-64, so this is a genuine two-way differential,
   not a one-sided deficit.

   Remaining in the cluster, each with its blocker named rather than left as a
   count: `fcmp`/`fcmpe` 5 cells (needs a real float NZCV model), `fcvtzu`/`ucvtf`
   2 (needs an unsigned `ScalarType`), `fmadd`/`fnmsub` 3 (a rendering decision),
   `movi v31.2d,#0` in 7, and `141_atomics` 7.

   The linked-list half is already a recorded correctness defect rather than a
   metric movement: `111_self_referential_struct:link_and_sum` declares `rbp` as
   a local and never assigns it, so every address computed from it is an
   uninitialised read. A self-referential struct is the linked list.

   Pass-attributed traces are now actually obtainable; the instrumentation was
   only reconnected in `0ecb8e1`.
9. Finish CFG completeness and verified region ownership, then target the large
   O2-noinline GED cohort.
10. Complete aggregate constraints and ABI handling, then project them to HIR.
    ~~**Promote ahead of item 2**~~ — **done**: partitioning the MIR frame
    object into per-variable extents landed in `a45c1ae` with covered runs,
    `Spanned`/`Abutting` evidence, `bounds_at` bounds and typed refusals, and the
    coordinate join was completed afterwards. What remains of item 10 is the
    classification and ABI work, not the partition.

    One soundness hole found and closed along the way, worth recording because
    it failed OPEN rather than closed: a phi's incoming edges are `ValueId`s
    inside `Definition::Phi`, not `MirUse`s, so the escape scan over
    `function.uses()` could not see them. Accesses through an unplaceable merged
    pointer rooted at the phi value instead, leaving the frame object reporting
    an empty conflict set while bounding variables in a frame written behind its
    back — `143_dynamic_frames:alloca_in_loop` reported `{}` with a runtime-sized
    alloca sitting in the middle of its frame. Census of falsely-bounded frames
    before the fix: gcc-O0 1 of 1363, gcc-O2 5 of 609, clang-O2 4 of 639.
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

