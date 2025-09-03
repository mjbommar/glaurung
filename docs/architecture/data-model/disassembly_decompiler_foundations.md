# Disassembly & Decompiler Foundations — Data Model and Capabilities

Purpose: Define the minimal, foundational data models and capabilities we need before wiring up disassembly and decompilation. This works backwards from the goals in docs/disassembly/ and docs/decompiler/, and aligns with existing core types in src/core/.

This document focuses on durable models, deterministic outputs, and integration seams that enable multiple engines and future IR/decompiler work.

## 0) Status Legend

- [x] Complete or present in repo
- [~] Partially present; needs extension
- [ ] Not yet implemented

Where helpful, we note file paths for what exists today.

## 1) Program View & Memory Model

Foundations to represent the loaded image and safe, deterministic reads by address.

- BinaryView: Aggregate sections/segments, relocations, symbols, imports/exports, image_base, uuid/build-id, timestamps
  - Status: [ ] New type; wrapper around Binary + loaders
  - Notes: Should be the canonical view passed to disassembly/analysis.
- MemoryView trait: Safe, bounded reads by `Address` (VA/RVA/FileOffset) with perm checks and relocation-aware reads
  - Status: [ ] New trait; backed by SafeReader (src/io/mod.rs)
- Address translation map: Deterministic VA↔RVA↔FileOffset conversion using section/segment maps and image base
  - Status: [~] Address has helpers; no centralized map yet
  - Files: src/core/address.rs, src/core/section.rs, src/core/segment.rs
- Loader coverage (ELF/PE/Mach-O): Populate BinaryView with sections, segments, image base, entry points, imports/exports, relocations
  - Status: [~] Symbols/headers exist; full loaders not integrated
  - Files: src/triage/headers.rs, src/symbols/{elf,pe,macho}.rs
- Overlay modeling in view (e.g., PE overlay, AppImage): Expose as AddressRange and optional node reference
  - Status: [~] Overlay detection exists; integrate into BinaryView
  - Files: src/triage/overlay.rs
- Relocation resolver: Resolve or expose reloc effects during memory reads and disassembly/lifting
  - Status: [ ] Model exists; resolver integration missing
  - Files: src/core/relocation.rs

References to study: cle (angr) BinaryView/Regions, LIEF loaders, object crate (Rust), Ghidra Program/Memory map, rizin/radare2 bin loaders.

### Mapping to existing src/ types and avoiding overlap

- Canonical descriptor: keep `src/core/binary.rs::Binary` as the immutable program descriptor. BinaryView is an analysis-time container that embeds a `Binary` and adds loaders’ results; it does not replace or extend `Binary` itself.
- Sections vs Segments: reuse `src/core/section.rs::Section` (file/RVA scope) and `src/core/segment.rs::Segment` (memory/VA scope). MemoryView performs AddressKind-aware translation on top; it should not introduce new section/segment types.
- Permissions: keep `SectionPerms` (sections/file view) and `Perms` (segments/memory view) separate but with identical r/w/x semantics; document intended usage in code.
- Addresses and spaces: reuse `src/core/address.rs::{Address, AddressKind}` and `src/core/address_space.rs::AddressSpace`. MemoryView takes these directly.
- Relocations: reuse `src/core/relocation.rs::Relocation` for data. Add a resolver utility (analysis layer) without new data models.
- Overlay: bridge `src/triage/overlay.rs` results into BinaryView as optional regions; triage remains the place for cheap overlay detection.

## 2) Disassembly Capabilities

Unifying trait exists; need a registry and adapters with deterministic outputs.

- DisassemblerRegistry + builder: Select engine per arch/mode; user override → performance → feature fallback
  - Status: [ ] New registry; guided by docs/disassembly
- Engine adapters: Safe wrappers for iced-x86/Zydis/Capstone/etc. that produce unified Instruction/Operand
  - Status: [ ] New modules
- Instruction normalization: Branch kinds, condition codes, arch mode (e.g., ARM Thumb), groups, prefixes
  - Status: [~] Instruction supports side_effects/groups/prefixes; add branch_kind/cond_code/mode where needed
  - Files: src/core/instruction.rs
- Deterministic decoding policy: Stable ordering for results; canonical text formatting per syntax
  - Status: [ ] Document and enforce per engine adapter
- Streaming/parallel decoding scaffolding: Thread-safe instances, chunking model
  - Status: [ ] New scheduler abstractions (design only here)

References to study: iced-x86 design, Zydis API, Capstone multi-arch, bddisasm; Ghidra’s Sleigh-backed decoders for shape of normalized outputs.

### Mapping to existing src/ types and avoiding overlap
- Trait: reuse `src/core/disassembler.rs::Disassembler`. Add a small registry (e.g., `src/disasm/registry.rs`) and engine adapters (e.g., `src/disasm/iced.rs`, `src/disasm/zydis.rs`, `src/disasm/capstone.rs`).
- Instruction: reuse `src/core/instruction.rs::Instruction`/`Operand`. If we need branch_kind/cond_code/mode, extend this struct rather than minting an alternative.
- Architecture: prefer a single enum across the codebase. Today we have `core::binary::Arch` and `core::disassembler::Architecture`. Add `From/Into` mappings and plan consolidation (recommended owner: `core::binary::Arch`).

## 3) Code Discovery, Basic Blocks, CFG, Xrefs

Data types exist for Function/BasicBlock/CFG/CallGraph/Reference. We need builders and consistent IDs.

- Function discovery: Seed via entry points and exports; hybrid recursive-descent + guarded linear sweep
  - Status: [ ] New implementation
- Basic block builder: Split on control flow; respect section perms; stop at code/data boundaries
  - Status: [ ] New implementation
- CFG builder: Build edges; stable block IDs (binary_id + start_address); validate invariants
  - Status: [ ] New implementation
- Xref indexer: Extract code→code, code→data, data→code; resolve when possible, track unresolved kind
  - Status: [ ] New implementation
- Jump table detection: Pattern + reloc/symbol aid; feed CFG
  - Status: [ ] New implementation
- No-return and tail-call modeling: Affect CFG exit edges and call graph
  - Status: [ ] New implementation
- Exception metadata integration: PE SEH; ELF/Mach-O CFI/EH to add edges to handlers
  - Status: [ ] New implementation

Existing types: [x] Instruction, [x] Operand, [x] BasicBlock (src/core/basic_block.rs), [x] Function (src/core/function.rs), [x] CFG (src/core/control_flow_graph.rs), [x] CallGraph (src/core/call_graph.rs), [x] Reference (src/core/reference.rs).

References to study: Ghidra Function/BasicBlock analyzers, rizin/radare2 analysis passes, B2R2 control-flow recovery.

### Mapping to existing src/ types and avoiding overlap
- Builders, not models: implement discovery/block/CFG/xref builders under `src/analysis/` (e.g., `analysis/discovery.rs`, `analysis/cfg.rs`, `analysis/xref.rs`). Reuse the existing core types; do not create parallel block/function types.
- Xrefs: reuse `src/core/reference.rs::Reference` (resolved/unresolved) for all code/data refs; avoid introducing a separate “edge” type for xrefs.

## 4) Intermediate Representations (IR) and Lifting

Define layers to support analysis and eventual decompilation.

- LLIR (low-level IR): Close to ISA; explicit side effects; jump target expressions
  - Status: [ ] New data model + per-arch lifters
- SSA/MLIR layer: SSA values, phi nodes, def-use, dominance
  - Status: [ ] New data model + construction passes
- HLIR scaffolding: Typed expressions and structured constructs (if/loops/switch)
  - Status: [ ] New data model (decompiler stage)
- Analysis primitives: Dominators/post-dominators; def-use; liveness; constant/stack propagation
  - Status: [ ] New analyses

References to study: B2R2 IR/lifters, Reko IR, RetDec/LLVM-based lowering, Ghidra pcode design.

### Mapping to existing src/ types and avoiding overlap
- Namespacing: place IR under `src/ir/` (`ir/llir.rs`, `ir/ssa.rs`, `ir/hlir.rs`) to avoid confusion with `src/core/`.
- Provenance: IR nodes reference Instruction addresses and Function/BasicBlock IDs. Instructions remain the canonical decode; IR is a separate layer.

## 5) Types, ABI, and Calling Conventions

- Type system: DataType + constraints (equal, subtype, callable, has_field); progressive refinement
  - Status: [ ] New models/passes
- ABI database: Per-arch calling conventions (SysV, Win64, AAPCS), callee-saved sets, arg/ret locations
  - Status: [ ] New data + helpers
- Stack/frame analysis: Prolog/epilog; frame size; saved registers; var locations; variadic detection
  - Status: [ ] New passes

References to study: Ghidra/RetDec type recovery, TIE paper, B2R2 calling convs, Reko signatures.

### Mapping to existing src/ types and avoiding overlap
- Data types & variables: extend `src/core/data_type.rs` and `src/core/variable.rs` (present) rather than introducing new parallel definitions. Place inference passes under `src/analysis/types/`.
- ABI data: add data-driven calling conventions under `src/analysis/abi/`; do not bake ABI details into core types.

## 6) Symbols, Debug Info, and Demangling

Solidification of symbol sources and naming.

- Symbol repository: Merge imports/exports/debug into unified symbols with provenance and visibility
  - Status: [~] Symbols exist; repository/merger missing
- Demangling & language hints: Itanium/MSVC/Rust/Swift/Go demanglers + heuristics
  - Status: [~] Demangling utilities exist; expand and integrate
- Debug info ingestion: DWARF, PDB, dSYM to seed names/types/lines
  - Status: [ ] New integrations

References to study: symbolic (Sentry) crate, object crate debug parsers, llvm-project for DWARF, Microsoft DIA for PDB, Ghidra importers.

### Mapping to existing src/ types and avoiding overlap
- Canonical symbol: `src/core/symbol.rs::Symbol` with `SymbolSource` to track provenance. Keep `src/symbols/types.rs::SymbolSummary` for triage/summary only.
- Avoid duplicate enums: plan to migrate `symbols/types.rs::SymbolBinding/SymbolType` usages to `core::symbol` equivalents or rename local enums; do not add a third variant.
- Debug ingestion: add `src/debug/{dwarf,pdb,dsym}.rs` that enrich `Symbol`/`Function` and preserve provenance.

## 7) Determinism, Schema, Caching, Budgets

Ensure repeatable outputs and efficient re-use.

- Schema-versioned artifacts for disassembly/CFG/IR/decomp outputs with explicit schema_version
  - Status: [ ] Extend artifact schemas beyond triage
- Deterministic ordering of all collections (functions, blocks, edges, symbols)
  - Status: [~] Many types stable; enforce globally for analysis outputs
- Content-addressable cache: Instructions/blocks/IR keyed by bytes+arch+mode and address; dependency graph
  - Status: [ ] New cache layer
- Budgets/limits: Time/bytes/depth with surfaced truncation flags and summaries
  - Status: [~] IO limits exist; extend to analysis passes

References to study: cle caching, Ghidra project cache, rizin analysis determinism flags.

### Mapping to existing src/ types and avoiding overlap
- Artifact envelope: use `src/core/artifact.rs::Artifact` for analysis outputs (Disassembly, CFG, IR, Decomp). Keep `src/core/triage/verdict.rs::TriagedArtifact` exclusively for triage/identification.
- Deterministic ordering: enforce in builders (stable sort of functions/blocks/edges/symbols) rather than post-hoc.

## 8) Concurrency & Streaming

- Work scheduler: Chunking + work-stealing; one engine instance per thread; deterministic merge
  - Status: [ ] New infra
- Streaming support: Progressive disassembly of large files via segments and bounded windows
  - Status: [ ] New infra

References to study: iced multi-thread examples, Ghidra headless analyzer batching, radare2 analysis workers.

### Mapping to existing src/ types and avoiding overlap
- Execution concerns live under `src/analysis/runtime/` or `src/runtime/`. Keep core models pure.
- Streaming: MemoryView composes over `src/io/mod.rs::SafeReader`; analysis code should not read files directly.

## 9) Testing & Validation

- Cross-engine differential tests (instruction decode; per-arch corpora)
  - Status: [ ] New tests
- CFG/CallGraph invariants and golden fixtures; real binaries coverage
  - Status: [ ] New tests
- IR roundtrip invariants; lifter-specific tests
  - Status: [ ] New tests

References to study: Dogbolt corpora, LLVM MC tests, zydis/iced test suites, BAP/angr samples.

### Mapping to existing src/ types and avoiding overlap
- Keep core type tests in `src/core/`; place builder/adapter tests next to their modules under `src/disasm/` and `src/analysis/`.

---

## Triage vs. Analysis: Responsibilities and Data Flow

Triage (fast identification)
- Inputs: raw bytes via SafeReader with strict budgets.
- Outputs: `TriagedArtifact` (format/arch/bits/endian hypotheses; entropy/strings; `SymbolSummary`; signing presence; packer hints; immediate `containers`; `recursion_summary`; `overlay`; budgets/errors), deterministic ordering.

Analysis (reverse engineering)
- Inputs: `Binary` + loaders → `BinaryView`; safe reads via `MemoryView`.
- Capabilities: disassembly registry; function/block/CFG/xref builders; reloc resolver; debug info; IR; types/ABI.
- Outputs: `Artifact` envelopes per analysis product with `schema_version` and deterministic ordering.

Bridge
- Triage children/overlay seed deeper analysis (spans → BinaryView subviews); analysis re-validates via loaders.
- Triage `SymbolSummary` cues; analysis constructs canonical `core::symbol::Symbol` with provenance.
- Triage arch/endian guesses hint the registry; analysis verifies.

---

## Module Layout Conventions (to reduce overlap)

- Core, immutable types: `src/core/**` (existing)
- Triage-only logic and types: `src/triage/**` (existing)
- Disassembly engines/integration: `src/disasm/**` (registry + adapters)
- Analysis passes/builders: `src/analysis/**` (view.rs, discovery.rs, cfg.rs, xref.rs, types/, abi/, runtime/)
- Intermediate Representations: `src/ir/**` (llir.rs, ssa.rs, hlir.rs)
- Debug info ingestion: `src/debug/**` (dwarf.rs, pdb.rs, dsym.rs)

Keep core models small and stable; add behavior and execution concerns under analysis/disasm/debug modules to avoid duplicating data models.

---

## Quick Status Checklist (Rollup)

Program & Memory
- [x] Address/AddressRange/AddressSpace (src/core/address.rs, address_range.rs, address_space.rs)
- [x] Binary (src/core/binary.rs)
- [x] Section/Segment (src/core/section.rs, segment.rs)
- [~] Overlay detection (src/triage/overlay.rs); integrate into view
- [ ] BinaryView (new) + loaders
- [ ] MemoryView trait (new)
- [ ] Relocation resolver integration (model exists)

Disassembly
- [x] Disassembler trait (src/core/disassembler.rs)
- [x] Instruction/Operand model (src/core/instruction.rs)
- [ ] Engine adapters (iced/zydis/capstone)
- [ ] Registry + selection
- [~] Normalized branch kinds / cond codes (extend Instruction)

Discovery & Flow
- [x] BasicBlock/Function/CFG/CallGraph/Reference types
- [ ] Function finder and block/CFG builders
- [ ] Xref extraction/index
- [ ] Jump table analysis
- [ ] Exception metadata integration

IR & Decompiler Prep
- [ ] LLIR + lifters
- [ ] SSA/MLIR + analyses
- [ ] HLIR scaffolding
- [ ] Type/ABI system and frame analysis

Symbols & Debug
- [~] Symbol lists + demangling utils
- [ ] Debug info (DWARF/PDB/dSYM) ingestion
- [ ] Unified symbol repository & provenance

Determinism & Infra
- [~] Schema/versioning in triage; extend to disasm/CFG/IR
- [ ] Content-addressable caches
- [ ] Work scheduler + streaming
- [ ] Comprehensive differential/fixture testing

---

## Implementation Notes (Prioritized Path)

Phase A: BinaryView + MemoryView + Relocations + Engine Registry
- Define BinaryView + MemoryView and wire loaders to populate sections/segments/image base.
- Implement disassembler registry with a single backend first (iced-x86 or Capstone) for x86_64.
- Add deterministic decoding conventions and minimal scheduling interface.

Phase B: Function/Block/CFG/Xrefs
- Add hybrid discovery, block builder, CFG construction, and xref index with deterministic IDs.
- Integrate overlay spans and relocations in discovery boundaries.

Phase C: LLIR + Lifter (x86_64), core analyses (dominators, def-use, const-prop)
- Provide just enough for IR-driven CFG refinement and subsequent decompiler work.

Phase D: ABI + Types skeleton; Debug info hooks
- Seed calling conventions; map known imports; prepare type constraints.

Each phase should surface schema_versioned artifacts and adopt stable ordering for outputs.

---

## Cross-References

- Disassembly Architecture: docs/disassembly/README.md
- Decompiler Architecture: docs/decompiler/README.md
- Data Model (unified plan): docs/data-model/README.md
- Nesting/Recursion data model: docs/data-model/nesting.md
- References to consult: reference/README.md
