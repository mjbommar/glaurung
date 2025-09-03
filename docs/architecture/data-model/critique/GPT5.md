# GLAURUNG Data Model Critique — GPT5

Context: Review and concrete recommendations for docs/data-model/proposals/CLAUDE.md to align with MVP scope, improve consistency, and separate core structural data from advanced/semantic concerns.

Format: Each action includes a verb, target, rationale, and impact.

---

## P0 — MVP Alignment (Do first)

- Change: Address.kind → `VA|RVA|FileOffset` (drop `Virtual|Physical|Relative|Symbolic`)
  - Rationale: Aligns with loaders and artifact portability; avoids ambiguous semantics early.
  - Impact: Medium

- Change: Address.width → `bits`; Address.space → optional (segmented models only)
  - Rationale: Consistent terminology with Binary.bits; keeps space narrow and optional.
  - Impact: Low

- Remove: Address.confidence
  - Rationale: Core addresses are canonical; uncertainty belongs in detection/analysis artifacts.
  - Impact: Medium

- Change: AddressRange to half‑open `{ start, size }` with `end` derived
  - Rationale: Standard pattern reduces off‑by‑one errors and duplication.
  - Impact: Medium

- Remove: AddressRange.attributes/tags/entropy
  - Rationale: Move content heuristics to Pattern/Metrics artifacts to keep ranges structural.
  - Impact: Medium

- Change: Binary.architecture → `arch`; add `bits`, `entry?`
  - Rationale: Consistency and minimum essential metadata for navigation.
  - Impact: Low

- Remove: Binary.analysis_state, Binary.knowledge_graph_ref
  - Rationale: Keep core Binary minimal; analysis lifecycle belongs to pipeline manifests.
  - Impact: Low

- Change: Segment.virtual_range/file_range → `range` (VA) + `file_offset`; `permissions` → `perms` (`r|w|x`)
  - Rationale: Simplifies model; matches common loaders/tooling.
  - Impact: Medium

- Change: Section.range explicit in VA/RVA + `file_offset`; Remove Section.entropy/hashes/characteristics
  - Rationale: Sections remain structural; heuristics live elsewhere.
  - Impact: Medium

- Change: Symbol.type → `kind` (`Function|Object|Import|Export|Section|Debug|Synthetic`); add `binding?`, `module?`
  - Rationale: Align with ELF/PE/Mach‑O conventions and downstream use.
  - Impact: Medium

- Change: Instruction.operands → start as list of strings (defer structured Operand)
  - Rationale: Ship early disassembly without IR/decoder coupling.
  - Impact: Low

- Remove: BasicBlock.dominators/loop_header/exception_handlers/complexity_metrics
  - Rationale: Move to analysis artifacts; keep CFG nodes lean.
  - Impact: Medium

- Change: BasicBlock fields → `start_address`, `end_address`, `instructions`, `successors`, `predecessors`
  - Rationale: Minimal, clear shape for initial CFG.
  - Impact: Low

- Remove: Function.parameters/local_variables/return_type/stack_frame_size/cyclomatic_complexity/is_thunk/is_library/confidence
  - Rationale: Defer to decompiler/type analysis layers; keep core function descriptor simple.
  - Impact: High

- Add: Reference object (xrefs) `{ id, from, to?, kind, width?, confidence, source }`
  - Rationale: Essential for navigation and CFG construction.
  - Impact: High

- Add: ControlFlowGraph (CFG) and CallGraph minimal types
  - Rationale: Enables graph queries and visualization early.
  - Impact: Medium

- Add: Pipeline envelope types — Artifact, ToolMetadata, Task, Manifest, Workspace
  - Rationale: Caching, provenance, and incremental pipelines require these.
  - Impact: High

- Add: Enumerations section (Format, Arch, Endianness, Perms, ReferenceKind, AddressKind)
  - Rationale: Shared vocabulary across types.
  - Impact: Low

---

## P1 — Structure and Consistency (Next)

- Refactor: Normalize field names (`type`→`kind`, `width`→`bits`, `permissions`→`perms`, `architecture`→`arch`)
  - Rationale: Consistency and readability across the model.
  - Impact: Medium

- Refactor: Split document into “Core Structural Types” vs “Analysis Outputs”
  - Rationale: Clarifies which data is canonical vs derived.
  - Impact: Low

- Add: StringLiteral.referenced_by (list of Addresses); make `raw_bytes` optional
  - Rationale: Practical cross‑ref linkage; avoid bloating payloads by default.
  - Impact: Low

- Change: Symbol.source to fixed set `DebugInfo|ImportTable|ExportTable|Heuristic|PDB|DWARF|AI`
  - Rationale: Standardize provenance values for filtering and merging.
  - Impact: Low

- Add: “Minimal Artifacts by Phase” section (Identify, Layout, Symbols, Disassembly, Xrefs, Strings, CFG)
  - Rationale: Ties types to concrete outputs and pipeline stages.
  - Impact: Low

- Add: “Open Questions” section (operands typing, address bits inference, function ranges)
  - Rationale: Makes deferred decisions explicit and tracked.
  - Impact: Low

- Remove: Security/heuristic stats from core entities; keep `Pattern` as separate detection artifact
  - Rationale: Decouple heuristics from structural data.
  - Impact: Medium

---

## P2 — Defer/Isolate Advanced Semantics (Later)

- Remove: KnowledgeGraph, BinaryOntology, OntologyClass, Triple, Resource, Literal, Property from core proposal
  - Rationale: Over‑scoped for MVP; risks blocking foundational work.
  - Impact: High

- Reorganize: Move semantic‑web content to `docs/semantics/ontology.md` with “experimental” status
  - Rationale: Preserve vision; isolate complexity.
  - Impact: Medium

- Add: Lightweight `Annotation`/`Evidence` model to attach notes/provenance/confidence to artifacts
  - Rationale: Practical provenance without RDF/OWL machinery.
  - Impact: Medium

- Add: Separate “Types & Decompiler” proposal (DataType, Variable, calling conventions) in its own doc
  - Rationale: Keep core data lean; stage decompiler/type system work.
  - Impact: Medium

- Defer: Instruction.semantics/side_effects/prefixes/groups until IR or richer decoder is chosen
  - Rationale: Avoid premature coupling and churn.
  - Impact: Medium

- Defer: Function signature inference and variable liveness to later SSA/IR phase
  - Rationale: Depends on non‑trivial infrastructure.
  - Impact: High

---

## Reorganization Plan (Document Layout)

- Change: Restructure CLAUDE.md into sections:
  - Core Domain Types (Address, AddressRange, Binary, Segment, Section, Symbol)
  - Code Representation (Instruction, BasicBlock, Function)
  - Graphs (ControlFlowGraph, CallGraph)
  - Strings (StringLiteral)
  - Pipeline (Artifact, ToolMetadata, Task, Manifest, Workspace)
  - Enumerations
  - Minimal Artifacts by Phase
  - Open Questions
  - Summary
  - Rationale: Improves scanability and separates concerns.
  - Impact: Low

- Refactor: Mark fields as optional where applicable and note provenance (canonical vs derived)
  - Rationale: Data hygiene and downstream reliability.
  - Impact: Low

- Refactor: Remove `confidence` from core entities; place confidence only in detection‑specific artifacts
  - Rationale: Clarifies authority and prevents accidental misuse.
  - Impact: Medium

---

## Additions Aligned With Project Direction

- Add: `Binary.uuid?` (ELF build‑id / Mach‑O UUID)
  - Rationale: Symbolication, caching, and cross‑tool mapping.
  - Impact: Low

- Add: `Binary.timestamps?` map (e.g., PE TimeDateStamp)
  - Rationale: Reproducibility and triage context.
  - Impact: Low

- Add: `Segment.alignment?` and `Section.type?` (format‑native)
  - Rationale: Loader fidelity and downstream layout reasoning.
  - Impact: Low

---

## Implementation Notes (P0 Definition of Done)

- Updated types in proposal reflecting all P0 changes.
- Introduced Reference, CFG, CallGraph, Artifact, ToolMetadata, Task, Manifest, Workspace.
- Enumerations consolidated and referenced consistently.
- Document split between core vs analysis sections.
- Confidence fields removed from core entities; present only in detection artifacts.

---

## Proposed File Moves / New Docs

- Move: Semantic web content → `docs/semantics/ontology.md` (status: experimental)
- Add: `docs/data-model/proposals/types-and-decompiler.md` for DataType/Variable/ABI work
- Add: `docs/pipeline/minimal-artifacts.md` describing Identify/Layout/Symbols/Disassembly/Xrefs/Strings/CFG payloads

