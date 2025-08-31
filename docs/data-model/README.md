# GLAURUNG Data Model — Unified Plan

This document synthesizes all proposals in `docs/data-model/proposals/` and the critiques in `docs/data-model/critique/` into a cohesive, long‑term data model for Glaurung. It preserves the ambitious semantic/AI vision while standardizing core structures for reliability and interoperability.

Goals
- Strong core primitives that match real binaries and loaders.
- Rich higher‑level representation for analysis, decompilation, and reasoning.
- Provenance, stability, and confidence modeling for AI‑assisted insights.
- Extensible, tool‑agnostic pipeline with artifact caching and history.

Guiding Conventions
- Addressing: Use `AddressKind = VA | RVA | FileOffset | Physical | Relative | Symbolic` with optional `space` for segmented/overlay models and `bits` for width.
- Ranges: Half‑open ranges with canonical `{ start, size }` and derived `end = start + size`.
- Naming: Prefer `arch`, `bits`, `perms`, `kind` for consistency; `type` stays where domain‑appropriate (e.g., ontologies).
- IDs: Stable, content‑ and context‑aware identifiers (UUID/build‑id for binaries; deterministic IDs for in‑binary entities).
- Provenance: Every derived datum links to producing tool/pass; confidence scores live on detection/analysis artifacts and can be attached as Evidence to core entities when boundaries are uncertain.

Scope Overview
- Core Structural Types: Binary, Address, AddressRange, Segment, Section, Symbol, Relocation, AddressSpace.
- Code Representation: Instruction, Operand, BasicBlock, Function, Reference; graphs for CFG and calls.
- Data & Types: DataType, Variable, StringLiteral, Pattern.
- Pipeline & Workspace: Artifact, ToolMetadata, Task, Manifest, Workspace, AnalysisProfile.
- Advanced/AI & Dynamic: AIInsight, Embedding, Similarity, DynamicTrace/TraceEvent, SteganographicContent.
- Semantics & Knowledge: KnowledgeGraph, BinaryOntology, Ontology entities, Inference rules, SPARQL queries, Semantic patterns, NamedGraph.
- Annotations & Evidence: Comment/Annotation, Evidence/Provenance attachments.

---

Core Structural Types

Address
- Purpose: Canonical location within a binary's addressing scheme, supporting segmented/overlay spaces and symbolic resolution.
- Fields:
  - `kind`: `VA | RVA | FileOffset | Physical | Relative | Symbolic`
  - `value`: u64
  - `space?`: string (address space identifier, e.g., `default`, `ram`, `rom`, `overlay`)
  - `bits`: u8 (16 | 32 | 64)
  - `symbol_ref?`: string (Symbol.id, required when kind=Symbolic)

AddressRange
- Purpose: Half‑open contiguous memory region.
- Fields:
  - `start`: `Address`
  - `size`: u64
  - `end`: derived (exclusive)
  - `alignment?`: Optional alignment in bytes

AddressSpace
- Purpose: Named addressing domain (default, overlays, stack/heap, MMIO).
- Fields:
  - `name`: string
  - `kind`: `Default | Overlay | Stack | Heap | MMIO | Other`
  - `size?`: u64 max size
  - `base_space?`: Parent space for overlays

Binary
- Purpose: Top‑level descriptor for a program under analysis.
- Fields:
  - `id`: Stable identifier (build‑id/UUID or hash‑derived)
  - `path`: filesystem path
  - `format`: `ELF | PE | MachO | Wasm | COFF | Raw | Unknown`
  - `arch`: `x86 | x86_64 | arm | aarch64 | mips | ppc | riscv | unknown`
  - `bits`: 32 | 64
  - `endianness`: `Little | Big`
  - `entry_points`: `[Address]`
  - `size_bytes`: u64
  - `hashes`: map `{ sha256: string, md5?: string, ... }`
  - `uuid?`: Mach‑O UUID / ELF build‑id
  - `timestamps?`: format‑specific times (e.g., PE TimeDateStamp)

Segment
- Purpose: Load‑time memory mapping unit.
- Fields:
  - `id`: string
  - `name?`: string
  - `range`: `AddressRange` in VA
  - `perms`: bitflags `r|w|x`
  - `file_offset`: `Address` (kind=`FileOffset`)
  - `alignment?`: u64
  - `compression?`: metadata
  - `encryption?`: metadata

Section
- Purpose: File‑format organizational unit (e.g., `.text`, `.data`).
- Fields:
  - `id`: string
  - `name`: string
  - `range`: `AddressRange` (VA or RVA per format)
  - `perms?`: bitflags `r|w|x`
  - `flags`: format‑specific flags
  - `type?`: format‑specific type (e.g., `PROGBITS`, `NOBITS`)
  - `file_offset`: `Address` (kind=`FileOffset`)

Relocation
- Purpose: Link‑time relocation entry.
- Fields:
  - `address`: `Address` to relocate
  - `kind`: relocation type enum (format‑specific)
  - `value?`: u64 resolved/addend
  - `symbol?`: `Symbol` reference (if applicable)

Symbol
- Purpose: Named program entity from symbol/debug/import/export sources.
- Fields:
  - `id`: string
  - `name`: mangled/exported name
  - `demangled?`: string
  - `kind`: `Function | Object | Section | Import | Export | Thunk | Debug | Synthetic | Other`
  - `address?`: `Address`
  - `size?`: u64
  - `binding?`: `Local | Global | Weak`
  - `module?`: module/library source
  - `visibility?`: `Public | Private | Protected | Hidden`
  - `source`: `DebugInfo | ImportTable | ExportTable | Heuristic | PDB | DWARF | AI`

---

Code Representation

Instruction
- Purpose: Decoded instruction at an address.
- Fields:
  - `address`: `Address`
  - `bytes`: byte[]
  - `mnemonic`: string
  - `operands`: `[Operand]` (typed) — allow text fallback where needed
  - `length`: u8/u16
  - `arch`: matches Binary.arch
  - `semantics?`: optional descriptor (future IR/SSA integrations)
  - `side_effects?`: `[MemoryWrite | RegisterModify | ...]`
  - `prefixes?`: string[]
  - `groups?`: string[] (e.g., `branch`, `simd`, `crypto`)

Operand
- Purpose: Structured operand representation.
- Fields:
  - `kind`: `Register | Immediate | Memory | Displacement | Relative`
  - `value`: variant
  - `size`: bits
  - `access`: `Read | Write | ReadWrite`
  - `segment?`, `scale?`, `base?`, `index?`

BasicBlock
- Purpose: Straight‑line code region.
- Fields:
  - `id`: string (deterministic: binary_id + start_address)
  - `start_address`: `Address`
  - `end_address`: `Address`
  - `instruction_count`: u32
  - `successor_ids`: `[string]` (BasicBlock.id references)
  - `predecessor_ids`: `[string]` (BasicBlock.id references)

Function
- Purpose: Callable region aggregating blocks/metadata.
- Fields:
  - `id`: string
  - `name?`: string
  - `entry`: `Address`
  - `range?`: `AddressRange`
  - `basic_block_ids`: `[string]` (BasicBlock.id references)
  - `parameter_ids?`: `[string]` (Variable.id references)
  - `local_variable_ids?`: `[string]` (Variable.id references)
  - `calling_convention?`: string
  - `return_type_id?`: string (DataType.id reference)
  - `stack_frame_size?`: u64
  - `cyclomatic_complexity?`: u32
  - `is_thunk?`: bool
  - `is_library?`: bool

Reference (Xref)
- Purpose: Directed relationship between code/data locations.
- Fields:
  - `id`: string
  - `from`: `Address`
  - `to`: variant:
    - Resolved: `Address`
    - Unresolved: `{ kind: Dynamic | Indirect | External | Unknown, expression?: string }`
  - `kind`: `Call | Jump | Branch | Return | Read | Write | Reloc | DataRef | Tail`
  - `width?`: u8 (in bits)
  - `confidence?`: f32 (0.0–1.0)
  - `source`: string (tool/pass identifier)

ControlFlowGraph (CFG)
- Purpose: Intra‑procedural flow graph.
- Fields:
  - `function_id?`: string
  - `block_ids`: `[string]` (BasicBlock.id references)
  - `edges`: `{ from_block_id: string, to_block_id: string, kind: Fallthrough|Branch|Call|Return }[]`

CallGraph
- Purpose: Inter‑procedural call relationships.
- Fields:
  - `nodes`: `[string]` (Function.id references)
  - `edges`: `{ caller: string, callee: string, call_sites?: [Address], call_type?: Direct|Indirect|Virtual|Tail, confidence?: f32 }[]`

Register
- Purpose: CPU register definitions.
- Fields:
  - `name`: string
  - `size`: u8 (in bits)
  - `kind`: `General | Float | Vector | Flags | Segment | Control | Debug`
  - `address?`: `Address` (for memory-mapped registers)
  - `parent_register?`: string (e.g., "al" parent is "rax")
  - `offset_in_parent?`: u8 (bit offset within parent)

---

Data & Types

DataType
- Purpose: Type system representation for decompilation and analysis.
- Fields:
  - `id`: string
  - `name`: string
  - `kind`: `Primitive | Pointer | Array | Struct | Union | Enum | Function | Typedef`
  - `size`: u64 (in bytes)
  - `alignment?`: u64 (in bytes)
  - `type_data`: variant based on kind:
    - Primitive: `{ }`
    - Pointer: `{ base_type_id: string, attributes?: [const|volatile] }`
    - Array: `{ base_type_id: string, count: u64 }`
    - Struct/Union: `{ fields: [{ name: string, type_id: string, offset: u64 }] }`
    - Enum: `{ underlying_type_id: string, members: [{ name: string, value: i64 }] }`
    - Function: `{ return_type_id?: string, parameter_type_ids: [string], variadic?: bool }`
    - Typedef: `{ base_type_id: string }`
  - `source?`: string (provenance)

Variable
- Purpose: Variables with storage and liveness.
- Fields:
  - `id`: string
  - `name?`: string
  - `type_id`: string (DataType.id reference)
  - `storage`: `Register | Stack | Heap | Global`
  - `location`: variant based on storage:
    - Register: `{ name: string }`
    - Stack: `{ offset: i64, frame_base?: string }`
    - Heap: `{ address: Address }`
    - Global: `{ address: Address }`
  - `liveness_range?`: `AddressRange`
  - `source?`: `Debug | Decompiler | AI`

StringLiteral
- Purpose: Extracted string with encoding and references.
- Fields:
  - `id`: string
  - `address`: `Address`
  - `value`: string
  - `raw_bytes?`: byte[]
  - `encoding`: `Ascii | Utf8 | Utf16 | Utf32 | Unknown | Base64`
  - `length_bytes`: u64
  - `referenced_by?`: `[Address]`
  - `language_hint?`, `classification?` (URL/Path/Email/Key), `entropy?`

Pattern
- Purpose: Detected signatures/anomalies (crypto, packers, anti‑debug, exploit techniques).
- Fields:
  - `id`: string
  - `type`: `Signature | Heuristic | Yara | Behavior | Statistical`
  - `name`: string
  - `addresses`: `[Address]`
  - `confidence`: f32 (0.0-1.0)
  - `pattern_definition`: variant based on type:
    - Signature: `{ bytes: string, mask?: string }`
    - Yara: `{ rule_id: string, matches: [{ offset: u64, identifier: string }] }`
    - Heuristic: `{ conditions: [string] }`
    - Behavior: `{ api_calls?: [string], sequences?: [string] }`
    - Statistical: `{ entropy?: f32, metrics?: JSON object }`
  - `description`: string
  - `references`: `[string]` (URLs, CVEs, etc.)
  - `metadata`: JSON object

SteganographicContent
- Purpose: Potential hidden/embedded payloads with indicators and entropy analysis.
- Fields: `id`, `location: AddressRange`, `method`, `content_type`, `extracted_data?`, `confidence`, `indicators`, `entropy_analysis`

---

Pipeline & Workspace

Artifact
- Purpose: Typed result envelope with caching and provenance.
- Fields:
  - `id`: string
  - `tool`: `ToolMetadata`
  - `created_at`: ISO 8601 timestamp
  - `input_refs`: `[string]` (Artifact.id references)
  - `schema_version`: string
  - `data_type`: string (e.g., "Binary", "CFG", "Symbols")
  - `data`: JSON object (structure defined by data_type)
  - `meta?`: JSON object

ToolMetadata
- Fields: `name`, `version`, `parameters?`, `source_kind?` (`Static | Dynamic | Heuristic | External`)

Task
- Purpose: Execution record for a tool/pass.
- Fields: `id`, `tool`, `input_artifacts`, `status`, `started_at?`, `finished_at?`, `error?`, `metrics?`, `logs_ref?`

Manifest
- Purpose: Per‑binary index of artifacts and relationships.
- Fields: `binary_id`, `created_at`, `artifacts`, `dependencies`, `latest_of_kind`

Workspace
- Purpose: Project workspace and session management.
- Fields: `id`, `name`, `root_path`, `binaries: [Binary.id]`, `active_binary?`, `analysis_profiles`, `plugins`, `settings`, `history`

AnalysisProfile
- Purpose: Configuration profiles for passes and tools.
- Fields: `id`, `name`, `description`, `tools`, `passes`, `confidence_thresholds`, `performance_hints`

Minimal Artifacts by Phase (anchor types to outputs)
- Identify → `Artifact<data = Binary>`
- Layout → `Artifact<data = { segments: [Segment], sections: [Section] }>`
- Symbols → `Artifact<data = [Symbol]>`
- Disassembly → `Artifact<data = [Instruction]>`
- Xrefs → `Artifact<data = [Reference]>`
- Strings → `Artifact<data = [StringLiteral]>`
- CFG → `Artifact<data = { functions: [Function], blocks: [BasicBlock], edges: [...] }>`

---

Advanced / AI & Dynamic

AIInsight
- Purpose: AI‑generated insights with explanations and confidence.
- Fields:
  - `id`: string
  - `type`: `Vulnerability | Behavior | Similarity | Anomaly`
  - `description`: string
  - `entity_ids`: `[string]` (polymorphic entity references)
  - `confidence`: f32 (0.0-1.0)
  - `model`: string
  - `reasoning?`: string
  - `suggested_actions`: `[string]`
  - `false_positive_score`: f32 (0.0-1.0)

Embedding
- Purpose: Vector embeddings for similarity/ML.
- Fields:
  - `id`: string
  - `entity_type`: string (e.g., "Function", "BasicBlock")
  - `entity_id`: string
  - `vector`: `[f32]`
  - `dimension`: u32
  - `model`: string
  - `timestamp`: ISO 8601 timestamp

Similarity
- Purpose: Relationships for clone/match detection.
- Fields:
  - `id`: string
  - `entity1_id`: string
  - `entity2_id`: string
  - `similarity_type`: string
  - `score`: f32 (0.0-1.0)
  - `method`: string
  - `details?`: JSON object

DynamicTrace
- Purpose: Runtime traces integrated with static analysis.
- Fields: `id`, `trace_type` (`Instruction | API | System`), `events: [TraceEvent]`, `coverage`, `input_vector?`, `timestamp`

TraceEvent
- Fields: `sequence_number`, `timestamp`, `address?`, `event_type`, `data`, `thread_id?`, `process_id?`

Annotation
- Purpose: Notes and annotations on entities/locations.
- Fields:
  - `id`: string
  - `address?`: `Address`
  - `entity_type?`: string (when entity_id is present)
  - `entity_id?`: string
  - `text`: string
  - `author`: string
  - `timestamp`: ISO 8601 timestamp
  - `type`: `Note | Warning | TODO | Analysis`
  - `priority?`: `Low | Medium | High`

Evidence (Attachment Model)
- Purpose: Attach provenance and confidence to any entity without polluting core fields.
- Fields:
  - `id`: string
  - `target_type`: string (entity type name, e.g., "Function", "Reference")
  - `target_id`: string (entity id)
  - `kind`: string
  - `source_tool`: string
  - `confidence`: f32 (0.0-1.0)
  - `justification`: string
  - `timestamp`: ISO 8601 timestamp
  - `links?`: `[string]` (URLs or references)

---

Semantics & Knowledge Graph

KnowledgeGraph
- Purpose: RDF‑inspired semantic graph representing analysis facts.
- Fields: `id`, `ontology`, `triples: [Triple]`, `named_graphs`, `prefixes`, `inference_rules`, `materialized_triples`

BinaryOntology / OntologyClass / Property / Resource / Literal
- Purpose: OWL‑inspired ontology to define classes, properties, constraints.
- Notes: Import external ontologies (STIX/MAEC) as needed; keep namespaces clear.

Triple
- Purpose: RDF-style fact representation.
- Fields:
  - `subject`: string (URI or entity ID)
  - `predicate`: string (URI or property name)
  - `object`: string | i64 | f64 | bool (literal value or URI/ID)
  - `graph_context?`: string (NamedGraph.id)
  - `confidence`: f32 (0.0-1.0)
  - `provenance`: string (source identifier)
  - `valid_time?`: ISO 8601 timestamp
  - `reification_id?`: string

InferenceRule / RuleAtom
- Purpose: SWRL‑like rules for reasoning over facts.

NamedGraph
- Purpose: Context‑specific subgraphs (by pass, by confidence threshold, etc.).

SPARQLQuery
- Purpose: SPARQL query definitions for knowledge graph.
- Fields:
  - `id`: string
  - `name`: string
  - `query`: string (SPARQL query text)
  - `description?`: string
  - `parameters?`: `[{ name: string, type: string }]`

SemanticPattern
- Purpose: Reusable semantic patterns for detection.
- Fields:
  - `id`: string
  - `name`: string
  - `pattern`: string (SPARQL WHERE clause pattern)
  - `severity`: `Low | Medium | High | Critical`
  - `category`: string (e.g., "malware", "vulnerability")
  - `description`: string
  - `mitre_attack_ids?`: `[string]`

---

Enumerations
- `Format`: `ELF | PE | MachO | Wasm | COFF | Raw | Unknown`
- `Arch`: `x86 | x86_64 | arm | aarch64 | mips | ppc | riscv | unknown`
- `Endianness`: `Little | Big`
- `Perms`: bitflags `r|w|x`
- `ReferenceKind`: `Call | Jump | Branch | Return | Read | Write | Reloc | DataRef | Tail`
- `AddressKind`: `VA | RVA | FileOffset | Physical | Relative | Symbolic`

---

Provenance, Confidence, and Validation
- Provenance is mandatory for all derived/analysis outputs (Artifacts, References, Patterns, AIInsights, Evidence), including tool name, version, parameters, and timestamps.
- Confidence lives primarily on analysis/detection artifacts and Evidence attachments. Canonical core data (e.g., `Binary.path`, `Address.value`) should remain authoritative.
- When boundaries are uncertain (e.g., function starts/ends), attach `Evidence` with confidence; optionally include convenience fields like `Function.confidence` when UX benefits, but treat them as derived.

Interoperability & Export
- Provide import/export for: JSON artifacts, Graph serialization (Turtle/JSON‑LD), and standard symbol/trace formats.
- Maintain stable IDs to enable cross‑tool mapping and deduplication.

Open Questions (to resolve during implementation)
- Operand structure vs. decoder coupling: start structured with a path for text fallback; keep IR evolution in mind.
- Address `bits` inference from Binary vs. explicit on Address for portability across artifacts.
- Function coverage representation: block‑derived vs. explicit `range` as best‑effort.
- Evidence/Confidence UI: how to present layered evidence to users without confusion.

Mapping Notes (how proposals informed this plan)
- CLAUDE: Provided the semantic/ontology foundation, rich instruction/operand modeling, AI/advanced artifacts, and extensibility patterns. Retained broadly, categorized to keep core vs. analysis clear.
- GPT5: Drove standardization of naming (`arch`, `bits`, `perms`, `kind`), half‑open ranges, introduction of `Reference`, and the pipeline envelope (Artifact/Task/Tool/Manifest/Workspace). These conventions are adopted across the model.
- GEMINI: Confirmed baseline core types and CFG modeling; merged its `Project` concept into `Workspace` and expanded Address into a richer shape.
- GROK4: Added explicit `AddressSpace`, `MemoryBlock` motivation (mapped onto `Segment/Section`), `Relocation`, and `Register`. These are integrated where they add fidelity.

Summary
This unified plan balances a pragmatic, minimal core with a comprehensive long‑term vision: accurate structural modeling; strong graphs for control‑ and call‑flow; a typed pipeline with provenance and caching; and a semantic layer for reasoning, AI insights, and advanced detection. The result is an extensible platform that supports today’s reverse‑engineering workflows and tomorrow’s knowledge‑driven analysis.

