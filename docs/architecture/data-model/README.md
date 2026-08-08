# Core data model

Glaurung does not have one universal object graph shared unchanged by Rust,
Python, triage JSON, the decompiler, and the persistent database. Each boundary
has a specific representation. Treat the public source at that boundary as the
contract; the adjacent proposal documents are historical design inputs.

## Rust structural core

`src/core/mod.rs` exports the reusable binary-analysis primitives. Current
families include:

- locations: `Address`, `AddressKind`, `AddressRange`, and `AddressSpace`;
- binary layout: `Binary`, `Format`, `Arch`, `Segment`, `Section`,
  `Relocation`, and `Symbol`;
- code: `Instruction`, `Operand`, `BasicBlock`, `Function`, control-flow and
  call graphs, and `Reference`;
- types and data: `DataType`, `Variable`, `StringLiteral`, and `Pattern`; and
- provenance/container support: `Artifact`, `ToolMetadata`, `Id`, and related
  enums.

Addresses carry a numeric value, bit width, address kind, and optional space or
symbol reference. `AddressRange` is half-open and stores `start` plus byte
`size`; its end is derived. Constructors validate invariants, so callers should
not reproduce the older proposal structs locally.

The Rust types use Serde and selected binary codecs internally, but that does
not make every serialized form a permanent cross-version file format.

## Triage artifacts

`src/triage/` owns the bounded `TriagedArtifact` returned by the native triage
API. It includes format/architecture verdicts and optional strings, symbols,
packers, similarity, containers, overlays, parser status, budgets, and errors.
It is intentionally not the same object as `core::Binary` or a persistent
project.

Use the [triage guide](../../triage/README.md) for field semantics and partial
result rules.

## Decompiler IR

`src/ir/` owns the low-level operations, SSA and structural recovery,
architecture-specific lifters, shared AST, type recovery, verification, and
rendering passes. These types evolve with the decompiler and should not be
confused with `src/core/` instructions or persisted KB nodes.

See the [decompiler architecture](../../analysis/decompiler/README.md) and dated
evidence checkpoints for the current maturity boundary.

## Python and persistence

Python bindings expose selected native types and functions, sometimes as a
projection designed for Python rather than a field-for-field Rust mirror.

`python/glaurung/llm/kb/` owns two additional layers:

- `KnowledgeBase` nodes and edges used by deterministic tools and agents; and
- `PersistentKnowledgeBase`, a SQLite-backed project plus subsystem tables for
  names, xrefs, types, frames, comments, undo/redo, and other accumulated state.

Read [persistent project databases](../PERSISTENT_PROJECT.md) before depending
on session scope, schema compatibility, or save/close behavior.

## Provenance and confidence

Provenance is boundary-specific. Examples include `ToolMetadata` in the Rust
core, evidence records and properties in the KB, and `set_by` fields with
precedence in persistent naming/type tables. Confidence belongs on uncertain
analysis results; it does not make a canonical address probabilistic.

Keep these distinct:

- an observed byte or decoded header;
- a parser or analysis inference;
- an analyst override;
- an LLM-generated hypothesis; and
- a verified behavioral result.

## Historical design records

The other files in this directory capture earlier unified-model proposals,
critiques, implementation plans, nesting designs, and disassembler/decompiler
foundations. Their status banners mark them as historical. They can explain why
some types exist, but their illustrative fields, paths, and checklists are not
current APIs.
