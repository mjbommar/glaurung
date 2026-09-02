# Core data model

> **Kind:** architecture · **Status:** maintained

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

## Program-scoped ownership

`src/program/` (23 files, 8,951 lines) is the layer between the raw core types
and analysis. It is what the decompiler entry points load a binary *through*,
and it exists so that program-wide facts have one owner rather than being
reassembled per caller.

- `ProgramSession` (`session.rs`) owns the expensive work — the parse, the
  validated `TargetSpec`, the symbol store, the type store, the DWARF types,
  and the cache keys those depend on. `from_path` and `from_image` are the two
  ways in.
- `ProgramImage` (`image.rs`) is the loaded image: sections, segments, and the
  byte spans (`spans.rs`) analysis reads through.
- `ProgramEnvironment` (`environment.rs`), with `format_environment.rs` and
  `caller_environment.rs`, holds the immutable semantic facts derived from the
  image and its debug information.
- `SymbolStore` (`symbols.rs`) is the one that repays reading. Its vocabulary
  is not "name at address": it distinguishes `SymbolAuthority` from
  `SymbolSource`, records `SymbolEvidence` per fact, keeps `SymbolConflict` and
  `SymbolIncompleteness` as first-class outcomes, and separates `AddressSymbol`
  from `AddressUnknown`. Competing evidence is retained and ranked rather than
  merged.
- `TypeStore` (`types.rs`) with `types/dwarf.rs`, `types/import.rs` and
  `types/verify.rs` is the same shape for types.
- `ReferenceResolver` (`references.rs`) resolves a reference site to a target
  and records `ReferenceOrigin` — how it was established — alongside it.
- `call_graph.rs` is the program-scoped call graph, distinct from
  `core::CallGraph`.

Two things about this layer are deliberate and easy to lose in a refactor: it
never merges conflicting evidence by name alone, and incompleteness never
silently becomes completeness. `src/program/diagnostics.rs`, which would give
those diagnostics one home, does not exist —
see [`module-boundaries.md`](module-boundaries.md) §1.

## Triage artifacts

`src/triage/` owns the bounded `TriagedArtifact` returned by the native triage
API. It includes format/architecture verdicts and optional strings, symbols,
packers, similarity, containers, overlays, parser status, budgets, and errors.
It is intentionally not the same object as `core::Binary` or a persistent
project.

Use the [triage guide](../guides/triage.md) for field semantics and partial
result rules.

## Decompiler IR

`src/ir/` owns the low-level operations, SSA and structural recovery,
architecture-specific lifters, shared AST, type recovery, verification, and
rendering passes. These types evolve with the decompiler and should not be
confused with `src/core/` instructions or persisted KB nodes.

See the [decompiler pipeline](decompiler-pipeline.md) for what is built,
[the pass list](../reference/decompiler-passes.md) for the order they run in,
and [the output format](../reference/decompiler-output-format.md) for what
comes out.

## Python and persistence

Python bindings expose selected native types and functions, sometimes as a
projection designed for Python rather than a field-for-field Rust mirror.

`python/glaurung/llm/kb/` owns two additional layers:

- `KnowledgeBase` nodes and edges used by deterministic tools and agents; and
- `PersistentKnowledgeBase`, a SQLite-backed project plus subsystem tables for
  names, xrefs, types, frames, comments, undo/redo, and other accumulated state.

Read [persistent project databases](persistent-project.md) before depending
on session scope, schema compatibility, or save/close behavior.

## Provenance and confidence

Provenance is boundary-specific and each boundary spells it differently:
`ToolMetadata` in the Rust core, `SymbolAuthority` / `SymbolSource` /
`SymbolEvidence` in `src/program/`, evidence records and node properties in the
KB, and the ranked `set_by` column in the persistent naming and type tables
([`../reference/provenance.md`](../reference/provenance.md)). Confidence belongs
on uncertain analysis results; it does not make a canonical address
probabilistic — which is why `Address` has no `confidence` field.

Keep these distinct:

- an observed byte or decoded header;
- a parser or analysis inference;
- an analyst override;
- an LLM-generated hypothesis; and
- a verified behavioral result.

## Where the shapes came from

A 2025 four-model design round produced parallel proposals and critiques for
roughly fifteen of these objects. They are archived in
[`../history/data-model-2025/`](../history/data-model-2025/) and are worth
consulting for one reason: they record what was *declined*, which the shipped
types cannot show.

`AddressKind` is the clearest case. It ships with six variants — `VA`,
`FileOffset`, `RVA`, `Physical`, `Relative`, `Symbolic` — and a review
explicitly proposed narrowing it to the first three. That narrowing was
considered and **not adopted**; the other two P0 recommendations from the same
review (renaming `width` to `bits`, and removing `Address.confidence`) were.
Without the record, six variants look like an oversight rather than a decision.
