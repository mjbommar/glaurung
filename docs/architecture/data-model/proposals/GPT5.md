# Data Model Proposals (GPT5)

## Notes
- Scope focuses on foundational domain objects (binaries, layout, code repr) and pipeline objects (artifacts, tasks, tools) that enable incremental analysis.
- Types use simple names for clarity; exact Rust/Python representations can refine later.

---

# Address

## Purpose
Canonical location within a binary's addressing scheme, supporting VA, RVA, and file offsets, with optional segmented spaces.

## Fields
- `kind`: One of `VA`, `RVA`, `FileOffset`.
- `value`: Unsigned 64-bit integer value for the address.
- `space?`: Optional string/identifier for segmented spaces (e.g., `CODE`, `DATA`, selector).
- `bits`: Address width: `32` or `64`.

---

# AddressRange

## Purpose
Half-open range describing a contiguous region in the binary address space.

## Fields
- `start`: The `Address` at which the range begins (inclusive).
- `size`: Unsigned 64-bit length in bytes.
- `end`: Derived convenience field: `start + size` (exclusive), provided for ergonomics.
- `alignment?`: Optional alignment in bytes.

---

# Binary

## Purpose
Top-level descriptor for an input program under analysis.

## Fields
- `id`: Stable `BinaryId` (e.g., SHA256 or UUID derived from content + path).
- `path`: Filesystem path to the binary.
- `format`: One of `ELF`, `PE`, `MachO`, `Wasm`, `Raw`, `Unknown`.
- `arch`: One of `x86`, `x86_64`, `arm`, `aarch64`, `mips`, `ppc`, `riscv`, `unknown`.
- `bits`: `32` or `64`.
- `endianness`: `Little` or `Big`.
- `entry?`: Optional entry `Address` (if known).
- `size_bytes`: Unsigned 64-bit size of the file.
- `hashes`: `{ sha256: string, md5?: string }`.
- `timestamps?`: Optional map of source-specific timestamps (e.g., PE header timestamp).
- `uuid?`: Optional binary UUID/Build ID (e.g., Mach-O UUID, ELF build-id).

---

# Segment

## Purpose
Memory mapping unit used at load time; large regions with permissions.

## Fields
- `id`: Stable identifier within a `Binary`.
- `name?`: Optional name/label (e.g., `LOAD0`).
- `range`: `AddressRange` in VA space.
- `perms`: Combination of `r`, `w`, `x` (read/write/execute).
- `file_offset`: `Address` of type `FileOffset` for start in file.
- `alignment?`: Optional alignment in bytes.

---

# Section

## Purpose
Format-level organization unit (e.g., `.text`, `.data`) with flags and type.

## Fields
- `id`: Stable identifier within a `Binary`.
- `name`: Section name.
- `range`: `AddressRange` in VA or RVA space (as appropriate for the format).
- `flags`: Bitflags (e.g., `ALLOC`, `EXEC`, `WRITE`).
- `type?`: Optional type tag (e.g., `PROGBITS`, `NOBITS`, `INIT_ARRAY`).
- `file_offset`: `Address` of type `FileOffset` for section start in file.

---

# Symbol

## Purpose
Named program entity discovered from debug info, import/export tables, or heuristics.

## Fields
- `id`: Stable symbol id.
- `name`: Mangled or exported name.
- `demangled?`: Optional demangled name.
- `kind`: One of `Function`, `Object`, `Section`, `Import`, `Export`, `Thunk`, `Other`.
- `address?`: Optional `Address` if known (not all imports have VA).
- `size?`: Optional byte length.
- `binding?`: One of `Local`, `Global`, `Weak` (if applicable).
- `module?`: Optional source module/library (e.g., `KERNEL32.dll`).
- `source`: Origin: `DebugInfo`, `ImportTable`, `ExportTable`, `Heuristic`, `PDB`, `DWARF`, etc.

---

# Reference

## Purpose
Directed relationship between two locations or entities (cross-references/xrefs).

## Fields
- `id`: Stable reference id.
- `from`: `Address` of the referring site.
- `to?`: Optional `Address` of the target (may be unresolved at creation time).
- `kind`: One of `Call`, `Jump`, `Branch`, `Read`, `Write`, `Reloc`, `DataRef`.
- `width?`: Optional width/size in bits (for memory refs or immediates).
- `confidence`: Float `0.0–1.0` indicating detection confidence.
- `source`: Tool or pass that produced the reference.

---

# Instruction

## Purpose
Decoded machine instruction at a specific address, with text and bytes.

## Fields
- `address`: `Address` of this instruction.
- `bytes`: Byte array for the instruction encoding.
- `mnemonic`: Lowercase mnemonic (e.g., `mov`, `bl`).
- `operands`: List of textual operands (opaque initially; can be structured later).
- `length`: Length in bytes.
- `arch`: Architecture tag matching the `Binary`.
- `is_branch?`: Optional bool indicating branch instruction.
- `is_call?`: Optional bool indicating call instruction.
- `is_ret?`: Optional bool indicating return instruction.

---

# BasicBlock

## Purpose
A `BasicBlock` is a fundamental unit of a Control Flow Graph. It represents a straight-line sequence of code with no jumps in or out, except at the very beginning and very end.

## Fields
- `start_address`: The `Address` of the first instruction in the block.
- `end_address`: The `Address` of the last instruction in the block.
- `instructions`: A list of `Instruction` objects that make up the block.
- `successors`: A list of `Address`es pointing to the start of subsequent basic blocks.
- `predecessors`: A list of `Address`es of the blocks that can branch to this one.

---

# Function

## Purpose
Callable code region identified via symbols or analysis, aggregating blocks and metadata.

## Fields
- `id`: Stable function id.
- `name?`: Optional function name (demangled preferred when available).
- `entry`: Entry `Address`.
- `range?`: Optional `AddressRange` covering the function body (if known).
- `blocks`: List of `BasicBlock` identifiers or embedded blocks.
- `calls_out`: List of `Address`es called by this function.
- `called_by`: List of `Address`es that call this function (populated later).
- `conv?`: Optional calling convention string/tag.
- `symbol_id?`: Optional linkage to a `Symbol` if derived from symbol tables.

---

# ControlFlowGraph

## Purpose
Graph representation of control flow within a function or region.

## Fields
- `function_id?`: Optional associated `Function` id (if per-function graph).
- `blocks`: List of `BasicBlock` nodes.
- `edges`: List of `{ from: Address, to: Address, kind: `Fallthrough|Branch|Call|Return` }`.

---

# CallGraph

## Purpose
Interprocedural call relationships among discovered functions.

## Fields
- `nodes`: List of `Function` ids.
- `edges`: List of `{ caller: FunctionId, callee: FunctionId }` pairs.

---

# StringLiteral

## Purpose
Extracted printable string within the binary for heuristics and navigation.

## Fields
- `address`: `Address` where the string begins.
- `value`: Extracted string contents.
- `encoding`: One of `Ascii`, `Utf8`, `Utf16`, `Utf32`, `Unknown`.
- `length_bytes`: Total byte length including terminator if applicable.
- `referenced_by?`: Optional list of `Address`es of instructions referencing this string.

---

# Artifact

## Purpose
Typed result envelope persisted by tools/passes, enabling caching, provenance, and incremental workflows.

## Fields
- `id`: Stable artifact id.
- `tool`: `ToolMetadata` describing the producing tool.
- `created_at`: Timestamp.
- `input_refs`: List of input `Artifact` ids this result depends on.
- `schema_version`: Version string for the data payload schema.
- `data`: Tool-specific typed payload (e.g., `Binary`, `[Section]`, `[Instruction]`).
- `meta?`: Optional free-form metadata (e.g., feature flags, parameters).

---

# ToolMetadata

## Purpose
Identity and configuration of a tool or pass that produces artifacts.

## Fields
- `name`: Unique tool name (e.g., `identify`, `loader.lief`, `disasm.capstone`).
- `version`: Semantic version or git SHA.
- `parameters?`: Optional map of parameter names to values.
- `source_kind?`: Classification such as `Static`, `Dynamic`, `Heuristic`, `External`.

---

# Task

## Purpose
Execution record for running a tool with given inputs to produce artifacts, with status and metrics.

## Fields
- `id`: Stable task id.
- `tool`: `ToolMetadata` snapshot at execution time.
- `input_artifacts`: List of `Artifact` ids provided as inputs.
- `status`: One of `Queued`, `Running`, `Completed`, `Failed`, `Partial`.
- `started_at?`: Optional start timestamp.
- `finished_at?`: Optional end timestamp.
- `error?`: Optional structured error `{ kind, message, backtrace? }`.
- `metrics?`: Optional resource stats `{ duration_ms, cpu_time_ms?, max_rss_bytes? }`.
- `logs_ref?`: Optional path or reference to task-scoped logs.

---

# Workspace

## Purpose
Physical layout and paths for storing analyses, artifacts, logs, and manifests for one or more binaries.

## Fields
- `root`: Filesystem root for the workspace.
- `analyses_dir`: Directory where per-binary analysis data is stored.
- `artifacts_dir`: Directory containing artifact payloads.
- `manifests_dir`: Directory containing per-binary manifests and indices.
- `logs_dir`: Directory for task and tool logs.
- `cache_dir?`: Optional directory for deduplicated caches.

---

# Manifest

## Purpose
Per-binary index of artifacts, their relationships, and quick-look metadata.

## Fields
- `binary_id`: Associated `Binary` id.
- `created_at`: Timestamp when the manifest was initialized.
- `artifacts`: List of `{ id, tool_name, kind, created_at }` summary entries.
- `dependencies`: List of edges `{ from_artifact: ArtifactId, to_artifact: ArtifactId }`.
- `latest_of_kind`: Map `{ kind -> ArtifactId }` for quick resolution.

---

# Enumerations

## Purpose
Common enums referenced by the core types.

## Items
- `Endianness`: `Little`, `Big`.
- `Format`: `ELF`, `PE`, `MachO`, `Wasm`, `Raw`, `Unknown`.
- `Arch`: `x86`, `x86_64`, `arm`, `aarch64`, `mips`, `ppc`, `riscv`, `unknown`.
- `Perms`: Bitflags `r`, `w`, `x` for segments/sections.
- `ReferenceKind`: `Call`, `Jump`, `Branch`, `Read`, `Write`, `Reloc`, `DataRef`.
- `AddressKind`: `VA`, `RVA`, `FileOffset`.

---

# Minimal Artifacts by Phase

## Purpose
Anchor early pipeline outputs to concrete types to validate the model.

## Items
- `Identify`: `Artifact<data = Binary>` created from hashing + format/arch detection.
- `Layout`: `Artifact<data = { segments: [Segment], sections: [Section] }>` produced by loader.
- `Symbols`: `Artifact<data = [Symbol]>` combined from imports/exports and debug info where available.
- `Disassembly`: `Artifact<data = [Instruction]>` produced per region/function, arch-aware.
- `Xrefs`: `Artifact<data = [Reference]>` derived from disassembly and relocations.
- `Strings`: `Artifact<data = [StringLiteral]>` with addresses and encodings.
- `CFG`: `Artifact<data = { functions: [Function], blocks: [BasicBlock], edges: [...] }>` per binary or per-function.

---

# Open Questions

## Purpose
Capture known decisions to be refined during implementation without blocking initial scaffolding.

## Items
- Should `Address.bits` be implicit from `Binary.bits` once attached to a specific binary? Kept explicit for portability across artifacts.
- Operand structure: start as opaque strings; evolve to typed operands when IR lands.
- `Function.range`: best-effort vs authoritative; prefer block-derived coverage.
- Multi-binary projects: project-level manifest vs per-binary manifests; start per-binary.
- Artifact storage: JSON lines vs JSON blobs; start with JSON blobs per artifact id.

---

# Summary
This proposal defines a lean, typed nucleus for binary description (Binary, Segment, Section, Symbol), code representation (Instruction, BasicBlock, Function, Graphs), and the pipeline envelope (Artifact, Task, ToolMetadata, Manifest, Workspace). It is intentionally minimal but sufficient to ship early phases (Identify, Layout, Symbols, Disassembly, Xrefs, Strings) while leaving room to evolve toward IR and dynamic analysis.

