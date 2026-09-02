# Glaurung architecture review diary — 2026-08-05

> **Kind:** record · **Date:** 2026-08-13

This is the evidence log for the architecture review synthesized in
[glaurung-architecture-redesign-2026-08-05.md](../plans-superseded/glaurung-architecture-redesign-2026-08-05.md).
It deliberately records observations before recommendations so that later
decisions can be checked against the repository state that motivated them.

## Scope and review boundary

The review covers the five requested themes:

1. a program-level symbol and type environment;
2. symbolic rendering and interpretation of constant operands, not only calls;
3. aggregate and structure recovery;
4. an architecture-parametric machine model, with ARM32 as the stress case; and
5. a sound definedness and reaching-definitions oracle.

It also examines how those themes interact with lifting, LLIR, SSA, decompilation,
general binary analysis, module composition, source-file size, performance, and
failure safety.

The checkout began at `89b220e` on `master`, equal to `origin/master`. It already
contained unrelated modified and untracked decompiler work. This review therefore
adds documentation only and does not edit or normalize any existing source or
design file.

## Pass 0 — governing documents and prior architecture work

- `CLAUDE.md` defines Glaurung as a safe-Rust analysis core with Python as the
  analyst surface, requires real-fixture TDD, and identifies decompiler quality as
  an active frontier.
- `docs/design/decompiler-middle-architecture.md` already identifies the need for
  an authoritative typed SSA/MIR between executable LLIR and structured HIR. Its
  key separation — machine sort, operation interpretation, and recovered source
  type — remains the right semantic foundation.
- `docs/architecture/2026-07-13-architecture-quality-review.md` identifies the
  broader missing runtime: a reusable analysis session, explicit pass dependencies
  and invalidation, a durable project repository, and bounded partial-result
  behavior.
- The current review must connect these two designs. A typed function-local middle
  IR without a program environment cannot keep callee signatures, globals,
  relocations, strings, aggregate layouts, and cross-function evidence coherent. A
  program session without verified function-level semantics merely caches
  inconsistent answers.

## Pass 1 — size and ownership baseline

The following measurements include Rust under `src/` and Python under
`python/glaurung/`, excluding tests, tools, generated artifacts, and bundled
reference implementations:

| Scope | Files | LOC | Mean | Median | Files over 1,000 LOC | LOC in those files |
|---|---:|---:|---:|---:|---:|---:|
| Rust + Python product code | 638 | 352,200 | 552.0 | 309.5 | 71 | 166,880 (47.4%) |
| `src/ir` | 53 | 97,745 | 1,844.2 | 1,014.0 | 27 | 83,005 (84.9%) |
| `src/analysis` | 27 | 22,113 | 819.0 | 353.0 | 5 | 14,001 (63.3%) |

The largest IR files are not merely large containers:

| File | LOC | Initial ownership concern |
|---|---:|---|
| `src/ir/ast.rs` | 15,385 | HIR data model, lowering, rewriting, validation, and tests |
| `src/ir/lift_x86.rs` | 7,913 | decode semantics, machine-state policy, and architecture utilities |
| `src/ir/call_args.rs` | 6,201 | ABI evidence, reaching definitions, call rewriting, and tests |
| `src/ir/types_recover.rs` | 5,467 | constraint collection, type decisions, rewriting, and tests |
| `src/ir/stack_locals.rs` | 5,141 | stack analysis, recovery policy, AST transformation, and tests |
| `src/ir/structure.rs` | 4,823 | graph analysis, region selection, lowering policy, and tests |
| `src/ir/lift_arm32.rs` | 3,847 | ARM-specific semantics with fewer shared abstractions than x86 |
| `src/ir/copy_prop.rs` | 3,826 | several optimization and semantic-cleanup responsibilities |
| `src/ir/value_number.rs` | 3,660 | value equivalence plus architecture- and pass-specific policy |
| `src/ir/lift_arm64.rs` | 3,506 | AArch64 instruction semantics and state effects |

The raw target should not be “every file below 1,000 lines.” The meaningful target
is one reason to change per module, narrow public interfaces, and test modules kept
outside production implementation files. File-size reduction should be a measured
consequence of those ownership changes.

## Questions carried into the code trace

- Where is the authoritative identity for a program symbol, a recovered type, a
  machine value, a memory object, and a definition?
- Which stage is allowed to turn an address-valued constant into a symbol, string,
  relocation, enum member, field address, or plain integer?
- Are aggregate layouts constraints over memory objects or late AST-printing
  guesses?
- Which pieces of x86, AArch64, and ARM32 lifting implement the same machine
  concepts differently, and which differences are genuinely architectural?
- Which transformations ask “what reaches here?” and how many incompatible local
  implementations answer that question?
- Where can incomplete evidence silently become plausible C?

## Pass 2 — the pipeline and its actual ownership boundaries

The public decompiler paths share a useful `run_ast_passes` helper, but they do
not yet share a decompiler pipeline. `decompile_at`, the range path, the all-functions
path, and the batched-address path each assemble discovery, lifting, ABI annotation,
SSA, structuring, value numbering, direct-callee recovery, lowering, AST passes,
type recovery, and rendering. Differences between those copies are therefore API
semantics rather than an explicit configuration.

The largest duplication is program setup. Depending on the entry point, the code
rebuilds some or all of these independent views of the same image:

- a flat address-to-name map;
- strings and read-only data;
- function-pointer tables;
- DWARF function/type records and PDB fields;
- discovered functions and the call graph; and
- direct-callee prototype and argument-layout caches.

There are 66 direct `object::read::File::parse`/`Object::parse` call sites in 31
Rust files. That count does not mean every decompilation executes all 66. It does
show that image ownership and derived-index reuse are not architectural
constraints. Direct-callee recovery is a particularly revealing local repair: it
lifts callees on demand into a cache scoped to one top-level operation instead of
asking a persistent program model for iteratively refined call facts.

`prepare_for_decbench_with_output` is a second, output-style-specific pipeline. It
runs a long ordered list of semantic transformations, including bounded repeated
passes. The implementation clones the complete HIR to detect a fixed point. The
renderer also maintains substantial type/name state in thread-local variables.
This makes rendering more than a pure projection and makes pass order difficult to
test independently from one output target.

The common helper is progress, but the missing abstraction is a typed pipeline
whose stages declare required and preserved analyses. A caller should select a
pipeline profile, not reconstruct a pass graph.

## Pass 3 — the five requested epics

### EPIC 1 — program-level symbols and types

There are good building blocks, but no authoritative program environment:

- `core::symbol::Symbol` models symbol kind, binding, visibility, address, and a
  source;
- `core::data_type::DataType` models recursive source types including structures,
  unions, enums, arrays, functions, pointers, and typedefs;
- DWARF and PDB each expose another aggregate/prototype model;
- the decompiler has `TypeMap`, `TypeMapV`, `TypeHint`, `PdbFieldMap`, prototype
  maps, string pools, read-only-data maps, and function-table records; and
- the Python knowledge base persists another set of types, fields, labels, and
  prototypes.

The decompiler usually collapses symbols to `HashMap<u64, String>`. That loses
symbol kind, size/range, binding, aliases, relocation addends, import/thunk
relationships, and evidence provenance. `TypeHint` is a small value-category
lattice, not a link to the richer recursive `DataType` model. Debug types enter
late as strings or printing hints instead of becoming constraints in a shared type
store.

The resulting problem is not merely duplication. Two facts cannot be compared or
merged coherently when they do not share identity. A manual analyst correction,
debug declaration, relocation-derived reference, ABI inference, and heuristic type
guess need to coexist with explicit authority and conflict reporting. Last-writer
wins is not safe enough for reverse engineering.

### EPIC 2 — constant operands as contextual references

The lifters preserve an important distinction for some operands: direct control
targets and recognized PC-relative address construction become `Value::Addr`,
while ordinary immediates become `Value::Const`. The distinction is incomplete:

- `name_resolve` primarily rewrites `Expr::Addr`;
- string recovery has special logic that reinterprets `Expr::Const` in selected
  call arguments and reconstructs AArch64 address idioms;
- read-only folding accepts either `Addr` or `Const`; and
- function-table recovery reparses relocations and sections independently.

These are symptoms of a missing reference model. The same bits can be an integer,
an enum member, a mapped address, a relocation plus addend, a string, a global, a
function pointer, or a field offset. A global rule such as "mapped integer means
address" would be wrong. Resolution must be attached to the operand use and backed
by evidence: relocation first, then decoded operand role and PC semantics, mapped
section properties, data-flow use, prototype/type constraints, and xrefs.

The machine value must remain available even after symbolization. Rendering a
symbol is a reversible interpretation of exact-width bits, not destructive
replacement of the bits with a name.

### EPIC 3 — aggregate recovery

Debug-data ingestion can recover real layouts, and stack recovery records some
object-like facts. Those facts do not meet in one semantic model. Today a PDB field
is represented as `Expr::PdbFieldAddr` with candidates selected largely by offset;
DWARF field annotation runs another local propagation and AST walk. The HIR has no
`ObjectId`, `TypeId`, semantic field access, or array-index access path. Hidden
aggregate returns are recognized in places but are not modeled end to end as ABI
object transfer.

Aggregate recovery needs memory-object identity before it needs pretty field
names. Each stack, global, heap, TLS, or parameter-pointee object should accumulate
access constraints: offset, width, read/write role, alignment, stride, lifetime,
overlap, and source instruction. Layout solving can then distinguish structure,
array, union/overlay, and unknown byte region, import exact debug layouts as strong
evidence, and retain conflicts rather than forcing one attractive spelling.

### EPIC 4 — architecture-parametric machine semantics

Architecture identity is currently split among at least three enums:
`core::binary::Arch`, `core::disassembler::Architecture`, and
`ir::regview::Arch`. They do not even use the same AArch64 spelling, and the
register-view enum supports only x86-64 and AArch64. Calling-convention and endian
models form further separate axes without one validated target descriptor.

The practical consequence is visible in shared IR code. `phys_reg_width` derives a
width from a string without an architecture and documents the `sp` collision;
SSA parent canonicalization tries x86-64 and AArch64 views, not ARM32; the execution
register model has the same two-architecture boundary. ARM32 has a substantial
lifter and hard-float-specific recovery, but it cannot participate in the same
register alias, SSA, and execution contracts. It is structurally second-class,
not merely behind in instruction coverage.

ARM32 is the right conformance target because it forces the design to separate ISA,
mode (A32/Thumb), endian, pointer/address width, register banks, condition-code
semantics, PC bias/literal pools, VFP aliases, and ABI choice. If those remain
strings and scattered `match` statements, adding more architectures will multiply
the current problem.

### EPIC 5 — definedness and reaching definitions

No current component is a sound shared oracle:

- `use_def` explicitly performs only intra-block reaching definitions;
- SSA versions registers but not memory, and version zero represents live-in
  reads rather than an explicit input definition;
- the LLIR verifier can prove that a temporary is written somewhere without
  proving that its definition dominates a use;
- the HIR verifier deliberately uses may-defined joins and skips flow-sensitive
  checks for goto/label functions; and
- several AST passes implement their own local definition maps and backward scans.

These are reasonable scoped tools, but treating any one of them as a semantic
oracle would be unsound. `def_uses` also has a single-definition return shape and
therefore records only the first output of a multi-output intrinsic.

A foundational value graph must distinguish explicit function input, concrete
definition, undefined architectural value, poison, unknown/unmodeled effect,
unreachable code, and incomplete graph. Memory requires versioned effects or a
region-aware MemorySSA equivalent. Calls and intrinsics must declare all register
and memory reads/writes. This analysis belongs on CFG-based MIR; trying to recover
sound reaching definitions from an already structured syntax tree is the wrong
layer.

## Pass 4 — lifting, completeness, and failure semantics

Function discovery has recently become materially safer than older architecture
notes describe. `FunctionDiscoveryStats` reports function/block/instruction limits,
per-function and total timeout, pending seeds, unresolved indirect transfers, and
resolved dispatches. Discovery is cancellable, and comments explicitly identify
these as completeness facts.

The facts do not survive the usual boundaries:

- convenience discovery APIs discard the stats;
- `Function` does not carry per-function completeness or diagnostics;
- `LlirFunction` contains only entry VA and blocks; and
- `lift_function_from_bytes` returns `Option`, silently skips blocks whose bytes
  cannot be mapped or whose ranges clip out, and drops successors to omitted
  blocks.

That means a correctly detected incomplete CFG can still become an apparently
ordinary LLIR/HIR function. The redesign should retain the existing discovery
telemetry and make completeness monotone: a downstream artifact can become less
trusted, never silently more complete.

The LLIR itself has further semantic holes. Values are untyped `Reg`, signed
`Const(i64)`, or `Addr(u64)`; temporary widths are inferred from producing ops;
`LlirFunction` has no target descriptor or explicit inputs. The boundary does
lower residual unknown instructions into intrinsics, which is a useful single
migration point, but unsupported or partial semantics still need typed diagnostics
and declared effects.

## Pass 5 — composition and large-file causes

Inline tests explain a meaningful part of the largest modules but not the core
problem:

| File | Total LOC | First top-level `cfg(test)` | Approx. production prefix |
|---|---:|---:|---:|
| `ast.rs` | 15,385 | 9,622 | 9,621 |
| `lift_x86.rs` | 7,913 | 4,447 | 4,446 |
| `call_args.rs` | 6,201 | 2,913 | 2,912 |
| `types_recover.rs` | 5,467 | 2,998 | 2,997 |
| `structure.rs` | 4,823 | 2,535 | 2,534 |
| `lift_arm32.rs` | 3,847 | 2,464 | 2,463 |

Moving tests would improve navigation but would not create architectural
boundaries. Concrete responsibility mixtures include:

- `ast.rs`: semantic model, LLIR/region lowering, transformations, output-specific
  preparation, three renderers, render-time type state, identifier analysis, and
  tests;
- lifters: decode adapters, instruction-family semantics, flag policy, register
  alias semantics, ABI-adjacent behavior, and tests;
- `call_args.rs`: ABI classification, definition discovery, call-site inference,
  and HIR rewriting; and
- `types_recover.rs`: evidence collection, constraint joining, prototype recovery,
  architecture-specific ABI behavior, and display type selection.

HIR traversal is duplicated with every new variant: `Expr::PdbFieldAddr` is
matched in 24 IR files and `Stmt::If` in 34. This is strong evidence for shared
visitors/rewriters and for moving semantic operations out of variant-by-variant
printing passes.

## Pass 6 — external reference check

The bundled `reference/kuna` checkout is at `a9e72a97` (tag `v1.11`). Its useful
comparative ideas are semantic, not cosmetic:

- a program database owns symbols, scopes, range queries, architecture, and a type
  factory;
- typed arena IDs give operations, blocks, and values stable identity;
- each value records its definition and descendant uses;
- function-local graph mutation is centralized; and
- analysis is organized into explicit phases from knowledge acquisition through
  lifting, data flow, calls, types, variables, regions, structuring, and emission.

Kuna also contains very large implementation files, so copying its file layout
would not solve Glaurung's maintainability goal. The lesson is to adopt stable
semantic identity, central graph ownership, and phase contracts while keeping
Glaurung's implementation modules small and independently testable.

## Working synthesis before the final plan

The five epics are not five independent features. Their dependency chain is:

```text
Program image + TargetSpec
          |
          +--> typed LLIR/MIR + explicit effects --> sound value/definedness graph
          |
          +--> ProgramEnv --> contextual references --> type/layout constraints
                                      |                         |
                                      +-------------------------+
                                                   |
                                   semantic HIR --> pure renderers
```

The dangerous sequencing would be to add more AST symbolization or aggregate
heuristics before value identity, target semantics, and program facts have a home.
The practical sequencing should preserve output while first installing the session
and pipeline seams, then make correctness foundations explicit, and only then move
the active constant-symbolization work onto those foundations.
