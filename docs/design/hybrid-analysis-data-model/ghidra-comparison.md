# Glaurung and Ghidra decompiler architecture

> **Kind:** design · **Status:** proposed

This comparison is based on Glaurung at `8b02bd4b` and Ghidra 12.1.3 source.
It compares architecture and representation, not decompilation quality or
benchmark scores. The two projects have no matched quality population from
which such a conclusion could be drawn.

## Executive assessment

Both systems use a compiler-shaped path from machine instructions through a
low-level IR, SSA and data-flow analysis, recovered variables and types,
structured control flow, and C-like output. They differ in where semantic
authority lives.

Ghidra concentrates per-function knowledge in a powerful mutable universe:
`Funcdata` owns p-code operations, varnodes, unstructured and structured block
graphs, SSA heritage, variable merging, prototypes, calls, jump tables, and
overrides. Glaurung instead produces several explicit artifacts: LLIR, SSA,
MemorySSA, value numbering, high variables, types, a region tree, AST, health,
completeness, and provenance.

Ghidra is consequently more unified and mature. Glaurung is safer and more
auditable in several modern respects, but semantic meaning is fragmented across
more representations and more ordered passes.

The architectural lesson is not to copy Ghidra's database or mutable C++
design. It is to establish one authoritative function-level semantic graph
before allowing binary and runtime analysis to share more state.

## Structural correspondence

| Ghidra | Glaurung | Important difference |
|---|---|---|
| `ProgramDB` | `ProgramImage`, `ProgramSession`, and `.glaurung` KB | Ghidra is a transactional reverse-engineering database; Glaurung separates immutable image input, cached analysis, and persisted analyst facts |
| SLEIGH `Language` and compiler specification | `TargetSpec`, lifters, and ABI modules | Ghidra's instruction semantics are declarative and broadly retargetable; Glaurung's decompiler lifters are architecture-specific |
| address spaces and `Varnode` | `VReg`, `Value`, `MemOp`, and `ValueId` | Ghidra starts from general storage ranges; Glaurung starts from more convenient typed Rust variants |
| `PcodeOp` and `PcodeOpBank` | LLIR operations, blocks, and functions | Both provide machine-independent operations, but p-code and address spaces cover more unusual storage models |
| `Funcdata` | prepared LLIR plus pipeline-local analysis artifacts | Glaurung has no single structure with equivalent semantic authority |
| `Heritage` | `SsaInfo`, `VersionedSsa`, definedness, and MemorySSA | Glaurung exposes invalidation well; Ghidra integrates storage, phi placement, calls, and memory effects more deeply |
| `HighVariable` | high-variable, recovered-variable, and stack-local analyses | Ghidra's live-range/cover-based variable identity is more central |
| `BlockGraph` | LLIR CFG and `Region` | Glaurung makes recovered structure and health explicit |
| `CollapseStructure` | verified structure recovery | Ghidra has greater algorithmic maturity; Glaurung makes incomplete or rejected structure more visible |
| data-type managers and `TypeFactory` | `TypeStore`, type maps, and debug-type environment | Ghidra has a larger and more integrated type universe |
| Clang token tree | AST, `OriginSet`, line mappings, and renderers | Ghidra retains stronger token-to-semantic-node navigation |
| actions and rewrite rules | LLIR preparation and ordered AST passes | Ghidra iterates rules over shared semantic state; Glaurung has clearer pass attribution but more semantic repair after AST lowering |
| `FuncProto` and call specifications | `CallPrototype`, call contracts, and `ProgramEnvironment` | Glaurung's program environment is clean and demand-driven, but less comprehensive |

Primary Ghidra references are its
[`Funcdata`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh),
[`Heritage`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/heritage.hh),
[`HighVariable`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/variable.hh), and
[`CollapseStructure`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.hh)
sources. Glaurung's current path is described by the
[decompiler pipeline](../../architecture/decompiler-pipeline.md).

## Program ownership

Ghidra's `ProgramDB` is the shared backing store for memory, listing, symbols,
functions, references, types, relocations, context, bookmarks, transactions,
and undo. Analysers and UI tools collaborate by mutating that program model.

Glaurung uses a smaller ownership hierarchy:

- `ProgramImage` owns immutable bytes and indices derived from one parse;
- `ProgramSession` owns image-scoped discovery, call-graph, program-
  environment, type, and symbol artifacts; and
- the knowledge base persists analyst and automated facts with provenance and
  manual precedence.

This is a strong library boundary and should be preserved. `ProgramSession`
should grow by referencing runtime evidence collections, not by turning into a
mutable process emulator or project database.

## Instruction semantics and storage

SLEIGH translates instruction encodings into assembly and machine-independent
p-code. P-code uses explicit address spaces, varnodes, and operations so the
same analysis machinery can operate across processors. The
[SLEIGH documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/languages/html/sleigh.html)
is the authoritative overview.

Glaurung LLIR has valuable properties of its own: explicit bit widths,
endianness, predicates, flags, memory operands, call effects, and an executable
interpretation shared by concrete and symbolic execution. Those properties are
particularly useful for hybrid analysis because an observed register or memory
value can be evaluated against the same operation semantics used by the
decompiler.

The weakness is storage identity. A physical register represented principally
by a string is not a sufficient universal key for overlapping registers,
subregister writes, vector lanes, register banks, joined storage, processor
modes, or runtime register-set formats. Before runtime observations attach to
LLIR values, Glaurung needs architecture-defined storage identities and explicit
projection rules.

## SSA, memory, and variables

Both projects use dominance and phi-placement algorithms. Ghidra heritage,
however, constructs SSA over storage in address spaces and handles overlapping
locations, calls, loads, stores, and returns in the same per-function model.

Glaurung has good explicit components: SSA dominators, frontiers, versions,
definitions and uses; stable value identities; conservative versioned
invalidation; separate MemorySSA, value-numbering and definedness analyses; and
high-variable and stack-local recovery.

Explicit invalidation is preferable to silently consuming stale analysis.
Separation becomes a defect when the components disagree about value, storage,
memory-object, or variable identity. Runtime observations would amplify that
defect: a captured register value, a traced store, and a decompiler variable
must not attach to three unrelated identifiers.

Ghidra's `HighVariable` demonstrates the right foundation for source variable
recovery: group storage instances using live-range cover and interference
evidence, then attach symbol and type information. Glaurung should retain
confidence and provenance while adopting that centrality.

## Types, control flow, and rendering

Ghidra's persistent data-type managers, propagation rules, archives, symbols,
prototypes, and user overrides form a broader type system. Glaurung's
`TypeStore`, ABI recovery, debug types, and per-value facts preserve evidence
well but are distributed across more stages.

For control flow, Ghidra repeatedly collapses and transforms block graphs.
Glaurung builds a verified region tree from LLIR and returns explicit CFG health.
Ghidra wins on maturity; Glaurung has the better contract for evidence-sensitive
automation because unsupported or incomplete structure can remain visible.

Ghidra's token tree links rendered output back to high functions, p-code,
varnodes, symbols, and addresses. Glaurung has AST origins and line mappings,
but the desired public chain is not yet one first-class contract:

```text
rendered token
  → high-level expression or statement
  → semantic value and operation
  → source machine instruction
  → static address or correlated runtime observation
  → evidence and transformation history
```

Runtime evidence makes this linkage more important, not less. Rendering must
remain a projection of semantic facts rather than the place those facts are
invented.

## Pass algorithms

Ghidra applies large groups of rewrite and analysis rules over shared p-code
state, with controlled iteration and restart. This lets types, expressions,
variables, prototypes, and control structure improve one another.

Glaurung has a more visibly ordered pipeline with named, timed, health-traced
passes and deliberate SSA recomputation after invalidating changes. That is
excellent for reproducibility and fault attribution. Its present weakness is
the amount of semantic recovery and repair performed after AST lowering.

The preferred synthesis is:

1. retain named stages, budgets, fingerprints, health, and invalidation;
2. move semantic transformations into a central function graph;
3. allow bounded fixed points among types, variables, expressions, prototypes,
   and memory objects; and
4. lower to high-level structure and rendering only after those facts settle.

## The function-level target

Glaurung needs one authoritative interface, provisionally called `FunctionIR`:

```text
FunctionIR
  identity and target
  operations and machine origins
  architecture-defined storage locations
  semantic values and definition/use relationships
  CFG and recovered regions
  register SSA and MemorySSA
  memory-object references
  high variables and live-range covers
  types, prototypes, ABI, and call effects
  provenance, confidence, completeness, and invalidation versions
```

This need not be one giant mutable Rust structure. Immutable graph generations
and versioned sidecars fit Glaurung better. It does need one vocabulary and one
set of identities that every analysis recognises.

## What to borrow and what to preserve

Borrow from Ghidra:

1. general address-space and storage identities;
2. a central function semantic graph;
3. cover-based high-variable merging;
4. direct rendered-token-to-semantic-node linkage;
5. declarative or generated instruction semantics; and
6. controlled fixed-point interaction among semantic analyses.

Preserve from Glaurung:

1. immutable image inputs;
2. explicit budgets, unknowns, and incompleteness;
3. versioned invalidation rather than implicit mutation;
4. the executable LLIR shared by concrete and symbolic execution;
5. provenance and analyst-precedence rules;
6. structured results and pure renderers; and
7. typed refusal when a target or recovery is unsupported.

The goal is not a Rust clone of `Funcdata`. It is a safer semantic spine with
equivalent authority and better evidence discipline.
