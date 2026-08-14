# Architecture review baseline — 2026-08-13

This is the evidence snapshot behind the mini-project portfolio. It describes
commit `fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4`; the working tree also contained
active, unrelated decompiler and program-environment work, so this review does
not treat the checkout as a release candidate.

## Review method

The review traced the crate/package entry points, module declarations, current
design roadmaps, largest Rust and Python production files, representative
public entry points, and focused tests. File size was used to find possible
mixed ownership, then source responsibilities determined the projects.

Commands used for the reproducible inventory included:

```bash
find src -type f -name '*.rs' -printf '%s %p\n' | sort -nr
find python/glaurung -type f -name '*.py' -printf '%s %p\n' | sort -nr
wc -l <candidate files>
rg '^(pub )?(struct|enum|trait|fn)|^class |^def ' <candidate files>
```

Focused validation at review time passed 10 Python tests covering the local
gate and DWARF types, and six `program::session` Rust tests. The Rust run emitted
nine warnings. Those focused results characterize reviewed seams; they are not
a substitute for the repository-wide completion gate.

## Concentration evidence

| File | Lines | Responsibilities observed | Portfolio owner |
|---|---:|---|---|
| `src/ir/ast.rs` | 19,158 | AST model, transformations, traversal, rendering support | Project 2 |
| `src/ir/lift_x86.rs` | 8,556 | x86 decoding-to-LLIR semantics and helpers | Project 2 |
| `src/ir/call_args.rs` | 7,222 | ABI/call evidence and recovery policy | Projects 1–2 |
| `src/analysis/cfg.rs` | 7,125 | graph model, discovery, mutation, algorithms | Project 3 |
| `src/ir/types_recover.rs` | 6,812 | type evidence, inference, and rewriting | Projects 1–2 |
| `python/glaurung/llm/tools/windows_function_pretty_lift.py` | 6,046 | schemas, extraction, rendering, validation, tool adapter | Project 5 |
| `src/ir/stack_locals.rs` | 5,915 | stack identities, recovery, naming/render-facing policy | Project 2 |
| `src/ir/structure.rs` | 4,938 | graph structuring and AST construction | Projects 2–3 |
| `src/ir/value_number.rs` | 4,437 | value equivalence and rewrite policy | Project 2 |
| `python/glaurung/cli/commands/windows.py` | 4,027 | registration, dispatch, orchestration, persistence, formatting | Project 5 |
| `src/python_bindings/ir.rs` | 3,875 | PyO3 types, conversion, registration, orchestration | Project 4 |
| `src/symbolic/explore.rs` | 3,617 | state exploration and symbolic policy | Project 7 |
| `python/glaurung/llm/kb/xref_db.py` | 3,434 | storage schema/query and domain-facing xref operations | Project 6 |

Line count alone does not require a split. `lift_x86.rs`, for example, may
remain comparatively large if its instruction-family modules share one tested
semantic contract. Conversely, a smaller file that creates a second symbol or
type authority must be consolidated even if it never crosses a threshold.

## Architectural strengths to preserve

- Rust and Python already have recognizable subsystem directories.
- `src/program/` is establishing the right program/session ownership seam.
- The IR exposes unknown operations instead of silently dropping unsupported
  instructions.
- Feature gates separate concrete execution, symbolic execution, and solvers.
- The repository has extensive native, Python, fixture, corpus, and workflow
  tests, including fail-closed checks.
- Existing decompiler plans correctly prioritize typed value identity, memory
  objects, CFG completeness, and evidence provenance over more AST heuristics.

## Cross-cutting design findings

### 1. Semantic authority is still fragmented

Symbols, debug layouts, prototypes, address maps, and inferred facts can be
assembled in multiple layers. This makes project 1 foundational: downstream
module movement must consume a shared immutable environment rather than mint
new local authorities.

### 2. Pipeline stages are directories in concept, not consistently in code

`src/ir/mod.rs` exposes many peer modules even though their contracts form a
directed pipeline. The flat topology makes it easy for late presentation logic
to reach backward into recovery. Project 2 installs enforceable stage edges.

### 3. CFG truth and CFG operations need different owners

Discovery completeness is evidence about the binary and budgets; dominance or
SCC computation is a pure graph operation. Combining them increases the chance
that a convenient graph shape is mistaken for complete recovery. Project 3
separates those responsibilities.

### 4. Transport layers perform application work

Large binding and CLI modules do more than validate, translate, and dispatch.
Projects 4 and 5 introduce native/Python services and deterministic Windows
fact packets so presentation surfaces cannot become alternate pipelines.

### 5. Persistence and symbolic execution each need capability boundaries

Database schema/migration policy should not leak into agents, and solver result
semantics should not leak into path scheduling or security-specific analysis.
Projects 6 and 7 establish those narrower contracts.

## Prioritization rationale

Program authority comes first because every other project needs stable symbol,
type, image, target, and completeness inputs. IR and CFG work follows because
they define the semantic core. Bindings can then become thin over stable native
services. Windows workflows and the KB can be separated without inventing
another domain model, while execution/symbolic work can reuse the verified IR
and CFG contracts.

The portfolio intentionally does not prescribe a single giant rewrite. Each
project begins with characterization, permits compatibility facades during a
bounded migration, and forbids two live production authorities.

