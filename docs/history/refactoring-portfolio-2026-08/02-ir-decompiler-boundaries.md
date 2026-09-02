# Mini-project 2: IR and decompiler boundaries

> **Kind:** record · **Date:** 2026-08-13

## Problem

`src/ir/` mixes machine lifting, SSA/data flow, semantic recovery, control-flow
structuring, AST representation, AST rewriting, and rendering. Several files
are large because they own multiple concepts: `ast.rs`, `types_recover.rs`,
`call_args.rs`, `stack_locals.rs`, `structure.rs`, and `value_number.rs`.

Mechanical splitting would leave the same coupling behind. The real boundary
must be the verified typed MIR described in the existing decompiler roadmap.

## Target pipeline

```text
machine instructions
  -> architecture lifter -> LLIR
  -> CFG-aware SSA + memory/object identities
  -> verified typed MIR
  -> semantic recovery services
  -> graph-complete HIR
  -> pure AST renderer
```

Every transition returns diagnostics and completeness. Rendered C is a view,
never an input to semantic recovery.

## Proposed directory shape

```text
src/ir/
  llir/          model, effects, validation
  lift/          shared contracts plus x86, arm32, arm64 adapters
  ssa/           value identity, phis, use-def, definedness, MemorySSA
  mir/           typed model, verifier, simplification
  recovery/      calls, stack objects, aggregates, globals, prototypes
  hir/           graph model, regions, fallback transfers, validation
  render/        AST model, C naming, formatting
  pipeline.rs    explicit orchestration only
```

These names describe ownership; implementation should migrate incrementally
and need not rename every module at once.

## Decomposing `ast.rs`

First classify its items into model, traversal, rewrite, validation, and render
owners. Move leaf concepts in this order:

1. immutable AST/HIR node definitions and visitor traits;
2. formatting/render policy;
3. traversal utilities;
4. individually named transformations with explicit pre/postconditions;
5. orchestration into the canonical pass pipeline.

No transformation may remain hidden in `Display`, constructors, or Python
conversion code.

## Phases

1. Capture dependency and size baselines plus public entry points.
2. Add stage-contract tests for unknown operations, widths, flags, memory
   objects, calls, and incomplete CFGs.
3. Make typed MIR verification mandatory before semantic recovery.
4. Move modules one owner at a time, preserving public facades temporarily.
5. Replace AST-local semantic guesses with MIR/program-environment queries.
6. Remove compatibility facades after all callers migrate; rerun corpus and
   behavior gates, not only generated-text metrics.

## Exit evidence

- There is one public pipeline entry point and one pass ordering.
- Lifters cannot import HIR, AST rendering, naming, or Python bindings.
- Render modules cannot mutate semantic facts.
- Every MIR-consuming pass declares required invariants and fails closed when
  they are absent.
- No production Rust source file in the reorganized pipeline exceeds 2,000
  lines without an explicit ownership justification in this folder.
- Exact CFG behavior and fixture semantics do not regress; GED is reported only
  alongside structural and behavioral gates.

## Stop conditions

Reject a split that adds cyclic dependencies, duplicates an IR type, changes
pass order implicitly, or improves pseudocode by discarding unknown effects or
unresolved edges.

