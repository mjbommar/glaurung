# Architecture refactoring portfolio

> **Kind:** record · **Date:** 2026-08-13

Status: proposed execution plan. This directory converts the repository-wide
architecture review into bounded mini-projects. A checked box in an existing
roadmap is not evidence that one of these projects is complete; each project
has its own exit evidence.

The measured findings and prioritization rationale are recorded in the
[2026-08-13 architecture review](architecture-review-2026-08-13.md).

## Why these projects

Glaurung has real subsystem boundaries, extensive tests, and a growing
program-scoped semantic model. Its main design risk is that several source
files still own multiple stages or policies. The largest examples in the
current checkout are `src/ir/ast.rs`, the three ISA lifters,
`src/analysis/cfg.rs`, `src/python_bindings/ir.rs`,
`python/glaurung/cli/commands/windows.py`, and
`python/glaurung/llm/tools/windows_function_pretty_lift.py`.

File size is a diagnostic, not the objective. A split is successful only when
it creates one authoritative owner for a semantic contract, reduces permitted
dependencies, and preserves observable behavior.

## Portfolio order

| Order | Mini-project | Architectural result | Depends on |
|---:|---|---|---|
| 1 | [Program semantic authority](01-program-semantic-authority.md) | One program/session owner for images, symbols, types, and provenance | — |
| 2 | [IR and decompiler boundaries](02-ir-decompiler-boundaries.md) | Stage-oriented modules around verified typed MIR | 1 |
| 3 | [CFG and discovery decomposition](03-cfg-discovery-decomposition.md) | Discovery, graph model, validation, and algorithms separated | 1 |
| 4 | [Native/Python API boundary](04-native-python-api-boundary.md) | Thin PyO3 adapters over Rust application services | 1–3 |
| 5 | [Windows workflow decomposition](05-windows-workflow-decomposition.md) | CLI, fact extraction, rendering, and validation separated | 4 |
| 6 | [Knowledge-base boundaries](06-knowledge-base-boundaries.md) | Explicit repositories, migrations, and provenance rules | 1, 4 |
| 7 | [Execution and symbolic boundaries](07-execution-symbolic-boundaries.md) | Interpreter mechanism separated from exploration and solver policy | 2–3 |

Projects 2 and 3 may proceed in parallel after project 1 establishes the
shared contracts. Projects 5–7 can then proceed independently, provided their
boundary tests are in place.

## Rules shared by every project

1. Start with characterization tests over real checked-in binaries or durable
   database fixtures. Do not change behavior and module topology in the same
   unmeasured step.
2. Move code by ownership, not by line count. A new module needs a named input,
   output, invariants, and error/completeness behavior.
3. Preserve raw evidence and provenance. Convenience renderers and LLM-facing
   views must not become semantic authorities.
4. Unsupported or incomplete analysis remains explicit; extraction must never
   convert it into a successful empty result.
5. Land small vertical slices. Each commit must compile and pass the focused
   tests; temporary duplicate production implementations are forbidden.
6. Record baseline and post-change measurements in the project folder.

## Repository-wide completion gate

The portfolio is complete only when all project checklists are satisfied and:

```bash
uv run pytest
cargo test
uvx ruff format --check .
uvx ruff check .
uvx ty check
scripts/decbench-local-gate.sh
git diff --check
```

The full gate must be reported lane by lane. A skipped tool, missing corpus,
stale extension, or running CI lane is not a pass.

## Existing design authority

These projects execute rather than replace the semantic direction in
[`../design/decompiler-roadmap.md`](../design/decompiler-roadmap-2026-08-13.md),
[`../design/decompiler-middle-architecture.md`](../design/plans-superseded/decompiler-middle-architecture.md),
and [`../design/glaurung-architecture-redesign-2026-08-05.md`](../design/plans-superseded/glaurung-architecture-redesign-2026-08-05.md).
