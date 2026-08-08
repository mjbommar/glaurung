# Glaurung LLM tool system

This page documents the implemented tool architecture. It is a contributor
guide, not a generic pydantic-ai tutorial.

The core rule is simple: analysis logic lives in typed `MemoryTool` objects that
can be called directly and tested without a model. `tool_to_pyd_ai` adapts those
objects for agent use, captures display telemetry, and attempts persistent
evidence logging.

## Architecture

```text
question
  │
  ├─ deterministic router (`tool_routing.py`) selects tool names
  │
  └─ agent (`agents/memory_agent.py`)
       │
       └─ pydantic-ai Tool from `tool_to_pyd_ai`
            │
            └─ MemoryTool.run(MemoryContext, KnowledgeBase, Args)
                 ├─ reads bounded binary/project data
                 ├─ may add typed KB nodes or edges
                 └─ returns a Pydantic result model
```

The main implementation points are:

| Concern | Source |
| --- | --- |
| Atomic contract and wrapper | `python/glaurung/llm/tools/base.py` |
| Context and resource budgets | `python/glaurung/llm/context.py` |
| In-memory KB | `python/glaurung/llm/kb/store.py` |
| Persistent SQLite KB | `python/glaurung/llm/kb/persistent.py` |
| Registration | `python/glaurung/llm/agents/memory_agent.py` |
| Question routing | `python/glaurung/llm/tool_routing.py` |
| Operator entry point | `python/glaurung/cli/commands/ask.py` |

## `MemoryTool` contract

Every atomic tool defines:

- `ToolMeta`: stable provider-facing name, description, and optional tags;
- a Pydantic input model that validates arguments;
- a Pydantic output model with structured results;
- `run(ctx, kb, args)`, which performs the operation; and
- a `build_tool()` factory.

The abstract contract is `MemoryTool[InputModelT, OutputModelT]`. A minimal tool
has this shape:

```python
from pydantic import BaseModel, Field

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.store import KnowledgeBase
from glaurung.llm.tools.base import MemoryTool, ToolMeta


class CountStringsArgs(BaseModel):
    limit: int = Field(default=200, ge=1, le=10_000)


class CountStringsResult(BaseModel):
    total: int
    inspected: int


class CountStringsTool(MemoryTool[CountStringsArgs, CountStringsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="count_strings",
                description="Count strings in the current triage artifact.",
                tags=("strings", "triage"),
            ),
            CountStringsArgs,
            CountStringsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: CountStringsArgs,
    ) -> CountStringsResult:
        strings = list(ctx.artifact.strings.strings)
        return CountStringsResult(
            total=len(strings),
            inspected=min(len(strings), args.limit),
        )


def build_tool() -> MemoryTool[CountStringsArgs, CountStringsResult]:
    return CountStringsTool()
```

This is an architectural example. Before adding a new tool, search the existing
tool directory and CLI for equivalent behavior; reuse a deterministic primitive
instead of duplicating it under a new name.

## `MemoryContext` and budgets

`MemoryContext` carries the current file path, triage artifact, knowledge base,
session identifier, and `Budgets`. Tools must honor the applicable caps rather
than reading or expanding input without bounds. Current budget fields include
function, block, instruction, disassembly-window, result, read-byte, file-size,
and timeout limits.

Two KB modes matter:

- `MemoryContext(...)` defaults to an in-memory `KnowledgeBase`. This is what
  standalone `glaurung ask` currently uses.
- `MemoryContext.open_persistent(...)` opens a `PersistentKnowledgeBase` over a
  `.glaurung` SQLite project. The REPL constructs an equivalent context around
  its already-open project.

Do not infer persistence merely because a tool mutates `ctx.kb`. Confirm how the
caller built the context.

## Agent adaptation and evidence

`tool_to_pyd_ai(tool)` creates a pydantic-ai `Tool` from the input model's JSON
schema. Its call wrapper:

1. validates provider arguments through the Pydantic input model;
2. calls `MemoryTool.run`;
3. appends a structured entry to `ctx._tool_calls` for CLI display; and
4. when the KB is persistent, attempts to append an `evidence_log` row.

Evidence logging is best-effort and deliberately cannot break the underlying
analysis. A missing row is not proof a call did not occur. Failed calls can be
recorded with an error summary. See the
[evidence guide](../tutorial/05-agent-workflows/evidence-and-citations.md) for
the full boundary.

The wrapper derives a VA range or file offset only from recognized input/result
fields. Use conventional names such as `va`, `va_start`, `entry_va`,
`function_va`, `length`, or `file_offset` when they accurately describe the
tool; do not rename fields merely to influence evidence indexing.

## Registration and routing

`register_analysis_tools` is the canonical registry. It registers both wrapped
`MemoryTool` objects and a smaller number of custom agent functions. A
`tool_filter` set can restrict registration to exact tool names.

The `ask --route` path calls `route_for_question` and
`select_tools_for_question`. Routing is deterministic keyword matching, not an
extra model call. The current intents cover vulnerability discovery, triage,
function walks, imports, strings, and a broad fallback.

```python
from glaurung.llm.tool_routing import (
    route_for_question,
    select_tools_for_question,
)

question = "Explain function 0x401000 and its callers"
intent = route_for_question(question)
tool_names = select_tools_for_question(question)
```

If you add or rename a registered tool:

1. update every relevant routing intent;
2. keep each intent within the tested routing budget;
3. ensure each intent retains a lightweight orientation tool;
4. test unknown filters and provider-specific registration; and
5. update operator docs only when the user-visible capability changes.

Provider limits are separate from analysis budgets. The wrapper selects relaxed
strict-schema behavior for Anthropic models, while focused routing keeps the
tool list manageable for providers with total-tool limits. Do not solve a tool
limit by silently changing the configured model family.

## Direct integration testing

Test deterministic behavior by calling the real tool on a real checked-in
sample. This avoids provider cost and separates tool correctness from agent
selection:

```python
from pathlib import Path

import glaurung as g

from glaurung.llm.context import Budgets, MemoryContext
from glaurung.llm.tools.view_hex import BytesViewArgs, build_tool


def test_view_hex_reads_elf_magic() -> None:
    sample = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/"
        "hello-gcc-O2"
    )
    artifact = g.triage.analyze_path(str(sample))
    ctx = MemoryContext(
        file_path=str(sample),
        artifact=artifact,
        budgets=Budgets(max_read_bytes=64),
    )

    result = build_tool().run(
        ctx,
        ctx.kb,
        BytesViewArgs(file_offset=0, length=4, add_to_kb=True),
    )

    assert result.bytes_hex == "7f454c46"
    assert result.evidence_node_id is not None
```

Use a temporary persistent project in a second test when evidence logging or
cross-process persistence is part of the contract. Do not replace binary data,
the KB, or native analysis with mocks when an inexpensive real fixture exists.

Agent registration and routing can use pydantic-ai's local `test` model; that
checks wiring without sending a provider request. Existing examples are in
`python/tests/test_tool_routing.py`.

Focused gates:

```bash
uv run pytest python/tests/test_tool_routing.py -q
uv run pytest python/tests/test_verify_recovery_tool.py -q
uvx ruff check python/glaurung/llm/tools python/tests/test_tool_routing.py
uvx ty check python/glaurung/llm/tools python/tests/test_tool_routing.py
```

These are focused tool gates, not the full repository suite.

## Tool addition checklist

Before implementation:

1. identify the deterministic primitive and search for an existing tool;
2. define the user question and the narrow structured result it needs;
3. choose read-only versus mutating behavior explicitly;
4. define file, byte, function, instruction, result, time, and recursion bounds;
5. decide whether the tool requires a raw binary, a project DB, or either; and
6. write a failing real-fixture test.

During implementation:

1. validate all arguments in the Pydantic model and in `run` where context is
   required;
2. return a typed result for empty, partial, and complete outcomes;
3. use specific exceptions and avoid logging secrets or full sensitive blobs;
4. preserve provenance and truncation metadata;
5. keep mutations explicit and idempotent where practical; and
6. never call an LLM from a tool described as deterministic.

Before completion:

1. pass direct tool tests and negative/limit cases;
2. test registration and routing by exact name;
3. test persistent evidence if promised;
4. run focused format, lint, and type gates;
5. run the broader relevant agent/CLI tests; and
6. document provider transmission, cost, side effects, and limitations at the
   user-facing entry point.

## Operational safety

- Treat model output, decompiler output, and heuristic classifications as
  hypotheses until independently verified.
- Do not expose filesystem-wide reads, arbitrary writes, subprocess execution,
  or network access without narrow validation and an explicit user workflow.
- Enforce bounds inside the tool even if the caller normally supplies safe
  defaults.
- Keep raw binary analysis deterministic where possible; reserve model calls
  for ambiguity that cannot be resolved by a parser or query.
- Preserve the distinction between a tool observation, an agent inference, a
  validated finding, and a demonstrated impact.

For operator usage, return to the [`ask` reference](../cli/ASK_COMMAND.md).
