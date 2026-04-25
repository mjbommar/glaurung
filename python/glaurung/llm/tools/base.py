from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, Type, TypeVar

from pydantic import BaseModel
from pydantic_ai import Tool, RunContext

from ..context import MemoryContext
from ..kb.store import KnowledgeBase


I = TypeVar("I", bound=BaseModel)
O = TypeVar("O", bound=BaseModel)


@dataclass
class ToolMeta:
    name: str
    description: str
    tags: tuple[str, ...] = ()


class MemoryTool(ABC, Generic[I, O]):
    """Atomic tool contract: a single responsibility and clear IO models."""

    meta: ToolMeta
    input_model: Type[I]
    output_model: Type[O]

    def __init__(self, meta: ToolMeta, input_model: Type[I], output_model: Type[O]):
        self.meta = meta
        self.input_model = input_model
        self.output_model = output_model

    @abstractmethod
    def run(self, ctx: MemoryContext, kb: KnowledgeBase, args: I) -> O: ...


def tool_to_pyd_ai(tool: MemoryTool[I, O]) -> Tool[MemoryContext]:
    """Wrap a MemoryTool into a pydantic-ai Tool.

    Side effects on every call:
      1. Append a `_tool_calls` entry on the context (CLI visualisation).
      2. **Record an evidence_log row** when the context's KB is a
         PersistentKnowledgeBase, so the agent's claims can cite this
         tool invocation by `cite_id` (#208 generic migration).
    """

    # Build a function taking RunContext
    def _impl(run_ctx: RunContext[MemoryContext], **kwargs) -> O:
        args_model = tool.input_model(**kwargs)
        ctx = run_ctx.deps
        result_model: O | None = None
        error_str: str | None = None
        try:
            result_model = tool.run(ctx, ctx.kb, args_model)
            return result_model
        except Exception as e:  # pragma: no cover - passthrough with logging
            error_str = str(e)
            raise
        finally:
            # Record tool call in context for CLI visualization
            try:
                # Attach a private call log list if missing
                calls = getattr(ctx, "_tool_calls", None)
                if calls is None:
                    calls = []
                    setattr(ctx, "_tool_calls", calls)
                entry = {
                    "tool": tool.meta.name,
                    "args": args_model.model_dump(),
                }
                if result_model is not None:
                    # Attempt to serialize pydantic result
                    try:
                        entry["result"] = result_model.model_dump()
                    except Exception:
                        entry["result"] = str(result_model)
                if error_str is not None:
                    entry["error"] = error_str
                calls.append(entry)
            except Exception:
                pass

            # #208 generic migration: record evidence whenever the KB
            # is persistent. The cite_id is held on the call entry so
            # callers (chat UI, repl, agent) can reference it.
            try:
                _record_tool_evidence(
                    ctx, tool.meta.name, args_model,
                    result_model, error_str,
                    last_call_entry=calls[-1] if calls else None,
                )
            except Exception:
                # Never let evidence-logging failures break the tool.
                pass

    return Tool(
        _impl,
        name=tool.meta.name,
        description=tool.meta.description,
        strict=True,
    )


def _record_tool_evidence(
    ctx: MemoryContext,
    tool_name: str,
    args_model: BaseModel,
    result_model: BaseModel | None,
    error_str: str | None,
    *,
    last_call_entry: dict | None = None,
) -> None:
    """Best-effort: write an evidence_log row for this tool call when
    the context's KB supports persistence. No-op otherwise.

    Picks a VA range from common result-model fields when available
    (`va`, `va_start`, `start_va`, `entry_va`) so cite filters by VA
    work correctly for tools that target a specific address.
    """
    kb = getattr(ctx, "kb", None)
    if kb is None:
        return
    # Persistent KB has a `binary_id` attribute; the in-memory KB
    # does not, so this filter naturally excludes the lightweight
    # path used by tests that don't open a project file.
    if not hasattr(kb, "binary_id"):
        return

    from ..kb.xref_db import record_evidence  # late import: avoids cycle

    args_dump: dict = {}
    try:
        args_dump = args_model.model_dump()
    except Exception:
        pass

    output_dump: dict | None = None
    if result_model is not None:
        try:
            output_dump = result_model.model_dump()
        except Exception:
            output_dump = None

    # Pick a VA range when the args / result obviously address one.
    va_start: int | None = None
    va_end: int | None = None
    file_offset: int | None = None
    for field_name in ("va", "va_start", "start_va", "entry_va", "function_va"):
        v = args_dump.get(field_name)
        if isinstance(v, int) and v > 0:
            va_start = int(v)
            break
    if va_start is None and output_dump:
        for field_name in ("va", "start_va", "entry_va"):
            v = output_dump.get(field_name)
            if isinstance(v, int) and v > 0:
                va_start = int(v)
                break
    if va_start is not None:
        # Try to compute an exclusive end from the args (length /
        # window_bytes / max_scan_bytes) so VA-range queries narrow
        # cleanly. Falls back to a 1-byte point span otherwise.
        for field_name in ("length", "window_bytes", "max_scan_bytes", "size"):
            v = args_dump.get(field_name)
            if isinstance(v, int) and v > 0:
                va_end = va_start + int(v)
                break
        if va_end is None:
            va_end = va_start + 1

    if va_start is None:
        # File-offset fallback so tools like view_hex(file_offset=…) get
        # filterable rows.
        for field_name in ("file_offset", "offset"):
            v = args_dump.get(field_name)
            if isinstance(v, int) and v >= 0:
                file_offset = int(v)
                break

    if error_str:
        summary = f"{tool_name}: error — {error_str[:120]}"
    else:
        summary = _summary_for_tool(tool_name, args_dump, output_dump)

    cite_id = record_evidence(
        kb,
        tool=tool_name,
        args=args_dump,
        summary=summary,
        va_start=va_start, va_end=va_end,
        file_offset=file_offset,
        output=output_dump,
    )
    if last_call_entry is not None:
        last_call_entry["cite_id"] = cite_id


def _summary_for_tool(
    tool_name: str, args: dict, output: dict | None,
) -> str:
    """Produce a 1-line summary suitable for the chat-UI cite table.
    Tools with structured outputs whose shape we know get a tailored
    line; everything else falls back to a generic label."""
    if output:
        # view_hex / scan_until_byte both report `length` / `bytes_consumed`.
        if "length" in output and "bytes_hex" in output:
            n = output.get('length')
            va = args.get('va')
            if va:
                where = hex(va)
            else:
                where = f"off:{args.get('file_offset')}"
            return f"{tool_name}: {n}b @ {where}"
        if "found" in output and "sentinel_value" in output:
            if output.get("found"):
                return (
                    f"{tool_name}: hit 0x{output.get('sentinel_value', 0):02x} "
                    f"at off {output.get('sentinel_offset')}"
                )
            return f"{tool_name}: no sentinel within {output.get('bytes_consumed')}b"
        if "matches" in output:
            ms = output.get("matches") or []
            return f"{tool_name}: {len(ms)} match(es)"
        if "evidence_node_id" in output:
            return f"{tool_name}: ok"
    if "va" in args:
        return f"{tool_name} @ {hex(args['va'])}"
    if "file_offset" in args:
        return f"{tool_name} @ off {args['file_offset']}"
    return tool_name
