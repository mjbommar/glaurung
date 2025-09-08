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
    """Wrap a MemoryTool into a pydantic-ai Tool."""

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

    return Tool(
        _impl,
        name=tool.meta.name,
        description=tool.meta.description,
        strict=True,
    )
