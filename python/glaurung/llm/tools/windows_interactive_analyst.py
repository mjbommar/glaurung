"""Memory-tool wrapper for the deterministic Windows analyst workflow."""

from __future__ import annotations

from ..agents.windows_interactive_analyst import (
    WindowsInteractiveAnalystConfig,
    WindowsInteractiveAnalystResult,
    run_windows_interactive_analyst,
)
from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class WindowsInteractiveAnalystTool(
    MemoryTool[WindowsInteractiveAnalystConfig, WindowsInteractiveAnalystResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_interactive_analyst",
                description=(
                    "Run a bounded deterministic Windows analyst intent such as "
                    "explaining a function start, reviewing boundary gaps, "
                    "building a triage queue, reviewing a patch diff, or handing "
                    "off a candidate packet. This is not a vulnerability claim."
                ),
                tags=("windows", "agent", "analyst", "interactive", "triage"),
            ),
            WindowsInteractiveAnalystConfig,
            WindowsInteractiveAnalystResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsInteractiveAnalystConfig,
    ) -> WindowsInteractiveAnalystResult:
        del ctx, kb
        return run_windows_interactive_analyst(args)


def build_tool() -> WindowsInteractiveAnalystTool:
    return WindowsInteractiveAnalystTool()
