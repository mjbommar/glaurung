"""LLM-safe access to deterministic persisted runtime facts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.runtime_relations import runtime_capture_summary_json
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class RuntimeProjectSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung project.")
    capture_id: str = Field(..., description="Exact persisted runtime capture ID.")


class RuntimeProjectSummaryResult(BaseModel):
    summary_schema: str
    capture_id: str
    summary: dict[str, Any]


class RuntimeProjectSummaryTool(
    MemoryTool[RuntimeProjectSummaryArgs, RuntimeProjectSummaryResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="runtime_project_summary",
                description=(
                    "Read deterministic, redacted runtime and observed-operation "
                    "facts from an existing .glaurung project. Never returns raw "
                    "payloads, registers, memory snapshots, paths, or event values."
                ),
                tags=("runtime", "project", "persisted", "redacted"),
            ),
            RuntimeProjectSummaryArgs,
            RuntimeProjectSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RuntimeProjectSummaryArgs,
    ) -> RuntimeProjectSummaryResult:
        del ctx, kb
        project_path = Path(args.project_path)
        if not project_path.is_file():
            raise ValueError(f"{project_path}: .glaurung project does not exist")
        project = PersistentKnowledgeBase.open(project_path)
        try:
            summary = json.loads(runtime_capture_summary_json(project, args.capture_id))
        finally:
            project.close()
        return RuntimeProjectSummaryResult(
            summary_schema=summary["schema"],
            capture_id=summary["capture"]["capture_id"],
            summary=summary,
        )


def build_tool() -> RuntimeProjectSummaryTool:
    return RuntimeProjectSummaryTool()
