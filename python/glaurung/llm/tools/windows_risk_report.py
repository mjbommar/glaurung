"""Tool: build a Windows-oriented risk report for the current binary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class WindowsRiskReportArgs(BaseModel):
    path: str | None = Field(
        None,
        description="Optional binary path. Defaults to the active MemoryContext file.",
    )
    max_functions: int = Field(4096, ge=1)
    max_candidates: int = Field(32, ge=1)
    max_decompile: int = Field(16, ge=0)
    timeout_ms: int = Field(1000, ge=1)
    str_min_len: int = Field(6, ge=1)
    str_max_samples: int = Field(10_000, ge=1)
    max_xrefs: int = Field(500_000, ge=1)
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache for decompiler naming.",
    )
    no_decompile: bool = Field(
        False,
        description="Skip decompiler-based API pattern detection.",
    )


class WindowsRiskReportResult(BaseModel):
    summary: dict[str, Any]
    risk_imports: dict[str, list[str]]
    risk_items: list[dict[str, Any]]
    functions: list[dict[str, Any]]


class WindowsRiskReportTool(MemoryTool[WindowsRiskReportArgs, WindowsRiskReportResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_risk_report",
                description=(
                    "Build a Windows/PE risk report: risky import buckets, "
                    "function-scoped string xrefs, decompiler API hits, and "
                    "parser-like patterns such as CreateFile/ReadFile/"
                    "allocation chains."
                ),
                tags=("windows", "pe", "risk", "triage", "xrefs"),
            ),
            WindowsRiskReportArgs,
            WindowsRiskReportResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRiskReportArgs,
    ) -> WindowsRiskReportResult:
        del kb
        path = Path(args.path or ctx.file_path)
        ns = SimpleNamespace(
            max_read_bytes=ctx.budgets.max_read_bytes,
            max_file_size=ctx.budgets.max_file_size,
            max_functions=args.max_functions,
            max_candidates=args.max_candidates,
            max_decompile=args.max_decompile,
            timeout_ms=args.timeout_ms,
            str_min_len=args.str_min_len,
            str_max_samples=args.str_max_samples,
            max_xrefs=args.max_xrefs,
            pdb_cache=args.pdb_cache,
            no_decompile=args.no_decompile,
        )
        report = _build_report(path, ns)
        return WindowsRiskReportResult(**report)


def _build_report(path: Path, args: SimpleNamespace) -> dict[str, Any]:
    from ...cli.commands.windows_risk import build_windows_risk_report

    return build_windows_risk_report(path, args)


def build_tool() -> MemoryTool[WindowsRiskReportArgs, WindowsRiskReportResult]:
    return WindowsRiskReportTool()
