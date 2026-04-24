"""Tool #20: enforce project-wide naming consistency.

Layer 3 cross-function coherence. The rewriter emits names
independently for each function, which produces a tree with
inconsistent style (``httpRequest`` next to ``http_request_parse``)
and inconsistent abbreviations (``tcp_ctx`` vs ``tcp_context``).
This tool takes every identifier in the recovered tree and produces
a rename map enforcing one style and one vocabulary.

The output is a *rename map*, not a rewritten tree — the orchestrator
applies the renames mechanically. That separation keeps this call
cheap (no source-level rewriting) and the result auditable (one flat
list of renames the user can review).
"""

from __future__ import annotations

import re
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


Style = Literal["snake_case", "camelCase", "PascalCase", "SCREAMING_SNAKE_CASE"]


class IdentifierKind(BaseModel):
    kind: Literal["function", "struct", "enum", "enum_variant", "string_symbol"]


class IdentifierEntry(BaseModel):
    current: str
    kind: Literal["function", "struct", "enum", "enum_variant", "string_symbol"]
    justification: str = ""


class ReconcileGlobalNamingArgs(BaseModel):
    identifiers: List[IdentifierEntry]
    preferred_style_functions: Style = "snake_case"
    preferred_style_types: Style = "snake_case"
    preferred_style_constants: Style = "SCREAMING_SNAKE_CASE"
    project_prefix: Optional[str] = Field(
        None,
        description="Optional short project prefix to apply to top-level "
                    "symbols (e.g. 'http_', 'kvs_').",
    )
    use_llm: bool = True


class StyleReportEntry(BaseModel):
    topic: str = Field(..., description="'abbreviations', 'style', 'prefix', …")
    observation: str
    decision: str


class RenameMap(BaseModel):
    renames: Dict[str, str] = Field(
        default_factory=dict,
        description="Old name → new name mapping covering every identifier "
                    "that should change.",
    )
    style_report: List[StyleReportEntry] = Field(
        default_factory=list,
        description="Every project-level naming decision the LLM made and "
                    "why — reviewer-facing summary.",
    )
    confidence: float = Field(ge=0.0, le=1.0)


class ReconcileGlobalNamingResult(BaseModel):
    map: RenameMap
    source: str = Field(..., description="'llm' | 'heuristic'")


_SNAKE_SPLIT = re.compile(r"[_\W]+")


def _to_style(name: str, style: Style) -> str:
    # First split into word tokens.
    words: List[str] = []
    # Handle existing camelCase / PascalCase boundaries.
    for part in _SNAKE_SPLIT.split(name):
        if not part:
            continue
        words.extend(re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z]|$)", part) or [part])
    words = [w.lower() for w in words if w]
    if not words:
        return name
    if style == "snake_case":
        return "_".join(words)
    if style == "SCREAMING_SNAKE_CASE":
        return "_".join(w.upper() for w in words)
    if style == "camelCase":
        return words[0] + "".join(w.title() for w in words[1:])
    if style == "PascalCase":
        return "".join(w.title() for w in words)
    return name


def _heuristic(args: ReconcileGlobalNamingArgs) -> RenameMap:
    mapping: Dict[str, str] = {}

    for e in args.identifiers:
        if e.kind == "function":
            target_style = args.preferred_style_functions
        elif e.kind in ("struct", "enum"):
            target_style = args.preferred_style_types
        elif e.kind == "enum_variant":
            target_style = args.preferred_style_constants
        else:  # string_symbol
            target_style = args.preferred_style_constants
        new_name = _to_style(e.current, target_style)
        if args.project_prefix and e.kind in ("function", "struct", "enum"):
            pref = _to_style(args.project_prefix.rstrip("_"), target_style)
            # Avoid double-prefixing.
            if not new_name.lower().startswith(pref.lower() + ("_" if target_style == "snake_case" else "")):
                join = "_" if target_style in ("snake_case", "SCREAMING_SNAKE_CASE") else ""
                new_name = pref + join + new_name
        if new_name != e.current:
            mapping[e.current] = new_name

    style_report = [
        StyleReportEntry(
            topic="style",
            observation="applied canonical style per identifier kind",
            decision=f"functions={args.preferred_style_functions}, "
                     f"types={args.preferred_style_types}, "
                     f"constants={args.preferred_style_constants}",
        )
    ]
    if args.project_prefix:
        style_report.append(
            StyleReportEntry(
                topic="prefix",
                observation="project prefix applied to top-level symbols",
                decision=f"prefix={args.project_prefix!r}",
            )
        )
    return RenameMap(
        renames=mapping,
        style_report=style_report,
        confidence=0.4,
    )


_SYSTEM_PROMPT = (
    "You are enforcing a recovered project's naming convention. You "
    "will receive every identifier in the project (functions, structs, "
    "enums, variants, string symbols) along with per-kind style "
    "preferences and an optional project prefix. Produce a rename map "
    "old_name → new_name. Beyond mechanical case conversion, consolidate "
    "inconsistent abbreviations (pick one — ctx vs context, req vs "
    "request — and apply it everywhere), drop meaningless prefixes, and "
    "apply the project prefix to top-level symbols. Record every "
    "decision you made in the style_report so a human reviewer sees "
    "the reasoning."
)


def _build_prompt(args: ReconcileGlobalNamingArgs) -> str:
    parts = [
        f"Function style: {args.preferred_style_functions}",
        f"Type style: {args.preferred_style_types}",
        f"Constant style: {args.preferred_style_constants}",
    ]
    if args.project_prefix:
        parts.append(f"Project prefix: {args.project_prefix!r}")
    parts.append("Identifiers:")
    for e in args.identifiers:
        parts.append(f"  {e.kind:14s} {e.current!r}")
    parts.append(
        "Return a RenameMap with renames and style_report; include "
        "only entries whose name actually changes."
    )
    return "\n\n".join(parts)


class ReconcileGlobalNamingTool(
    MemoryTool[ReconcileGlobalNamingArgs, ReconcileGlobalNamingResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="reconcile_global_naming",
                description="Enforce project-wide naming style and abbreviation "
                            "vocabulary. Produces a flat rename map the "
                            "orchestrator applies mechanically.",
                tags=("llm", "naming", "layer3"),
            ),
            ReconcileGlobalNamingArgs,
            ReconcileGlobalNamingResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ReconcileGlobalNamingArgs,
    ) -> ReconcileGlobalNamingResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return ReconcileGlobalNamingResult(map=heur, source="heuristic")

        prompt = _build_prompt(args)
        rmap = run_structured_llm(
            prompt=prompt,
            output_type=RenameMap,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if rmap is heur else "llm"
        return ReconcileGlobalNamingResult(map=rmap, source=source)


def build_tool() -> MemoryTool[
    ReconcileGlobalNamingArgs, ReconcileGlobalNamingResult
]:
    return ReconcileGlobalNamingTool()
