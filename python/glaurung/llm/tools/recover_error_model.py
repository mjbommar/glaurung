"""Tool #9: unify ad-hoc error returns into one project-wide error enum.

Layer 1 structural recovery. A real binary has 20–100 ``return -1;``
sites spread across many functions, each with its own error string
shown to the user (``"couldn't allocate"``, ``"out of memory"``,
``"memory exhausted"``). Without unification the rewritten source has
inconsistent error paths that break as soon as the reader tries to
reason about them.

This tool takes every observed error-returning site and the strings
associated with them and produces one unified ``enum`` plus a
``code → message`` table. Each site is mapped to a canonical code so
the Layer-2 function rewriter emits ``return ERR_NOMEM;`` everywhere
instead of three different numeric constants.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm
from .recover_enum import _slug


class ErrorSite(BaseModel):
    function_va: int = Field(
        0, description="VA of the function that returns this error"
    )
    function_name: str = Field("", description="Function name if known")
    return_value: int = Field(..., description="The numeric value returned")
    associated_string: str = Field(
        "",
        description="Error string printed on or near this path — usually "
                    "the best naming signal.",
    )
    snippet: str = Field("", description="Short pseudocode excerpt")


class RecoverErrorModelArgs(BaseModel):
    sites: List[ErrorSite]
    enum_hint_name: Optional[str] = Field(
        None, description="Defaults to the project name + '_error'"
    )
    variant_prefix: Optional[str] = Field(
        None, description="Prefix for error variants — defaults to 'ERR_'"
    )
    use_llm: bool = True


class ErrorCode(BaseModel):
    name: str = Field(..., description="SCREAMING_SNAKE_CASE variant name")
    value: int
    message: str = Field(..., description="Canonical message for this code")
    aliases: List[str] = Field(
        default_factory=list,
        description="Alternative strings observed on sites mapped to this code",
    )


class ErrorModel(BaseModel):
    enum_name: str
    variant_prefix: str
    codes: List[ErrorCode] = Field(default_factory=list)
    site_map: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from 'func_va:return_value' → canonical code name. "
                    "Used by the Layer-2 rewriter to emit a uniform "
                    "`return CODE;` everywhere.",
    )
    c_definition: str = Field(
        ..., description="Full C enum + a matching strerror-style table"
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RecoverErrorModelResult(BaseModel):
    model: ErrorModel
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: RecoverErrorModelArgs) -> ErrorModel:
    """Collapse sites with identical error strings; everything else stays
    distinct. Crude but deterministic."""
    enum_name = args.enum_hint_name or "app_error"
    prefix = args.variant_prefix or "ERR_"
    # Keep the value with the lowest magnitude (negative numbers closer
    # to zero) as the canonical value for each unique message.
    canonical: Dict[str, ErrorCode] = {}
    site_map: Dict[str, str] = {}
    for s in args.sites:
        key = s.associated_string.strip().lower() or f"code_{s.return_value}"
        if key not in canonical:
            stem = _slug(s.associated_string) or f"CODE_{abs(s.return_value)}"
            canonical[key] = ErrorCode(
                name=f"{prefix}{stem}",
                value=s.return_value,
                message=s.associated_string or f"error {s.return_value}",
                aliases=[],
            )
        elif (
            s.associated_string
            and s.associated_string not in canonical[key].aliases
            and s.associated_string != canonical[key].message
        ):
            canonical[key].aliases.append(s.associated_string)
        site_map[f"{s.function_va}:{s.return_value}"] = canonical[key].name

    codes = sorted(canonical.values(), key=lambda c: -c.value)
    lines = [f"enum {enum_name} {{"]
    for c in codes:
        lines.append(f"    {c.name} = {c.value},  /* {c.message} */")
    lines.append("};")
    lines.append("")
    lines.append(f"static inline const char *{enum_name}_str(int code) {{")
    lines.append("    switch (code) {")
    for c in codes:
        msg = c.message.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'        case {c.name}: return "{msg}";')
    lines.append('        default: return "unknown error";')
    lines.append("    }")
    lines.append("}")

    return ErrorModel(
        enum_name=enum_name,
        variant_prefix=prefix,
        codes=codes,
        site_map=site_map,
        c_definition="\n".join(lines),
        confidence=0.4,
        rationale="collapsed sites by exact error-string equality",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer unifying a project's ad-hoc error "
    "returns into one coherent enum. Collapse sites that plainly "
    "describe the same error (e.g. 'out of memory', 'memory exhausted', "
    "'couldn't allocate' → ERR_NOMEM) under a single canonical code. "
    "Pick a stable enum name and prefix, write a clean per-code message, "
    "and record every observed-but-not-canonical string as an alias. "
    "Map every input site to exactly one canonical code. Produce a C "
    "enum *and* a matching `_str()` lookup so the rewritten source has "
    "a place to send errno translation."
)


def _build_prompt(args: RecoverErrorModelArgs) -> str:
    parts = [f"Error sites (count={len(args.sites)}):"]
    for s in args.sites:
        parts.append(
            f"  fn={s.function_name or f'sub_{s.function_va:x}'}  "
            f"ret={s.return_value}  msg={s.associated_string!r}"
        )
    if args.enum_hint_name:
        parts.append(f"Enum name hint: {args.enum_hint_name}")
    parts.append(
        "Return an ErrorModel with enum_name, variant_prefix, codes "
        "(with aliases), site_map keyed by 'function_va:return_value', "
        "and c_definition (enum + strerror-style helper)."
    )
    return "\n\n".join(parts)


class RecoverErrorModelTool(
    MemoryTool[RecoverErrorModelArgs, RecoverErrorModelResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="recover_error_model",
                description="Unify ad-hoc error returns across a binary into "
                            "one project-wide error enum with a matching "
                            "strerror-style lookup.",
                tags=("llm", "types", "layer1"),
            ),
            RecoverErrorModelArgs,
            RecoverErrorModelResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RecoverErrorModelArgs,
    ) -> RecoverErrorModelResult:
        if not args.sites:
            return RecoverErrorModelResult(
                model=ErrorModel(
                    enum_name=args.enum_hint_name or "app_error",
                    variant_prefix=args.variant_prefix or "ERR_",
                    codes=[],
                    site_map={},
                    c_definition="enum app_error { /* empty */ };",
                    confidence=0.1,
                    rationale="no error sites supplied",
                ),
                source="heuristic",
            )

        heur = _heuristic(args)
        if not args.use_llm:
            return RecoverErrorModelResult(model=heur, source="heuristic")

        prompt = _build_prompt(args)
        model = run_structured_llm(
            prompt=prompt,
            output_type=ErrorModel,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if model is heur else "llm"
        return RecoverErrorModelResult(model=model, source=source)


def build_tool() -> MemoryTool[RecoverErrorModelArgs, RecoverErrorModelResult]:
    return RecoverErrorModelTool()
