"""Tool #5: name one local variable from its def/use slice.

Layer 0 atomic labeler — the single highest-volume LLM call in the
pipeline. Every `%var3`, `%arg0`, and `%t7` needs a human-readable
name before the rewritten source is readable, and only the uses
disambiguate what the role is (`response_len` vs `offset` vs `i`).

Input: the variable's current identifier, its recovered type, and a
small slice of the pseudocode showing how it is read and written.
Output: a snake_case name with a one-line rationale.

A pure heuristic fallback generates names from the type alone (``len``
for integer types that are compared to another variable, ``buf`` for
pointer types that are dereferenced) so offline runs still produce
*some* signal.
"""

from __future__ import annotations

import re
from typing import List, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


class NameLocalVariableArgs(BaseModel):
    current_id: str = Field(
        ..., description="Current identifier as it appears in pseudocode (%var3, arg0, t7)"
    )
    recovered_type: str = Field(
        "int",
        description="Type from the type-recovery pass — 'u8*', 'int', 'size_t', ...",
    )
    def_use_slice: List[str] = Field(
        default_factory=list,
        description="Pseudocode lines showing how the variable is read and "
                    "written. Keep compact — 10 lines is plenty.",
    )
    role_hint: Literal[
        "parameter", "local", "return", "global", "unknown"
    ] = "unknown"
    use_llm: bool = True


class VariableName(BaseModel):
    name: str = Field(..., description="snake_case identifier")
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class NameLocalVariableResult(BaseModel):
    current_id: str
    named: VariableName
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic fallback — conservative shape-based guesses. The real value
# comes from the LLM path; this just keeps offline runs producing
# slightly-better-than-raw names.
# ---------------------------------------------------------------------------

_SNAKE_RE = re.compile(r"[^A-Za-z0-9_]+")


def _slugify(name: str) -> str:
    n = _SNAKE_RE.sub("_", name).strip("_").lower()
    return n or "var"


def _heuristic(
    current_id: str, ty: str, slice_: List[str], role: str
) -> VariableName:
    t = ty.strip().lower()
    is_ptr = t.endswith("*")
    base = t.rstrip("*")
    body = "\n".join(slice_)

    # Common-shape guesses.
    if is_ptr and "char" in base:
        if any("strlen" in line or "strcmp" in line or "strcpy" in line for line in slice_):
            return VariableName(
                name="str", confidence=0.5,
                rationale="char* used with string functions",
            )
        return VariableName(
            name="buf", confidence=0.4,
            rationale="generic char pointer",
        )
    if is_ptr:
        return VariableName(
            name="ptr", confidence=0.35, rationale="non-char pointer",
        )
    if "size" in base or t in ("size_t", "usize"):
        return VariableName(
            name="len", confidence=0.4, rationale="size/length-sized integer",
        )
    if base in ("bool", "_bool"):
        return VariableName(
            name="flag", confidence=0.5, rationale="boolean",
        )
    if re.search(r"\+\s*1\b", body) and re.search(r"<\s*\w+", body):
        return VariableName(
            name="i", confidence=0.6, rationale="bounded incrementing counter",
        )
    if role == "return":
        return VariableName(
            name="ret", confidence=0.5, rationale="value returned from function",
        )

    # Give up — sanitise the current id rather than returning gibberish.
    return VariableName(
        name=_slugify(current_id) or "var",
        confidence=0.2,
        rationale="no distinguishing features; sanitised original id",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer naming a local variable in a function "
    "being rewritten from decompiler output to idiomatic source. Pick a "
    "snake_case name that describes the variable's *role*, not its "
    "type. Favour short, concrete names: buf, len, offset, path, err, "
    "response, status, ctx, fd. Avoid one-letter names except for "
    "canonical loop counters (i, j, k) and return values (ret). Use "
    "the def/use slice to decide — a char* compared to \"HTTP/\" is a "
    "`method`, not a `str`. Return a confidence in [0, 1] and one-line "
    "rationale citing the specific use that decided the name."
)


def _build_prompt(args: NameLocalVariableArgs) -> str:
    parts = [
        f"Current id: {args.current_id}",
        f"Recovered type: {args.recovered_type}",
        f"Role: {args.role_hint}",
    ]
    if args.def_use_slice:
        parts.append(
            "Uses:\n" + "\n".join(f"    {line}" for line in args.def_use_slice[:12])
        )
    parts.append(
        "Propose one snake_case name. One line rationale. Confidence in [0, 1]."
    )
    return "\n\n".join(parts)


class NameLocalVariableTool(
    MemoryTool[NameLocalVariableArgs, NameLocalVariableResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="name_local_variable",
                description="Propose a snake_case name for one local variable "
                            "given its recovered type and a slice of its "
                            "uses. Highest-volume Layer-0 call.",
                tags=("llm", "naming", "layer0"),
            ),
            NameLocalVariableArgs,
            NameLocalVariableResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: NameLocalVariableArgs,
    ) -> NameLocalVariableResult:
        heur = _heuristic(
            args.current_id, args.recovered_type, args.def_use_slice, args.role_hint
        )
        if not args.use_llm:
            return NameLocalVariableResult(
                current_id=args.current_id, named=heur, source="heuristic"
            )

        prompt = _build_prompt(args)
        named = run_structured_llm(
            prompt=prompt,
            output_type=VariableName,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        # Sanitise whatever the LLM returned so downstream rewriters can
        # trust the identifier.
        named = VariableName(
            name=_slugify(named.name) or heur.name,
            confidence=named.confidence,
            rationale=named.rationale,
        )
        source = "heuristic" if named.name == heur.name and named.rationale == heur.rationale else "llm"
        return NameLocalVariableResult(
            current_id=args.current_id, named=named, source=source
        )


def build_tool() -> MemoryTool[NameLocalVariableArgs, NameLocalVariableResult]:
    return NameLocalVariableTool()
