"""Tool #14: rewrite one function into idiomatic source.

Layer 2 workhorse. Every earlier tool exists to feed this one:

- Layer-0 labelers give it named variables, symbolic constants, named
  string literals, classified loops.
- Layer-1 recoverers give it the struct/enum/error-model tables, a
  full function signature with direction/ownership/nullability, and
  protocol/CLI anchors.

With all of that in hand the LLM rewrites the pseudocode body into
source that reads like something a human wrote — no register names,
no synthetic ``var3`` locals, no bare numeric constants. The
``assumptions`` list tracks every rewrite decision that is not
mechanically provable from the input so #17
``verify_semantic_equivalence`` can later challenge them.
"""

from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


Language = Literal["c", "rust", "go", "python"]


class StructDef(BaseModel):
    name: str
    c_definition: str


class EnumDef(BaseModel):
    name: str
    c_definition: str


class ErrorCodeRef(BaseModel):
    canonical_name: str = Field(..., description="e.g. 'ERR_NOMEM'")
    numeric_value: int


class RewriteFunctionArgs(BaseModel):
    entry_va: int = Field(..., description="Entry VA of the function")
    pseudocode: Optional[str] = Field(
        None,
        description="Function pseudocode. When omitted, the tool calls "
                    "g.ir.decompile_at itself.",
    )
    c_prototype: str = Field(
        ..., description="Recovered prototype from #10"
    )
    role: Optional[str] = Field(
        None, description="Role label from #13"
    )
    variable_names: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from raw identifier (var3, arg0, t7) to the "
                    "name picked by #5. The rewriter substitutes these.",
    )
    constant_labels: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from string-rendered constant value ('0x4002') "
                    "to its symbolic form ('O_RDWR | O_DIRECT') from #2.",
    )
    string_names: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from raw string literal to SCREAMING_SNAKE_CASE "
                    "name from #3.",
    )
    loop_idioms: List[str] = Field(
        default_factory=list,
        description="Human-readable descriptions of loop replacements from "
                    "#4 — e.g. 'line 12 loop replaced with memcpy(dst, src, len)'.",
    )
    structs: List[StructDef] = Field(default_factory=list)
    enums: List[EnumDef] = Field(default_factory=list)
    error_codes: List[ErrorCodeRef] = Field(default_factory=list)
    target_language: Language = "c"
    timeout_ms: int = 500


class RewrittenFunction(BaseModel):
    source: str = Field(..., description="Final source for this function")
    language: Language
    assumptions: List[str] = Field(
        default_factory=list,
        description="Every non-mechanical rewrite decision — dropped dead "
                    "stores, idiom replacements, renamed variables whose "
                    "intent the LLM inferred. Feeds #17.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RewriteFunctionResult(BaseModel):
    entry_va: int
    rewrite: RewrittenFunction
    source: str = Field(..., description="'llm' | 'heuristic'")


def _apply_substitutions(text: str, mappings: Dict[str, str]) -> str:
    """Simple textual substitution used by the heuristic fallback.

    Not safe for real rewrites (substrings, identifier collisions) but
    produces a cosmetically-cleaner fallback for offline mode.
    """
    out = text
    # Longest first so "arg10" isn't eaten by "arg1".
    for k in sorted(mappings, key=len, reverse=True):
        out = out.replace(k, mappings[k])
    return out


def _heuristic(
    args: RewriteFunctionArgs, pseudocode: str
) -> RewrittenFunction:
    text = pseudocode
    text = _apply_substitutions(text, args.variable_names)
    text = _apply_substitutions(text, args.constant_labels)
    # String literal substitution uses the *content* as the key and the
    # symbolic name as the value, but we only want to substitute quoted
    # occurrences — the simplest safe match is the full quoted form.
    for raw, symbolic in args.string_names.items():
        quoted = f'"{raw}"'
        text = text.replace(quoted, symbolic)

    source = (
        f"// auto-rewritten (heuristic) — {args.c_prototype}\n"
        f"{args.c_prototype.rstrip(';')}\n"
        f"{{\n"
        f"    /* {pseudocode.count(chr(10))} lines of pseudocode below */\n"
        f"{text}\n"
        f"}}"
    )
    return RewrittenFunction(
        source=source,
        language=args.target_language,
        assumptions=[
            "Heuristic rewrite — LLM not consulted; treat output as "
            "lightly-substituted pseudocode, not real source."
        ],
        confidence=0.2,
        rationale="offline fallback — no semantic transformation performed",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer rewriting one decompiled function into "
    "idiomatic source in the requested language. You will be given:\n"
    "  - the pseudocode body\n"
    "  - the recovered C prototype\n"
    "  - the function's role label\n"
    "  - renaming tables for variables, constants, and string literals\n"
    "  - loop-idiom replacements (e.g. 'lines 8–12 = memcpy')\n"
    "  - recovered struct/enum/error definitions available for use\n\n"
    "Rewrite the body so it reads as if a human wrote it before "
    "compilation. Apply all renamings. Replace loops with library "
    "calls when the idiom table says so. Use recovered error "
    "constants in `return` statements. Remove optimizer artefacts "
    "(obvious strength reductions, loop unrolling, dead-store chains). "
    "Any non-mechanical decision you make — replacing a loop with "
    "`memcpy`, collapsing two branches, inferring a cast — goes in "
    "the `assumptions` list so a reviewer can audit it. Do not "
    "invent code that has no binary backing."
)


def _build_prompt(args: RewriteFunctionArgs, pseudocode: str) -> str:
    parts = []
    parts.append(f"Target language: {args.target_language}")
    parts.append(f"Prototype: {args.c_prototype}")
    if args.role:
        parts.append(f"Role: {args.role}")
    parts.append(f"Pseudocode:\n```\n{pseudocode}\n```")
    if args.variable_names:
        parts.append(
            "Variable renames:\n"
            + "\n".join(f"  {k} -> {v}" for k, v in args.variable_names.items())
        )
    if args.constant_labels:
        parts.append(
            "Constant rewrites:\n"
            + "\n".join(f"  {k} -> {v}" for k, v in args.constant_labels.items())
        )
    if args.string_names:
        parts.append(
            "String literal names:\n"
            + "\n".join(
                f"  {k!r} -> {v}" for k, v in list(args.string_names.items())[:12]
            )
        )
    if args.loop_idioms:
        parts.append("Loop idiom replacements:\n" + "\n".join(
            f"  - {entry}" for entry in args.loop_idioms
        ))
    if args.structs:
        parts.append("Available struct definitions:\n" + "\n\n".join(
            s.c_definition for s in args.structs
        ))
    if args.enums:
        parts.append("Available enum definitions:\n" + "\n\n".join(
            e.c_definition for e in args.enums
        ))
    if args.error_codes:
        parts.append(
            "Error codes available:\n"
            + "\n".join(
                f"  {e.canonical_name} = {e.numeric_value}"
                for e in args.error_codes
            )
        )
    parts.append(
        "Return RewrittenFunction with source, language, assumptions "
        "list (critical), confidence, and rationale."
    )
    return "\n\n".join(parts)


class RewriteFunctionIdiomaticTool(
    MemoryTool[RewriteFunctionArgs, RewriteFunctionResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="rewrite_function_idiomatic",
                description="Rewrite one function from pseudocode to idiomatic "
                            "source in C/Rust/Go/Python, consuming all "
                            "Layer-0/Layer-1 evidence. The central creative "
                            "step of source recovery.",
                tags=("llm", "rewrite", "layer2"),
            ),
            RewriteFunctionArgs,
            RewriteFunctionResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RewriteFunctionArgs,
    ) -> RewriteFunctionResult:
        pseudocode = args.pseudocode
        if pseudocode is None:
            try:
                pseudocode = g.ir.decompile_at(
                    str(ctx.file_path),
                    int(args.entry_va),
                    timeout_ms=max(200, int(args.timeout_ms)),
                    style="",
                )
            except Exception as e:
                pseudocode = f"// decompile failed: {e}"

        heur = _heuristic(args, pseudocode)
        prompt = _build_prompt(args, pseudocode)
        rewrite = run_structured_llm(
            prompt=prompt,
            output_type=RewrittenFunction,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if rewrite is heur else "llm"
        return RewriteFunctionResult(
            entry_va=int(args.entry_va), rewrite=rewrite, source=source
        )


def build_tool() -> MemoryTool[RewriteFunctionArgs, RewriteFunctionResult]:
    return RewriteFunctionIdiomaticTool()
