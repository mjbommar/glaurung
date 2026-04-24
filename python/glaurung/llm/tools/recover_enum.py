"""Tool #8: recover a C enum from a jump-table switch and its branch strings.

Layer 1 structural recovery. A lowered switch statement is ``case 0:``,
``case 1:`` — useless for readability. But when case 0 prints
``"connecting"`` and case 1 prints ``"authenticating"``, the LLM can
confidently propose::

    enum conn_state {
        CS_CONNECTING      = 0,
        CS_AUTHENTICATING  = 1,
        ...
    };

That mapping from numeric dispatch values to symbolic variants is the
single biggest improvement you can make to recovered source below the
function-rewrite layer — every ``switch`` in the project suddenly
reads like real code.

Input: the raw switch pseudocode plus, for each case, the string or
constant associated with that branch. Output: a full ``enum``
definition and a per-variant doc line.
"""

from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


class EnumCaseEvidence(BaseModel):
    value: int = Field(..., description="The case label (may be a constant)")
    evidence: str = Field(
        ...,
        description="The string printed, constant returned, or function "
                    "called in this branch. Used as the naming signal.",
    )


class RecoverEnumArgs(BaseModel):
    switch_pseudocode: str = Field(
        ...,
        description="Full switch body with every branch visible. Keep it "
                    "terse — a few hundred tokens is usually enough.",
    )
    cases: List[EnumCaseEvidence] = Field(
        ...,
        description="One entry per case — (value, short evidence string).",
    )
    enum_hint_name: Optional[str] = Field(
        None, description="Optional hint for the enum's name"
    )
    variant_prefix: Optional[str] = Field(
        None,
        description="Optional prefix for variant names. Defaults based on "
                    "the enum name (e.g. 'conn_state' → 'CS_').",
    )
    underlying_type: Literal["int", "unsigned", "uint8_t", "uint16_t", "uint32_t"] = "int"
    use_llm: bool = True


class EnumVariant(BaseModel):
    name: str = Field(..., description="SCREAMING_SNAKE_CASE variant name")
    value: int
    doc: str = Field(
        "",
        description="One-line description of when this variant is used",
    )


class EnumDefinition(BaseModel):
    enum_name: str
    variant_prefix: str
    variants: List[EnumVariant] = Field(default_factory=list)
    c_definition: str = Field(
        ..., description="Full C enum definition ready to paste"
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RecoverEnumResult(BaseModel):
    definition: EnumDefinition
    source: str = Field(..., description="'llm' | 'heuristic'")


_SLUG_RE = re.compile(r"[^A-Za-z0-9]+")


def _slug(text: str, max_len: int = 20) -> str:
    name = _SLUG_RE.sub("_", text).strip("_").upper()
    if not name:
        return "VARIANT"
    if len(name) > max_len:
        name = name[:max_len].rstrip("_")
    return name


def _default_prefix(enum_name: str) -> str:
    # `conn_state` → `CS_`; `http_method` → `HM_`
    words = [w for w in enum_name.split("_") if w]
    if not words:
        return ""
    if len(words) == 1:
        return words[0][:3].upper() + "_"
    return "".join(w[0] for w in words[:3]).upper() + "_"


def _heuristic(args: RecoverEnumArgs) -> EnumDefinition:
    enum_name = args.enum_hint_name or "recovered_enum"
    prefix = args.variant_prefix or _default_prefix(enum_name)
    variants: List[EnumVariant] = []
    for c in sorted(args.cases, key=lambda c: c.value):
        stem = _slug(c.evidence) or f"CASE_{c.value}"
        variants.append(
            EnumVariant(
                name=f"{prefix}{stem}",
                value=c.value,
                doc=c.evidence[:80],
            )
        )
    lines = [f"enum {enum_name} {{"]
    for v in variants:
        lines.append(f"    {v.name} = {v.value},  /* {v.doc} */")
    lines.append("};")
    return EnumDefinition(
        enum_name=enum_name,
        variant_prefix=prefix,
        variants=variants,
        c_definition="\n".join(lines),
        confidence=0.45,
        rationale="names slugged directly from branch evidence",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer recovering a C enum from a jump-table "
    "switch. Pick a descriptive snake_case enum name, a short prefix "
    "for variants (usually 2–3 letters derived from the name), and "
    "name each variant using the branch evidence provided — the string "
    "printed, the constant returned, or the function called on that "
    "branch. Write one-line docs per variant. Return a ready-to-paste "
    "C enum definition."
)


def _build_prompt(args: RecoverEnumArgs) -> str:
    parts = []
    if args.enum_hint_name:
        parts.append(f"Enum hint: {args.enum_hint_name}")
    parts.append(f"Switch:\n```\n{args.switch_pseudocode}\n```")
    parts.append("Cases:")
    for c in sorted(args.cases, key=lambda c: c.value):
        parts.append(f"  {c.value}: {c.evidence!r}")
    parts.append(
        "Return an EnumDefinition with enum_name, variant_prefix, variants "
        "(name/value/doc), c_definition, and a confidence."
    )
    return "\n\n".join(parts)


class RecoverEnumTool(MemoryTool[RecoverEnumArgs, RecoverEnumResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="recover_enum",
                description="Recover a C enum from a jump-table switch plus "
                            "the evidence string/constant for each branch.",
                tags=("llm", "types", "layer1"),
            ),
            RecoverEnumArgs,
            RecoverEnumResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RecoverEnumArgs,
    ) -> RecoverEnumResult:
        if not args.cases:
            return RecoverEnumResult(
                definition=EnumDefinition(
                    enum_name=args.enum_hint_name or "recovered_enum",
                    variant_prefix=args.variant_prefix
                    or _default_prefix(args.enum_hint_name or "recovered_enum"),
                    variants=[],
                    c_definition=f"enum {args.enum_hint_name or 'recovered_enum'} "
                                 "{ /* empty */ };",
                    confidence=0.1,
                    rationale="no case evidence supplied",
                ),
                source="heuristic",
            )

        heur = _heuristic(args)
        if not args.use_llm:
            return RecoverEnumResult(definition=heur, source="heuristic")

        prompt = _build_prompt(args)
        defn = run_structured_llm(
            prompt=prompt,
            output_type=EnumDefinition,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if defn is heur else "llm"
        return RecoverEnumResult(definition=defn, source=source)


def build_tool() -> MemoryTool[RecoverEnumArgs, RecoverEnumResult]:
    return RecoverEnumTool()
