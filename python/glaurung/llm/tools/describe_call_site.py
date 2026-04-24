"""Tool #6: describe an indirect-call site.

Layer 0 atomic labeler. Direct calls are already resolved by the
callgraph; indirect calls (``call %reg``, vtable dispatch,
function-pointer in a struct field) are where the graph stops. For
those, an LLM reading the surrounding code can often guess what is
being invoked — a virtual method lookup, a callback stored at init
time, a handler table indexed by opcode.

The output ``inferred_callee`` is intentionally a *hypothesis*, not an
assertion: it carries its own confidence and the rationale that names
the pattern ("field at offset 0x10 was assigned the address of
`parse_header` during construction — so this call likely goes there").

Feeds Layer 1 struct recovery (#7) because vtable field names live
exactly at these indirect call sites.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


CallSiteKind = Literal[
    "direct",
    "vtable",
    "field_pointer",
    "table_lookup",
    "callback",
    "register_indirect",
    "tail_call",
    "unknown",
]


class DescribeCallSiteArgs(BaseModel):
    call_site_snippet: str = Field(
        ...,
        description="10–15 lines of pseudocode around the indirect call. "
                    "Include the target pointer's load so the LLM can see "
                    "where it came from.",
    )
    context_hint: str = Field(
        "",
        description="Optional — the name or role of the containing function, "
                    "or a caller name. Cheap extra signal.",
    )
    use_llm: bool = True


class CallSiteDescription(BaseModel):
    kind: CallSiteKind
    description: str = Field(
        ..., description="One-line plain English description of the call"
    )
    inferred_callee: str = Field(
        "",
        description="Best-guess symbolic name of the callee — e.g. "
                    "'conn->vt->recv' or 'handlers[opcode]' or the name "
                    "of a specific function if we can nail it down.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class DescribeCallSiteResult(BaseModel):
    description: CallSiteDescription
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic shape recognisers. These only spot the *kind* of indirect call;
# the LLM is the one that names the callee.
# ---------------------------------------------------------------------------

_VTABLE_RE = re.compile(
    # Either a nested dereference on one line, or a load of a vtable
    # pointer followed by a call through one of its slots.
    r"\*\s*\(\s*\*\s*\w+\s*\+\s*(?:0x[0-9a-f]+|\d+)\s*\)"
    r"|(?:(?:\w+\s*=\s*)?\*\s*\(?\s*\w+(?:\s*\+\s*(?:0x[0-9a-f]+|\d+))?\s*\)?.*\n"
    r".*call\s+\*\s*\(?\s*\w+\s*\+\s*(?:0x[0-9a-f]+|\d+))",
    re.IGNORECASE,
)
_FIELD_PTR_RE = re.compile(
    r"call\s+\*\s*\(\s*\w+\s*\+\s*(?:0x[0-9a-f]+|\d+)\s*\)"
)
_TABLE_RE = re.compile(r"\w+\[\s*\w+\s*\]\s*\(")
# Register-indirect: "call %rax" — require a percent-sign prefix (or a
# bare single-word register name) so plain ``call 0x401230`` is *not*
# matched as indirect.
_REG_INDIRECT_RE = re.compile(
    r"\bcall\s+%\w+\b|\bcall\s+(?:rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r1[0-5])\b",
    re.IGNORECASE,
)
_DIRECT_RE = re.compile(r"\bcall\s+0x[0-9a-f]+\b", re.IGNORECASE)


def _heuristic(snippet: str) -> CallSiteDescription:
    # Direct call — nothing indirect to describe.
    if _DIRECT_RE.search(snippet) and not any(
        r.search(snippet) for r in (_VTABLE_RE, _TABLE_RE, _FIELD_PTR_RE, _REG_INDIRECT_RE)
    ):
        return CallSiteDescription(
            kind="direct",
            description="direct call to a known VA",
            inferred_callee="",
            confidence=0.9,
            rationale="no indirection in the snippet",
        )
    if _VTABLE_RE.search(snippet):
        return CallSiteDescription(
            kind="vtable",
            description="looks like a virtual-method dispatch through a "
                        "vtable pointer",
            inferred_callee="obj->vt->method",
            confidence=0.55,
            rationale="double-deref pattern (load vtable, then load slot)",
        )
    if _TABLE_RE.search(snippet):
        return CallSiteDescription(
            kind="table_lookup",
            description="indirect call through an array/table indexed by a "
                        "runtime value",
            inferred_callee="table[index]",
            confidence=0.5,
            rationale="indexed function-pointer array",
        )
    if _FIELD_PTR_RE.search(snippet):
        return CallSiteDescription(
            kind="field_pointer",
            description="indirect call through a struct field",
            inferred_callee="obj->callback",
            confidence=0.45,
            rationale="structure-field dereference then call",
        )
    if _REG_INDIRECT_RE.search(snippet):
        return CallSiteDescription(
            kind="register_indirect",
            description="indirect call through a register — source of pointer "
                        "not obvious from the snippet",
            inferred_callee="",
            confidence=0.3,
            rationale="bare register-indirect call",
        )
    return CallSiteDescription(
        kind="unknown",
        description="no indirect-call pattern recognised",
        inferred_callee="",
        confidence=0.1,
        rationale="snippet may not contain an indirect call",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer examining an indirect-call site. "
    "Classify the call's shape (vtable, field_pointer, table_lookup, "
    "callback, register_indirect, tail_call, unknown), describe it in "
    "one line, and make a best-guess symbolic name for the callee — "
    "like 'conn->vt->recv' or 'opcode_handlers[op]' or the name of a "
    "specific function you can trace. Be honest with confidence; "
    "indirect calls are inherently uncertain."
)


def _build_prompt(snippet: str, hint: str) -> str:
    parts = []
    if hint:
        parts.append(f"Context: {hint}")
    parts.append(f"Snippet:\n```\n{snippet}\n```")
    parts.append(
        "Return kind, description, inferred_callee, confidence, rationale."
    )
    return "\n\n".join(parts)


class DescribeCallSiteTool(
    MemoryTool[DescribeCallSiteArgs, DescribeCallSiteResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="describe_call_site",
                description="Describe an indirect-call site (vtable dispatch, "
                            "table lookup, struct-field pointer, register-"
                            "indirect) and guess the callee.",
                tags=("llm", "callgraph", "layer0"),
            ),
            DescribeCallSiteArgs,
            DescribeCallSiteResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: DescribeCallSiteArgs,
    ) -> DescribeCallSiteResult:
        heur = _heuristic(args.call_site_snippet)
        if not args.use_llm:
            return DescribeCallSiteResult(description=heur, source="heuristic")

        prompt = _build_prompt(args.call_site_snippet, args.context_hint)
        desc = run_structured_llm(
            prompt=prompt,
            output_type=CallSiteDescription,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if desc is heur else "llm"
        return DescribeCallSiteResult(description=desc, source=source)


def build_tool() -> MemoryTool[DescribeCallSiteArgs, DescribeCallSiteResult]:
    return DescribeCallSiteTool()
