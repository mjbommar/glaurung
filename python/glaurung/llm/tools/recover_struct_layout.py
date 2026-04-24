"""Tool #7: recover a C struct layout from clustered field accesses.

Layer 1 structural recovery. Given every ``[base + k]`` access that
plausibly dereferences the same struct, together with the Layer-0
type labels for each offset, an LLM names the struct, picks field
names, and flags alignment padding. The deterministic layer can
compute offsets, widths, and whether an offset is ever written vs
only read — but it cannot decide that the field at +0x10 is a
``refcount`` because of the ``lock xadd`` pattern elsewhere in the
body. That naming step is where the LLM earns its keep.

Input: a list of ``AccessTrace`` records, one per distinct field
access we have seen. Output: a ``struct`` definition and a set of
unresolved offsets the LLM could not explain (they become padding or
future fields).
"""

from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


AccessKind = Literal["read", "write", "read_write", "call_through"]


class AccessTrace(BaseModel):
    offset: int = Field(..., description="Byte offset from struct base")
    width: int = Field(
        ..., description="Access width in bytes (1, 2, 4, 8, 16)"
    )
    kind: AccessKind
    type_hint: str = Field(
        "",
        description="Layer-0 type label for this offset — 'u8*', 'size_t', "
                    "'function_pointer', 'FILE *', …",
    )
    use_snippet: str = Field(
        "",
        description="One short pseudocode line showing the access — e.g. "
                    "'strlen(*(obj + 0x8))' or '*(obj + 0x10) += 1'.",
    )


class RecoverStructLayoutArgs(BaseModel):
    struct_hint_name: Optional[str] = Field(
        None,
        description="Optional project-level name hint (e.g. from a nearby "
                    "function name). The LLM is free to override.",
    )
    accesses: List[AccessTrace] = Field(
        ...,
        description="All distinct field accesses clustered onto this struct.",
    )
    context: str = Field(
        "",
        description="Optional extra context — e.g. 'constructed by "
                    "http_request_new, freed by http_request_free'.",
    )
    use_llm: bool = True


class StructField(BaseModel):
    offset: int
    c_type: str = Field(..., description="Field type in C syntax")
    name: str = Field(..., description="snake_case field name")
    rationale: str = ""


class StructLayout(BaseModel):
    struct_name: str
    fields: List[StructField] = Field(default_factory=list)
    total_size: int = Field(..., description="Inferred size in bytes")
    c_definition: str = Field(
        ...,
        description="Full C struct definition ready to paste into a header",
    )
    unresolved_offsets: List[int] = Field(
        default_factory=list,
        description="Offsets seen in access traces that the LLM could not "
                    "name — likely padding or fields we did not observe.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RecoverStructLayoutResult(BaseModel):
    layout: StructLayout
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic fallback: compose a struct from the access traces directly,
# using the type hints and picking field names from the snippet. The
# LLM will override everything; this just makes offline mode produce
# a syntactically valid struct.
# ---------------------------------------------------------------------------

_NAME_FROM_CALL_RE = re.compile(r"\b(?:strlen|strcmp|fopen|open|free|close)\b")
_NAME_HINT_RE = re.compile(r"\b([a-z_][a-z0-9_]{2,})\b")


def _type_hint_to_c(hint: str, width: int) -> str:
    """Fallback C type when the Layer-0 hint is thin."""
    h = (hint or "").strip()
    if h:
        return h
    if width == 1:
        return "uint8_t"
    if width == 2:
        return "uint16_t"
    if width == 4:
        return "uint32_t"
    if width == 8:
        return "uint64_t"
    if width == 16:
        return "uint64_t /* wide */"
    return "uint8_t"


def _heuristic(args: RecoverStructLayoutArgs) -> StructLayout:
    by_offset: dict[int, AccessTrace] = {}
    for a in sorted(args.accesses, key=lambda x: x.offset):
        # Keep the widest access per offset.
        cur = by_offset.get(a.offset)
        if cur is None or a.width > cur.width:
            by_offset[a.offset] = a

    name = args.struct_hint_name or "recovered_struct"
    fields: List[StructField] = []
    last_end = 0
    unresolved: List[int] = []
    for off in sorted(by_offset):
        a = by_offset[off]
        if off > last_end:
            # Padding gap — record as unresolved so the LLM can name it.
            unresolved.append(last_end)
        c_type = _type_hint_to_c(a.type_hint, a.width)
        # Try to extract a plausible name from the snippet.
        fname = f"field_{off:x}"
        if a.kind == "call_through":
            fname = f"fn_{off:x}"
        elif a.type_hint:
            m = _NAME_HINT_RE.findall(a.type_hint)
            if m:
                fname = m[-1]
        fields.append(
            StructField(
                offset=off,
                c_type=c_type,
                name=fname,
                rationale=f"width={a.width} kind={a.kind} hint={a.type_hint!r}",
            )
        )
        last_end = off + a.width

    total = last_end
    lines = [f"struct {name} {{"]
    for fld in fields:
        lines.append(f"    {fld.c_type} {fld.name};  /* +0x{fld.offset:x} */")
    lines.append("};")
    return StructLayout(
        struct_name=name,
        fields=fields,
        total_size=total,
        c_definition="\n".join(lines),
        unresolved_offsets=unresolved,
        confidence=0.4,
        rationale="field widths/kinds from access traces; names are generic "
                  "placeholders",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer recovering a C struct layout from a set "
    "of observed field accesses. Name the struct descriptively (from "
    "the hint and context), name each field semantically (using the "
    "snippet to decide that +0x8 is `name` because it is passed to "
    "strlen, or that +0x0 is `vt` because it is dereferenced to find "
    "function pointers), and pick idiomatic C types. If an offset gap "
    "is not explained by the accesses, list it in unresolved_offsets "
    "rather than inventing a field. Produce a complete C struct "
    "definition the user could paste into a header file."
)


def _build_prompt(args: RecoverStructLayoutArgs) -> str:
    parts = []
    if args.struct_hint_name:
        parts.append(f"Struct name hint: {args.struct_hint_name}")
    if args.context:
        parts.append(f"Context: {args.context}")
    parts.append("Field accesses (offset, width, kind, type hint, snippet):")
    for a in sorted(args.accesses, key=lambda x: x.offset):
        parts.append(
            f"  +0x{a.offset:x}  w={a.width}  {a.kind:12s}  "
            f"hint={a.type_hint!r}  snippet={a.use_snippet!r}"
        )
    parts.append(
        "Return a StructLayout with struct_name, fields "
        "(offset/c_type/name/rationale), total_size, c_definition, "
        "and any unresolved_offsets."
    )
    return "\n\n".join(parts)


class RecoverStructLayoutTool(
    MemoryTool[RecoverStructLayoutArgs, RecoverStructLayoutResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="recover_struct_layout",
                description="Recover a C struct from clustered field accesses. "
                            "Names the struct and each field, emits a ready-"
                            "to-paste definition.",
                tags=("llm", "types", "layer1"),
            ),
            RecoverStructLayoutArgs,
            RecoverStructLayoutResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RecoverStructLayoutArgs,
    ) -> RecoverStructLayoutResult:
        if not args.accesses:
            return RecoverStructLayoutResult(
                layout=StructLayout(
                    struct_name=args.struct_hint_name or "recovered_struct",
                    fields=[],
                    total_size=0,
                    c_definition=(
                        f"struct {args.struct_hint_name or 'recovered_struct'} "
                        "{ /* empty */ };"
                    ),
                    unresolved_offsets=[],
                    confidence=0.1,
                    rationale="no accesses supplied",
                ),
                source="heuristic",
            )

        heur = _heuristic(args)
        if not args.use_llm:
            return RecoverStructLayoutResult(layout=heur, source="heuristic")

        prompt = _build_prompt(args)
        layout = run_structured_llm(
            prompt=prompt,
            output_type=StructLayout,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if layout is heur else "llm"
        return RecoverStructLayoutResult(layout=layout, source=source)


def build_tool() -> MemoryTool[RecoverStructLayoutArgs, RecoverStructLayoutResult]:
    return RecoverStructLayoutTool()
