"""Tool #10: infer a function's full C prototype with parameter semantics.

Layer 1 structural recovery. Where
:mod:`glaurung.llm.tools.propose_types_for_function` only sees the
callee's body, this tool reads the callee *plus* a handful of its
callers. That cross-boundary view is what resolves ambiguity like
"``arg0`` is ``void *``" vs "``arg0`` is ``FILE *``" — the caller
always passes the result of ``fopen``, so the LLM has enough context
to commit to the richer type.

Output carries per-parameter semantics (``[in]`` / ``[in, out]`` /
``[out]`` / ``[consumed]``, nullability, ownership) because those are
exactly the annotations that make the rewritten source readable.
"""

from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


Direction = Literal["in", "in_out", "out", "consumed"]


class CallerSnippet(BaseModel):
    caller_name: str
    pseudocode: str = Field(
        ..., description="Short excerpt of the caller's pseudocode around the call site"
    )


class InferFunctionSignatureArgs(BaseModel):
    va: int = Field(..., description="Entry VA of the callee")
    callee_pseudocode: Optional[str] = Field(
        None,
        description="Pseudocode for the callee. When omitted, the tool calls "
                    "g.ir.decompile_at itself.",
    )
    caller_snippets: List[CallerSnippet] = Field(
        default_factory=list,
        description="Optional caller-side context. Supply 2–4 snippets for "
                    "the best result.",
    )
    target_language: Literal["c", "rust", "go"] = "c"
    timeout_ms: int = 500
    use_llm: bool = True


class InferredParameter(BaseModel):
    name: str = Field(..., description="snake_case name")
    c_type: str = Field(..., description="Type in the target language's idiom")
    direction: Direction = "in"
    nullable: bool = False
    owned: bool = Field(
        False,
        description="True when the callee takes ownership (e.g. free()s it "
                    "or stores it beyond the call).",
    )
    rationale: str = ""


class FunctionSignature(BaseModel):
    return_type: str
    parameters: List[InferredParameter] = Field(default_factory=list)
    c_prototype: str = Field(
        ...,
        description="Full prototype as it should appear at the top of the "
                    "rewritten source, including return type and semicolon.",
    )
    side_effects: List[str] = Field(
        default_factory=list,
        description="Non-parameter observable effects — writes a global, "
                    "spawns a thread, touches errno, etc.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class InferFunctionSignatureResult(BaseModel):
    entry_va: int
    signature: FunctionSignature
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic fallback — inherits the logic from propose_types_for_function
# (structural regex) and lifts it into the richer schema. Any semantic
# richness (direction, ownership, nullability) stays null/default.
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(
    r"(?:fn|function)\s+(?P<name>\w+)\s*"
    r"(?:\((?P<params>[^)]*)\))?\s*"
    r"(?:->\s*(?P<ret>[A-Za-z0-9_*\s]+))?"
    r"(?:\s*@\s*0x[0-9a-fA-F]+)?\s*\{"
)


def _rust_to_c(ty: str) -> str:
    t = ty.strip().replace(" ", "")
    base_map = {
        "i8": "int8_t", "i16": "int16_t", "i32": "int", "i64": "long",
        "u8": "uint8_t", "u16": "uint16_t", "u32": "uint32_t",
        "u64": "uint64_t", "usize": "size_t", "isize": "ssize_t",
        "bool": "bool", "void": "void", "()": "void",
    }
    stars = 0
    while t.endswith("*"):
        stars += 1
        t = t[:-1]
    base = base_map.get(t, t or "int")
    return base + ("*" * stars)


def _heuristic(va: int, pseudocode: str) -> FunctionSignature:
    m = _HEADER_RE.search(pseudocode)
    return_type = "void"
    params: List[InferredParameter] = []
    if m:
        if m.group("ret"):
            return_type = _rust_to_c(m.group("ret"))
        raw = (m.group("params") or "").strip()
        if raw:
            for i, p in enumerate(
                [x.strip() for x in raw.split(",") if x.strip()]
            ):
                if ":" in p:
                    name, ty = [x.strip() for x in p.split(":", 1)]
                else:
                    name, ty = f"arg{i}", p
                params.append(
                    InferredParameter(
                        name=name,
                        c_type=_rust_to_c(ty),
                        direction="in",
                        rationale="inherited from decompiler header",
                    )
                )

    # Fallback when header gave us nothing: use the "first read before
    # first write" heuristic from propose_types_for_function.
    if not params:
        first_use: dict[int, str] = {}
        for line in pseudocode.splitlines():
            for mm in re.finditer(
                r"(?P<write>\barg(?P<wn>\d+)\s*=\s*)"
                r"|(?P<read>\barg(?P<rn>\d+)\b)",
                line,
            ):
                if mm.group("write"):
                    first_use.setdefault(int(mm.group("wn")), "w")
                elif mm.group("read"):
                    first_use.setdefault(int(mm.group("rn")), "r")
        for n in sorted(n for n, mode in first_use.items() if mode == "r"):
            params.append(
                InferredParameter(
                    name=f"arg{n}",
                    c_type="long",
                    direction="in",
                    rationale="read-before-write structural marker",
                )
            )

    proto = (
        f"{return_type} sub_{va:x}("
        + (", ".join(f"{p.c_type} {p.name}" for p in params) or "void")
        + ");"
    )
    return FunctionSignature(
        return_type=return_type,
        parameters=params,
        c_prototype=proto,
        side_effects=[],
        confidence=0.35,
        rationale="heuristic read of decompiler header and arg-register use",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer recovering a function's source-level C "
    "prototype. You will be shown the callee's decompiled pseudocode "
    "and a few caller snippets. Use both to decide parameter types "
    "(e.g. `FILE *` when callers always pass the result of fopen), "
    "directions ([in] / [in, out] / [out] / [consumed]), nullability, "
    "and ownership. Prefer idiomatic C types (FILE *, size_t, "
    "uint32_t, const char *) over decompiler register widths. Emit a "
    "complete c_prototype string that could be pasted at the top of a "
    "header file."
)


def _build_prompt(
    va: int,
    callee: str,
    callers: List[CallerSnippet],
    target_language: str,
) -> str:
    parts = [f"Function entry VA: {va:#x}", f"Target language: {target_language}"]
    parts.append(f"Callee pseudocode:\n```\n{callee}\n```")
    if callers:
        parts.append(
            "Caller context:\n" + "\n\n".join(
                f"from `{c.caller_name}`:\n```\n{c.pseudocode}\n```"
                for c in callers[:4]
            )
        )
    parts.append(
        "Return a full FunctionSignature: return_type, parameters with "
        "direction/nullable/owned, c_prototype string, and any global "
        "side effects."
    )
    return "\n\n".join(parts)


class InferFunctionSignatureTool(
    MemoryTool[InferFunctionSignatureArgs, InferFunctionSignatureResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="infer_function_signature",
                description="Recover a function's full C prototype with "
                            "parameter directions, nullability, and "
                            "ownership — reads the callee and a few callers.",
                tags=("llm", "types", "layer1"),
            ),
            InferFunctionSignatureArgs,
            InferFunctionSignatureResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: InferFunctionSignatureArgs,
    ) -> InferFunctionSignatureResult:
        pseudocode = args.callee_pseudocode
        if pseudocode is None:
            try:
                pseudocode = g.ir.decompile_at(
                    str(ctx.file_path),
                    int(args.va),
                    timeout_ms=max(200, int(args.timeout_ms)),
                    style="",
                )
            except Exception as e:
                pseudocode = f"// decompile failed: {e}"

        heur = _heuristic(int(args.va), pseudocode)
        if not args.use_llm:
            return InferFunctionSignatureResult(
                entry_va=int(args.va), signature=heur, source="heuristic"
            )

        prompt = _build_prompt(
            int(args.va), pseudocode, args.caller_snippets, args.target_language
        )
        sig = run_structured_llm(
            prompt=prompt,
            output_type=FunctionSignature,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if sig is heur else "llm"
        return InferFunctionSignatureResult(
            entry_va=int(args.va), signature=sig, source=source
        )


def build_tool() -> MemoryTool[
    InferFunctionSignatureArgs, InferFunctionSignatureResult
]:
    return InferFunctionSignatureTool()
