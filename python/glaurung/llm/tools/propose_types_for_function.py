"""Tool: propose a C-style type signature for a function.

Given pseudocode and the immediate callers' usage patterns, ask the
LLM what the function's parameter types and return type most likely
are. The decompiler's type-recovery pass already assigns shapes
(``i32``, ``u8*``, ``void*``), but those are register-level and rarely
match the source ABI — an LLM is much better at the *intent* ("this
parameter is a ``char*`` holding a URL" rather than the structural
``u8*`` the decompiler sees).

Returns a structured ``ProposedSignature`` with the full signature
string, individual parameters, and a rationale citing the specific
evidence used.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from pydantic import BaseModel, Field
from pydantic_ai import Agent

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ProposeTypesArgs(BaseModel):
    va: int = Field(..., description="Entry VA of the function to type")
    use_llm: bool = Field(
        True, description="Use LLM (disable to get the heuristic-only result)"
    )
    timeout_ms: int = Field(500, description="Per-function decompile timeout")
    max_pseudocode_lines: int = Field(
        120, description="Cap on pseudocode lines fed to the LLM prompt"
    )


class ProposedParameter(BaseModel):
    name: str = Field(..., description="Suggested parameter name")
    c_type: str = Field(..., description="Suggested C type, e.g. 'const char *'")
    rationale: str = Field("", description="Why this type fits the evidence")


class ProposedSignature(BaseModel):
    signature: str = Field(
        ...,
        description="Full proposed C-style prototype, e.g. "
                    "'int parse_config(const char *path, size_t len);'",
    )
    return_type: str
    parameters: List[ProposedParameter] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field("", description="Overall rationale citing evidence")


class ProposeTypesResult(BaseModel):
    entry_va: int
    signature: ProposedSignature
    used_llm: bool


class ProposeTypesForFunctionTool(
    MemoryTool[ProposeTypesArgs, ProposeTypesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="propose_types_for_function",
                description="Propose a C-style prototype (return type + "
                            "parameter types) for the function at `va`, based "
                            "on its decompilation. Uses the configured LLM by "
                            "default.",
                tags=("analysis", "llm", "types"),
            ),
            ProposeTypesArgs,
            ProposeTypesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ProposeTypesArgs,
    ) -> ProposeTypesResult:
        pseudocode = self._decompile(
            str(ctx.file_path), int(args.va), int(args.timeout_ms)
        )
        lines = pseudocode.splitlines()
        if len(lines) > args.max_pseudocode_lines:
            lines = lines[: args.max_pseudocode_lines] + [
                f"... ({len(pseudocode.splitlines()) - args.max_pseudocode_lines} "
                "more lines truncated)"
            ]
        pseudocode = "\n".join(lines)

        used_llm = False
        if args.use_llm:
            sig = self._propose_with_llm(pseudocode, int(args.va))
            if sig is not None:
                used_llm = True
                return ProposeTypesResult(
                    entry_va=int(args.va), signature=sig, used_llm=True
                )

        # Heuristic fallback — best-effort parse of the decompiler's own
        # ``fn foo(arg0: i32, arg1: u8*) -> u64 {`` header.
        sig = self._heuristic_signature(pseudocode, int(args.va))
        return ProposeTypesResult(
            entry_va=int(args.va), signature=sig, used_llm=used_llm
        )

    def _decompile(self, path: str, va: int, timeout_ms: int) -> str:
        try:
            return g.ir.decompile_at(
                path, va, timeout_ms=max(200, timeout_ms), style=""
            )
        except Exception as e:
            return f"// decompile failed: {e}"

    def _propose_with_llm(
        self, pseudocode: str, va: int
    ) -> Optional[ProposedSignature]:
        from ..config import get_config

        cfg = get_config()
        if not any(cfg.available_models().values()):
            return None

        # Nested pydantic-ai Agent.run_sync would deadlock — fall back when
        # called from inside a running event loop.
        try:
            asyncio.get_running_loop()
            return None
        except RuntimeError:
            pass

        prompt = (
            f"The following is glaurung-decompiled pseudocode for a function "
            f"at entry VA {va:#x}. Propose a plausible C-style prototype — "
            f"return type and named parameter types — based on how arguments "
            f"are used (dereferenced, passed to fprintf, returned as int, "
            f"etc.). Prefer standard types (const char *, size_t, FILE *, "
            f"int, uint32_t). Provide a short per-parameter rationale.\n\n"
            f"Pseudocode:\n```\n{pseudocode}\n```\n"
        )

        agent = Agent[str, ProposedSignature](
            model=cfg.preferred_model(),
            output_type=ProposedSignature,
            system_prompt=(
                "You are a reverse engineering assistant recovering source-"
                "level C types from decompiled pseudocode. Weigh concrete "
                "evidence — pointer dereferences, library calls whose "
                "signatures are known, string literals, arithmetic width — "
                "more heavily than register widths. Return a compact, "
                "idiomatic prototype."
            ),
        )
        try:
            result = agent.run_sync(prompt)
            return result.output
        except Exception:
            return None

    def _heuristic_signature(
        self, pseudocode: str, va: int
    ) -> ProposedSignature:
        # Try to parse the glaurung header ``fn <name>(arg0: T, ..) -> RT {``.
        import re

        m = re.search(
            r"(?:fn|function)\s+\w+\s*"
            r"(?:\(([^)]*)\))?\s*"
            r"(?:->\s*([A-Za-z0-9_*\s]+))?"
            r"(?:\s*@\s*0x[0-9a-fA-F]+)?\s*\{",
            pseudocode,
        )
        params: List[ProposedParameter] = []
        return_type = "void"
        if m:
            if m.group(2):
                return_type = _rust_like_to_c(m.group(2).strip())
            raw_params = (m.group(1) or "").strip()
            if raw_params:
                for pi, p in enumerate(
                    [x.strip() for x in raw_params.split(",") if x.strip()]
                ):
                    if ":" in p:
                        name, ty = [x.strip() for x in p.split(":", 1)]
                    else:
                        name, ty = f"arg{pi}", p
                    params.append(
                        ProposedParameter(
                            name=name,
                            c_type=_rust_like_to_c(ty),
                            rationale="Inherited from decompiler's type-"
                                      "recovery pass; no LLM refinement.",
                        )
                    )

        # If no parameter list is emitted, count only arg<N> registers that
        # appear as a *read* before any write — that's the best structural
        # signal we have without full use-def info. Writes like
        # ``arg3 = 256;`` are outgoing-call argument setup, not parameters.
        if not params:
            first_use: dict[int, str] = {}
            for line in pseudocode.splitlines():
                for m2 in re.finditer(
                    r"(?P<write>\barg(?P<wn>\d+)\s*=\s*)"
                    r"|(?P<read>\barg(?P<rn>\d+)\b)",
                    line,
                ):
                    if m2.group("write"):
                        n = int(m2.group("wn"))
                        first_use.setdefault(n, "w")
                    elif m2.group("read"):
                        n = int(m2.group("rn"))
                        first_use.setdefault(n, "r")
            incoming = sorted(n for n, mode in first_use.items() if mode == "r")
            for n in incoming:
                params.append(
                    ProposedParameter(
                        name=f"arg{n}",
                        c_type="long",
                        rationale="Read before any write — structural marker "
                                  "of an incoming parameter register.",
                    )
                )
        sig_str = f"{return_type} sub_{va:x}(" + ", ".join(
            f"{p.c_type} {p.name}" for p in params
        ) + ");"
        return ProposedSignature(
            signature=sig_str,
            return_type=return_type,
            parameters=params,
            confidence=0.35,
            rationale="Fallback: heuristic read of the decompiler-emitted "
                      "header, no LLM input.",
        )


def _rust_like_to_c(ty: str) -> str:
    """Best-effort mapping from glaurung's Rust-like type notation to C.

    The decompiler emits ``i32``, ``u8*``, ``i64``, ``void``, etc.; we
    translate to the closest idiomatic C rendering so the resulting
    prototype looks natural.
    """
    t = ty.strip().replace(" ", "")
    mapping = {
        "i8": "int8_t",
        "i16": "int16_t",
        "i32": "int",
        "i64": "long",
        "u8": "uint8_t",
        "u16": "uint16_t",
        "u32": "uint32_t",
        "u64": "uint64_t",
        "usize": "size_t",
        "isize": "ssize_t",
        "bool": "bool",
        "void": "void",
        "()": "void",
    }
    # Trailing-* pointer forms such as "u8*" / "i32**" pass through with
    # the stem remapped.
    pointer_depth = 0
    while t.endswith("*"):
        pointer_depth += 1
        t = t[:-1]
    base = mapping.get(t, t or "int")
    return base + ("*" * pointer_depth)


def build_tool() -> MemoryTool[ProposeTypesArgs, ProposeTypesResult]:
    return ProposeTypesForFunctionTool()
