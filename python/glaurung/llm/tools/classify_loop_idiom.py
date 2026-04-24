"""Tool #4: classify a loop body as a well-known idiom.

Layer 0 atomic labeler. Optimizers unroll loops, strength-reduce
counters, and rearrange operations — pattern matching alone
misclassifies most of them. Feeding the body into an LLM together
with a small vocabulary of known idioms lets us replace the whole
loop with a library call in the rewritten source, which is the single
biggest readability win in Layer 2.

The output contains both the label and a parameter map (src / dst /
len / seed / output) so the rewriter knows exactly how to slot the
library call into the surrounding code.
"""

from __future__ import annotations

import re
from typing import Dict, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


LoopIdiom = Literal[
    "strlen",
    "memcpy",
    "memset",
    "memcmp",
    "strcmp",
    "crc16",
    "crc32",
    "hash_update",
    "parse_decimal",
    "parse_hex",
    "base64_decode",
    "base64_encode",
    "aes_round",
    "rc4_prga",
    "shift_register",
    "array_fill",
    "array_copy",
    "custom",
]


class ClassifyLoopIdiomArgs(BaseModel):
    loop_body: str = Field(
        ...,
        description="Pseudocode of the loop body (one basic block or tight "
                    "nested pair). Include the header — the comparison and "
                    "increment — so the LLM sees the exit condition.",
    )
    use_llm: bool = True


class LoopIdiomLabel(BaseModel):
    idiom: LoopIdiom
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Parameter map keyed by role — src, dst, len, seed, "
                    "output, key, polynomial — to variable names as they "
                    "appear in the loop body.",
    )
    library_call: Optional[str] = Field(
        None,
        description="C library call that should replace the loop in "
                    "rewritten source, e.g. 'strlen(src)' or "
                    "'memcpy(dst, src, len)'. None for custom idioms.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class ClassifyLoopIdiomResult(BaseModel):
    label: LoopIdiomLabel
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic fallback. Recognises the simplest idioms unambiguously; anything
# more subtle (CRC, AES round, base64) requires the LLM.
# ---------------------------------------------------------------------------

_STRLEN_HINTS = re.compile(r"\*\s*\w+\s*(?:!=|==)\s*0", re.IGNORECASE)
_MEMCPY_HINTS = re.compile(
    r"\*\s*(\w+)\s*=\s*\*\s*(\w+)", re.IGNORECASE
)
_MEMSET_HINTS = re.compile(r"\*\s*\w+\s*=\s*(?:0|0x[0-9a-f]+|[0-9]+)\b")
_CRC_HINT = re.compile(r"(?:0xedb88320|0x04c11db7|0xa001|0x8408)", re.IGNORECASE)


def _heuristic(body: str) -> LoopIdiomLabel:
    text = body
    if _CRC_HINT.search(text):
        return LoopIdiomLabel(
            idiom="crc32",
            parameters={},
            library_call=None,
            confidence=0.75,
            rationale="contains a standard CRC polynomial constant",
        )
    if _STRLEN_HINTS.search(text) and "+" in text:
        return LoopIdiomLabel(
            idiom="strlen",
            parameters={},
            library_call="strlen(src)",
            confidence=0.6,
            rationale="byte-at-a-time scan with null terminator check",
        )
    if _MEMCPY_HINTS.search(text):
        return LoopIdiomLabel(
            idiom="memcpy",
            parameters={},
            library_call="memcpy(dst, src, len)",
            confidence=0.5,
            rationale="pointer-to-pointer byte copy",
        )
    if _MEMSET_HINTS.search(text):
        return LoopIdiomLabel(
            idiom="memset",
            parameters={},
            library_call="memset(dst, value, len)",
            confidence=0.5,
            rationale="pointer write with constant value",
        )
    return LoopIdiomLabel(
        idiom="custom",
        parameters={},
        library_call=None,
        confidence=0.2,
        rationale="no well-known pattern matched",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer identifying classic loop idioms in "
    "decompiled pseudocode. Pick the single best label from: strlen, "
    "memcpy, memset, memcmp, strcmp, crc16, crc32, hash_update, "
    "parse_decimal, parse_hex, base64_decode, base64_encode, "
    "aes_round, rc4_prga, shift_register, array_fill, array_copy, "
    "custom. Fill the parameters map with the variable names the loop "
    "uses in each role (src, dst, len, seed, key, polynomial, "
    "output). If it is a recognisable idiom, produce the C library "
    "call that could replace the loop; otherwise leave library_call "
    "null and briefly describe what the loop does in the rationale."
)


class ClassifyLoopIdiomTool(
    MemoryTool[ClassifyLoopIdiomArgs, ClassifyLoopIdiomResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="classify_loop_idiom",
                description="Label a loop body as a known idiom (strlen, "
                            "memcpy, crc32, aes_round, …) and return the "
                            "parameter map and the C library call that "
                            "would replace it.",
                tags=("llm", "loops", "layer0"),
            ),
            ClassifyLoopIdiomArgs,
            ClassifyLoopIdiomResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ClassifyLoopIdiomArgs,
    ) -> ClassifyLoopIdiomResult:
        heur = _heuristic(args.loop_body)
        if not args.use_llm or heur.confidence >= 0.75:
            return ClassifyLoopIdiomResult(label=heur, source="heuristic")

        prompt = f"Loop body:\n```\n{args.loop_body}\n```"
        label = run_structured_llm(
            prompt=prompt,
            output_type=LoopIdiomLabel,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if label is heur else "llm"
        return ClassifyLoopIdiomResult(label=label, source=source)


def build_tool() -> MemoryTool[ClassifyLoopIdiomArgs, ClassifyLoopIdiomResult]:
    return ClassifyLoopIdiomTool()
