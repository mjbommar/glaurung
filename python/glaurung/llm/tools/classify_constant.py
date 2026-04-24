"""Tool #2: classify a single integer/float literal from a binary.

Layer 0 atomic labeler. ``0x41`` is ``'A'`` or ``65`` depending on the
instruction context. ``0x400`` could be ``PAGE_SIZE``, ``MAX_PATH/2``,
or ``O_DIRECT``. The deterministic layer resolves well-known table
entries (errno values, POSIX open flags, memory sizes); the LLM
handles the residual based on how the constant is used.

The output includes a ``symbolic`` rendering — the form to emit in the
rewritten source — so downstream tools can substitute the constant
directly without a second lookup.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


ConstantKind = Literal[
    "char",
    "mask",
    "flag_or",
    "enum_value",
    "size",
    "offset",
    "magic_number",
    "errno",
    "page_size",
    "syscall_number",
    "timeout_ms",
    "raw_numeric",
    "unknown",
]


# ---------------------------------------------------------------------------
# Small, curated known-constant tables — covers the "obvious" cases so we
# don't burn an LLM call on them. Intentionally *not* exhaustive; the goal
# is to claim only what we are confident about.
# ---------------------------------------------------------------------------

_ERRNO_TABLE = {
    1: "EPERM", 2: "ENOENT", 5: "EIO", 9: "EBADF", 11: "EAGAIN",
    12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 17: "EEXIST", 21: "EISDIR",
    22: "EINVAL", 23: "ENFILE", 24: "EMFILE", 28: "ENOSPC", 32: "EPIPE",
    38: "ENOSYS", 110: "ETIMEDOUT", 111: "ECONNREFUSED",
}

# POSIX open(2) flags — values are Linux glibc canonical.
_OPEN_FLAGS = [
    (0x0000, "O_RDONLY"),
    (0x0001, "O_WRONLY"),
    (0x0002, "O_RDWR"),
    (0x0040, "O_CREAT"),
    (0x0080, "O_EXCL"),
    (0x0200, "O_TRUNC"),
    (0x0400, "O_APPEND"),
    (0x0800, "O_NONBLOCK"),
    (0x4000, "O_DIRECT"),
    (0x8000, "O_DIRECTORY"),
]

_SIZE_TABLE = {
    0x400: "1024 (1 KiB)",
    0x1000: "4096 (PAGE_SIZE)",
    0x2000: "8192 (8 KiB)",
    0x10000: "65536 (64 KiB)",
    0x100000: "1 MiB",
    0x1000000: "16 MiB",
}

_MAGIC_TABLE = {
    0x7F454C46: "ELF magic (0x7F 'E' 'L' 'F')",
    0x4D5A: "MZ (DOS/PE magic)",
    0xFEEDFACE: "Mach-O 32-bit magic",
    0xFEEDFACF: "Mach-O 64-bit magic",
    0xCAFEBABE: "Java class file magic",
    0x504B0304: "ZIP / JAR local file header",
    0x1F8B0800: "gzip member",
    0x89504E47: "PNG magic",
    0xFFD8FFE0: "JPEG JFIF magic",
}


class ClassifyConstantArgs(BaseModel):
    value: int = Field(..., description="The integer constant (already sign-extended)")
    context_snippet: str = Field(
        "",
        description="Short pseudocode snippet where the constant appears — "
                    "e.g. 'open(path, 0x4002)' or 'if arg0 == 0x41'.",
    )
    call_site_hint: str = Field(
        "",
        description="Optional name of the library function this constant is "
                    "passed to (open, mmap, ioctl, …). Dramatically improves "
                    "classification quality.",
    )
    use_llm: bool = True


class ConstantLabel(BaseModel):
    kind: ConstantKind
    symbolic: str = Field(
        ...,
        description="The form to emit in rewritten source, e.g. "
                    "\"O_RDWR | O_DIRECT\" or \"'A'\" or \"PAGE_SIZE\".",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class ClassifyConstantResult(BaseModel):
    value: int
    label: ConstantLabel
    source: str = Field(..., description="'table' | 'heuristic' | 'llm'")


def _table_lookup(
    value: int, call_site_hint: str
) -> Optional[ConstantLabel]:
    hint = call_site_hint.lower()

    # Context-dependent tables first.
    if "open" in hint:
        parts = []
        v = value
        for flag_val, flag_name in _OPEN_FLAGS:
            # Access modes are the low two bits, exactly one of them is set.
            if flag_val <= 2:
                if (v & 0x3) == flag_val and flag_name not in parts:
                    parts.append(flag_name)
            elif v & flag_val:
                parts.append(flag_name)
        if parts:
            return ConstantLabel(
                kind="flag_or",
                symbolic=" | ".join(parts),
                confidence=0.9,
                rationale="open(2)-family call with flag bits decoded",
            )

    # Unconditional tables.
    if value in _ERRNO_TABLE:
        return ConstantLabel(
            kind="errno",
            symbolic=f"-{_ERRNO_TABLE[value]}" if value != 0 else "0",
            confidence=0.75,
            rationale="matches a common POSIX errno value",
        )
    if value in _MAGIC_TABLE:
        return ConstantLabel(
            kind="magic_number",
            symbolic=_MAGIC_TABLE[value],
            confidence=0.95,
            rationale="matches a well-known file-format magic",
        )
    if value in _SIZE_TABLE:
        return ConstantLabel(
            kind="size",
            symbolic=_SIZE_TABLE[value],
            confidence=0.8,
            rationale="matches a power-of-two buffer/page size",
        )

    # Printable ASCII — only claim this when context hints at a
    # character-comparison or ldrb-style read.
    if 0x20 <= value < 0x7F and any(
        k in hint for k in ("cmp", "strcmp", "memcmp", "switch")
    ):
        return ConstantLabel(
            kind="char",
            symbolic=repr(chr(value)),
            confidence=0.8,
            rationale="printable ASCII in a character-comparison context",
        )

    return None


_SYSTEM_PROMPT = (
    "You are a reverse engineer annotating a constant that appeared in "
    "decompiled pseudocode. Pick the single best label from: char, "
    "mask, flag_or, enum_value, size, offset, magic_number, errno, "
    "page_size, syscall_number, timeout_ms, raw_numeric. Produce a "
    "symbolic rendering that you would want to appear in cleaned-up "
    "source code — e.g. `O_RDWR | O_CREAT` for 0x42 when passed to "
    "open(), `'A'` for 0x41 in a character comparison, `PAGE_SIZE` for "
    "4096 when used to align a pointer, or just `0x1337` when nothing "
    "better fits. Keep confidence honest — low when context is thin."
)


def _build_prompt(value: int, snippet: str, hint: str) -> str:
    parts = [f"Value: {value} (0x{value:x})"]
    if hint:
        parts.append(f"Passed to / used by: {hint}")
    if snippet:
        parts.append(f"Context:\n```\n{snippet}\n```")
    parts.append(
        "Return a kind, a symbolic rendering suitable for emitting in "
        "source code, a confidence in [0, 1], and a short rationale."
    )
    return "\n\n".join(parts)


class ClassifyConstantTool(
    MemoryTool[ClassifyConstantArgs, ClassifyConstantResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="classify_constant",
                description="Classify a single integer/float literal and "
                            "produce its symbolic rendering (O_RDWR | "
                            "O_CREAT, 'A', PAGE_SIZE, …). Curated table "
                            "first; LLM for residual.",
                tags=("llm", "constants", "layer0"),
            ),
            ClassifyConstantArgs,
            ClassifyConstantResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ClassifyConstantArgs,
    ) -> ClassifyConstantResult:
        tbl = _table_lookup(int(args.value), args.call_site_hint)
        if tbl is not None:
            return ClassifyConstantResult(
                value=int(args.value), label=tbl, source="table"
            )

        # Bare fallback — no LLM, no table match.
        default = ConstantLabel(
            kind="raw_numeric",
            symbolic=hex(args.value) if abs(args.value) >= 10 else str(args.value),
            confidence=0.3,
            rationale="no contextual hint available",
        )

        if not args.use_llm:
            return ClassifyConstantResult(
                value=int(args.value), label=default, source="heuristic"
            )

        prompt = _build_prompt(
            int(args.value), args.context_snippet, args.call_site_hint
        )
        label = run_structured_llm(
            prompt=prompt,
            output_type=ConstantLabel,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: default,
        )
        source = "heuristic" if label is default else "llm"
        return ClassifyConstantResult(
            value=int(args.value), label=label, source=source
        )


def build_tool() -> MemoryTool[ClassifyConstantArgs, ClassifyConstantResult]:
    return ClassifyConstantTool()
