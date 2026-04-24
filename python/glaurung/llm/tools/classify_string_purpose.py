"""Tool #1: classify one string literal's semantic purpose.

Layer 0 atomic labeler — runs thousands of times across a binary. The
output label is the building block every later layer uses when it
reasons about the string instead of the raw bytes.

Input: one string literal and, optionally, a short list of the
call-site contexts where it is used (e.g. ``call printf(_, %var0, …)``).
Output: a single-label classification with confidence and a brief
rationale citing the specific feature that tipped the decision.

The deterministic layer (regex pre-filter) handles the easy cases —
pure URLs, POSIX paths, sprintf format templates. The LLM is only
invoked for strings the regex does not confidently classify. When no
LLM is configured, the regex verdict is returned as-is with LOW
confidence.
"""

from __future__ import annotations

import re
from typing import List, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


StringKind = Literal[
    "url",
    "path",
    "format",
    "sql",
    "regex",
    "error_message",
    "log_template",
    "crypto_const",
    "key_material",
    "user_agent",
    "cmdline",
    "c2_beacon",
    "benign",
    "unknown",
]


class ClassifyStringPurposeArgs(BaseModel):
    text: str = Field(..., description="The string literal to classify")
    use_sites: List[str] = Field(
        default_factory=list,
        description="Optional — short pseudocode snippets where the string is "
                    "used. Improves disambiguation between formats and "
                    "plain messages.",
    )
    use_llm: bool = Field(
        True, description="Fall back to heuristics only if False"
    )


class StringPurpose(BaseModel):
    kind: StringKind
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(
        "",
        description="One-sentence justification citing the specific feature "
                    "that drove the classification (a %s format token, a "
                    "'http://' prefix, an ERR_ word, etc.).",
    )


class ClassifyStringPurposeResult(BaseModel):
    text: str
    purpose: StringPurpose
    source: str = Field(
        ..., description="'llm' when the model decided, 'heuristic' otherwise"
    )


# ---------------------------------------------------------------------------
# Heuristic pre-filter. Returns (kind, confidence) when very confident, or
# ("unknown", 0.0) when the LLM should decide.
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]{1,15}://", re.IGNORECASE)
_PATH_RE = re.compile(r"^(/[A-Za-z0-9._\-]+){2,}/?$")
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:\\")
_SQL_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE\s+TABLE|DROP|ALTER)\b",
    re.IGNORECASE,
)
_FORMAT_RE = re.compile(
    r"%[-+#0 ]*\d*(?:\.\d+)?[hljztL]*[diouxXeEfgGaAcspn]"
)
_CRYPTO_RE = re.compile(
    r"^(-----BEGIN |ssh-rsa |ssh-ed25519 |\$2[aby]\$|"
    r"MII[A-Za-z0-9+/]{16,})"
)
_USER_AGENT_RE = re.compile(r"(Mozilla/|curl/|Go-http-client/|python-requests/)")
_ERROR_WORD_RE = re.compile(
    r"\b(?:error|failed|cannot|invalid|unable|denied|timeout|refused|missing)\b",
    re.IGNORECASE,
)


def _heuristic(text: str) -> StringPurpose:
    s = text.strip()
    if not s:
        return StringPurpose(kind="benign", confidence=0.3, rationale="empty string")

    if _URL_RE.match(s):
        return StringPurpose(
            kind="url", confidence=0.95, rationale="scheme:// prefix"
        )
    if _USER_AGENT_RE.search(s):
        return StringPurpose(
            kind="user_agent",
            confidence=0.9,
            rationale="contains a known UA stem",
        )
    if _SQL_RE.search(s):
        return StringPurpose(
            kind="sql",
            confidence=0.85,
            rationale="contains an SQL keyword",
        )
    if _CRYPTO_RE.match(s):
        return StringPurpose(
            kind="key_material",
            confidence=0.9,
            rationale="matches PEM/SSH/bcrypt key prefix",
        )
    # Format vs error_message vs log_template is the ambiguous region
    # where the LLM actually earns its keep. Only claim a deterministic
    # verdict when we have one feature at a time.
    has_format = bool(_FORMAT_RE.search(s))
    has_error = bool(_ERROR_WORD_RE.search(s))
    if has_format and not has_error:
        return StringPurpose(
            kind="format",
            confidence=0.7,
            rationale="contains printf-style format token",
        )
    if has_error and not has_format:
        return StringPurpose(
            kind="error_message",
            confidence=0.7,
            rationale="contains an error-family word",
        )
    if _PATH_RE.match(s) or _WIN_PATH_RE.match(s):
        return StringPurpose(
            kind="path", confidence=0.8, rationale="matches filesystem path shape"
        )
    # Nothing confident — let the LLM decide.
    return StringPurpose(kind="unknown", confidence=0.0, rationale="")


_SYSTEM_PROMPT = (
    "You are a reverse engineer triaging string literals from a binary. "
    "Given one string and the call-site context in which it is used, "
    "pick the single best label from: url, path, format, sql, regex, "
    "error_message, log_template, crypto_const, key_material, "
    "user_agent, cmdline, c2_beacon, benign. Prefer a more specific "
    "label over a more general one — 'log_template' beats 'format' "
    "when the string is obviously a log line. Return a confidence in "
    "[0,1] and a one-sentence rationale citing the specific feature "
    "that decided it."
)


def _build_prompt(text: str, use_sites: List[str]) -> str:
    parts = [f"String: {text!r}"]
    if use_sites:
        # Cap to keep prompt small — 5 sites is usually sufficient.
        sites = use_sites[:5]
        parts.append(
            "Call sites:\n" + "\n".join(f"  - {s}" for s in sites)
        )
    parts.append(
        "Pick the best label, a confidence in [0, 1], and a short "
        "rationale citing the feature that decided it."
    )
    return "\n\n".join(parts)


class ClassifyStringPurposeTool(
    MemoryTool[ClassifyStringPurposeArgs, ClassifyStringPurposeResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="classify_string_purpose",
                description="Classify a single string literal into one of a "
                            "fixed label set (url, path, format, sql, "
                            "error_message, …). Heuristic pre-filter; LLM "
                            "fallback for ambiguous cases.",
                tags=("llm", "strings", "layer0"),
            ),
            ClassifyStringPurposeArgs,
            ClassifyStringPurposeResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ClassifyStringPurposeArgs,
    ) -> ClassifyStringPurposeResult:
        heur = _heuristic(args.text)
        # High-confidence heuristic → no LLM round-trip needed.
        if heur.confidence >= 0.8:
            return ClassifyStringPurposeResult(
                text=args.text, purpose=heur, source="heuristic"
            )

        if not args.use_llm:
            return ClassifyStringPurposeResult(
                text=args.text, purpose=heur, source="heuristic"
            )

        prompt = _build_prompt(args.text, args.use_sites)
        purpose = run_structured_llm(
            prompt=prompt,
            output_type=StringPurpose,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        # Distinguish "LLM answered" from "LLM unavailable → heuristic"
        # by checking identity against the heuristic object.
        source = "heuristic" if purpose is heur else "llm"
        return ClassifyStringPurposeResult(
            text=args.text, purpose=purpose, source=source
        )


def build_tool() -> MemoryTool[
    ClassifyStringPurposeArgs, ClassifyStringPurposeResult
]:
    return ClassifyStringPurposeTool()
