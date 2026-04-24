"""Tool #3: name a string literal and annotate its format arguments.

Layer 0 atomic labeler. Produces the ``static const char[]`` symbol
name downstream source will reference, plus — when the string is a
printf/log template — an annotated list of the parameters it expects.

Example:
    input:  "error: cannot open %s (errno=%d)"
    output: name="ERR_FOPEN_FMT"
            format_args=[{name="path", c_type="const char *"},
                         {name="err",  c_type="int"}]

The regex layer is good at *positional* format tokens (``%s``,
``%d``, ``%ld``) but bad at naming them — an LLM reading the
surrounding message decides that ``%s`` is a path, not a username.
"""

from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


_FORMAT_TOKEN_RE = re.compile(
    r"%[-+#0 ]*\d*(?:\.\d+)?"
    r"(?P<length>hh|h|ll|l|j|z|t|L)?"
    r"(?P<spec>[diouxXeEfgGaAcspn%])"
)


def _c_type_for(length: str, spec: str) -> str:
    """Default C type for a printf conversion specifier + length modifier.

    Feeds the heuristic fallback; the LLM can override with something
    more semantic (``const char *path`` instead of ``const char *arg0``).
    """
    if spec == "s":
        return "const char *"
    if spec == "p":
        return "const void *"
    if spec == "c":
        return "int"
    if spec == "n":
        return "int *"
    if spec in "diouxX":
        if length in ("ll", "j"):
            return "long long" if spec in "di" else "unsigned long long"
        if length == "l":
            return "long" if spec in "di" else "unsigned long"
        if length == "h":
            return "short" if spec in "di" else "unsigned short"
        if length == "hh":
            return "signed char" if spec in "di" else "unsigned char"
        if length == "z":
            return "size_t"
        if length == "t":
            return "ptrdiff_t"
        return "int" if spec in "di" else "unsigned int"
    if spec in "eEfgGaA":
        return "long double" if length == "L" else "double"
    return "int"


def _slugify(text: str, max_len: int = 24) -> str:
    """Pure-Python, deterministic fallback name generator."""
    words = re.findall(r"[A-Za-z0-9]+", text.lower())[:4]
    if not words:
        return "STR_LITERAL"
    name = "_".join(words).upper()
    if len(name) > max_len:
        name = name[:max_len].rstrip("_")
    return name or "STR_LITERAL"


class NameStringLiteralArgs(BaseModel):
    text: str = Field(..., description="The string literal to name")
    use_sites: List[str] = Field(
        default_factory=list,
        description="Optional — pseudocode snippets where the string is used. "
                    "Help the LLM name format arguments semantically.",
    )
    use_llm: bool = True


class FormatArgument(BaseModel):
    name: str = Field(..., description="Suggested parameter name (snake_case)")
    c_type: str = Field(..., description="Inferred C type — 'const char *', 'int', …")
    rationale: str = ""


class NamedString(BaseModel):
    symbolic_name: str = Field(
        ...,
        description="SCREAMING_SNAKE_CASE name for the static const char[]",
    )
    format_args: List[FormatArgument] = Field(
        default_factory=list,
        description="Positional format arguments when text is a template; "
                    "empty when the string is static.",
    )
    is_template: bool = False
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class NameStringLiteralResult(BaseModel):
    text: str
    named: NamedString
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(text: str) -> NamedString:
    name = _slugify(text)
    tokens = list(_FORMAT_TOKEN_RE.finditer(text))
    # '%%' is the escaped percent sign and should not produce an argument.
    real_tokens = [m for m in tokens if m.group("spec") != "%"]
    if real_tokens:
        # Give it a suffix that signals it's a template.
        if not name.endswith("_FMT"):
            name = (name + "_FMT")[:28]
        args: List[FormatArgument] = []
        for i, m in enumerate(real_tokens):
            ctype = _c_type_for(m.group("length") or "", m.group("spec"))
            args.append(
                FormatArgument(
                    name=f"arg{i}",
                    c_type=ctype,
                    rationale=f"from '%{m.group('length') or ''}{m.group('spec')}' "
                              "token width/type",
                )
            )
        return NamedString(
            symbolic_name=name,
            format_args=args,
            is_template=True,
            confidence=0.55,
            rationale=f"{len(real_tokens)} format token(s) detected",
        )
    return NamedString(
        symbolic_name=name,
        format_args=[],
        is_template=False,
        confidence=0.6,
        rationale="no format tokens; treated as a static string",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer naming a string constant that will appear "
    "as a `static const char NAME[]` in recovered source code. Produce a "
    "SCREAMING_SNAKE_CASE name of at most 28 characters. Keep the name "
    "*descriptive of purpose*, not verbatim content — 'ERR_FOPEN_FMT' for "
    "\"error: cannot open %s (errno=%d)\", not 'ERROR_CANNOT_OPEN'. When "
    "the string contains printf-style format tokens, set is_template=True "
    "and fill format_args with one entry per positional argument, picking "
    "semantic names ('path', 'err', 'user_id') over generic ones and "
    "using idiomatic C types."
)


def _build_prompt(text: str, use_sites: List[str]) -> str:
    parts = [f"String: {text!r}"]
    if use_sites:
        parts.append(
            "Call sites:\n" + "\n".join(f"  - {s}" for s in use_sites[:5])
        )
    parts.append(
        "Give it a SCREAMING_SNAKE_CASE name. If it is a template, name "
        "each positional argument semantically and give its C type."
    )
    return "\n\n".join(parts)


class NameStringLiteralTool(
    MemoryTool[NameStringLiteralArgs, NameStringLiteralResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="name_string_literal",
                description="Propose a SCREAMING_SNAKE_CASE symbol name for "
                            "a string literal and, when it is a printf "
                            "template, semantically name and type each "
                            "positional argument.",
                tags=("llm", "strings", "layer0"),
            ),
            NameStringLiteralArgs,
            NameStringLiteralResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: NameStringLiteralArgs,
    ) -> NameStringLiteralResult:
        heur = _heuristic(args.text)
        if not args.use_llm:
            return NameStringLiteralResult(
                text=args.text, named=heur, source="heuristic"
            )

        prompt = _build_prompt(args.text, args.use_sites)
        named = run_structured_llm(
            prompt=prompt,
            output_type=NamedString,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if named is heur else "llm"
        return NameStringLiteralResult(
            text=args.text, named=named, source=source
        )


def build_tool() -> MemoryTool[NameStringLiteralArgs, NameStringLiteralResult]:
    return NameStringLiteralTool()
