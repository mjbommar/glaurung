"""Tool #15: write a docstring for a freshly-rewritten function.

Layer 2 function-level. Separates doc generation from the rewrite
itself (#14) because:

- Keeps each LLM call small and focused.
- Lets docs be regenerated when a project-wide rename changes a
  function or struct name, without re-rewriting the body.
- The doc prompt can include caller usage — the function body alone
  rarely hints at why the function exists, but one real caller
  call-site usually does.

Output emits in the target language's native docstring dialect:
Doxygen for C/C++, rustdoc for Rust, godoc for Go, Google-style for
Python.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


DocStyle = Literal["doxygen", "rustdoc", "godoc", "python"]


class SynthesizeDocstringArgs(BaseModel):
    source: str = Field(..., description="Rewritten function source from #14")
    style: DocStyle = "doxygen"
    printed_strings: List[str] = Field(
        default_factory=list,
        description="String literals the function prints or logs — often the "
                    "single best signal for what the function does.",
    )
    caller_snippet: Optional[str] = Field(
        None,
        description="One real caller snippet showing a typical invocation. "
                    "Feeds the @example block.",
    )
    use_llm: bool = True


class FunctionDocstring(BaseModel):
    docblock: str = Field(
        ...,
        description="The complete doc-comment block, ready to paste above the "
                    "function definition.",
    )
    style: DocStyle
    example: Optional[str] = Field(
        None, description="Standalone one-liner example inferred from caller"
    )
    confidence: float = Field(ge=0.0, le=1.0)


class SynthesizeDocstringResult(BaseModel):
    doc: FunctionDocstring
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: SynthesizeDocstringArgs) -> FunctionDocstring:
    """Stub fallback: emit a minimal comment shell with the signature echoed.

    The offline path is intentionally plain so a reviewer recognises it
    as a placeholder.
    """
    if args.style == "doxygen":
        block = (
            "/**\n"
            " * @brief TODO — describe this function.\n"
            " *\n"
            " * Auto-generated placeholder; no LLM was available to write "
            "docs.\n"
            " */"
        )
    elif args.style == "rustdoc":
        block = "/// TODO — describe this function. (Auto-placeholder.)"
    elif args.style == "godoc":
        block = "// TODO — describe this function. (Auto-placeholder.)"
    else:  # python
        block = '"""TODO — describe this function. (Auto-placeholder.)"""'
    return FunctionDocstring(
        docblock=block,
        style=args.style,
        example=None,
        confidence=0.1,
    )


def _system_prompt(style: DocStyle) -> str:
    style_rules = {
        "doxygen": (
            "Emit a Doxygen comment block (`/** ... */`). Use @brief, "
            "@param NAME DESCRIPTION for each parameter, @return, "
            "@retval for notable return values, @note, and @code/@endcode "
            "for the example."
        ),
        "rustdoc": (
            "Emit rustdoc `///` line comments. Start with a one-line "
            "summary, blank line, details, then `# Examples` with a "
            "```rust fenced block. Use `# Errors` when applicable."
        ),
        "godoc": (
            "Emit godoc-style `//` line comments immediately above the "
            "function declaration, starting with the function name."
        ),
        "python": (
            "Emit a Google-style triple-quoted docstring with sections: "
            "summary, Args, Returns, Raises, Example."
        ),
    }[style]
    return (
        "You are a reverse engineer writing documentation for a freshly "
        "recovered function. You will be shown its source and some "
        "context (the strings it prints, one real caller call-site). "
        "Write a concise, accurate doc block describing what the "
        "function does, its parameters, its return value, and when it "
        "errors. Cite concrete evidence from the source — do not "
        "invent requirements. " + style_rules
    )


def _build_prompt(args: SynthesizeDocstringArgs) -> str:
    parts = [f"Source:\n```\n{args.source}\n```"]
    if args.printed_strings:
        parts.append(
            "Strings printed:\n"
            + "\n".join(f"  - {s!r}" for s in args.printed_strings[:8])
        )
    if args.caller_snippet:
        parts.append(f"Caller example:\n```\n{args.caller_snippet}\n```")
    parts.append(
        "Write the docblock. Include a short example only when the "
        "caller snippet makes one obvious."
    )
    return "\n\n".join(parts)


class SynthesizeDocstringTool(
    MemoryTool[SynthesizeDocstringArgs, SynthesizeDocstringResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="synthesize_docstring",
                description="Write a Doxygen/rustdoc/godoc/Python docstring "
                            "for a rewritten function from its source plus "
                            "string and caller evidence.",
                tags=("llm", "docs", "layer2"),
            ),
            SynthesizeDocstringArgs,
            SynthesizeDocstringResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: SynthesizeDocstringArgs,
    ) -> SynthesizeDocstringResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return SynthesizeDocstringResult(doc=heur, source="heuristic")

        prompt = _build_prompt(args)
        doc = run_structured_llm(
            prompt=prompt,
            output_type=FunctionDocstring,
            system_prompt=_system_prompt(args.style),
            fallback=lambda: heur,
        )
        source = "heuristic" if doc is heur else "llm"
        return SynthesizeDocstringResult(doc=doc, source=source)


def build_tool() -> MemoryTool[
    SynthesizeDocstringArgs, SynthesizeDocstringResult
]:
    return SynthesizeDocstringTool()
