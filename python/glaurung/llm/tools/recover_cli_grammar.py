"""Tool #12: recover a binary's command-line grammar.

Layer 1 structural recovery. Hand-written argv parsers do not follow
any single template: some use ``getopt``, some use a ``strcmp`` ladder,
some a hash table, some roll their own state machine. Only an LLM
reading the argv-handling pseudocode plus any ``-h``/``--help`` text
can recover the synopsis, flag list, required/optional status, and
subcommand tree reliably.

The output feeds #22 (``write_readme_and_manpage``) directly: its
``synopsis`` field becomes the SYNOPSIS section of the manpage, its
``flags`` become the OPTIONS table, and its ``subcommands`` become
the subcommand documentation.
"""

from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


FlagKind = Literal["boolean", "string", "integer", "count", "choice"]


class RecoverCliGrammarArgs(BaseModel):
    argv_pseudocode: str = Field(
        ..., description="Pseudocode of the main() argv-handling block"
    )
    help_strings: List[str] = Field(
        default_factory=list,
        description="Raw -h / --help text extracted verbatim from the "
                    "binary. Best single naming signal if present.",
    )
    program_name_hint: Optional[str] = Field(
        None, description="Short program name hint (basename)"
    )
    use_llm: bool = True


class CliFlag(BaseModel):
    long_name: Optional[str] = Field(None, description="--long-name (without dashes)")
    short_name: Optional[str] = Field(None, description="Single character -s")
    kind: FlagKind = "boolean"
    required: bool = False
    default_value: Optional[str] = None
    help_text: str = ""
    choices: List[str] = Field(
        default_factory=list,
        description="Populated only when kind='choice'",
    )


class CliSubcommand(BaseModel):
    name: str
    help_text: str = ""
    flags: List[CliFlag] = Field(default_factory=list)
    positional: List[str] = Field(default_factory=list)


class CliGrammar(BaseModel):
    program_name: str
    synopsis: str = Field(
        ..., description="One-line SYNOPSIS suitable for a manpage"
    )
    description: str = Field(
        "", description="Short paragraph describing what the program does"
    )
    flags: List[CliFlag] = Field(default_factory=list)
    positional: List[str] = Field(
        default_factory=list,
        description="Positional arguments in order — 'path', 'count', …",
    )
    subcommands: List[CliSubcommand] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RecoverCliGrammarResult(BaseModel):
    grammar: CliGrammar
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic: harvest every --flag / -f token from argv pseudocode or the
# help text. Always low confidence — this is a stop-gap so offline mode
# at least produces a flag list.
# ---------------------------------------------------------------------------

_LONG_RE = re.compile(r"--([A-Za-z][A-Za-z0-9_\-]+)")
_SHORT_RE = re.compile(r"(?<![A-Za-z])-([A-Za-z])(?![A-Za-z])")


def _heuristic(args: RecoverCliGrammarArgs) -> CliGrammar:
    blob = args.argv_pseudocode + "\n" + "\n".join(args.help_strings)
    longs = sorted(set(_LONG_RE.findall(blob)))
    shorts = sorted(set(_SHORT_RE.findall(blob)))

    flags: List[CliFlag] = []
    for lg in longs:
        flags.append(
            CliFlag(
                long_name=lg,
                short_name=lg[0] if lg[0] in shorts else None,
                kind="boolean",
                help_text="",
            )
        )
    # Short flags that did not pair up with a long one.
    consumed_shorts = {f.short_name for f in flags if f.short_name}
    for sh in shorts:
        if sh in consumed_shorts:
            continue
        flags.append(
            CliFlag(
                long_name=None,
                short_name=sh,
                kind="boolean",
                help_text="",
            )
        )

    name = args.program_name_hint or "program"
    synopsis = f"{name} [OPTIONS]"
    return CliGrammar(
        program_name=name,
        synopsis=synopsis,
        description="",
        flags=flags,
        positional=[],
        subcommands=[],
        confidence=0.35 if flags else 0.15,
        rationale="harvested flag tokens from argv pseudocode and help text",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer recovering a program's command-line "
    "grammar from its argv-handling pseudocode and any -h/--help text "
    "baked into the binary. Produce the synopsis line, a short "
    "description, and the full flag list with long/short names, kind "
    "(boolean, string, integer, count, choice), required/optional, "
    "default values, and help text. If the program has subcommands "
    "(like `git clone`, `tar xzf`), list them with their own flags "
    "and positional arguments. Prefer verbatim help text over guesses "
    "for help_text."
)


def _build_prompt(args: RecoverCliGrammarArgs) -> str:
    parts = []
    if args.program_name_hint:
        parts.append(f"Program name: {args.program_name_hint}")
    parts.append(f"argv pseudocode:\n```\n{args.argv_pseudocode}\n```")
    if args.help_strings:
        parts.append(
            "Help text strings:\n"
            + "\n".join(f"  {s!r}" for s in args.help_strings[:10])
        )
    parts.append(
        "Return a CliGrammar with synopsis, description, flags, "
        "positional, and subcommands. Be honest about confidence."
    )
    return "\n\n".join(parts)


class RecoverCliGrammarTool(
    MemoryTool[RecoverCliGrammarArgs, RecoverCliGrammarResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="recover_cli_grammar",
                description="Recover a program's full CLI grammar from "
                            "argv-handling pseudocode and help text: "
                            "synopsis, flags, positional args, subcommands.",
                tags=("llm", "cli", "layer1"),
            ),
            RecoverCliGrammarArgs,
            RecoverCliGrammarResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RecoverCliGrammarArgs,
    ) -> RecoverCliGrammarResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return RecoverCliGrammarResult(grammar=heur, source="heuristic")

        prompt = _build_prompt(args)
        gramm = run_structured_llm(
            prompt=prompt,
            output_type=CliGrammar,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if gramm is heur else "llm"
        return RecoverCliGrammarResult(grammar=gramm, source=source)


def build_tool() -> MemoryTool[RecoverCliGrammarArgs, RecoverCliGrammarResult]:
    return RecoverCliGrammarTool()
