"""Tool #22: write README.md and a manpage from recovered inputs.

Layer 3 cross-function coherence. By the time this tool runs the hard
work has already been done — we have the module tree, the CLI
grammar, and one-line descriptions of everything. This tool is pure
text synthesis on top of the inputs; no code reasoning required.

Output is a ``README.md`` aimed at developers (what the project is,
how to build it, how to use it) and a troff-formatted manpage (section
1 for executables, section 3 for libraries).
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


class ModuleDescription(BaseModel):
    path: str
    purpose: str


class CliFlagDoc(BaseModel):
    long_name: Optional[str] = None
    short_name: Optional[str] = None
    help_text: str = ""


class WriteReadmeAndManpageArgs(BaseModel):
    project_name: str
    synopsis: str = Field(
        ..., description="One-line SYNOPSIS from #12"
    )
    description: str = Field(
        "", description="Short paragraph describing what the project does"
    )
    modules: List[ModuleDescription] = Field(default_factory=list)
    flags: List[CliFlagDoc] = Field(default_factory=list)
    subcommands: List[str] = Field(default_factory=list)
    build_instructions: str = Field(
        "", description="Build instructions derived from #21"
    )
    target_language: Literal["c", "rust", "go", "python"] = "c"
    manpage_section: int = 1
    use_llm: bool = True


class DocumentationBundle(BaseModel):
    readme: str = Field(..., description="Full README.md content")
    manpage: str = Field(..., description="Troff-formatted manpage")
    confidence: float = Field(ge=0.0, le=1.0)


class WriteReadmeAndManpageResult(BaseModel):
    docs: DocumentationBundle
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: WriteReadmeAndManpageArgs) -> DocumentationBundle:
    # README
    readme_parts = [f"# {args.project_name}", ""]
    if args.description:
        readme_parts.append(args.description)
        readme_parts.append("")
    readme_parts.append("## Synopsis")
    readme_parts.append("")
    readme_parts.append(f"```\n{args.synopsis}\n```")
    readme_parts.append("")
    if args.build_instructions:
        readme_parts.append("## Build")
        readme_parts.append("")
        readme_parts.append(args.build_instructions)
        readme_parts.append("")
    if args.modules:
        readme_parts.append("## Modules")
        readme_parts.append("")
        for m in args.modules:
            readme_parts.append(f"- `{m.path}` — {m.purpose}")
        readme_parts.append("")
    if args.flags:
        readme_parts.append("## Options")
        readme_parts.append("")
        for f in args.flags:
            flags = []
            if f.short_name:
                flags.append(f"-{f.short_name}")
            if f.long_name:
                flags.append(f"--{f.long_name}")
            readme_parts.append(
                f"- `{', '.join(flags) or '(unnamed)'}` — {f.help_text or 'TODO'}"
            )
        readme_parts.append("")
    readme = "\n".join(readme_parts).rstrip() + "\n"

    # Manpage (troff)
    manpage_parts = [
        f".TH {args.project_name.upper()} {args.manpage_section}",
        ".SH NAME",
        f"{args.project_name} \\- {args.description or 'TODO'}",
        ".SH SYNOPSIS",
        f".B {args.synopsis}",
    ]
    if args.flags:
        manpage_parts.append(".SH OPTIONS")
        for f in args.flags:
            flags = []
            if f.short_name:
                flags.append(f"-{f.short_name}")
            if f.long_name:
                flags.append(f"--{f.long_name}")
            manpage_parts.append(".TP")
            manpage_parts.append(f".B {', '.join(flags) or '(unnamed)'}")
            manpage_parts.append(f.help_text or "TODO")
    manpage = "\n".join(manpage_parts) + "\n"

    return DocumentationBundle(
        readme=readme,
        manpage=manpage,
        confidence=0.45,
    )


_SYSTEM_PROMPT = (
    "You are writing developer-facing documentation for a recovered "
    "project. Produce a README.md aimed at a developer who wants to "
    "build and use the project: sections for what it is, how to "
    "build, how to run, and a module tour. Separately produce a "
    "troff-formatted manpage in the requested section — NAME / "
    "SYNOPSIS / DESCRIPTION / OPTIONS / SEE ALSO. Keep the content "
    "honest and rooted in the inputs — don't invent features."
)


def _build_prompt(args: WriteReadmeAndManpageArgs) -> str:
    parts = [
        f"Project: {args.project_name}",
        f"Synopsis: {args.synopsis}",
        f"Description: {args.description}",
        f"Language: {args.target_language}",
        f"Manpage section: {args.manpage_section}",
    ]
    if args.modules:
        parts.append(
            "Modules:\n"
            + "\n".join(f"  - {m.path}: {m.purpose}" for m in args.modules)
        )
    if args.flags:
        parts.append(
            "Flags:\n"
            + "\n".join(
                f"  -{f.short_name or ''} --{f.long_name or ''}: {f.help_text}"
                for f in args.flags
            )
        )
    if args.build_instructions:
        parts.append(f"Build notes:\n{args.build_instructions}")
    parts.append("Return a DocumentationBundle with readme + manpage.")
    return "\n\n".join(parts)


class WriteReadmeAndManpageTool(
    MemoryTool[WriteReadmeAndManpageArgs, WriteReadmeAndManpageResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="write_readme_and_manpage",
                description="Produce README.md + troff manpage for a "
                            "recovered project given its module tree, CLI "
                            "grammar, and build instructions.",
                tags=("llm", "docs", "layer3"),
            ),
            WriteReadmeAndManpageArgs,
            WriteReadmeAndManpageResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WriteReadmeAndManpageArgs,
    ) -> WriteReadmeAndManpageResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return WriteReadmeAndManpageResult(docs=heur, source="heuristic")

        prompt = _build_prompt(args)
        docs = run_structured_llm(
            prompt=prompt,
            output_type=DocumentationBundle,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if docs is heur else "llm"
        return WriteReadmeAndManpageResult(docs=docs, source=source)


def build_tool() -> MemoryTool[
    WriteReadmeAndManpageArgs, WriteReadmeAndManpageResult
]:
    return WriteReadmeAndManpageTool()
