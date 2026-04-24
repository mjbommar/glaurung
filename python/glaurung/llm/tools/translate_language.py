"""Tool #24: re-target a recovered C tree to another language.

Layer 4 cross-language. Separate from #14 because the skill is
different: #14 turns pseudocode into clean source in any target
language; this tool takes *already-clean* source and translates it
idiomatically to another language. That separation keeps each call
tractable — by the time we reach this tool the input is syntactically
valid, the types are recovered, the names are reconciled. What
remains is idiom translation:

- ``malloc`` / ``free`` → Rust ``Box`` / ``Drop``
- ``-errno`` returns → ``Result<T, E>``
- Callbacks → closures or trait objects
- Goto-based error unwinding → ``?``
- ``NULL`` → ``Option<&T>``

The output includes ``idiom_notes`` so a reviewer sees exactly which
non-mechanical transformations the LLM performed per file.
"""

from __future__ import annotations

from typing import List, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


SourceLanguage = Literal["c", "rust", "go", "python"]
TargetLanguage = Literal["rust", "go", "python", "c"]


class SourceFile(BaseModel):
    path: str
    content: str


class TranslateLanguageArgs(BaseModel):
    source_language: SourceLanguage = "c"
    target_language: TargetLanguage
    files: List[SourceFile] = Field(
        ..., description="Clean recovered source tree — one entry per file"
    )
    project_name: str = "recovered"
    use_llm: bool = True


class IdiomNote(BaseModel):
    file: str
    original_pattern: str = Field(
        ..., description="Brief description of what the source used"
    )
    translated_pattern: str = Field(
        ..., description="What the target-language version uses instead"
    )
    rationale: str = ""


class TranslatedTree(BaseModel):
    files: List[SourceFile] = Field(default_factory=list)
    idiom_notes: List[IdiomNote] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = ""


class TranslateLanguageResult(BaseModel):
    tree: TranslatedTree
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: TranslateLanguageArgs) -> TranslatedTree:
    """Offline fallback: wrap each file in a 'not translated' stub so the
    output is still a valid tree, just a pass-through one."""
    stubbed: List[SourceFile] = []
    ext_map = {"rust": "rs", "go": "go", "python": "py", "c": "c"}
    for f in args.files:
        base = f.path.rsplit(".", 1)[0]
        new_path = f"{base}.{ext_map[args.target_language]}"
        body = (
            f"// TODO — translate from {args.source_language} to "
            f"{args.target_language}. LLM unavailable; source preserved below.\n"
            f"/*\n{f.content}\n*/"
            if args.target_language in ("c", "rust", "go")
            else (
                f'"""TODO — translate from {args.source_language}. '
                f'LLM unavailable."""\n'
                + "\n".join(f"# {ln}" for ln in f.content.splitlines())
            )
        )
        stubbed.append(SourceFile(path=new_path, content=body))
    return TranslatedTree(
        files=stubbed,
        idiom_notes=[],
        confidence=0.1,
        summary="offline stub — no translation performed",
    )


def _system_prompt(src: str, tgt: str) -> str:
    return (
        f"You are a senior engineer translating an already-clean "
        f"{src} source tree into idiomatic {tgt}. The input is not "
        f"pseudocode — it has good names, recovered types, and a real "
        f"module layout. Your job is *idiom translation*: take each "
        f"file and rewrite it using the target language's natural "
        f"facilities. "
        f"For C → Rust specifically: malloc/free become Box/Drop; "
        f"errno-style negative returns become Result<T, E>; callbacks "
        f"become closures or trait objects; goto-based error unwinding "
        f"becomes `?`; NULL-checked pointers become Option. "
        f"For C → Go: errno returns become (T, error); manual memory "
        f"management disappears; callbacks become interface method "
        f"calls; globals become package-level vars. "
        f"For C → Python: structs become dataclasses; enums become "
        f"enum.IntEnum; errno returns become exceptions. "
        f"Record every non-mechanical transformation per file as an "
        f"idiom_note — that is the user's audit trail."
    )


def _build_prompt(args: TranslateLanguageArgs) -> str:
    parts = [
        f"Source language: {args.source_language}",
        f"Target language: {args.target_language}",
        f"Project: {args.project_name}",
        f"Files ({len(args.files)}):",
    ]
    for f in args.files:
        parts.append(f"--- {f.path} ---\n```\n{f.content}\n```")
    parts.append(
        "Return a TranslatedTree with files (translated), idiom_notes "
        "(one per non-mechanical rewrite), confidence, and summary."
    )
    return "\n\n".join(parts)


class TranslateLanguageTool(
    MemoryTool[TranslateLanguageArgs, TranslateLanguageResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="translate_language",
                description="Translate a clean recovered source tree to a "
                            "different target language, with per-file idiom "
                            "notes describing every non-mechanical rewrite.",
                tags=("llm", "translate", "layer4"),
            ),
            TranslateLanguageArgs,
            TranslateLanguageResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: TranslateLanguageArgs,
    ) -> TranslateLanguageResult:
        if not args.files:
            return TranslateLanguageResult(
                tree=TranslatedTree(
                    files=[], idiom_notes=[], confidence=0.1,
                    summary="empty input tree"
                ),
                source="heuristic",
            )
        if not args.use_llm:
            return TranslateLanguageResult(tree=_heuristic(args), source="heuristic")

        prompt = _build_prompt(args)
        tree = run_structured_llm(
            prompt=prompt,
            output_type=TranslatedTree,
            system_prompt=_system_prompt(
                args.source_language, args.target_language
            ),
            fallback=lambda: _heuristic(args),
        )
        source = "llm" if tree.confidence > 0.2 else "heuristic"
        return TranslateLanguageResult(tree=tree, source=source)


def build_tool() -> MemoryTool[TranslateLanguageArgs, TranslateLanguageResult]:
    return TranslateLanguageTool()
