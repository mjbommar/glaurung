"""Tool #18: cluster functions into source-file modules.

Layer 3 cross-function coherence. Given every function's role,
one-line summary, and the callgraph edges between them, propose a
source-file layout (``net/http_parser.c``, ``crypto/aes_ctr.c``,
``util/buffer.c``, …). Graph modularity provides the structural
skeleton; the LLM supplies the module names and arbitrates helper
functions that could belong to more than one module.

The output is a flat list of modules — no subdirectory hierarchy
beyond one level, because deeper trees require project-specific
conventions the LLM cannot infer from the binary alone.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


class FunctionSummary(BaseModel):
    name: str
    entry_va: int
    role: str = ""
    one_line_summary: str = ""


class CallEdge(BaseModel):
    caller: str
    callee: str


class ClusterFunctionsIntoModulesArgs(BaseModel):
    functions: List[FunctionSummary]
    edges: List[CallEdge] = Field(default_factory=list)
    project_name_hint: Optional[str] = Field(
        None, description="Project name — used as a fallback module prefix."
    )
    target_language: str = "c"
    use_llm: bool = True


class Module(BaseModel):
    name: str = Field(..., description="File path — e.g. 'net/http_parser.c'")
    purpose: str = Field(..., description="One-line description of module's role")
    members: List[str] = Field(
        ..., description="Function names assigned to this module"
    )


class ModuleLayout(BaseModel):
    modules: List[Module] = Field(default_factory=list)
    unassigned: List[str] = Field(
        default_factory=list,
        description="Functions the LLM could not confidently place",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class ClusterFunctionsIntoModulesResult(BaseModel):
    layout: ModuleLayout
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic: cluster by role label. Every role gets its own module; the
# LLM path upgrades this to semantically-named modules and reassigns
# multi-role helpers.
# ---------------------------------------------------------------------------

_ROLE_TO_MODULE = {
    "parser": "parsers",
    "serializer": "serialize",
    "validator": "validate",
    "crypto_core": "crypto",
    "network_io": "net",
    "file_io": "io",
    "dispatch_table": "dispatch",
    "ioctl_handler": "ioctl",
    "state_machine_step": "state",
    "getter": "accessors",
    "setter": "accessors",
    "wrapper": "wrappers",
    "entry_stub": "main",
    "ctor_dtor": "init",
    "other": "core",
}


def _language_ext(target: str) -> str:
    return {"rust": "rs", "go": "go", "python": "py"}.get(target, "c")


def _heuristic(args: ClusterFunctionsIntoModulesArgs) -> ModuleLayout:
    ext = _language_ext(args.target_language)
    buckets: Dict[str, List[str]] = defaultdict(list)
    for f in args.functions:
        module = _ROLE_TO_MODULE.get(f.role or "other", "core")
        buckets[module].append(f.name)
    prefix = args.project_name_hint or ""
    modules: List[Module] = []
    for mod, members in sorted(buckets.items()):
        filename = f"{prefix + '/' if prefix else ''}{mod}/{mod}.{ext}"
        modules.append(
            Module(
                name=filename,
                purpose=f"functions classified as '{mod}'",
                members=sorted(members),
            )
        )
    return ModuleLayout(
        modules=modules,
        unassigned=[],
        confidence=0.4,
        rationale="grouped by heuristic role label",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer proposing a source-file layout for a "
    "recovered project. You will be given every function's name, role, "
    "and one-line summary, plus the callgraph edges between them. "
    "Propose a flat set of modules — one source file per module — "
    "named like `net/http_parser.c` or `crypto/aes.c`. Use the "
    "callgraph as the structural skeleton: functions that only call "
    "one another belong in the same module; a helper called from "
    "everywhere goes in `util/` or `common/`. Be specific with module "
    "names (not just 'core' or 'misc'). List any functions you cannot "
    "confidently place in `unassigned` rather than inventing a module "
    "for them."
)


def _build_prompt(args: ClusterFunctionsIntoModulesArgs) -> str:
    parts = []
    if args.project_name_hint:
        parts.append(f"Project: {args.project_name_hint}")
    parts.append(f"Target language: {args.target_language}")
    parts.append("Functions (name, role, summary):")
    for f in args.functions:
        parts.append(
            f"  {f.name}  role={f.role!r}  -- {f.one_line_summary[:80]}"
        )
    if args.edges:
        parts.append(
            "Callgraph edges (caller → callee):\n"
            + "\n".join(
                f"  {e.caller} -> {e.callee}" for e in args.edges[:200]
            )
        )
    parts.append(
        "Return a ModuleLayout with modules (name/purpose/members), "
        "unassigned list, confidence, rationale."
    )
    return "\n\n".join(parts)


class ClusterFunctionsIntoModulesTool(
    MemoryTool[
        ClusterFunctionsIntoModulesArgs, ClusterFunctionsIntoModulesResult
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="cluster_functions_into_modules",
                description="Propose the source-file layout of a recovered "
                            "project — module names and function-to-module "
                            "assignments — from roles, summaries, and the "
                            "callgraph.",
                tags=("llm", "modules", "layer3"),
            ),
            ClusterFunctionsIntoModulesArgs,
            ClusterFunctionsIntoModulesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ClusterFunctionsIntoModulesArgs,
    ) -> ClusterFunctionsIntoModulesResult:
        if not args.functions:
            return ClusterFunctionsIntoModulesResult(
                layout=ModuleLayout(
                    modules=[], unassigned=[], confidence=0.1,
                    rationale="no functions supplied",
                ),
                source="heuristic",
            )

        heur = _heuristic(args)
        if not args.use_llm:
            return ClusterFunctionsIntoModulesResult(layout=heur, source="heuristic")

        prompt = _build_prompt(args)
        layout = run_structured_llm(
            prompt=prompt,
            output_type=ModuleLayout,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if layout is heur else "llm"
        return ClusterFunctionsIntoModulesResult(layout=layout, source=source)


def build_tool() -> MemoryTool[
    ClusterFunctionsIntoModulesArgs, ClusterFunctionsIntoModulesResult
]:
    return ClusterFunctionsIntoModulesTool()
