"""Tool #21: infer a build system for a recovered source tree.

Layer 3 cross-function coherence. The module layout tells us what
files to emit; this tool tells the orchestrator *how to build* them.
Outputs a complete build-file set for the target language:

- C     → ``CMakeLists.txt`` (+ ``compile_commands.json`` hook)
- Rust  → ``Cargo.toml`` (+ ``Cargo.lock`` is the user's problem)
- Go    → ``go.mod``
- Python → ``pyproject.toml``

Platform guard detection (``_WIN32`` / ``__linux__`` / ``__APPLE__``)
comes from the binary's imports. External library dependencies come
from the module-level import table produced by the orchestrator.
"""

from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


Language = Literal["c", "rust", "go", "python"]


class ModuleBuildInfo(BaseModel):
    path: str = Field(..., description="Module file path — 'net/http.c'")
    imports: List[str] = Field(
        default_factory=list,
        description="External library names referenced by this module",
    )
    platform: Optional[str] = Field(
        None,
        description="'windows' | 'linux' | 'darwin' | None when cross-platform",
    )


class InferBuildSystemArgs(BaseModel):
    target_language: Language = "c"
    project_name: str
    modules: List[ModuleBuildInfo]
    binary_imports: List[str] = Field(
        default_factory=list,
        description="All imported symbols from the binary — used to infer "
                    "which external libraries must be linked.",
    )
    platform_hint: Optional[str] = Field(
        None, description="'windows' | 'linux' | 'darwin' | None"
    )
    use_llm: bool = True


class BuildFile(BaseModel):
    path: str = Field(..., description="Filename relative to project root")
    content: str


class BuildSystem(BaseModel):
    files: List[BuildFile] = Field(default_factory=list)
    targets: List[str] = Field(
        default_factory=list, description="Top-level build targets"
    )
    dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="name → version-spec mapping for external deps",
    )
    notes: List[str] = Field(
        default_factory=list,
        description="Caveats — unresolved symbols, platform-specific code paths",
    )
    confidence: float = Field(ge=0.0, le=1.0)


class InferBuildSystemResult(BaseModel):
    build: BuildSystem
    source: str = Field(..., description="'llm' | 'heuristic'")


# ---------------------------------------------------------------------------
# Heuristic templates — enough structure to build the project offline.
# ---------------------------------------------------------------------------

_LIBC_HINTS = {"printf", "malloc", "strlen", "memcpy", "fopen", "open", "read", "write"}
_PTHREAD_HINTS = {"pthread_create", "pthread_mutex_lock", "pthread_cond_wait"}
_OPENSSL_HINTS = {"SSL_", "EVP_", "CRYPTO_"}
_CURL_HINTS = {"curl_easy_"}


def _guess_libs(imports: List[str]) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    joined = " ".join(imports)
    if any(h in joined for h in _PTHREAD_HINTS):
        deps["pthread"] = "system"
    if any(h in joined for h in _OPENSSL_HINTS):
        deps["openssl"] = ">=1.1"
    if any(h in joined for h in _CURL_HINTS):
        deps["libcurl"] = "*"
    return deps


def _heuristic_c(args: InferBuildSystemArgs) -> BuildSystem:
    deps = _guess_libs(args.binary_imports)
    sources = "\n    ".join(m.path for m in args.modules)
    link_libs = ""
    if deps:
        link_libs = "\ntarget_link_libraries(" + args.project_name + " PRIVATE " + \
                    " ".join(deps.keys()) + ")"
    content = (
        f"cmake_minimum_required(VERSION 3.16)\n"
        f"project({args.project_name} C)\n\n"
        f"set(CMAKE_C_STANDARD 11)\n"
        f"set(CMAKE_C_STANDARD_REQUIRED ON)\n\n"
        f"add_executable({args.project_name}\n    {sources}\n){link_libs}\n"
    )
    return BuildSystem(
        files=[BuildFile(path="CMakeLists.txt", content=content)],
        targets=[args.project_name],
        dependencies=deps,
        notes=["heuristic CMake file — library names are guesses"],
        confidence=0.45,
    )


def _heuristic_rust(args: InferBuildSystemArgs) -> BuildSystem:
    deps = {}  # keep minimal; LLM path fills real crate names
    cargo = (
        f'[package]\nname = "{args.project_name}"\nversion = "0.1.0"\n'
        f'edition = "2021"\n\n[dependencies]\n'
    )
    return BuildSystem(
        files=[BuildFile(path="Cargo.toml", content=cargo)],
        targets=[args.project_name],
        dependencies=deps,
        notes=["heuristic Cargo.toml — no crate deps inferred"],
        confidence=0.35,
    )


def _heuristic_go(args: InferBuildSystemArgs) -> BuildSystem:
    content = f"module {args.project_name}\n\ngo 1.21\n"
    return BuildSystem(
        files=[BuildFile(path="go.mod", content=content)],
        targets=[args.project_name],
        dependencies={},
        notes=["heuristic go.mod"],
        confidence=0.35,
    )


def _heuristic_python(args: InferBuildSystemArgs) -> BuildSystem:
    content = (
        f'[project]\nname = "{args.project_name}"\nversion = "0.1.0"\n'
        f'requires-python = ">=3.11"\n'
    )
    return BuildSystem(
        files=[BuildFile(path="pyproject.toml", content=content)],
        targets=[args.project_name],
        dependencies={},
        notes=["heuristic pyproject.toml"],
        confidence=0.35,
    )


def _heuristic(args: InferBuildSystemArgs) -> BuildSystem:
    return {
        "c": _heuristic_c,
        "rust": _heuristic_rust,
        "go": _heuristic_go,
        "python": _heuristic_python,
    }[args.target_language](args)


_SYSTEM_PROMPT = (
    "You are setting up the build system for a recovered project in "
    "the requested target language. Produce ONLY build-control files: "
    "CMakeLists.txt / Cargo.toml / go.mod / pyproject.toml / Makefile "
    "/ build.gradle / etc. Do NOT emit source files (.c, .cpp, .rs, "
    ".go, .py) or header files (.h, .hpp) — the source tree already "
    "exists separately and any .cpp/.c entry you return will be "
    "rejected by the orchestrator. Infer external library dependencies "
    "from the binary's import list (openssl, libcurl, pthread, zlib, "
    "…). Wrap platform-specific modules in the appropriate conditional "
    "(CMake's if(WIN32), Cargo's cfg(target_os)). Produce complete, "
    "syntactically valid files — not fragments."
)


def _build_prompt(args: InferBuildSystemArgs) -> str:
    parts = [
        f"Target language: {args.target_language}",
        f"Project name: {args.project_name}",
    ]
    if args.platform_hint:
        parts.append(f"Primary platform: {args.platform_hint}")
    parts.append("Modules:")
    for m in args.modules:
        plat = f" [{m.platform}]" if m.platform else ""
        parts.append(
            f"  {m.path}{plat}  imports: {m.imports}"
        )
    if args.binary_imports:
        parts.append(
            "Binary import list (sample):\n"
            + "\n".join(f"  - {n}" for n in args.binary_imports[:30])
        )
    parts.append(
        "Return a BuildSystem with files (path + content), targets, "
        "dependencies (name → version), and any caveats as notes."
    )
    return "\n\n".join(parts)


class InferBuildSystemTool(
    MemoryTool[InferBuildSystemArgs, InferBuildSystemResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="infer_build_system",
                description="Produce CMake / Cargo / go.mod / pyproject.toml "
                            "for a recovered source tree given module layout "
                            "and the binary's imports.",
                tags=("llm", "build", "layer3"),
            ),
            InferBuildSystemArgs,
            InferBuildSystemResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: InferBuildSystemArgs,
    ) -> InferBuildSystemResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return InferBuildSystemResult(build=heur, source="heuristic")

        prompt = _build_prompt(args)
        build = run_structured_llm(
            prompt=prompt,
            output_type=BuildSystem,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if build is heur else "llm"
        return InferBuildSystemResult(build=build, source=source)


def build_tool() -> MemoryTool[InferBuildSystemArgs, InferBuildSystemResult]:
    return InferBuildSystemTool()
