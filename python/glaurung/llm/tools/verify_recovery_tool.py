"""Memory-tool wrappers for the recovery-verification pipeline (#202/#171).

Lets the agent call `compile_check` / `build_and_run` /
`compare_runtime_to_target` directly. The agent's typical workflow
becomes:

  1. decompile_function(va) → pseudocode
  2. (LLM rewrites pseudocode into idiomatic C)
  3. verify_compile(rewritten_c)        → gate 1
  4. verify_runtime(rewritten_c, target) → gate 2
  5. propose_function_name(rewritten_c)  → record findings

Each tool result includes the existing CompileResult / RunResult /
RuntimeComparison shape; the generic evidence-recording wrapper
(#208) automatically writes a citable evidence_log row for each
invocation.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


# ---------------------------------------------------------------------------
# verify_compile
# ---------------------------------------------------------------------------

class VerifyCompileArgs(BaseModel):
    source: str = Field(..., description="Recovered C / C++ source to syntax-check")
    language: str = Field("c", description='"c" or "cpp"')
    timeout_seconds: float = Field(15.0, description="Compiler timeout")


class VerifyCompileResult(BaseModel):
    ok: bool
    compiler: str
    stderr: str
    exit_code: int


class VerifyCompileTool(MemoryTool[VerifyCompileArgs, VerifyCompileResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="verify_compile",
                description=(
                    "Syntax-check a piece of recovered C/C++ source by piping "
                    "it through gcc/clang -fsyntax-only. Returns ok=False "
                    "with stderr populated when the compiler rejects the "
                    "source. Use this as the first gate after rewriting a "
                    "decompiled function — if it doesn't compile, fix the "
                    "rewrite before claiming recovery is complete."
                ),
                tags=("verify", "compile"),
            ),
            VerifyCompileArgs, VerifyCompileResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: VerifyCompileArgs,
    ) -> VerifyCompileResult:
        from ..kb.verify_recovery import compile_check
        r = compile_check(
            args.source, language=args.language,
            timeout_seconds=args.timeout_seconds,
        )
        return VerifyCompileResult(
            ok=r.ok, compiler=r.compiler,
            stderr=(r.stderr or "")[:4000],  # cap the agent context bloat
            exit_code=r.exit_code,
        )


def build_verify_compile_tool() -> VerifyCompileTool:
    return VerifyCompileTool()


# ---------------------------------------------------------------------------
# verify_runtime
# ---------------------------------------------------------------------------

class VerifyRuntimeArgs(BaseModel):
    source: str = Field(..., description="Recovered C / C++ source")
    target_binary: Optional[str] = Field(
        None,
        description="Optional path to target binary; when set, also runs "
        "the target with the same args/stdin and reports agreement.",
    )
    args: List[str] = Field(default_factory=list, description="argv to pass")
    stdin: Optional[str] = Field(None, description="stdin to pipe in")
    language: str = Field("c", description='"c" or "cpp"')
    timeout_seconds: float = Field(5.0, description="per-execution timeout")


class VerifyRuntimeResult(BaseModel):
    compile_ok: bool
    exit_code: int
    stdout: str
    stderr: str
    runtime_ms: float
    # Comparison fields (populated only when target_binary was given).
    same_exit_code: Optional[bool] = None
    same_stdout: Optional[bool] = None
    same_stderr: Optional[bool] = None
    target_exit_code: Optional[int] = None
    target_stdout: Optional[str] = None


class VerifyRuntimeTool(MemoryTool[VerifyRuntimeArgs, VerifyRuntimeResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="verify_runtime",
                description=(
                    "Compile and execute a piece of recovered source. With "
                    "target_binary set, also runs the target on the same "
                    "args/stdin and reports whether outputs agree — the "
                    "behavioral-equivalence gate. Use this as the second "
                    "verification step after verify_compile passes."
                ),
                tags=("verify", "run"),
            ),
            VerifyRuntimeArgs, VerifyRuntimeResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: VerifyRuntimeArgs,
    ) -> VerifyRuntimeResult:
        from ..kb.verify_recovery import (
            build_and_run, compare_runtime_to_target,
        )
        if args.target_binary:
            cmp = compare_runtime_to_target(
                args.source, args.target_binary,
                args=args.args, stdin=args.stdin,
                language=args.language,
                timeout_seconds=args.timeout_seconds,
            )
            rec = cmp.recovered_run
            tgt = cmp.target_run
            return VerifyRuntimeResult(
                compile_ok=rec.compile_ok,
                exit_code=rec.exit_code,
                stdout=(rec.stdout or "")[:4000],
                stderr=(rec.stderr or "")[:4000],
                runtime_ms=rec.runtime_ms,
                same_exit_code=cmp.same_exit_code,
                same_stdout=cmp.same_stdout,
                same_stderr=cmp.same_stderr,
                target_exit_code=tgt.exit_code,
                target_stdout=(tgt.stdout or "")[:4000],
            )
        rr = build_and_run(
            args.source, args=args.args, stdin=args.stdin,
            language=args.language, timeout_seconds=args.timeout_seconds,
        )
        return VerifyRuntimeResult(
            compile_ok=rr.compile_ok,
            exit_code=rr.exit_code,
            stdout=(rr.stdout or "")[:4000],
            stderr=(rr.stderr or "")[:4000],
            runtime_ms=rr.runtime_ms,
        )


def build_verify_runtime_tool() -> VerifyRuntimeTool:
    return VerifyRuntimeTool()
