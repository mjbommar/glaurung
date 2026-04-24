"""Specialised pydantic-ai agents for common RE workflows.

Each factory here returns a fully-wired ``pydantic_ai.Agent`` with:

- the complete glaurung analysis tool surface registered (via
  :func:`register_analysis_tools`)
- a focused system prompt describing the agent's role
- a structured output schema so downstream code can consume the result
  without string-scraping

The implementations are deliberately thin — the heavy lifting lives in
the individual :mod:`glaurung.llm.tools` modules. These agents just
pose the question, let the LLM plan the tool calls, and structure the
reply.

All agents accept a ``MemoryContext`` as deps.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from ..config import get_config
from ..context import MemoryContext
from .memory_agent import register_analysis_tools
from .memory_foundation import inject_kb_context


def _make_agent(
    output_type: type,
    system_prompt: str,
    model: Optional[str] = None,
) -> Agent:
    cfg = get_config()
    avail = cfg.available_models()
    model_name = model or (cfg.preferred_model() if any(avail.values()) else "test")
    agent = Agent(
        model=model_name,
        system_prompt=system_prompt,
        deps_type=MemoryContext,
        output_type=output_type,
    )

    @agent.system_prompt
    async def _inject(ctx: RunContext[MemoryContext]) -> str:
        return inject_kb_context(ctx)

    return register_analysis_tools(agent)


# ---------------------------------------------------------------------------
# 1. FunctionExplainAgent — "what does sub_XXXX do?"
# ---------------------------------------------------------------------------


class FunctionExplanation(BaseModel):
    entry_va: int
    suggested_name: str = Field(..., description="snake_case name proposal")
    summary: str = Field(..., description="One-paragraph plain-English summary")
    key_operations: List[str] = Field(
        default_factory=list,
        description="Bullet list of the function's observable behaviour — "
                    "library calls, string uses, I/O, arithmetic invariants.",
    )
    calls: List[str] = Field(
        default_factory=list, description="Resolved direct-call targets"
    )
    confidence: float = Field(ge=0.0, le=1.0)


def build_function_explain_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=FunctionExplanation,
        system_prompt=(
            "You are a reverse engineering assistant focused on *one function*. "
            "When asked about a function at some VA, use `decompile_function` "
            "to read its pseudocode and `list_calls_from_function` / "
            "`list_xrefs_to` for its callgraph context. Prefer concrete "
            "evidence (string literals, resolved library calls, control-flow "
            "shape) over speculation. Summarise the behaviour crisply."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 2. BinaryTriageAgent — "what is this file?"
# ---------------------------------------------------------------------------


class BinaryTriageReport(BaseModel):
    format: Optional[str]
    arch: Optional[str]
    bits: Optional[int]
    compiler: Optional[str]
    language: Optional[str]
    likely_purpose: str = Field(
        ..., description="One-paragraph hypothesis of what the binary does"
    )
    notable_strings: List[str] = Field(default_factory=list)
    notable_imports: List[str] = Field(default_factory=list)
    risks: List[str] = Field(
        default_factory=list,
        description="Concrete red flags (network I/O, crypto, debugger checks, ...)",
    )
    confidence: float = Field(ge=0.0, le=1.0)


def build_binary_triage_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=BinaryTriageReport,
        system_prompt=(
            "You are a senior triage analyst. Given a single binary, "
            "produce a one-page overview. Start with "
            "`identify_compiler_and_runtime`, then "
            "`list_suspicious_imports`, `view_strings`, and "
            "`list_functions` (ordered by size / fan-in). Use the remaining "
            "tools as needed to resolve open questions. Be concrete — cite "
            "strings and imports rather than speaking in generalities."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 3. VulnerabilityHuntAgent — pattern-match classic C-level bugs
# ---------------------------------------------------------------------------


class PotentialVulnerability(BaseModel):
    entry_va: int
    function_name: str
    kind: str = Field(
        ...,
        description="'buffer-overflow', 'format-string', 'integer-overflow', "
                    "'use-after-free', 'command-injection', 'toctou', 'other'",
    )
    evidence: str = Field(..., description="Pseudocode excerpt and reasoning")
    severity: str = Field(..., description="'low' | 'medium' | 'high'")


class VulnerabilityHuntReport(BaseModel):
    findings: List[PotentialVulnerability] = Field(default_factory=list)
    summary: str
    confidence: float = Field(ge=0.0, le=1.0)


def build_vulnerability_hunt_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=VulnerabilityHuntReport,
        system_prompt=(
            "You are a vulnerability researcher looking for classic C/C++ "
            "bugs. Start with `list_suspicious_imports` to find candidates "
            "(strcpy/sprintf/gets, system/popen/execve, malloc+strcpy "
            "pairs, ...). For each hit, locate callers via `list_xrefs_to` "
            "and read the pseudocode with `decompile_function`. Report only "
            "findings you can justify with a specific pseudocode excerpt — "
            "no speculation."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 4. SecurityPostureAgent — check binary hardening
# ---------------------------------------------------------------------------


class SecurityPostureReport(BaseModel):
    pie: Optional[bool] = None
    nx: Optional[bool] = None
    relro: Optional[str] = None
    stack_canary: Optional[bool] = None
    aslr: Optional[bool] = None
    stripped: Optional[bool] = None
    missing_mitigations: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    overall_grade: str = Field(..., description="'A' | 'B' | 'C' | 'D' | 'F'")


def build_security_posture_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=SecurityPostureReport,
        system_prompt=(
            "You are a binary hardening auditor. Extract PIE/NX/RELRO/ASLR/"
            "canary/stripped status — triage data is already in the KB, "
            "and `identify_compiler_and_runtime` surfaces additional "
            "signals. If a mitigation is missing, state the concrete "
            "action (e.g. 'recompile with -Wl,-z,relro -Wl,-z,now'). "
            "Grade the posture A–F based on how many baseline mitigations "
            "are enabled."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 5. CallGraphNavigatorAgent — "does X reach Y?"
# ---------------------------------------------------------------------------


class CallPathFinding(BaseModel):
    source_va: int
    target_name: str
    reachable: bool
    path: List[str] = Field(
        default_factory=list,
        description="Function-name chain from source to target (inclusive).",
    )
    notes: str = Field("", description="Caveats — indirect calls, plt stubs, etc.")


def build_call_graph_navigator_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=CallPathFinding,
        system_prompt=(
            "You navigate the binary's callgraph to answer reachability "
            "questions ('does main reach execve?'). Start from the caller "
            "and walk forward with `list_xrefs_from` / "
            "`list_calls_from_function`, decompiling functions only when "
            "needed to decide between alternative branches. When the "
            "target is an imported symbol, check PLT/GOT maps. Be explicit "
            "about indirect calls you could not resolve."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 6. RenameSweepAgent — rename the top-N functions by significance
# ---------------------------------------------------------------------------


class RenameDecision(BaseModel):
    entry_va: int
    old_name: str
    new_name: str
    rationale: str


class RenameSweepReport(BaseModel):
    renamed: List[RenameDecision] = Field(default_factory=list)
    skipped: List[str] = Field(
        default_factory=list,
        description="Function names the agent declined to rename, with a brief reason.",
    )
    summary: str


def build_rename_sweep_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=RenameSweepReport,
        system_prompt=(
            "You perform a bulk rename pass. Use `list_functions` to pick "
            "candidates (prefer large `total_instr_count` and high "
            "`callers_count`; skip tiny stubs and already-named libc/crt "
            "helpers). For each, call `name_function` (LLM-backed) to "
            "propose a snake_case name, then `rename_in_kb` to persist it. "
            "Do not rename `main`, `_start`, `__libc_csu_init`, or other "
            "well-known runtime symbols unless the evidence is overwhelming."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 7. StringClusterAgent — group strings into semantic themes
# ---------------------------------------------------------------------------


class StringCluster(BaseModel):
    label: str = Field(..., description="Short cluster name, e.g. 'HTTP URLs'")
    examples: List[str] = Field(default_factory=list)
    purpose: str = Field(..., description="Why these strings exist in the binary")


class StringClusterReport(BaseModel):
    clusters: List[StringCluster] = Field(default_factory=list)
    outliers: List[str] = Field(
        default_factory=list,
        description="Strings that don't fit any cluster and are interesting.",
    )
    summary: str


def build_string_cluster_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=StringClusterReport,
        system_prompt=(
            "You are a corpus linguist for binary strings. Use "
            "`view_strings` to pull the list, then cluster them by "
            "*semantic purpose*: URLs, error messages, file paths, crypto "
            "constants, formatting templates, log lines, etc. Name each "
            "cluster, give 3–5 representative examples, and call out "
            "outliers that hint at unusual functionality (e.g. a lone "
            "base64 blob, a user-agent string, a registry key)."
        ),
        model=model,
    )


# ---------------------------------------------------------------------------
# 8. TaintTraceAgent — follow a function's parameter through its uses
# ---------------------------------------------------------------------------


class TaintStep(BaseModel):
    va: int
    function_name: str
    description: str = Field(..., description="How the tainted value flows here")


class TaintTraceReport(BaseModel):
    source_va: int
    source_parameter: str = Field(
        ..., description="Parameter name/index of the initially tainted value"
    )
    steps: List[TaintStep] = Field(default_factory=list)
    sinks: List[str] = Field(
        default_factory=list,
        description="Dangerous functions the taint reaches (system, execve, strcpy, ...)",
    )
    summary: str


def build_taint_trace_agent(model: Optional[str] = None) -> Agent:
    return _make_agent(
        output_type=TaintTraceReport,
        system_prompt=(
            "You perform lightweight, structural taint analysis. Given a "
            "function and a parameter, `decompile_function` the entry and "
            "follow uses of that parameter: when it is passed to another "
            "function, recurse; when it lands in a library sink "
            "(strcpy/system/execve/sprintf/memcpy without a length check), "
            "flag it. Report the call chain you traced. This is a *static* "
            "trace — be explicit about joins you couldn't resolve (indirect "
            "calls, table-driven dispatch)."
        ),
        model=model,
    )


__all__ = [
    "FunctionExplanation",
    "BinaryTriageReport",
    "PotentialVulnerability",
    "VulnerabilityHuntReport",
    "SecurityPostureReport",
    "CallPathFinding",
    "RenameDecision",
    "RenameSweepReport",
    "StringCluster",
    "StringClusterReport",
    "TaintStep",
    "TaintTraceReport",
    "build_function_explain_agent",
    "build_binary_triage_agent",
    "build_vulnerability_hunt_agent",
    "build_security_posture_agent",
    "build_call_graph_navigator_agent",
    "build_rename_sweep_agent",
    "build_string_cluster_agent",
    "build_taint_trace_agent",
]
