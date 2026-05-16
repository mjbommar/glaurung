"""Convenience runners for Java/JVM pydantic-ai agents."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.adapters import import_triage
from ..tools.java_agent_context import JavaAgentContextResult
from .java import (
    JavaRecoveryAssessment,
    JavaSecurityAssessment,
    JavaTriageAssessment,
    build_java_recovery_agent,
    build_java_security_agent,
    build_java_triage_agent,
    prime_java_agent_context,
)


JavaAgentRunProfile = Literal["triage", "security", "recovery"]
JavaAgentAssessment = (
    JavaTriageAssessment | JavaSecurityAssessment | JavaRecoveryAssessment
)


class JavaAgentToolCall(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    seeded: bool = False


class JavaAgentRunResult(BaseModel):
    path: str
    profile: JavaAgentRunProfile
    model: str
    prompt: str
    assessment_type: str
    assessment: JavaAgentAssessment
    context: JavaAgentContextResult
    tool_calls: list[JavaAgentToolCall] = Field(default_factory=list)
    tool_call_count: int = 0


def run_java_agent_analysis(
    path: str | Path,
    *,
    profile: JavaAgentRunProfile,
    model: str | None = None,
    prompt: str | None = None,
    config_roots: list[str] | None = None,
    mapping_path: str | None = None,
    max_classes: int = 512,
    max_resources: int = 128,
    max_findings: int = 64,
) -> JavaAgentRunResult:
    """Run a focused Java agent end-to-end for one archive."""

    archive_path = Path(path)
    artifact = g.triage.analyze_path(str(archive_path), 700_000_000, 200_000_000, 1)
    ctx = MemoryContext(file_path=str(archive_path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(archive_path))

    seeded = prime_java_agent_context(
        ctx,
        profile=profile,
        config_roots=config_roots or [],
        mapping_path=mapping_path,
        max_classes=max_classes,
        max_resources=max_resources,
        max_findings=max_findings,
    )

    selected_model = model or _default_model()
    agent = _build_agent(profile, selected_model)
    final_prompt = prompt or _default_prompt(profile)
    result = agent.run_sync(final_prompt, deps=ctx)
    assessment = result.output
    calls = [
        _coerce_tool_call(call) for call in (getattr(ctx, "_tool_calls", []) or [])
    ]

    return JavaAgentRunResult(
        path=str(archive_path),
        profile=profile,
        model=selected_model,
        prompt=final_prompt,
        assessment_type=type(assessment).__name__,
        assessment=assessment,
        context=seeded,
        tool_calls=calls,
        tool_call_count=len(calls),
    )


def run_java_triage_analysis(
    path: str | Path,
    **kwargs: Any,
) -> JavaAgentRunResult:
    return run_java_agent_analysis(path, profile="triage", **kwargs)


def run_java_security_analysis(
    path: str | Path,
    **kwargs: Any,
) -> JavaAgentRunResult:
    return run_java_agent_analysis(path, profile="security", **kwargs)


def run_java_recovery_analysis(
    path: str | Path,
    **kwargs: Any,
) -> JavaAgentRunResult:
    return run_java_agent_analysis(path, profile="recovery", **kwargs)


def _default_model() -> str:
    from ..config import get_config

    return get_config().preferred_model()


def _build_agent(profile: JavaAgentRunProfile, model: str) -> Any:
    if profile == "security":
        return build_java_security_agent(model=model)
    if profile == "recovery":
        return build_java_recovery_agent(model=model)
    return build_java_triage_agent(model=model)


def _default_prompt(profile: JavaAgentRunProfile) -> str:
    if profile == "security":
        return (
            "Analyze this Java archive for evidence-backed security-relevant "
            "behavior. Use java_risk_report before making findings, and do not "
            "call behavior malicious unless the evidence supports it."
        )
    if profile == "recovery":
        return (
            "Assess how recoverable this Java archive is as clean source. Use "
            "bounded recovery/report tools and separate automatic repairs from "
            "manual blockers."
        )
    return (
        "Triage this Java archive. Identify archive type, packages, entrypoints, "
        "frameworks, obfuscation, and the best next tools."
    )


def _coerce_tool_call(call: Any) -> JavaAgentToolCall:
    if not isinstance(call, dict):
        return JavaAgentToolCall(tool=str(call))
    result = call.get("result")
    return JavaAgentToolCall(
        tool=str(call.get("tool", "")),
        args=call.get("args", {}) if isinstance(call.get("args"), dict) else {},
        result=result if isinstance(result, dict) else None,
        error=str(call["error"]) if call.get("error") is not None else None,
        seeded=bool(call.get("seeded", False)),
    )


__all__ = [
    "JavaAgentRunProfile",
    "JavaAgentRunResult",
    "JavaAgentToolCall",
    "run_java_agent_analysis",
    "run_java_recovery_analysis",
    "run_java_security_analysis",
    "run_java_triage_analysis",
]
