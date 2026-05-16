"""Specialized pydantic-ai agents for Java/JVM workflows."""

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from ..config import get_config
from ..context import MemoryContext
from .memory_agent import register_analysis_tools
from .memory_foundation import inject_kb_context


JavaFindingSeverity = Literal["info", "low", "medium", "high", "critical"]


class JavaFinding(BaseModel):
    title: str
    severity: JavaFindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    class_name: str | None = None
    method_name: str | None = None
    method_descriptor: str | None = None
    source_file: str | None = None
    evidence: list[str] = Field(default_factory=list)
    next_action: str = ""


class JavaTriageAssessment(BaseModel):
    summary: str
    archive_type: str = "java"
    notable_packages: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    obfuscation_assessment: str = ""
    recommended_next_tools: list[str] = Field(default_factory=list)
    findings: list[JavaFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class JavaSecurityAssessment(BaseModel):
    summary: str
    findings: list[JavaFinding] = Field(default_factory=list)
    risky_categories: list[str] = Field(default_factory=list)
    requires_reachability_confirmation: bool = True
    recommended_next_tools: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class JavaRecoveryAssessment(BaseModel):
    summary: str
    recovery_status: str
    compile_status: str | None = None
    compatibility_score: float | None = Field(None, ge=0.0, le=1.0)
    automatic_repairs: list[str] = Field(default_factory=list)
    manual_repairs: list[str] = Field(default_factory=list)
    blockers: list[JavaFinding] = Field(default_factory=list)
    recommended_next_tools: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


def _make_java_agent(
    *,
    output_type: type[BaseModel],
    system_prompt: str,
    model: str | None = None,
) -> Any:
    cfg = get_config()
    available = cfg.available_models()
    model_name = model or (cfg.preferred_model() if any(available.values()) else "test")
    agent = Agent(
        model=model_name,
        system_prompt=system_prompt,
        deps_type=MemoryContext,
        output_type=output_type,
    )

    @agent.system_prompt
    async def _inject(ctx: RunContext[MemoryContext]) -> str:
        return inject_kb_context(ctx)

    return register_analysis_tools(cast(Any, agent))


def build_java_triage_agent(model: str | None = None) -> Any:
    return _make_java_agent(
        output_type=JavaTriageAssessment,
        system_prompt=(
            "You are a Java/JVM reverse-engineering triage agent. Always call "
            "`java_agent_context` with profile=`triage` first. Use the returned "
            "runbook to choose follow-up tools. Prefer `java_list_classes`, "
            "`java_list_methods`, `java_view_class`, and manifest/service tools "
            "before decompiling. If the archive is Minecraft or obfuscated, use "
            "mapping-aware tools before drawing semantic conclusions. Cite tool "
            "names and class/method descriptors in evidence fields."
        ),
        model=model,
    )


def build_java_security_agent(model: str | None = None) -> Any:
    return _make_java_agent(
        output_type=JavaSecurityAssessment,
        system_prompt=(
            "You are a Java/JVM security analysis agent. Always call "
            "`java_agent_context` with profile=`security` first. Rank findings by "
            "severity, reachability, config correlation, and entrypoint proximity. "
            "Use `java_risk_report`, `java_trace_to_sink`, and `java_reachability` "
            "to distinguish capability-only code from behavior that is reachable. "
            "Treat secrets and encoded blobs as concerning only when correlated "
            "with decode/load/network/process/file behavior. Do not call behavior "
            "malicious unless the evidence supports it."
        ),
        model=model,
    )


def build_java_recovery_agent(model: str | None = None) -> Any:
    return _make_java_agent(
        output_type=JavaRecoveryAssessment,
        system_prompt=(
            "You are a Java source recovery agent. Always call `java_agent_context` "
            "with profile=`recovery` first, then run `java_recovery_report` on a "
            "bounded package or class slice before broad recovery. Use compile "
            "diagnostics, source/bytecode links, and validation_summary from the "
            "report. Prefer dependency/build repair over source edits for missing "
            "packages, and separate automatic repairs from manual repairs. Do not "
            "claim clean recovery unless compile and the selected validation profile "
            "pass."
        ),
        model=model,
    )


__all__ = [
    "JavaFinding",
    "JavaRecoveryAssessment",
    "JavaSecurityAssessment",
    "JavaTriageAssessment",
    "build_java_recovery_agent",
    "build_java_security_agent",
    "build_java_triage_agent",
]
