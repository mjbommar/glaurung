"""Specialized pydantic-ai agents for Java/JVM workflows."""

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from ..config import get_config
from ..context import MemoryContext
from ..tools.java_agent_context import (
    JavaAgentContextResult,
    JavaAgentProfile,
    build_tool as build_java_agent_context,
)
from .java_toolsets import JavaAgentToolProfile, register_java_agent_tools
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
    context_profile: JavaAgentToolProfile,
    model: str | None = None,
    tool_strict: bool | None = True,
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
        seed_note = ""
        try:
            seeded = prime_java_agent_context(ctx.deps, profile=context_profile)
            seed_note = (
                "\n\nJava agent context has already been seeded with "
                f"profile={seeded.profile!r}: {seeded.headline}"
            )
        except Exception as exc:
            seed_note = (
                "\n\nJava agent context pre-seeding failed; call "
                f"`java_agent_context` with profile={context_profile!r} before "
                f"deep analysis. Error: {type(exc).__name__}: {exc}"
            )
        return inject_kb_context(ctx) + seed_note

    return register_java_agent_tools(
        cast(Any, agent),
        profile=context_profile,
        strict=tool_strict,
    )


def prime_java_agent_context(
    ctx: MemoryContext,
    *,
    profile: JavaAgentProfile,
    config_roots: list[str] | None = None,
    mapping_path: str | None = None,
    max_classes: int = 512,
    max_resources: int = 128,
    max_findings: int = 64,
    force: bool = False,
) -> JavaAgentContextResult:
    """Seed a MemoryContext with profile-specific Java kickoff evidence.

    This takes the "always call java_agent_context first" rule out of the
    model's hands. Agents can still call the tool again when they need fresh
    or differently-budgeted context, but every run starts with the intended
    profile already in the KB.
    """

    seeded_profiles = getattr(ctx, "_java_agent_context_seeded_profiles", set())
    seeded_results = getattr(ctx, "_java_agent_context_seeded_results", {})
    if not isinstance(seeded_profiles, set):
        seeded_profiles = set(seeded_profiles)
    if not isinstance(seeded_results, dict):
        seeded_results = {}
    cached = seeded_results.get(profile)
    if profile in seeded_profiles and isinstance(cached, JavaAgentContextResult):
        if not force:
            return cached

    tool = build_java_agent_context()
    args = tool.input_model(
        profile=profile,
        config_roots=config_roots or [],
        mapping_path=mapping_path,
        max_classes=max_classes,
        max_resources=max_resources,
        max_findings=max_findings,
    )
    result = tool.run(ctx, ctx.kb, args)
    seeded_profiles.add(profile)
    seeded_results[profile] = result
    setattr(ctx, "_java_agent_context_seeded_profiles", seeded_profiles)
    setattr(ctx, "_java_agent_context_seeded_results", seeded_results)

    calls = getattr(ctx, "_tool_calls", None)
    if calls is None:
        calls = []
        setattr(ctx, "_tool_calls", calls)
    calls.append(
        {
            "tool": tool.meta.name,
            "args": args.model_dump(),
            "result": result.model_dump(),
            "seeded": True,
        }
    )
    return result


def build_java_triage_agent(model: str | None = None) -> Any:
    return _make_java_agent(
        output_type=JavaTriageAssessment,
        system_prompt=(
            "You are a Java/JVM reverse-engineering triage agent. Always call "
            "`java_agent_context` with profile=`triage` first when refreshed "
            "context is needed. The host pre-seeds triage context before the "
            "model run. Use the returned runbook to choose follow-up tools. "
            "Prefer `java_list_classes`, "
            "`java_list_methods`, `java_view_class`, and manifest/service tools "
            "before decompiling. If the archive is Minecraft or obfuscated, use "
            "mapping-aware tools before drawing semantic conclusions. Cite tool "
            "names and class/method descriptors in evidence fields."
        ),
        context_profile="triage",
        model=model,
    )


def build_java_security_agent(model: str | None = None) -> Any:
    return _make_java_agent(
        output_type=JavaSecurityAssessment,
        system_prompt=(
            "You are a Java/JVM security analysis agent. Always call "
            "`java_agent_context` with profile=`security` first when refreshed "
            "context is needed. The host pre-seeds security context before the "
            "model run. Rank findings by severity, reachability, config "
            "correlation, and entrypoint proximity. "
            "Use `java_risk_report`, `java_trace_to_sink`, and `java_reachability` "
            "to distinguish capability-only code from behavior that is reachable. "
            "Treat secrets and encoded blobs as concerning only when correlated "
            "with decode/load/network/process/file behavior. Do not call behavior "
            "malicious unless the evidence supports it."
        ),
        context_profile="security",
        model=model,
    )


def build_java_recovery_agent(model: str | None = None) -> Any:
    return _make_java_agent(
        output_type=JavaRecoveryAssessment,
        system_prompt=(
            "You are a Java source recovery agent. Always call `java_agent_context` "
            "with profile=`recovery` first when refreshed context is needed. The "
            "host pre-seeds recovery context before the model run, then you should "
            "run `java_recovery_report` on a bounded package or class slice before "
            "broad recovery. Use compile "
            "diagnostics, source/bytecode links, and validation_summary from the "
            "report. Prefer dependency/build repair over source edits for missing "
            "packages, and separate automatic repairs from manual repairs. Do not "
            "claim clean recovery unless compile and the selected validation profile "
            "pass."
        ),
        context_profile="recovery",
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
    "prime_java_agent_context",
]
