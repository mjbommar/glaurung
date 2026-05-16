from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_detect_entrypoints import build_tool as build_java_detect_entrypoints
from .java_detect_frameworks import build_tool as build_java_detect_frameworks
from .java_detect_obfuscation import build_tool as build_java_detect_obfuscation
from .java_detect_security_sensitive_behavior import (
    build_tool as build_java_detect_sensitive_behavior,
)
from .java_detect_secrets import build_tool as build_java_detect_secrets
from .java_detect_suspicious_blobs import (
    build_tool as build_java_detect_suspicious_blobs,
)
from .java_index_archive import build_tool as build_java_index_archive
from .java_infer_build_system import build_tool as build_java_infer_build_system
from .java_infer_dependencies import build_tool as build_java_infer_dependencies
from .java_risk_report import build_tool as build_java_risk_report
from .minecraft_detect_archive import build_tool as build_minecraft_detect_archive


JavaAgentProfile = Literal["triage", "security", "recovery", "deobfuscation"]


class JavaAgentContextArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    profile: JavaAgentProfile = Field(
        "triage",
        description=(
            "Agent workflow profile. triage is cheap general context; security "
            "adds risk/sink/secret/blob summaries; recovery adds build/dependency "
            "planning; deobfuscation emphasizes mapping/readability guidance."
        ),
    )
    config_roots: list[str] = Field(default_factory=list)
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for mapped Java evidence.",
    )
    max_classes: int = Field(512, ge=0)
    max_resources: int = Field(128, ge=0)
    max_findings: int = Field(64, ge=0)


class JavaAgentArchiveFacts(BaseModel):
    class_count: int
    parsed_class_count: int
    resource_count: int
    manifest_main_class: str | None = None
    signed: bool = False
    nested_archive_count: int = 0
    service_descriptor_count: int = 0
    module_info_present: bool = False
    maven_artifact_count: int = 0
    multi_release: bool = False
    suspicious_entry_count: int = 0


class JavaAgentMinecraftFacts(BaseModel):
    is_minecraft: bool
    loader: str
    side: str
    minecraft_version: str | None = None
    mapping_recommended: bool = False
    preferred_mapping_source: str | None = None
    rationale: str


class JavaAgentObfuscationFacts(BaseModel):
    level: str
    confidence: float
    mapping_recommended: bool
    short_class_name_count: int
    short_member_name_count: int
    examples: list[str] = Field(default_factory=list)
    rationale: str


class JavaAgentEntrypointFacts(BaseModel):
    entrypoint_count: int
    summary_by_category: dict[str, int] = Field(default_factory=dict)
    samples: list[str] = Field(default_factory=list)


class JavaAgentFrameworkFacts(BaseModel):
    framework_count: int
    summary_by_kind: dict[str, int] = Field(default_factory=dict)
    samples: list[str] = Field(default_factory=list)


class JavaAgentSecurityFacts(BaseModel):
    sensitive_finding_count: int = 0
    risk_item_count: int = 0
    secret_candidate_count: int = 0
    suspicious_blob_count: int = 0
    highest_severity: str = "none"
    max_risk_score: int = 0
    summary_by_category: dict[str, int] = Field(default_factory=dict)
    top_findings: list[str] = Field(default_factory=list)


class JavaAgentRecoveryFacts(BaseModel):
    dependency_count: int = 0
    build_tool: str | None = None
    java_release: int | None = None
    generated_files: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class JavaAgentContextResult(BaseModel):
    archive_path: str
    profile: JavaAgentProfile
    is_java_archive: bool
    headline: str
    summary_lines: list[str] = Field(default_factory=list)
    runbook: list[str] = Field(default_factory=list)
    recommended_next_tools: list[str] = Field(default_factory=list)
    archive: JavaAgentArchiveFacts | None = None
    minecraft: JavaAgentMinecraftFacts | None = None
    obfuscation: JavaAgentObfuscationFacts | None = None
    entrypoints: JavaAgentEntrypointFacts | None = None
    frameworks: JavaAgentFrameworkFacts | None = None
    security: JavaAgentSecurityFacts | None = None
    recovery: JavaAgentRecoveryFacts | None = None
    context_node_id: str | None = None


class JavaAgentContextTool(
    MemoryTool[JavaAgentContextArgs, JavaAgentContextResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_agent_context",
                description=(
                    "Build a compact Java/JAR agent kickoff context and runbook "
                    "from existing Java tools. Use this before deeper Java "
                    "triage, security, recovery, or deobfuscation analysis."
                ),
                tags=("java", "agent", "workflow", "kb"),
            ),
            JavaAgentContextArgs,
            JavaAgentContextResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaAgentContextArgs,
    ) -> JavaAgentContextResult:
        path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(path):
            return JavaAgentContextResult(
                archive_path=str(path),
                profile=args.profile,
                is_java_archive=False,
                headline="Input is not a Java archive.",
                summary_lines=["The path is not a ZIP/JAR archive."],
                runbook=["Switch to the generic binary/archive workflow."],
                recommended_next_tools=["import_triage", "analyze_recursively"],
            )

        archive = _archive_facts(ctx, kb, path, args)
        minecraft = _minecraft_facts(ctx, kb, path)
        obfuscation = _obfuscation_facts(ctx, kb, path, args)
        entrypoints = _entrypoint_facts(ctx, kb, path, args)
        frameworks = _framework_facts(ctx, kb, path, args)
        security = (
            _security_facts(ctx, kb, path, args)
            if args.profile == "security"
            else None
        )
        recovery = (
            _recovery_facts(ctx, kb, path, args) if args.profile == "recovery" else None
        )

        result = JavaAgentContextResult(
            archive_path=str(path),
            profile=args.profile,
            is_java_archive=True,
            headline=_headline(args.profile, archive, minecraft, obfuscation, security),
            summary_lines=_summary_lines(
                archive, minecraft, obfuscation, entrypoints, frameworks, security
            ),
            runbook=_runbook(args.profile, minecraft, obfuscation),
            recommended_next_tools=_recommended_next_tools(
                args.profile, minecraft, obfuscation, security
            ),
            archive=archive,
            minecraft=minecraft,
            obfuscation=obfuscation,
            entrypoints=entrypoints,
            frameworks=frameworks,
            security=security,
            recovery=recovery,
        )
        node = kb.add_node(
            Node(
                kind=NodeKind.java_agent_context,
                label=f"Java agent context: {args.profile}",
                text="\n".join(result.summary_lines),
                props={
                    "tool": "java_agent_context",
                    "archive_path": str(path),
                    "profile": args.profile,
                    "headline": result.headline,
                    "recommended_next_tools": result.recommended_next_tools,
                },
                tags=["java", "agent", args.profile],
            )
        )
        result.context_node_id = node.id
        return result


def _archive_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaAgentContextArgs,
) -> JavaAgentArchiveFacts:
    tool = build_java_index_archive()
    result = tool.run(
        ctx,
        kb,
        tool.input_model(
            path=str(path),
            max_classes=args.max_classes,
            include_resources=True,
            max_resources=args.max_resources,
        ),
    )
    return JavaAgentArchiveFacts(
        class_count=result.class_count,
        parsed_class_count=result.parsed_class_count,
        resource_count=result.resource_count,
        manifest_main_class=result.manifest_main_class,
        signed=result.signed,
        nested_archive_count=result.nested_archive_count,
        service_descriptor_count=result.service_descriptor_count,
        module_info_present=result.module_info_present,
        maven_artifact_count=result.maven_artifact_count,
        multi_release=result.manifest_multi_release
        or result.multi_release_class_count > 0,
        suspicious_entry_count=len(result.suspicious_entries),
    )


def _minecraft_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
) -> JavaAgentMinecraftFacts:
    tool = build_minecraft_detect_archive()
    result = tool.run(ctx, kb, tool.input_model(path=str(path)))
    return JavaAgentMinecraftFacts(
        is_minecraft=result.is_minecraft,
        loader=result.loader,
        side=result.side,
        minecraft_version=result.minecraft_version,
        mapping_recommended=result.mapping_recommended,
        preferred_mapping_source=result.preferred_mapping_source,
        rationale=result.rationale,
    )


def _obfuscation_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaAgentContextArgs,
) -> JavaAgentObfuscationFacts:
    tool = build_java_detect_obfuscation()
    result = tool.run(
        ctx,
        kb,
        tool.input_model(path=str(path), max_classes=max(args.max_classes, 1)),
    )
    examples = [
        *result.short_class_examples[:4],
        *result.short_member_examples[:4],
    ]
    return JavaAgentObfuscationFacts(
        level=result.level,
        confidence=result.confidence,
        mapping_recommended=result.mapping_recommended,
        short_class_name_count=result.short_class_name_count,
        short_member_name_count=result.short_member_name_count,
        examples=examples[:8],
        rationale=result.rationale,
    )


def _entrypoint_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaAgentContextArgs,
) -> JavaAgentEntrypointFacts:
    tool = build_java_detect_entrypoints()
    result = tool.run(
        ctx,
        kb,
        tool.input_model(
            path=str(path),
            max_classes=args.max_classes,
            max_entrypoints=min(max(args.max_findings, 1), 128),
        ),
    )
    return JavaAgentEntrypointFacts(
        entrypoint_count=result.entrypoint_count,
        summary_by_category=result.summary_by_category,
        samples=[
            f"{item.category}:{item.class_name}.{item.method_name or '<class>'}"
            for item in result.entrypoints[:8]
        ],
    )


def _framework_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaAgentContextArgs,
) -> JavaAgentFrameworkFacts:
    tool = build_java_detect_frameworks()
    result = tool.run(
        ctx,
        kb,
        tool.input_model(path=str(path), max_frameworks=min(args.max_findings, 128)),
    )
    return JavaAgentFrameworkFacts(
        framework_count=result.framework_count,
        summary_by_kind=result.summary_by_kind,
        samples=[
            f"{item.kind}:{item.name}" for item in result.frameworks[:8]
        ],
    )


def _security_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaAgentContextArgs,
) -> JavaAgentSecurityFacts:
    sensitive_tool = build_java_detect_sensitive_behavior()
    sensitive = sensitive_tool.run(
        ctx,
        kb,
        sensitive_tool.input_model(
            path=str(path),
            mapping_path=args.mapping_path,
            max_classes=args.max_classes,
            max_findings=args.max_findings,
        ),
    )
    secrets_tool = build_java_detect_secrets()
    secrets = secrets_tool.run(
        ctx,
        kb,
        secrets_tool.input_model(
            path=str(path),
            max_classes=args.max_classes,
            max_candidates=args.max_findings,
        ),
    )
    blobs_tool = build_java_detect_suspicious_blobs()
    blobs = blobs_tool.run(
        ctx,
        kb,
        blobs_tool.input_model(
            path=str(path),
            max_classes=args.max_classes,
            max_findings=args.max_findings,
            include_benign_resource_like=False,
        ),
    )
    risk_tool = build_java_risk_report()
    risk = risk_tool.run(
        ctx,
        kb,
        risk_tool.input_model(
            path=str(path),
            config_roots=args.config_roots,
            mapping_path=args.mapping_path,
            max_classes=args.max_classes,
            max_findings=args.max_findings,
            max_risk_items=max(args.max_findings, 1),
            max_secret_candidates=args.max_findings,
            max_reachability_targets=min(args.max_findings, 16),
        ),
    )
    summary_by_category = dict(risk.summary_by_category)
    for category, count in sensitive.summary_by_category.items():
        summary_by_category.setdefault(category, count)
    top_findings = [
        f"{item.severity}:{item.category}:{item.message}"
        for item in risk.risk_items[:8]
    ]
    if not top_findings:
        top_findings = [
            f"{item.severity}:{item.category}:{item.message}"
            for item in sensitive.findings[:8]
        ]
    return JavaAgentSecurityFacts(
        sensitive_finding_count=sensitive.finding_count,
        risk_item_count=risk.risk_item_count,
        secret_candidate_count=secrets.candidate_count,
        suspicious_blob_count=blobs.finding_count,
        highest_severity=risk.highest_severity,
        max_risk_score=risk.max_risk_score,
        summary_by_category=summary_by_category,
        top_findings=top_findings,
    )


def _recovery_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaAgentContextArgs,
) -> JavaAgentRecoveryFacts:
    deps_tool = build_java_infer_dependencies()
    deps = deps_tool.run(
        ctx,
        kb,
        deps_tool.input_model(path=str(path), max_classes=args.max_classes),
    )
    build_tool = build_java_infer_build_system()
    build = build_tool.run(
        ctx,
        kb,
        build_tool.input_model(path=str(path), max_dependencies=args.max_findings),
    )
    return JavaAgentRecoveryFacts(
        dependency_count=deps.dependency_count,
        build_tool=build.selected_build_tool,
        java_release=build.java_release,
        generated_files=[item.path for item in build.build_files],
        warnings=[*deps.stop_reasons, *build.warnings, *build.stop_reasons],
    )


def _headline(
    profile: JavaAgentProfile,
    archive: JavaAgentArchiveFacts,
    minecraft: JavaAgentMinecraftFacts,
    obfuscation: JavaAgentObfuscationFacts,
    security: JavaAgentSecurityFacts | None,
) -> str:
    subject = (
        f"Minecraft {minecraft.loader}/{minecraft.side}"
        if minecraft.is_minecraft
        else "Java archive"
    )
    if profile == "security" and security is not None:
        return (
            f"{subject}: {security.risk_item_count} risk item(s), "
            f"highest severity {security.highest_severity}."
        )
    if obfuscation.mapping_recommended:
        return f"{subject}: mapping/deobfuscation recommended before deep analysis."
    return f"{subject}: {archive.class_count} class(es), {archive.resource_count} resource(s)."


def _summary_lines(
    archive: JavaAgentArchiveFacts,
    minecraft: JavaAgentMinecraftFacts,
    obfuscation: JavaAgentObfuscationFacts,
    entrypoints: JavaAgentEntrypointFacts,
    frameworks: JavaAgentFrameworkFacts,
    security: JavaAgentSecurityFacts | None,
) -> list[str]:
    lines = [
        (
            f"Archive has {archive.class_count} classes, "
            f"{archive.resource_count} resources, "
            f"{archive.nested_archive_count} nested archives."
        ),
        (
            f"Entrypoints: {entrypoints.entrypoint_count}; "
            f"framework hints: {frameworks.framework_count}."
        ),
        (
            f"Obfuscation level is {obfuscation.level} "
            f"(confidence {obfuscation.confidence:.2f})."
        ),
    ]
    if archive.manifest_main_class:
        lines.append(f"Manifest Main-Class: {archive.manifest_main_class}.")
    if minecraft.is_minecraft:
        lines.append(
            "Minecraft metadata detected: "
            f"loader={minecraft.loader}, side={minecraft.side}, "
            f"version={minecraft.minecraft_version or 'unknown'}."
        )
    if security is not None:
        lines.append(
            "Security profile: "
            f"{security.sensitive_finding_count} sensitive call(s), "
            f"{security.risk_item_count} risk item(s), "
            f"{security.secret_candidate_count} secret candidate(s), "
            f"{security.suspicious_blob_count} suspicious blob(s)."
        )
        if security.summary_by_category:
            categories = ", ".join(
                f"{key}={value}"
                for key, value in sorted(security.summary_by_category.items())
            )
            lines.append(f"Risk categories: {categories}.")
    return lines


def _runbook(
    profile: JavaAgentProfile,
    minecraft: JavaAgentMinecraftFacts,
    obfuscation: JavaAgentObfuscationFacts,
) -> list[str]:
    common = [
        "Start with java_agent_context, then cite the specific follow-up tool outputs.",
        "Use class/method descriptors when discussing JVM methods.",
    ]
    if profile == "security":
        return [
            *common,
            "Triage risk findings by severity, reachability, config state, and entrypoint proximity.",
            "Use java_trace_to_sink or java_reachability before calling behavior malicious.",
            "Treat secrets and high-entropy blobs as suspicious only when correlated with decode/load/use sites.",
        ]
    if profile == "recovery":
        return [
            *common,
            "Run java_recovery_report for a bounded package slice before broad recovery.",
            "Prefer build/classpath repair before editing source for missing packages.",
            "Use validation_summary and rebuilt JAR compatibility before claiming clean recovery.",
        ]
    if profile == "deobfuscation" or obfuscation.mapping_recommended:
        mapping_source = minecraft.preferred_mapping_source or "ProGuard/Tiny/Mojang"
        return [
            *common,
            f"Apply or inspect {mapping_source} mappings before reading obfuscated names.",
            "Use java_lookup_mapping, mapping-aware xrefs, and decompiled source anchors together.",
            "Name behavior from descriptors, strings, and call sites, not just short class names.",
        ]
    return [
        *common,
        "Use java_list_classes/java_list_methods to pick targets, then java_view_class or bytecode tools.",
        "Escalate to java_risk_report for security questions and java_recovery_report for source recovery.",
    ]


def _recommended_next_tools(
    profile: JavaAgentProfile,
    minecraft: JavaAgentMinecraftFacts,
    obfuscation: JavaAgentObfuscationFacts,
    security: JavaAgentSecurityFacts | None,
) -> list[str]:
    tools = ["java_list_classes", "java_list_methods", "java_view_class"]
    if minecraft.is_minecraft or obfuscation.mapping_recommended:
        tools.extend(["java_lookup_mapping", "java_annotate_mappings"])
    if profile == "security":
        tools.extend(["java_risk_report", "java_trace_to_sink", "java_reachability"])
        if security is not None and security.suspicious_blob_count:
            tools.append("java_detect_suspicious_blobs")
    elif profile == "recovery":
        tools.extend(["java_recovery_report", "java_recover_project"])
    elif profile == "deobfuscation":
        tools.extend(["java_view_bytecode", "java_xrefs_from", "java_call_graph"])
    return list(dict.fromkeys(tools))


def build_tool() -> MemoryTool[JavaAgentContextArgs, JavaAgentContextResult]:
    return JavaAgentContextTool()
