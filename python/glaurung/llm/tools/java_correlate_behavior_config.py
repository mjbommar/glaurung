from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_detect_sensitive_behavior import JavaSensitiveFinding
from .java_detect_security_sensitive_behavior import build_tool as build_sensitive_tool
from .java_extract_config_surface import JavaConfigBinding
from .java_extract_config_surface import build_tool as build_config_tool
from .java_trace_to_sink import build_tool as build_trace_tool


ConfigState = Literal[
    "capability_only",
    "configured_enabled",
    "configured_disabled",
    "configured_unknown",
]


class JavaCorrelateBehaviorConfigArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    config_roots: list[str] = Field(default_factory=list)
    category: str | None = None
    rule_id: str | None = None
    max_classes: int = Field(50_000, ge=0)
    max_findings: int = Field(256, ge=0)
    max_correlations: int = Field(128, ge=0)
    max_trace_constants: int = Field(32, ge=0)


class JavaConfigBindingSummary(BaseModel):
    path: str
    key: str
    value: str | None
    value_kind: str
    redacted_value_hash: str | None = None
    source_type: str
    parser: str


class JavaBehaviorConfigCorrelation(BaseModel):
    correlation_id: str
    finding: JavaSensitiveFinding
    config_state: ConfigState
    matched_config_keys: list[str]
    matched_constants: list[str]
    matched_bindings: list[JavaConfigBindingSummary]
    confidence: float
    rationale: str


class JavaCorrelateBehaviorConfigResult(BaseModel):
    archive_path: str
    finding_count: int
    config_binding_count: int
    correlation_count: int
    correlations: list[JavaBehaviorConfigCorrelation]
    summary_by_state: dict[str, int]
    truncated: bool = False


class JavaCorrelateBehaviorConfigTool(
    MemoryTool[JavaCorrelateBehaviorConfigArgs, JavaCorrelateBehaviorConfigResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_correlate_behavior_config",
                description=(
                    "Correlate Java sensitive-behavior findings with extracted "
                    "configuration keys and nearby trace constants, classifying "
                    "capability-only versus configured behavior."
                ),
                tags=("java", "jar", "config", "audit", "correlation", "kb"),
            ),
            JavaCorrelateBehaviorConfigArgs,
            JavaCorrelateBehaviorConfigResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaCorrelateBehaviorConfigArgs,
    ) -> JavaCorrelateBehaviorConfigResult:
        path = args.path or ctx.file_path
        sensitive_tool = build_sensitive_tool()
        sensitive = sensitive_tool.run(
            ctx,
            kb,
            sensitive_tool.input_model(
                path=path,
                max_classes=args.max_classes,
                max_findings=args.max_findings,
            ),
        )
        config_tool = build_config_tool()
        config = config_tool.run(
            ctx,
            kb,
            config_tool.input_model(
                path=path,
                config_roots=args.config_roots,
            ),
        )
        bindings_by_key = _bindings_by_key(config.bindings)
        correlations: list[JavaBehaviorConfigCorrelation] = []
        truncated = False

        for finding in sensitive.findings:
            if args.category is not None and finding.category != args.category:
                continue
            if args.rule_id is not None and finding.rule_id != args.rule_id:
                continue
            if len(correlations) >= args.max_correlations:
                truncated = True
                break
            trace_constants = _trace_constants_for_finding(
                ctx=ctx,
                kb=kb,
                path=path,
                finding=finding,
                max_constants=args.max_trace_constants,
            )
            matched_constants = _matched_constants(trace_constants, bindings_by_key)
            matched_bindings = [
                JavaConfigBindingSummary(**binding.model_dump())
                for key in matched_constants
                for binding in bindings_by_key.get(key, [])
            ]
            correlation = _correlation(
                finding=finding,
                matched_constants=matched_constants,
                matched_bindings=matched_bindings,
            )
            correlations.append(correlation)
            _add_correlation_node(kb, path, correlation)

        summary_by_state: dict[str, int] = {}
        for correlation in correlations:
            summary_by_state[correlation.config_state] = (
                summary_by_state.get(correlation.config_state, 0) + 1
            )

        return JavaCorrelateBehaviorConfigResult(
            archive_path=path,
            finding_count=sensitive.finding_count,
            config_binding_count=config.binding_count,
            correlation_count=len(correlations),
            correlations=correlations,
            summary_by_state=summary_by_state,
            truncated=truncated or sensitive.truncated or config.truncated,
        )


def _trace_constants_for_finding(
    *,
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: str,
    finding: JavaSensitiveFinding,
    max_constants: int,
) -> list[str]:
    trace_tool = build_trace_tool()
    trace = trace_tool.run(
        ctx,
        kb,
        trace_tool.input_model(
            path=path,
            finding_id=finding.finding_id,
            max_constants=max_constants,
            max_neighbor_xrefs=0,
        ),
    )
    return [
        constant.value for constant in trace.constants if constant.value is not None
    ]


def _bindings_by_key(
    bindings: list[JavaConfigBinding],
) -> dict[str, list[JavaConfigBinding]]:
    out: dict[str, list[JavaConfigBinding]] = {}
    for binding in bindings:
        out.setdefault(binding.key, []).append(binding)
    return out


def _matched_constants(
    constants: list[str],
    bindings_by_key: dict[str, list[JavaConfigBinding]],
) -> list[str]:
    return sorted(
        {
            value
            for value in constants
            if value in bindings_by_key and _specific_config_key(value)
        }
    )


_GENERIC_CONFIG_KEYS = {
    "id",
    "key",
    "name",
    "type",
    "value",
    "version",
    "description",
    "enabled",
    "disabled",
}


def _specific_config_key(value: str) -> bool:
    lowered = value.lower()
    if lowered in _GENERIC_CONFIG_KEYS:
        return False
    if lowered.startswith(("msg.", "text.", "tooltip.", "title.", "item.", "block.")):
        return False
    if len(value) < 5:
        return False
    if any(separator in value for separator in (".", "_", "-", "/")):
        return True
    return any(
        word in lowered
        for word in (
            "endpoint",
            "telemetry",
            "token",
            "secret",
            "password",
            "config",
        )
    )


def _correlation(
    *,
    finding: JavaSensitiveFinding,
    matched_constants: list[str],
    matched_bindings: list[JavaConfigBindingSummary],
) -> JavaBehaviorConfigCorrelation:
    state = _config_state(matched_bindings)
    key = (
        f"{finding.finding_id}:{state}:"
        f"{','.join(binding.path + ':' + binding.key for binding in matched_bindings)}"
    )
    return JavaBehaviorConfigCorrelation(
        correlation_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        finding=finding,
        config_state=state,
        matched_config_keys=sorted({binding.key for binding in matched_bindings}),
        matched_constants=matched_constants,
        matched_bindings=matched_bindings,
        confidence=_confidence(state, matched_bindings),
        rationale=_rationale(finding, state, matched_bindings),
    )


def _config_state(bindings: list[JavaConfigBindingSummary]) -> ConfigState:
    if not bindings:
        return "capability_only"
    bool_values = [
        _bool_value(binding.value)
        for binding in bindings
        if binding.value is not None and binding.value_kind in {"bool", "string"}
    ]
    if any(value is True for value in bool_values):
        return "configured_enabled"
    if bool_values and all(value is False for value in bool_values):
        return "configured_disabled"
    return "configured_unknown"


def _bool_value(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _confidence(
    state: ConfigState,
    bindings: list[JavaConfigBindingSummary],
) -> float:
    if state == "capability_only":
        return 0.45
    if any(binding.source_type == "external_config" for binding in bindings):
        return 0.85
    return 0.72


def _rationale(
    finding: JavaSensitiveFinding,
    state: ConfigState,
    bindings: list[JavaConfigBindingSummary],
) -> str:
    if state == "capability_only":
        return (
            f"{finding.category} capability was detected, but no matching config "
            "key was found in supplied or embedded config."
        )
    keys = ", ".join(sorted({binding.key for binding in bindings}))
    if state == "configured_enabled":
        return (
            f"{finding.category} capability is linked to enabled config key(s): {keys}."
        )
    if state == "configured_disabled":
        return f"{finding.category} capability is linked to disabled config key(s): {keys}."
    return f"{finding.category} capability is linked to config key(s) with non-boolean or redacted values: {keys}."


def _add_correlation_node(
    kb: KnowledgeBase,
    archive_path: str,
    correlation: JavaBehaviorConfigCorrelation,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_config_correlation,
            label=(
                f"{correlation.config_state}: "
                f"{correlation.finding.category}:"
                f"{correlation.finding.class_name}#{correlation.finding.method_name}"
            ),
            text=correlation.rationale,
            props={
                "tool": "java_correlate_behavior_config",
                "archive_path": archive_path,
                **correlation.model_dump(),
            },
            tags=["java", "config", "correlation", correlation.config_state],
        )
    )


def build_tool() -> MemoryTool[
    JavaCorrelateBehaviorConfigArgs, JavaCorrelateBehaviorConfigResult
]:
    return JavaCorrelateBehaviorConfigTool()
