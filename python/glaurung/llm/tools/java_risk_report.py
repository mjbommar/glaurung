from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_correlate_behavior_config import (
    ConfigState,
    JavaBehaviorConfigCorrelation,
    build_tool as build_config_correlation_tool,
)
from .java_detect_entrypoints import build_tool as build_entrypoints_tool
from .java_detect_secrets import (
    JavaSecretCandidate,
    build_tool as build_secrets_tool,
)
from .java_reachability import (
    JavaReachabilityResult,
    build_tool as build_reachability_tool,
)


RiskItemKind = Literal["sensitive_behavior", "secret"]
ReachabilityState = Literal[
    "not_analyzed",
    "unknown",
    "direct_entrypoint",
    "reachable",
    "library_only",
    "dead_code_candidate",
]
DynamicObservationState = Literal["not_analyzed", "not_observed", "observed"]


class JavaRiskReportArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    config_roots: list[str] = Field(default_factory=list)
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscating names",
    )
    max_classes: int = Field(50_000, ge=0)
    max_findings: int = Field(256, ge=0)
    max_risk_items: int = Field(64, ge=1)
    max_secret_candidates: int = Field(128, ge=0)
    include_secrets: bool = True
    include_entrypoints: bool = True
    include_reachability: bool = True
    max_reachability_targets: int = Field(16, ge=0)
    max_reachability_depth: int = Field(6, ge=0)
    max_reachability_edges: int = Field(50_000, ge=0)
    max_reachability_paths: int = Field(4, ge=0)
    max_reachability_entrypoints: int = Field(1_000, ge=0)


class JavaRiskItem(BaseModel):
    risk_id: str
    kind: RiskItemKind
    category: str
    severity: str
    confidence: float
    risk_score: int
    class_name: str | None = None
    mapped_class_name: str | None = None
    method_name: str | None = None
    mapped_method_names: list[str] = Field(default_factory=list)
    method_descriptor: str | None = None
    bci: int | None = None
    rule_id: str | None = None
    config_state: ConfigState | None = None
    matched_config_keys: list[str] = Field(default_factory=list)
    reachability_state: ReachabilityState = "not_analyzed"
    reachability_path_count: int = 0
    reachability_target_match_count: int = 0
    reachability_stop_reasons: list[str] = Field(default_factory=list)
    reachability_entrypoint_count: int = 0
    dynamic_observation_state: DynamicObservationState = "not_analyzed"
    source_path: str | None = None
    redacted_value_hash: str | None = None
    message: str
    evidence_ids: list[str] = Field(default_factory=list)


class JavaRiskReportResult(BaseModel):
    archive_path: str
    sha256: str
    risk_item_count: int
    risk_items: list[JavaRiskItem]
    sensitive_finding_count: int
    config_correlation_count: int
    config_binding_count: int
    secret_candidate_count: int
    entrypoint_count: int
    reachability_analysis_count: int
    summary_by_category: dict[str, int]
    summary_by_config_state: dict[str, int]
    summary_by_reachability_state: dict[str, int]
    highest_severity: str
    max_risk_score: int
    truncated: bool = False
    report_node_id: str | None = None


class JavaRiskReportTool(MemoryTool[JavaRiskReportArgs, JavaRiskReportResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_risk_report",
                description=(
                    "Build a generic Java/JVM risk report from sensitive API "
                    "findings, config correlation, entrypoints, and redacted "
                    "secret candidates."
                ),
                tags=("java", "jar", "audit", "risk", "config", "secrets", "kb"),
            ),
            JavaRiskReportArgs,
            JavaRiskReportResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaRiskReportArgs,
    ) -> JavaRiskReportResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        risk_items: list[JavaRiskItem] = []

        correlation_tool = build_config_correlation_tool()
        correlations = correlation_tool.run(
            ctx,
            kb,
            correlation_tool.input_model(
                path=str(path),
                config_roots=args.config_roots,
                mapping_path=args.mapping_path,
                max_classes=args.max_classes,
                max_findings=args.max_findings,
                max_correlations=args.max_findings,
            ),
        )

        reachability_by_correlation_id: dict[str, JavaReachabilityResult] = {}
        reachability_truncated = False
        if (
            args.include_reachability
            and args.max_reachability_targets > 0
            and correlations.correlations
        ):
            for correlation in _reachability_candidates(
                correlations.correlations,
                args.max_reachability_targets,
            ):
                reachability = _reachability_for_correlation(
                    ctx=ctx,
                    kb=kb,
                    path=path,
                    correlation=correlation,
                    args=args,
                )
                reachability_by_correlation_id[correlation.correlation_id] = (
                    reachability
                )
                reachability_truncated = (
                    reachability_truncated or reachability.truncated
                )

        for correlation in correlations.correlations:
            risk_items.append(
                _risk_item_from_correlation(
                    correlation,
                    reachability_by_correlation_id.get(correlation.correlation_id),
                )
            )

        secret_candidate_count = 0
        secrets_truncated = False
        if args.include_secrets and args.max_secret_candidates > 0:
            secrets_tool = build_secrets_tool()
            secrets = secrets_tool.run(
                ctx,
                kb,
                secrets_tool.input_model(
                    path=str(path),
                    max_classes=args.max_classes,
                    max_candidates=args.max_secret_candidates,
                ),
            )
            secret_candidate_count = secrets.candidate_count
            secrets_truncated = secrets.truncated
            for candidate in secrets.candidates:
                risk_items.append(_risk_item_from_secret(candidate))

        entrypoint_count = 0
        entrypoints_truncated = False
        if args.include_entrypoints:
            entrypoints_tool = build_entrypoints_tool()
            entrypoints = entrypoints_tool.run(
                ctx,
                kb,
                entrypoints_tool.input_model(
                    path=str(path),
                    max_classes=args.max_classes,
                    max_entrypoints=1_000,
                ),
            )
            entrypoint_count = entrypoints.entrypoint_count
            entrypoints_truncated = entrypoints.truncated

        risk_items = sorted(
            risk_items,
            key=lambda item: (
                item.risk_score,
                _SEVERITY_RANK.get(item.severity, 0),
                item.confidence,
            ),
            reverse=True,
        )
        truncated = len(risk_items) > args.max_risk_items
        risk_items = risk_items[: args.max_risk_items]
        for item in risk_items:
            _add_risk_node(kb, path, item)

        report_node = kb.add_node(
            Node(
                kind=NodeKind.note,
                label="Java risk report",
                text=(
                    f"Java risk report for {path}: "
                    f"items={len(risk_items)}, "
                    f"highest_severity={_highest_severity(risk_items)}, "
                    f"max_risk_score={_max_risk_score(risk_items)}."
                ),
                props={
                    "tool": "java_risk_report",
                    "archive_path": str(path),
                    "sha256": digest,
                    "risk_item_count": len(risk_items),
                    "sensitive_finding_count": correlations.finding_count,
                    "config_correlation_count": correlations.correlation_count,
                    "config_binding_count": correlations.config_binding_count,
                    "secret_candidate_count": secret_candidate_count,
                    "entrypoint_count": entrypoint_count,
                    "reachability_analysis_count": len(reachability_by_correlation_id),
                    "summary_by_reachability_state": (
                        _summary_by_reachability_state(risk_items)
                    ),
                    "truncated": truncated
                    or correlations.truncated
                    or secrets_truncated
                    or entrypoints_truncated
                    or reachability_truncated,
                },
                tags=["java", "risk-report", "audit"],
            )
        )

        return JavaRiskReportResult(
            archive_path=str(path),
            sha256=digest,
            risk_item_count=len(risk_items),
            risk_items=risk_items,
            sensitive_finding_count=correlations.finding_count,
            config_correlation_count=correlations.correlation_count,
            config_binding_count=correlations.config_binding_count,
            secret_candidate_count=secret_candidate_count,
            entrypoint_count=entrypoint_count,
            reachability_analysis_count=len(reachability_by_correlation_id),
            summary_by_category=_summary_by_category(risk_items),
            summary_by_config_state=_summary_by_config_state(risk_items),
            summary_by_reachability_state=_summary_by_reachability_state(risk_items),
            highest_severity=_highest_severity(risk_items),
            max_risk_score=_max_risk_score(risk_items),
            truncated=truncated
            or correlations.truncated
            or secrets_truncated
            or entrypoints_truncated
            or reachability_truncated,
            report_node_id=report_node.id,
        )


def _risk_item_from_correlation(
    correlation: JavaBehaviorConfigCorrelation,
    reachability: JavaReachabilityResult | None = None,
) -> JavaRiskItem:
    finding = correlation.finding
    risk_id = f"risk:{correlation.correlation_id}"
    reachability_state = _reachability_state(reachability)
    message = (
        f"{finding.category} behavior via {finding.owner}.{finding.name}"
        f"{finding.descriptor}; {correlation.rationale}"
    )
    evidence_ids = [finding.finding_id, correlation.correlation_id]
    if reachability is not None and reachability.reachability_node_id is not None:
        evidence_ids.append(reachability.reachability_node_id)
    return JavaRiskItem(
        risk_id=risk_id,
        kind="sensitive_behavior",
        category=finding.category,
        severity=finding.severity,
        confidence=correlation.confidence,
        risk_score=_risk_score(
            finding.severity,
            correlation.confidence,
            correlation.config_state,
            reachability_state,
        ),
        class_name=finding.class_name,
        mapped_class_name=finding.mapped_class_name,
        method_name=finding.method_name,
        mapped_method_names=finding.mapped_method_names,
        method_descriptor=finding.method_descriptor,
        bci=finding.bci,
        rule_id=finding.rule_id,
        config_state=correlation.config_state,
        matched_config_keys=correlation.matched_config_keys,
        reachability_state=reachability_state,
        reachability_path_count=reachability.path_count if reachability else 0,
        reachability_target_match_count=(
            reachability.target_match_count if reachability else 0
        ),
        reachability_stop_reasons=(
            list(reachability.stop_reasons) if reachability else []
        ),
        reachability_entrypoint_count=(
            reachability.entrypoint_count if reachability else 0
        ),
        message=message,
        evidence_ids=evidence_ids,
    )


def _risk_item_from_secret(candidate: JavaSecretCandidate) -> JavaRiskItem:
    risk_id = f"risk:{candidate.candidate_id}"
    return JavaRiskItem(
        risk_id=risk_id,
        kind="secret",
        category=candidate.category,
        severity=candidate.severity,
        confidence=candidate.confidence,
        risk_score=_risk_score(candidate.severity, candidate.confidence, None, None),
        class_name=candidate.class_name,
        method_name=candidate.method_name,
        method_descriptor=candidate.method_descriptor,
        bci=candidate.bci,
        source_path=candidate.path,
        redacted_value_hash=candidate.redacted_value_hash,
        message=(
            f"Redacted {candidate.category} candidate in "
            f"{candidate.source_type} at {candidate.path}."
        ),
        evidence_ids=[candidate.candidate_id],
    )


_SEVERITY_RANK = {
    "none": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

_SEVERITY_BASE_SCORE = {
    "none": 0,
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}

_STATE_SCORE_ADJUSTMENT: dict[ConfigState, int] = {
    "capability_only": 0,
    "configured_enabled": 15,
    "configured_unknown": 8,
    "configured_disabled": -15,
}

_REACHABILITY_SCORE_ADJUSTMENT: dict[ReachabilityState, int] = {
    "not_analyzed": 0,
    "unknown": 0,
    "direct_entrypoint": 15,
    "reachable": 10,
    "library_only": 0,
    "dead_code_candidate": -10,
}


def _risk_score(
    severity: str,
    confidence: float,
    config_state: ConfigState | None,
    reachability_state: ReachabilityState | None,
) -> int:
    score = _SEVERITY_BASE_SCORE.get(severity, 10)
    if config_state is not None:
        score += _STATE_SCORE_ADJUSTMENT[config_state]
    if reachability_state is not None:
        score += _REACHABILITY_SCORE_ADJUSTMENT[reachability_state]
    return max(0, min(100, round(score * confidence)))


def _reachability_candidates(
    correlations: list[JavaBehaviorConfigCorrelation],
    limit: int,
) -> list[JavaBehaviorConfigCorrelation]:
    ordered = sorted(
        correlations,
        key=lambda correlation: _risk_score(
            correlation.finding.severity,
            correlation.confidence,
            correlation.config_state,
            None,
        ),
        reverse=True,
    )
    return ordered[:limit]


def _reachability_for_correlation(
    *,
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    correlation: JavaBehaviorConfigCorrelation,
    args: JavaRiskReportArgs,
) -> JavaReachabilityResult:
    finding = correlation.finding
    reachability_tool = build_reachability_tool()
    return reachability_tool.run(
        ctx,
        kb,
        reachability_tool.input_model(
            path=str(path),
            mapping_path=args.mapping_path,
            target_owner=finding.owner,
            target_name=finding.name,
            target_descriptor=finding.descriptor,
            target_source_class_name=finding.class_name,
            target_source_method_name=finding.method_name,
            target_source_method_descriptor=finding.method_descriptor,
            target_bci=finding.bci,
            max_classes=args.max_classes,
            max_edges=args.max_reachability_edges,
            max_entrypoints=args.max_reachability_entrypoints,
            max_depth=args.max_reachability_depth,
            max_paths=args.max_reachability_paths,
        ),
    )


def _reachability_state(
    reachability: JavaReachabilityResult | None,
) -> ReachabilityState:
    if reachability is None:
        return "not_analyzed"
    if reachability.reachable:
        if any(path.depth == 1 for path in reachability.paths):
            return "direct_entrypoint"
        return "reachable"
    if reachability.truncated or reachability.target_match_count == 0:
        return "unknown"
    if reachability.entrypoint_count == 0:
        return "library_only"
    return "dead_code_candidate"


def _summary_by_category(risk_items: list[JavaRiskItem]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in risk_items:
        summary[item.category] = summary.get(item.category, 0) + 1
    return summary


def _summary_by_config_state(risk_items: list[JavaRiskItem]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in risk_items:
        if item.config_state is None:
            continue
        summary[item.config_state] = summary.get(item.config_state, 0) + 1
    return summary


def _summary_by_reachability_state(
    risk_items: list[JavaRiskItem],
) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in risk_items:
        summary[item.reachability_state] = summary.get(item.reachability_state, 0) + 1
    return summary


def _highest_severity(risk_items: list[JavaRiskItem]) -> str:
    highest = "none"
    for item in risk_items:
        if _SEVERITY_RANK.get(item.severity, 0) > _SEVERITY_RANK.get(highest, 0):
            highest = item.severity
    return highest


def _max_risk_score(risk_items: list[JavaRiskItem]) -> int:
    if not risk_items:
        return 0
    return max(item.risk_score for item in risk_items)


def _add_risk_node(kb: KnowledgeBase, archive_path: Path, item: JavaRiskItem) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_risk_finding,
            label=f"{item.severity}: {item.category}: {item.kind}",
            text=item.message,
            props={
                "tool": "java_risk_report",
                "archive_path": str(archive_path),
                **item.model_dump(),
            },
            tags=["java", "risk", item.kind, item.category, item.severity],
        )
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[JavaRiskReportArgs, JavaRiskReportResult]:
    return JavaRiskReportTool()
