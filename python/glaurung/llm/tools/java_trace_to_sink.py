from __future__ import annotations

import hashlib
import math
import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_detect_security_sensitive_behavior import (
    JavaSensitiveFinding,
    build_tool as build_sensitive_tool,
)


TraceDirection = Literal["backward", "forward", "both"]


class JavaTraceToSinkArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    finding_id: str | None = Field(None, description="Sensitive finding ID to trace")
    class_name: str | None = Field(None, description="Internal or dotted class name")
    method_name: str | None = None
    method_descriptor: str | None = None
    category: str | None = None
    rule_id: str | None = None
    sink_owner: str | None = None
    sink_name: str | None = None
    bci: int | None = Field(None, ge=0)
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscating names",
    )
    direction: TraceDirection = "both"
    include_constants: bool = True
    include_neighbor_xrefs: bool = True
    max_classes: int = Field(50_000, ge=0)
    max_findings: int = Field(2_000, ge=0)
    max_constants: int = Field(64, ge=0)
    max_neighbor_xrefs: int = Field(64, ge=0)


class JavaTraceConstant(BaseModel):
    bci: int
    value: str | None
    value_kind: str
    redacted_value_hash: str | None = None
    distance_to_sink: int | None = None


class JavaTraceXref(BaseModel):
    bci: int
    opcode: int | None
    kind: str
    owner: str
    name: str
    descriptor: str
    target: str
    distance_to_sink: int | None = None


class JavaTraceToSinkResult(BaseModel):
    archive_path: str
    sha256: str
    sink_found: bool
    finding: JavaSensitiveFinding | None = None
    class_name: str | None = None
    mapped_class_name: str | None = None
    method_name: str | None = None
    mapped_method_names: list[str] = Field(default_factory=list)
    method_descriptor: str | None = None
    constants: list[JavaTraceConstant] = Field(default_factory=list)
    neighbor_xrefs: list[JavaTraceXref] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    note_node_id: str | None = None


class JavaTraceToSinkTool(MemoryTool[JavaTraceToSinkArgs, JavaTraceToSinkResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_trace_to_sink",
                description=(
                    "Build a bounded evidence trace around a sensitive Java API sink "
                    "using method-level bytecode xrefs, constants, mappings, and "
                    "explicit stop reasons where precise dataflow is unavailable."
                ),
                tags=("java", "jar", "audit", "trace", "sink", "kb"),
            ),
            JavaTraceToSinkArgs,
            JavaTraceToSinkResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaTraceToSinkArgs,
    ) -> JavaTraceToSinkResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        if not zipfile.is_zipfile(path):
            return JavaTraceToSinkResult(
                archive_path=str(path),
                sha256=digest,
                sink_found=False,
                stop_reasons=["input_not_zip"],
            )

        finding = _select_finding(ctx, kb, args, path)
        if finding is None:
            return JavaTraceToSinkResult(
                archive_path=str(path),
                sha256=digest,
                sink_found=False,
                stop_reasons=["no_matching_sensitive_finding"],
            )

        method = _find_method(path, finding)
        if method is None:
            return JavaTraceToSinkResult(
                archive_path=str(path),
                sha256=digest,
                sink_found=False,
                finding=finding,
                stop_reasons=["method_not_found"],
            )

        xrefs = _method_xrefs(method)
        constants = (
            _constants_for_method(
                xrefs,
                sink_bci=finding.bci,
                limit=args.max_constants,
            )
            if args.include_constants
            else []
        )
        neighbor_xrefs = (
            _neighbor_xrefs(
                xrefs,
                sink_bci=finding.bci,
                direction=args.direction,
                limit=args.max_neighbor_xrefs,
            )
            if args.include_neighbor_xrefs
            else []
        )
        stop_reasons = [
            "precise_dataflow_not_yet_available",
            "call_graph_not_yet_available",
        ]
        note = kb.add_node(
            Node(
                kind=NodeKind.note,
                label="Java trace to sink",
                text=(
                    f"Trace around {finding.category} sink "
                    f"{finding.class_name}#{finding.method_name}"
                    f"{finding.method_descriptor}@bci={finding.bci}."
                ),
                props={
                    "tool": "java_trace_to_sink",
                    "archive_path": str(path),
                    "finding": finding.model_dump(),
                    "constant_count": len(constants),
                    "neighbor_xref_count": len(neighbor_xrefs),
                    "stop_reasons": stop_reasons,
                },
                tags=["java", "trace-to-sink", finding.category],
            )
        )

        return JavaTraceToSinkResult(
            archive_path=str(path),
            sha256=digest,
            sink_found=True,
            finding=finding,
            class_name=finding.class_name,
            mapped_class_name=finding.mapped_class_name,
            method_name=finding.method_name,
            mapped_method_names=finding.mapped_method_names,
            method_descriptor=finding.method_descriptor,
            constants=constants,
            neighbor_xrefs=neighbor_xrefs,
            stop_reasons=stop_reasons,
            confidence=_trace_confidence(constants, neighbor_xrefs),
            note_node_id=note.id,
        )


def _select_finding(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: JavaTraceToSinkArgs,
    path: Path,
) -> JavaSensitiveFinding | None:
    sensitive_tool = build_sensitive_tool()
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
    for finding in sensitive.findings:
        if _finding_matches(finding, args):
            return finding
    return None


def _finding_matches(
    finding: JavaSensitiveFinding,
    args: JavaTraceToSinkArgs,
) -> bool:
    class_name = _internal(args.class_name) if args.class_name else None
    checks = (
        args.finding_id is None or finding.finding_id == args.finding_id,
        class_name is None or finding.class_name == class_name,
        args.method_name is None
        or finding.method_name == args.method_name
        or args.method_name in finding.mapped_method_names,
        args.method_descriptor is None
        or finding.method_descriptor == args.method_descriptor,
        args.category is None or finding.category == args.category,
        args.rule_id is None or finding.rule_id == args.rule_id,
        args.sink_owner is None or finding.owner == args.sink_owner,
        args.sink_name is None or finding.name == args.sink_name,
        args.bci is None or finding.bci == args.bci,
    )
    return all(checks)


def _find_method(path: Path, finding: JavaSensitiveFinding) -> dict[str, Any] | None:
    java_analysis = getattr(g, "analysis")
    entry_name = f"{finding.class_name}.class"
    with zipfile.ZipFile(path) as zf:
        try:
            data = zf.read(entry_name)
        except KeyError:
            return None
        parsed = java_analysis.parse_java_class_bytes(data)
    if parsed is None:
        return None
    for method in parsed["methods"]:
        if (
            str(method["name"]) == finding.method_name
            and str(method["descriptor"]) == finding.method_descriptor
        ):
            return method
    return None


def _method_xrefs(method: dict[str, Any]) -> list[dict[str, Any]]:
    code = method.get("code")
    if not isinstance(code, dict):
        return []
    return [xref for xref in code.get("xrefs", []) if isinstance(xref, dict)]


def _constants_for_method(
    xrefs: list[dict[str, Any]],
    *,
    sink_bci: int | None,
    limit: int,
) -> list[JavaTraceConstant]:
    constants: list[JavaTraceConstant] = []
    for xref in sorted(xrefs, key=lambda value: int(value.get("bci", 0))):
        if xref.get("kind") != "string":
            continue
        value = xref.get("string_value")
        if not isinstance(value, str):
            continue
        redacted, redacted_hash = _redaction(value)
        constants.append(
            JavaTraceConstant(
                bci=int(xref.get("bci", 0)),
                value=None if redacted else value,
                value_kind=_value_kind(value),
                redacted_value_hash=redacted_hash,
                distance_to_sink=_distance(int(xref.get("bci", 0)), sink_bci),
            )
        )
        if len(constants) >= limit:
            break
    return constants


def _neighbor_xrefs(
    xrefs: list[dict[str, Any]],
    *,
    sink_bci: int | None,
    direction: TraceDirection,
    limit: int,
) -> list[JavaTraceXref]:
    out: list[JavaTraceXref] = []
    for xref in sorted(
        xrefs,
        key=lambda value: (
            _distance(int(value.get("bci", 0)), sink_bci) or 0,
            int(value.get("bci", 0)),
        ),
    ):
        kind = str(xref.get("kind", ""))
        if kind == "string":
            continue
        bci = int(xref.get("bci", 0))
        if not _direction_includes(bci, sink_bci, direction):
            continue
        opcode = xref.get("opcode")
        out.append(
            JavaTraceXref(
                bci=bci,
                opcode=opcode if isinstance(opcode, int) else None,
                kind=kind,
                owner=str(xref.get("owner", "")),
                name=str(xref.get("name", "")),
                descriptor=str(xref.get("descriptor", "")),
                target=str(xref.get("target", "")),
                distance_to_sink=_distance(bci, sink_bci),
            )
        )
        if len(out) >= limit:
            break
    return out


def _direction_includes(
    bci: int,
    sink_bci: int | None,
    direction: TraceDirection,
) -> bool:
    if sink_bci is None or direction == "both":
        return True
    if direction == "backward":
        return bci <= sink_bci
    return bci >= sink_bci


def _distance(bci: int, sink_bci: int | None) -> int | None:
    if sink_bci is None:
        return None
    return abs(bci - sink_bci)


def _value_kind(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    if value.isupper() and "_" in value and " " not in value:
        return "environment_variable"
    if "." in value and " " not in value and "/" not in value:
        return "system_property"
    if "/" in value or "\\" in value or value.endswith((".txt", ".json", ".toml")):
        return "path_or_resource"
    return "string"


_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer ",
    "session=",
)


def _redaction(value: str) -> tuple[bool, str | None]:
    lowered = value.lower()
    looks_like_env_name = value.isupper() and "_" in value and "=" not in value
    if looks_like_env_name:
        return False, None
    has_secret_hint = any(hint in lowered for hint in _SECRET_HINTS)
    if has_secret_hint or (len(value) >= 32 and _entropy(value) >= 4.0):
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return True, digest
    return False, None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _trace_confidence(
    constants: list[JavaTraceConstant],
    neighbor_xrefs: list[JavaTraceXref],
) -> float:
    score = 0.4
    if constants:
        score += 0.25
    if neighbor_xrefs:
        score += 0.25
    return min(score, 0.9)


def _internal(class_name: str) -> str:
    return class_name.removesuffix(".class").replace(".", "/")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[JavaTraceToSinkArgs, JavaTraceToSinkResult]:
    return JavaTraceToSinkTool()
