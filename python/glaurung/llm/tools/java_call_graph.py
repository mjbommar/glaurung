from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import parse_proguard_mappings
from .java_xrefs_common import (
    _class_candidates,
    _line_number_for_bci,
    _line_numbers,
    _lookup_class_mapping,
    _member_mapping_annotation,
    _method_descriptor_matches,
    _method_name_matches,
    _mapped_method_names,
)


JavaCallGraphMode = Literal["constant_pool"]


class JavaCallGraphArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_name: str | None = Field(
        None,
        description="Optional source class name, internal or dotted",
    )
    method_name: str | None = Field(None, description="Optional source method name")
    method_descriptor: str | None = Field(
        None,
        description="Optional source method descriptor",
    )
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    mode: JavaCallGraphMode = Field(
        "constant_pool",
        description="Call graph construction mode",
    )
    include_external: bool = Field(
        True,
        description="Include target methods that are not defined in the archive",
    )
    max_classes: int = Field(50_000, ge=0)
    max_edges: int = Field(10_000, ge=0)


class JavaCallGraphMethodNode(BaseModel):
    method_id: str
    class_name: str
    method_name: str
    method_descriptor: str
    defined: bool


class JavaCallGraphEdge(BaseModel):
    edge_id: str
    source_method_id: str
    target_method_id: str
    source_class_name: str
    source_method_name: str
    source_method_descriptor: str
    mapped_source_class_name: str | None = None
    mapped_source_method_names: list[str] = Field(default_factory=list)
    target_owner: str
    target_name: str
    target_descriptor: str
    mapped_target_owner: str | None = None
    mapped_target_names: list[str] = Field(default_factory=list)
    mapped_target_descriptor: str | None = None
    target_defined: bool
    bci: int
    line_number: int | None = None
    opcode: int | None = None
    invoke_kind: str


class JavaCallGraphResult(BaseModel):
    archive_path: str
    mode: JavaCallGraphMode
    class_count: int
    parsed_class_count: int
    parse_error_count: int
    method_count: int
    node_count: int
    edge_count: int
    external_target_count: int
    dynamic_dispatch_edge_count: int
    nodes: list[JavaCallGraphMethodNode] = Field(default_factory=list)
    edges: list[JavaCallGraphEdge] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    truncated: bool = False
    call_graph_node_id: str | None = None


class JavaCallGraphTool(MemoryTool[JavaCallGraphArgs, JavaCallGraphResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_call_graph",
                description=(
                    "Build an initial bounded JVM call graph from method invocation "
                    "xrefs, with source BCI/line anchors and defined-vs-external "
                    "target classification."
                ),
                tags=("java", "call-graph", "xref", "bytecode", "kb"),
            ),
            JavaCallGraphArgs,
            JavaCallGraphResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaCallGraphArgs,
    ) -> JavaCallGraphResult:
        path = Path(args.path or ctx.file_path)
        result = _build_call_graph(path, args)
        graph_node = kb.add_node(
            Node(
                kind=NodeKind.java_call_graph,
                label=f"{path.name} call graph ({result.edge_count} edges)",
                props={
                    "tool": "java_call_graph",
                    "archive_path": str(path),
                    "mode": result.mode,
                    "class_count": result.class_count,
                    "parsed_class_count": result.parsed_class_count,
                    "parse_error_count": result.parse_error_count,
                    "method_count": result.method_count,
                    "node_count": result.node_count,
                    "edge_count": result.edge_count,
                    "external_target_count": result.external_target_count,
                    "dynamic_dispatch_edge_count": result.dynamic_dispatch_edge_count,
                    "stop_reasons": result.stop_reasons,
                    "truncated": result.truncated,
                },
                tags=["java", "call-graph", "xref"],
            )
        )
        return JavaCallGraphResult(
            **result.model_dump(exclude={"call_graph_node_id"}),
            call_graph_node_id=graph_node.id,
        )


def _build_call_graph(
    archive_path: Path,
    args: JavaCallGraphArgs,
) -> JavaCallGraphResult:
    defined_methods: set[tuple[str, str, str]] = set()
    edge_inputs: list[dict[str, Any]] = []
    class_count = 0
    parsed_class_count = 0
    parse_error_count = 0
    method_count = 0
    truncated = False
    stop_reasons: list[str] = []
    mappings = (
        parse_proguard_mappings(Path(args.mapping_path))
        if args.mapping_path is not None
        else None
    )
    source_class_filter = (
        _class_candidates(mappings, args.class_name) if args.class_name else None
    )

    if not zipfile.is_zipfile(archive_path):
        return JavaCallGraphResult(
            archive_path=str(archive_path),
            mode=args.mode,
            class_count=0,
            parsed_class_count=0,
            parse_error_count=1,
            method_count=0,
            node_count=0,
            edge_count=0,
            external_target_count=0,
            dynamic_dispatch_edge_count=0,
            stop_reasons=["not_zip_archive"],
        )

    java_analysis = getattr(g, "analysis")
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".class"):
                continue
            class_count += 1
            if class_count > args.max_classes:
                truncated = True
                stop_reasons.append("max_classes")
                break
            try:
                parsed = java_analysis.parse_java_class_bytes(zf.read(info))
            except RuntimeError:
                parse_error_count += 1
                continue
            if parsed is None:
                parse_error_count += 1
                continue
            parsed_class_count += 1
            class_name = str(parsed["class_name"])
            source_class_mapping = _lookup_class_mapping(mappings, class_name)
            for method in parsed["methods"]:
                if not isinstance(method, dict):
                    continue
                method_name = str(method["name"])
                method_descriptor = str(method["descriptor"])
                defined_methods.add((class_name, method_name, method_descriptor))
                method_count += 1
                if not _source_matches(
                    class_name=class_name,
                    method=method,
                    method_descriptor=method_descriptor,
                    source_class_filter=source_class_filter,
                    source_method_name=args.method_name,
                    source_method_descriptor=args.method_descriptor,
                    mappings=mappings,
                    source_class_mapping=source_class_mapping,
                ):
                    continue
                code = method.get("code")
                if not isinstance(code, dict):
                    continue
                line_numbers = _line_numbers(code)
                for xref in code.get("xrefs", []):
                    if not isinstance(xref, dict) or not _is_method_xref(xref):
                        continue
                    target_owner = str(xref.get("owner", ""))
                    target_name = str(xref.get("name", ""))
                    target_descriptor = str(xref.get("descriptor", ""))
                    (
                        mapped_target_owner,
                        mapped_target_names,
                        mapped_target_descriptor,
                    ) = _member_mapping_annotation(
                        mappings=mappings,
                        owner=target_owner,
                        kind=str(xref.get("kind", "")),
                        name=target_name,
                        descriptor=target_descriptor,
                    )
                    edge_inputs.append(
                        {
                            "source_class_name": class_name,
                            "source_method_name": method_name,
                            "source_method_descriptor": method_descriptor,
                            "mapped_source_class_name": (
                                source_class_mapping.official_name
                                if source_class_mapping is not None
                                else None
                            ),
                            "mapped_source_method_names": _mapped_method_names(
                                mappings=mappings,
                                class_mapping=source_class_mapping,
                                method_name=method_name,
                                descriptor=method_descriptor,
                            ),
                            "target_owner": target_owner,
                            "target_name": target_name,
                            "target_descriptor": target_descriptor,
                            "mapped_target_owner": mapped_target_owner,
                            "mapped_target_names": mapped_target_names,
                            "mapped_target_descriptor": mapped_target_descriptor,
                            "bci": int(xref.get("bci", 0)),
                            "line_number": _line_number_for_bci(
                                line_numbers,
                                int(xref.get("bci", 0)),
                            ),
                            "opcode": xref.get("opcode"),
                            "invoke_kind": _invoke_kind(xref.get("opcode")),
                        }
                    )
                    if len(edge_inputs) >= args.max_edges:
                        truncated = True
                        stop_reasons.append("max_edges")
                        break
                if truncated and "max_edges" in stop_reasons:
                    break
            if truncated and "max_edges" in stop_reasons:
                break

    nodes: dict[str, JavaCallGraphMethodNode] = {}
    edges: list[JavaCallGraphEdge] = []
    external_targets: set[str] = set()
    dynamic_dispatch_edge_count = 0
    for item in edge_inputs:
        target_key = (
            str(item["target_owner"]),
            str(item["target_name"]),
            str(item["target_descriptor"]),
        )
        target_defined = target_key in defined_methods
        if not target_defined and not args.include_external:
            continue

        source_id = _method_id(
            str(item["source_class_name"]),
            str(item["source_method_name"]),
            str(item["source_method_descriptor"]),
        )
        target_id = _method_id(*target_key)
        nodes[source_id] = JavaCallGraphMethodNode(
            method_id=source_id,
            class_name=str(item["source_class_name"]),
            method_name=str(item["source_method_name"]),
            method_descriptor=str(item["source_method_descriptor"]),
            defined=True,
        )
        nodes[target_id] = JavaCallGraphMethodNode(
            method_id=target_id,
            class_name=target_key[0],
            method_name=target_key[1],
            method_descriptor=target_key[2],
            defined=target_defined,
        )
        if not target_defined:
            external_targets.add(target_id)
        if item["invoke_kind"] in {"invokevirtual", "invokeinterface"}:
            dynamic_dispatch_edge_count += 1
        edges.append(
            JavaCallGraphEdge(
                edge_id=_edge_id(
                    source_id,
                    target_id,
                    int(item["bci"]),
                    str(item["invoke_kind"]),
                ),
                source_method_id=source_id,
                target_method_id=target_id,
                source_class_name=str(item["source_class_name"]),
                source_method_name=str(item["source_method_name"]),
                source_method_descriptor=str(item["source_method_descriptor"]),
                mapped_source_class_name=(
                    str(item["mapped_source_class_name"])
                    if isinstance(item["mapped_source_class_name"], str)
                    else None
                ),
                mapped_source_method_names=[
                    str(name)
                    for name in item["mapped_source_method_names"]
                    if isinstance(name, str)
                ],
                target_owner=target_key[0],
                target_name=target_key[1],
                target_descriptor=target_key[2],
                mapped_target_owner=(
                    str(item["mapped_target_owner"])
                    if isinstance(item["mapped_target_owner"], str)
                    else None
                ),
                mapped_target_names=[
                    str(name)
                    for name in item["mapped_target_names"]
                    if isinstance(name, str)
                ],
                mapped_target_descriptor=(
                    str(item["mapped_target_descriptor"])
                    if isinstance(item["mapped_target_descriptor"], str)
                    else None
                ),
                target_defined=target_defined,
                bci=int(item["bci"]),
                line_number=(
                    item["line_number"]
                    if isinstance(item["line_number"], int)
                    else None
                ),
                opcode=item["opcode"] if isinstance(item["opcode"], int) else None,
                invoke_kind=str(item["invoke_kind"]),
            )
        )

    ordered_nodes = sorted(nodes.values(), key=lambda node: node.method_id)
    return JavaCallGraphResult(
        archive_path=str(archive_path),
        mode=args.mode,
        class_count=class_count,
        parsed_class_count=parsed_class_count,
        parse_error_count=parse_error_count,
        method_count=method_count,
        node_count=len(ordered_nodes),
        edge_count=len(edges),
        external_target_count=len(external_targets),
        dynamic_dispatch_edge_count=dynamic_dispatch_edge_count,
        nodes=ordered_nodes,
        edges=edges,
        stop_reasons=stop_reasons,
        truncated=truncated,
    )


def _source_matches(
    *,
    class_name: str,
    method: dict[str, Any],
    method_descriptor: str,
    source_class_filter: set[str] | None,
    source_method_name: str | None,
    source_method_descriptor: str | None,
    mappings: Any,
    source_class_mapping: Any,
) -> bool:
    return all(
        (
            source_class_filter is None or class_name in source_class_filter,
            source_method_name is None
            or _method_name_matches(
                mappings=mappings,
                class_mapping=source_class_mapping,
                method=method,
                method_name=source_method_name,
            ),
            source_method_descriptor is None
            or _method_descriptor_matches(
                mappings=mappings,
                class_mapping=source_class_mapping,
                method=method,
                method_descriptor=source_method_descriptor,
            ),
        )
    )


def _is_method_xref(xref: dict[str, Any]) -> bool:
    return str(xref.get("kind", "")) in {
        "method",
        "interface_method",
        "invokedynamic",
    }


def _invoke_kind(opcode: Any) -> str:
    if not isinstance(opcode, int):
        return "unknown"
    return {
        0xB6: "invokevirtual",
        0xB7: "invokespecial",
        0xB8: "invokestatic",
        0xB9: "invokeinterface",
        0xBA: "invokedynamic",
    }.get(opcode, "unknown")


def _method_id(class_name: str, method_name: str, method_descriptor: str) -> str:
    owner = class_name or "<dynamic>"
    return f"{owner}#{method_name}{method_descriptor}"


def _edge_id(
    source_method_id: str,
    target_method_id: str,
    bci: int,
    invoke_kind: str,
) -> str:
    key = f"{source_method_id}->{target_method_id}@{bci}:{invoke_kind}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def build_tool() -> MemoryTool[JavaCallGraphArgs, JavaCallGraphResult]:
    return JavaCallGraphTool()
