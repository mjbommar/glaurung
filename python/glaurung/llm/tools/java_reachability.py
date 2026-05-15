from __future__ import annotations

from collections import deque
import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_call_graph import JavaCallGraphEdge, build_tool as build_call_graph_tool
from .java_detect_entrypoints import JavaEntrypointSummary
from .java_detect_entrypoints import build_tool as build_entrypoints_tool


class JavaReachabilityArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    target_owner: str | None = Field(
        None,
        description="Target owner class name, internal, dotted, obfuscated, or mapped",
    )
    target_name: str | None = Field(None, description="Target method name")
    target_descriptor: str | None = Field(
        None, description="Optional target descriptor"
    )
    entrypoint_categories: list[str] = Field(default_factory=list)
    max_classes: int = Field(50_000, ge=0)
    max_edges: int = Field(50_000, ge=0)
    max_entrypoints: int = Field(1_000, ge=0)
    max_depth: int = Field(6, ge=0)
    max_paths: int = Field(16, ge=0)


class JavaReachabilityEdgeStep(BaseModel):
    edge_id: str
    source_method_id: str
    target_method_id: str
    source_class_name: str
    source_method_name: str
    source_method_descriptor: str
    target_owner: str
    target_name: str
    target_descriptor: str
    target_defined: bool
    bci: int
    line_number: int | None = None
    invoke_kind: str


class JavaReachabilityPath(BaseModel):
    path_id: str
    entrypoint_category: str
    entrypoint_method_id: str
    target_method_id: str
    depth: int
    edges: list[JavaReachabilityEdgeStep] = Field(default_factory=list)


class JavaReachabilityResult(BaseModel):
    archive_path: str
    reachable: bool
    path_count: int
    paths: list[JavaReachabilityPath] = Field(default_factory=list)
    entrypoint_count: int
    graph_edge_count: int
    target_match_count: int
    stop_reasons: list[str] = Field(default_factory=list)
    truncated: bool = False
    reachability_node_id: str | None = None


class JavaReachabilityTool(MemoryTool[JavaReachabilityArgs, JavaReachabilityResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_reachability",
                description=(
                    "Find bounded call-graph paths from detected Java entrypoints "
                    "to a requested method or external sink target."
                ),
                tags=("java", "reachability", "call-graph", "entrypoint", "kb"),
            ),
            JavaReachabilityArgs,
            JavaReachabilityResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaReachabilityArgs,
    ) -> JavaReachabilityResult:
        path = Path(args.path or ctx.file_path)
        stop_reasons: list[str] = []
        if args.target_owner is None and args.target_name is None:
            stop_reasons.append("target_not_specified")
            return _result(path, [], 0, 0, 0, stop_reasons, False, kb)

        entrypoints_tool = build_entrypoints_tool()
        entrypoints = entrypoints_tool.run(
            ctx,
            kb,
            entrypoints_tool.input_model(
                path=str(path),
                max_classes=args.max_classes,
                max_entrypoints=args.max_entrypoints,
            ),
        )
        call_graph_tool = build_call_graph_tool()
        graph = call_graph_tool.run(
            ctx,
            kb,
            call_graph_tool.input_model(
                path=str(path),
                mapping_path=args.mapping_path,
                include_external=True,
                max_classes=args.max_classes,
                max_edges=args.max_edges,
            ),
        )

        seed_entrypoints = [
            entrypoint
            for entrypoint in entrypoints.entrypoints
            if entrypoint.method_name is not None
            and entrypoint.method_descriptor is not None
            and (
                not args.entrypoint_categories
                or entrypoint.category in args.entrypoint_categories
            )
        ]
        paths, target_match_count, truncated = _find_paths(
            seed_entrypoints,
            graph.edges,
            args=args,
        )
        if not paths and not stop_reasons:
            stop_reasons.append("target_not_reached")
        if graph.truncated:
            stop_reasons.extend(graph.stop_reasons or ["call_graph_truncated"])
            truncated = True
        if entrypoints.truncated:
            stop_reasons.append("entrypoints_truncated")
            truncated = True
        return _result(
            path,
            paths,
            entrypoints.entrypoint_count,
            graph.edge_count,
            target_match_count,
            stop_reasons,
            truncated,
            kb,
        )


def _find_paths(
    entrypoints: list[JavaEntrypointSummary],
    edges: list[JavaCallGraphEdge],
    *,
    args: JavaReachabilityArgs,
) -> tuple[list[JavaReachabilityPath], int, bool]:
    adjacency: dict[str, list[JavaCallGraphEdge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.source_method_id, []).append(edge)

    target_match_count = sum(1 for edge in edges if _edge_matches_target(edge, args))
    paths: list[JavaReachabilityPath] = []
    truncated = False
    for entrypoint in entrypoints:
        seed = _method_id(
            entrypoint.class_name,
            entrypoint.method_name or "",
            entrypoint.method_descriptor or "",
        )
        queue = deque([(seed, [])])
        seen = {(seed, 0)}
        while queue:
            method_id, path_edges = queue.popleft()
            if len(path_edges) > args.max_depth:
                continue
            for edge in adjacency.get(method_id, []):
                next_path = [*path_edges, edge]
                if _edge_matches_target(edge, args):
                    paths.append(_path(entrypoint, next_path))
                    if len(paths) >= args.max_paths:
                        return paths, target_match_count, True
                    continue
                if len(next_path) >= args.max_depth:
                    continue
                state = (edge.target_method_id, len(next_path))
                if state in seen:
                    continue
                seen.add(state)
                queue.append((edge.target_method_id, next_path))
    return paths, target_match_count, truncated


def _edge_matches_target(edge: JavaCallGraphEdge, args: JavaReachabilityArgs) -> bool:
    owner_matches = (
        args.target_owner is None
        or edge.target_owner == _internal(args.target_owner)
        or edge.mapped_target_owner == args.target_owner
    )
    name_matches = (
        args.target_name is None
        or edge.target_name == args.target_name
        or args.target_name in edge.mapped_target_names
    )
    descriptor_matches = (
        args.target_descriptor is None
        or edge.target_descriptor == args.target_descriptor
        or edge.mapped_target_descriptor == args.target_descriptor
    )
    return owner_matches and name_matches and descriptor_matches


def _path(
    entrypoint: JavaEntrypointSummary,
    edges: list[JavaCallGraphEdge],
) -> JavaReachabilityPath:
    target = (
        edges[-1].target_method_id
        if edges
        else _method_id(
            entrypoint.class_name,
            entrypoint.method_name or "",
            entrypoint.method_descriptor or "",
        )
    )
    key = f"{entrypoint.entrypoint_id}:{target}:{','.join(edge.edge_id for edge in edges)}"
    return JavaReachabilityPath(
        path_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        entrypoint_category=entrypoint.category,
        entrypoint_method_id=_method_id(
            entrypoint.class_name,
            entrypoint.method_name or "",
            entrypoint.method_descriptor or "",
        ),
        target_method_id=target,
        depth=len(edges),
        edges=[
            JavaReachabilityEdgeStep(
                edge_id=edge.edge_id,
                source_method_id=edge.source_method_id,
                target_method_id=edge.target_method_id,
                source_class_name=edge.source_class_name,
                source_method_name=edge.source_method_name,
                source_method_descriptor=edge.source_method_descriptor,
                target_owner=edge.target_owner,
                target_name=edge.target_name,
                target_descriptor=edge.target_descriptor,
                target_defined=edge.target_defined,
                bci=edge.bci,
                line_number=edge.line_number,
                invoke_kind=edge.invoke_kind,
            )
            for edge in edges
        ],
    )


def _result(
    path: Path,
    paths: list[JavaReachabilityPath],
    entrypoint_count: int,
    graph_edge_count: int,
    target_match_count: int,
    stop_reasons: list[str],
    truncated: bool,
    kb: KnowledgeBase,
) -> JavaReachabilityResult:
    node = kb.add_node(
        Node(
            kind=NodeKind.java_reachability,
            label=f"Java reachability: {'reachable' if paths else 'unreachable'}",
            props={
                "tool": "java_reachability",
                "archive_path": str(path),
                "reachable": bool(paths),
                "path_count": len(paths),
                "entrypoint_count": entrypoint_count,
                "graph_edge_count": graph_edge_count,
                "target_match_count": target_match_count,
                "stop_reasons": stop_reasons,
                "truncated": truncated,
            },
            tags=["java", "reachability", "call-graph"],
        )
    )
    return JavaReachabilityResult(
        archive_path=str(path),
        reachable=bool(paths),
        path_count=len(paths),
        paths=paths,
        entrypoint_count=entrypoint_count,
        graph_edge_count=graph_edge_count,
        target_match_count=target_match_count,
        stop_reasons=stop_reasons,
        truncated=truncated,
        reachability_node_id=node.id,
    )


def _method_id(class_name: str, method_name: str, method_descriptor: str) -> str:
    return f"{_internal(class_name)}#{method_name}{method_descriptor}"


def _internal(class_name: str) -> str:
    return class_name.removesuffix(".class").replace(".", "/")


def build_tool() -> MemoryTool[JavaReachabilityArgs, JavaReachabilityResult]:
    return JavaReachabilityTool()
