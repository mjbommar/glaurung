from __future__ import annotations

from pathlib import Path

from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase


def add_java_hierarchy_edges(
    kb: KnowledgeBase,
    *,
    archive_path: Path,
    class_node_id: str,
    super_class: str | None,
    interfaces: list[str],
) -> None:
    """Add coarse Java inheritance/interface edges for a class node."""
    if super_class and super_class != "java/lang/Object":
        _add_target_edge(
            kb,
            archive_path=archive_path,
            class_node_id=class_node_id,
            target_class=super_class,
            edge_kind="extends",
        )
    for interface in interfaces:
        if interface:
            _add_target_edge(
                kb,
                archive_path=archive_path,
                class_node_id=class_node_id,
                target_class=interface,
                edge_kind="implements",
            )


def _add_target_edge(
    kb: KnowledgeBase,
    *,
    archive_path: Path,
    class_node_id: str,
    target_class: str,
    edge_kind: str,
) -> None:
    target_node = kb.add_node(
        Node(
            kind=NodeKind.java_class,
            label=target_class.replace("/", "."),
            props={
                "tool": "java_hierarchy",
                "archive_path": str(archive_path),
                "class_name": target_class,
                "dotted_class_name": target_class.replace("/", "."),
                "placeholder": True,
            },
            tags=["java", "class", "hierarchy", "placeholder"],
        )
    )
    kb.add_edge(
        Edge(
            src=class_node_id,
            dst=target_node.id,
            kind=edge_kind,
            props={"target_class": target_class},
        )
    )
