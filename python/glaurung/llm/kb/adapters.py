from __future__ import annotations

from typing import Optional

import glaurung as g

from .models import Node, Edge, NodeKind
from .store import KnowledgeBase


def import_triage(
    kb: KnowledgeBase, artifact: g.triage.TriagedArtifact, file_path: str
) -> str:
    """Import a triage artifact into the KB.

    Returns the file node id.
    """
    file_node = kb.add_node(
        Node(
            kind=NodeKind.file,
            label=file_path,
            text=None,
            props={"size": artifact.size_bytes},
        )
    )

    art_node = kb.add_node(
        Node(kind=NodeKind.artifact, label="triage", props={"path": file_path})
    )
    kb.add_edge(Edge(src=file_node.id, dst=art_node.id, kind="has_artifact"))

    # imports summary if available
    if artifact.symbols and getattr(artifact.symbols, "import_names", None):
        for name in artifact.symbols.import_names[:200]:
            imp = kb.add_node(
                Node(kind=NodeKind.import_sym, label=str(name), tags=["import"])
            )
            kb.add_edge(Edge(src=file_node.id, dst=imp.id, kind="uses_import"))

    # strings samples (short)
    if artifact.strings and getattr(artifact.strings, "samples", None):
        for s in artifact.strings.samples[:100]:
            st = kb.add_node(Node(kind=NodeKind.string, label=str(s)[:80], text=str(s)))
            kb.add_edge(Edge(src=file_node.id, dst=st.id, kind="contains_string"))

    return file_node.id


def import_binary_evidence(
    kb: KnowledgeBase, evidence: "BinaryEvidence", file_node_id: Optional[str] = None
) -> str:
    """Import BinaryEvidence into KB. Returns an evidence node id."""
    ev_node = kb.add_node(
        Node(
            kind=NodeKind.evidence, label=f"evidence:{evidence.format}:{evidence.arch}"
        )
    )
    if file_node_id:
        kb.add_edge(Edge(src=file_node_id, dst=ev_node.id, kind="has_evidence"))

    # functions
    for f in evidence.functions:
        fn = kb.add_node(
            Node(
                kind=NodeKind.function,
                label=f.name,
                props={"entry_va": f.entry_va, "instr": f.instruction_count_provided},
            )
        )
        kb.add_edge(Edge(src=ev_node.id, dst=fn.id, kind="has_function"))
        # strings
        for s in f.strings:
            sn = kb.add_node(Node(kind=NodeKind.string, label=s.text[:64], text=s.text))
            kb.add_edge(Edge(src=fn.id, dst=sn.id, kind="references_string"))
        # calls
        for c in f.calls:
            tgt = c.target_name or (
                f"0x{c.target_va:x}" if c.target_va is not None else "call"
            )
            cn = kb.add_node(
                Node(kind=NodeKind.note, label=f"call {tgt}", props={"va": c.va})
            )
            kb.add_edge(Edge(src=fn.id, dst=cn.id, kind="calls"))

    return ev_node.id
