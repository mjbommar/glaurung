from __future__ import annotations

from typing import Dict, List, Iterable, Optional, Tuple
from collections import defaultdict

from .models import Node, Edge, KBView


class KnowledgeBase:
    """In-memory knowledge base with simple text indexing.

    - Adds nodes/edges and maintains inverted index over node.label/text.
    - Provides text search, tag filtering, and neighborhood selection.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, Edge] = {}
        self._by_tag: Dict[str, set[str]] = defaultdict(set)
        self._inv: Dict[str, set[str]] = defaultdict(set)

    # ----------------------------- add/update -----------------------------
    def add_node(self, node: Node) -> Node:
        self._nodes[node.id] = node
        for t in node.tags:
            self._by_tag[t].add(node.id)
        self._index_text(node)
        return node

    def add_edge(self, edge: Edge) -> Edge:
        if edge.src not in self._nodes or edge.dst not in self._nodes:
            raise ValueError("edge endpoints must exist")
        self._edges[edge.id] = edge
        return edge

    def tag_node(self, node_id: str, *tags: str) -> None:
        n = self._nodes[node_id]
        for t in tags:
            if t not in n.tags:
                n.tags.append(t)
                self._by_tag[t].add(n.id)

    # ------------------------------- access -------------------------------
    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def nodes(self) -> Iterable[Node]:
        return self._nodes.values()

    def edges(self) -> Iterable[Edge]:
        return self._edges.values()

    def neighbors(self, node_id: str) -> List[Node]:
        out = []
        for e in self._edges.values():
            if e.src == node_id:
                n = self._nodes.get(e.dst)
                if n:
                    out.append(n)
            elif e.dst == node_id:
                n = self._nodes.get(e.src)
                if n:
                    out.append(n)
        # unique preserve order
        seen = set()
        result = []
        for n in out:
            if n.id not in seen:
                seen.add(n.id)
                result.append(n)
        return result

    # ------------------------------- search ------------------------------
    def search_text(self, query: str, limit: int = 50) -> List[Tuple[Node, int]]:
        """Very simple token-based search over label/text.

        Returns list of (node, score) sorted by score desc.
        """
        tokens = _tokenize(query)
        counts: Dict[str, int] = defaultdict(int)
        for tok in tokens:
            for nid in self._inv.get(tok, ()):  # type: ignore[arg-type]
                counts[nid] += 1
        ranked = sorted(
            ((self._nodes[nid], score) for nid, score in counts.items()),
            key=lambda x: -x[1],
        )
        return ranked[:limit]

    def by_tag(self, tag: str) -> List[Node]:
        return [self._nodes[nid] for nid in self._by_tag.get(tag, [])]

    def view(self, node_ids: Iterable[str]) -> KBView:
        node_set = set(node_ids)
        nodes = [self._nodes[n] for n in node_set if n in self._nodes]
        edges = [
            e for e in self._edges.values() if e.src in node_set and e.dst in node_set
        ]
        return KBView(nodes=nodes, edges=edges)

    # ------------------------------ internal -----------------------------
    def _index_text(self, node: Node) -> None:
        text = (node.label or "") + "\n" + (node.text or "")
        for tok in _tokenize(text):
            self._inv[tok].add(node.id)


def _tokenize(text: str) -> List[str]:
    # very basic for now: split on non-alnum and lowercase
    import re

    return [t for t in re.split(r"[^A-Za-z0-9_]+", text.lower()) if t]
