from glaurung.llm.kb.store import KnowledgeBase
from glaurung.llm.kb.models import Node, NodeKind, Edge


def test_kb_add_and_search():
    kb = KnowledgeBase()
    n1 = kb.add_node(Node(kind=NodeKind.note, label="First Node", text="hello world"))
    n2 = kb.add_node(Node(kind=NodeKind.note, label="Second", text="contains malware string"))
    kb.add_edge(Edge(src=n1.id, dst=n2.id, kind="related"))

    hits = kb.search_text("malware", limit=5)
    assert hits and hits[0][0].id == n2.id

    neigh = kb.neighbors(n2.id)
    assert neigh and neigh[0].id == n1.id

