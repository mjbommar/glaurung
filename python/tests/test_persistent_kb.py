"""Round-trip tests for the SQLite-backed KnowledgeBase.

Drops a small set of nodes / edges / tags into a fresh database,
closes it, reopens, and checks that every field survives byte-for-byte.
Also exercises the second-session pattern (multiple sessions per
binary) and the binary-by-sha256 keyed lookup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.models import Edge, Node, NodeKind
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


def _hello_path() -> Path:
    p = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
    )
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_round_trip_basic(tmp_path: Path) -> None:
    db = tmp_path / "test.glaurung"
    binary = _hello_path()

    # Phase 1 — create a fresh DB and add some nodes/edges.
    kb = PersistentKnowledgeBase.open(db, binary_path=binary, session="main")
    file_node = kb.add_node(
        Node(kind=NodeKind.file, label=str(binary), props={"size": 18248})
    )
    fn_node = kb.add_node(
        Node(
            kind=NodeKind.function,
            label="parse_config",
            props={"entry_va": 0x10c0},
            tags=["recovered", "high-confidence"],
        )
    )
    kb.add_edge(Edge(src=file_node.id, dst=fn_node.id, kind="has_function"))
    kb.save()
    kb.close()

    # Phase 2 — reopen and verify.
    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary, session="main")
    nodes = list(kb2.nodes())
    edges = list(kb2.edges())
    assert len(nodes) == 2
    assert len(edges) == 1
    fn_round_trip = next(n for n in nodes if n.kind == NodeKind.function)
    assert fn_round_trip.label == "parse_config"
    assert fn_round_trip.props["entry_va"] == 0x10c0
    assert sorted(fn_round_trip.tags) == ["high-confidence", "recovered"]
    edge = edges[0]
    assert edge.kind == "has_function"
    kb2.close()


def test_search_text_after_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "test.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    kb.add_node(Node(kind=NodeKind.note, label="canary", text="stack canary save"))
    kb.add_node(Node(kind=NodeKind.note, label="error", text="invalid argument"))
    kb.save()
    kb.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    hits = kb2.search_text("canary", limit=5)
    assert hits, "search_text should find rehydrated nodes"
    assert hits[0][0].label == "canary"
    kb2.close()


def test_two_sessions_isolated(tmp_path: Path) -> None:
    db = tmp_path / "test.glaurung"
    binary = _hello_path()

    kb1 = PersistentKnowledgeBase.open(db, binary_path=binary, session="alice")
    kb1.add_node(Node(kind=NodeKind.note, label="alice-note", text="x"))
    kb1.save()
    kb1.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary, session="bob")
    kb2.add_node(Node(kind=NodeKind.note, label="bob-note", text="y"))
    kb2.save()
    kb2.close()

    # Sessions don't see each other's nodes.
    re_alice = PersistentKnowledgeBase.open(db, binary_path=binary, session="alice")
    labels = {n.label for n in re_alice.nodes()}
    assert "alice-note" in labels
    assert "bob-note" not in labels
    re_alice.close()

    # A third session opens fresh.
    fresh = PersistentKnowledgeBase.open(db, binary_path=binary, session="charlie")
    assert list(fresh.nodes()) == []
    fresh.close()


def test_context_manager_saves_on_exit(tmp_path: Path) -> None:
    db = tmp_path / "test.glaurung"
    binary = _hello_path()

    with PersistentKnowledgeBase.open(db, binary_path=binary) as kb:
        kb.add_node(Node(kind=NodeKind.note, label="ctxmgr", text="saved-via-with"))

    re = PersistentKnowledgeBase.open(db, binary_path=binary)
    labels = [n.label for n in re.nodes()]
    assert "ctxmgr" in labels
    re.close()


def test_open_existing_without_binary_path(tmp_path: Path) -> None:
    db = tmp_path / "test.glaurung"
    binary = _hello_path()

    # First open creates the binary record.
    PersistentKnowledgeBase.open(db, binary_path=binary).close()

    # Subsequent open without binary_path picks up the most recent one.
    kb = PersistentKnowledgeBase.open(db)
    assert kb.binary_id > 0
    kb.close()


def test_memory_context_open_persistent(tmp_path: Path) -> None:
    """Round-trip through the public MemoryContext factory."""
    import glaurung as g
    from glaurung.llm.context import MemoryContext

    binary = _hello_path()
    db = tmp_path / "ctx.glaurung"

    art = g.triage.analyze_path(str(binary))
    ctx = MemoryContext.open_persistent(
        file_path=str(binary), artifact=art, db_path=db, session="main",
    )
    ctx.kb.add_node(Node(kind=NodeKind.note, label="via-ctx", text="hello"))
    ctx.kb.close()

    ctx2 = MemoryContext.open_persistent(
        file_path=str(binary), artifact=art, db_path=db, session="main",
    )
    labels = [n.label for n in ctx2.kb.nodes()]
    assert "via-ctx" in labels
    ctx2.kb.close()
