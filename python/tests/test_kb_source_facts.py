"""Source facts written into a `.glaurung` project.

Phase 4 of `docs/development/roadmap/source-semantics.md`. The front end reads
prototypes, declared types and data dependence out of one translation unit;
these check that they land in the knowledge base with `set_by = "source"` and
that the provenance ladder -- not arrival order -- decides what wins.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.kb.source_facts import SET_BY, ingest_source, ingest_source_path
from glaurung.llm.kb.xref_db import FunctionParam, set_function_prototype

CODE = """
int parse_header(const char *buf, unsigned int len)
{
    unsigned int magic = len;
    int dead = 7;
    if (len < 8) {
        return 0;
    }
    return (int)magic;
}
"""


@pytest.fixture
def kb(tmp_path: Path) -> PersistentKnowledgeBase:
    """An open project over a throwaway binary."""
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    handle = PersistentKnowledgeBase.open(
        str(tmp_path / "p.glaurung"), binary_path=str(binary)
    )
    yield handle
    handle.close()


@pytest.mark.core
def test_a_prototype_is_written_with_source_provenance(kb):
    counts = ingest_source(kb, CODE, origin="parse.c")
    assert counts.functions == 1
    assert counts.prototypes == 1

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by, params_json, source FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, "parse_header"),
    )
    row = cur.fetchone()
    assert row is not None, "no prototype row"
    assert row[0] == SET_BY
    assert "buf" in row[1] and "len" in row[1]
    assert row[2] == "parse.c"


@pytest.mark.core
def test_parameter_types_are_the_ones_the_source_spells(kb):
    import json

    ingest_source(kb, CODE)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT params_json FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, "parse_header"),
    )
    params = json.loads(cur.fetchone()[0])
    by_name = {p["name"]: p["c_type"] for p in params}
    assert by_name["buf"] == "const char *"
    assert by_name["len"] == "unsigned int"


@pytest.mark.core
def test_manual_outranks_source(kb):
    """The one rule that predates the ladder still holds."""
    set_function_prototype(
        kb,
        "parse_header",
        return_type="int",
        params=[FunctionParam(name="analyst", c_type="void *")],
        set_by="manual",
    )
    ingest_source(kb, CODE)

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by, params_json FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, "parse_header"),
    )
    set_by, params = cur.fetchone()
    assert set_by == "manual", "source overwrote the analyst"
    assert "analyst" in params


@pytest.mark.core
def test_source_outranks_a_heuristic(kb):
    """And the ladder works downward too, which is the half that was broken
    before `kb/provenance.py` existed."""
    set_function_prototype(
        kb,
        "parse_header",
        return_type=None,
        params=[FunctionParam(name="guess", c_type="int")],
        set_by="auto",
    )
    ingest_source(kb, CODE)

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, "parse_header"),
    )
    assert cur.fetchone()[0] == SET_BY


@pytest.mark.core
def test_dependence_edges_land_as_typed_edges(kb):
    counts = ingest_source(kb, CODE, origin="parse.c")
    assert counts.dependence_edges > 0

    cur = kb._conn.cursor()
    cur.execute("SELECT COUNT(*) FROM kb_edges WHERE kind = 'source_data_dependence'")
    assert cur.fetchone()[0] == counts.dependence_edges

    # Both endpoints of every edge exist as nodes.
    cur.execute(
        "SELECT src_node_id, dst_node_id FROM kb_edges "
        "WHERE kind = 'source_data_dependence'"
    )
    for src, dst in cur.fetchall():
        for node_id in (src, dst):
            cur.execute("SELECT COUNT(*) FROM kb_nodes WHERE node_id = ?", (node_id,))
            assert cur.fetchone()[0] == 1, f"dangling endpoint {node_id}"


@pytest.mark.core
def test_a_dependence_edge_names_its_variable(kb):
    import json

    ingest_source(kb, CODE)
    cur = kb._conn.cursor()
    cur.execute("SELECT props_json FROM kb_edges WHERE kind = 'source_data_dependence'")
    for (props,) in cur.fetchall():
        parsed = json.loads(props)
        assert parsed["variable"], parsed
        assert parsed["set_by"] == SET_BY


@pytest.mark.core
def test_dependence_can_be_skipped(kb):
    counts = ingest_source(kb, CODE, write_dependence=False)
    assert counts.prototypes == 1
    assert counts.dependence_edges == 0


@pytest.mark.core
def test_ingesting_twice_is_idempotent(kb):
    first = ingest_source(kb, CODE)
    second = ingest_source(kb, CODE)
    assert first.dependence_edges == second.dependence_edges

    cur = kb._conn.cursor()
    cur.execute("SELECT COUNT(*) FROM kb_edges WHERE kind = 'source_data_dependence'")
    assert cur.fetchone()[0] == first.dependence_edges, "rows duplicated on re-ingest"


@pytest.mark.core
def test_input_that_is_not_c_writes_nothing_and_does_not_raise(kb):
    for junk in ["", "\x00\x01", "int f(", "}}}"]:
        counts = ingest_source(kb, junk)
        assert counts.prototypes == 0


@pytest.mark.core
def test_the_dead_store_and_unused_counts_are_reported(kb):
    counts = ingest_source(kb, CODE)
    # `dead` is written and never read.
    assert counts.dead_stores >= 1, counts


@pytest.mark.core
def test_a_file_is_read_lossily(kb, tmp_path: Path):
    """A byte that is not UTF-8 costs the byte, never the file."""
    target = tmp_path / "broken.c"
    target.write_bytes(b'int f(int a) { char *s = "\xff\xfe"; return a; }\n')
    counts = ingest_source_path(kb, target)
    assert counts.functions == 1
