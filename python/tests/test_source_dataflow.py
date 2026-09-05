"""Reaching definitions and dead stores, through `glaurung.source`.

The Rust unit tests in `src/csource/dataflow.rs` pin the analysis against
hand-written C, including the cases that took several rounds to get right: a
bare `int x;` is not a store, `a[i] = v` does not define `a`, `sum = sum + i`
reads the value that reached the statement rather than the one it is about to
write, and a shadowed declaration is a different variable.

What is here is what only Python can check -- the boundary, the shape of the
result, and the one measurement that justifies the feature: hand-written C has
almost no dead stores and decompiler output has many.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import glaurung

SUM = "int f(int n) { int s = 0; int dead = 7; for (int i = 0; i < n; i++) { s = s + i; } return s; }"


@pytest.mark.core
def test_the_boundary_returns_every_field():
    flows = glaurung.source.data_flow(SUM)
    assert len(flows) == 1
    flow = flows[0]
    assert flow["name"] == "f"
    for key in ("definitions", "uses", "edges", "unresolved_uses", "dead_stores"):
        assert key in flow, key
    assert flow["definitions"], "no definitions"
    assert flow["edges"], "no edges"


@pytest.mark.core
def test_a_parameter_is_a_definition_and_a_loop_carries_one_backwards():
    flow = glaurung.source.data_flow(SUM)[0]
    kinds = {d["name"]: d["kind"] for d in flow["definitions"]}
    assert kinds["n"] == "parameter"
    assert kinds["i"] in {"declaration", "inc_dec"}
    # `s` is both declared and assigned in the loop, and the read inside the
    # loop must see both.
    s_defs = [d for d in flow["definitions"] if d["name"] == "s"]
    assert len(s_defs) == 2, s_defs


@pytest.mark.core
def test_a_write_nothing_reads_is_a_dead_store():
    flow = glaurung.source.data_flow(SUM)[0]
    dead = [flow["definitions"][i]["name"] for i in flow["dead_stores"]]
    assert dead == ["dead"], dead


@pytest.mark.core
def test_every_edge_names_its_variable_and_both_ends_agree():
    flow = glaurung.source.data_flow(SUM)[0]
    for edge in flow["edges"]:
        definition = flow["definitions"][edge["definition"]]
        use = flow["uses"][edge["use"]]
        assert edge["variable"] == definition["name"] == use["name"], edge


@pytest.mark.core
def test_the_defect_lists_are_consistent_with_the_edges():
    flow = glaurung.source.data_flow(SUM)[0]
    reached_uses = {e["use"] for e in flow["edges"]}
    for index in flow["unresolved_uses"]:
        assert index not in reached_uses
    read_defs = {e["definition"] for e in flow["edges"]}
    for index in flow["dead_stores"]:
        assert index not in read_defs


@pytest.mark.core
def test_analysis_is_total_on_input_that_is_not_c():
    for junk in ["", "\x00\x01", "int f(", "}}}", "中文"]:
        assert isinstance(glaurung.source.data_flow(junk), list)


@pytest.mark.core
def test_the_ddg_exports_in_every_format():
    for fmt in glaurung.source.EXPORT_FORMATS:
        graphs = glaurung.source.export_graphs(SUM, repr="ddg", format=fmt)
        assert graphs and all(body.strip() for _, body in graphs)


@pytest.mark.core
def test_the_json_ddg_marks_dead_stores_and_labels_edges():
    body = dict(glaurung.source.export_graphs(SUM, repr="ddg", format="json"))["f"]
    graph = json.loads(body)
    dead = [n["variable"] for n in graph["nodes"] if n.get("dead_store") == "true"]
    assert dead == ["dead"], dead
    assert all(e.get("variable") for e in graph["edges"])


@pytest.mark.slow
def test_hand_written_c_has_almost_no_dead_stores():
    """The measurement the feature exists for, from the source side.

    900 functions of deliberately awkward hand-written C. If a change starts
    calling ordinary code dead, this is where it shows up.
    """
    root = Path(__file__).resolve().parents[2] / "tests" / "decompiler_fixtures" / "src"
    functions = dead = 0
    for path in sorted(root.glob("*.c")):
        for flow in glaurung.source.data_flow(path.read_text(errors="replace")):
            functions += 1
            dead += len(flow["dead_stores"])
    assert functions > 500, functions
    assert dead * 20 < functions, f"{dead} dead stores over {functions} functions"
