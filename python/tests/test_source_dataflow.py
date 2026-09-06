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


@pytest.mark.core
def test_control_dependence_reports_nodes_edges_and_depth():
    flows = glaurung.source.control_dependence(SUM)
    assert len(flows) == 1
    flow = flows[0]
    assert flow["name"] == "f"
    assert flow["nodes"] and flow["edges"]
    for node in flow["nodes"]:
        for key in ("id", "kind", "depth", "ipdom"):
            assert key in node, key
    for edge in flow["edges"]:
        assert edge["kind"] in {
            "true",
            "false",
            "case",
            "default",
            "fall",
            "fall_through",
            "jump",
        }, edge


@pytest.mark.core
def test_the_entry_is_control_dependent_on_nothing():
    flow = glaurung.source.control_dependence(SUM)[0]
    entry = next(node for node in flow["nodes"] if node["kind"] == "entry")
    assert entry["depth"] == 0
    assert not any(edge["node"] == entry["id"] for edge in flow["edges"])


@pytest.mark.core
def test_a_loop_body_is_deeper_than_the_function_entry():
    flow = glaurung.source.control_dependence(SUM)[0]
    depths = [node["depth"] for node in flow["nodes"]]
    assert min(depths) == 0
    assert max(depths) >= 1, depths


@pytest.mark.core
def test_a_region_that_cannot_reach_the_exit_is_reported_not_dropped():
    """The shape with no post-dominator tree unless a virtual exit is added.

    `goto` to its own label, rather than `while (1)`: the front end folds no
    constants, so a `while (1)` header still carries a false arm to whatever
    follows it and the graph is not stuck. An unconditional `goto` genuinely
    is, which is the case the virtual exit exists for.
    """
    flows = glaurung.source.control_dependence("int f(void) { L: goto L; }")
    assert len(flows) == 1
    assert flows[0]["nodes"]
    assert flows[0]["unreachable_exit"], "the stuck region was dropped silently"


@pytest.mark.core
def test_an_unfoldable_infinite_loop_still_exports():
    """`while (1)` is not stuck to a front end that folds no constants."""
    flows = glaurung.source.control_dependence(
        "int f(void) { while (1) { } return 0; }"
    )
    assert len(flows) == 1 and flows[0]["nodes"]
    assert flows[0]["unreachable_exit"] == []


@pytest.mark.core
def test_a_backward_slice_includes_its_seed_and_is_sorted():
    flow = glaurung.source.control_dependence(SUM)[0]
    last = flow["nodes"][-1]["id"]
    sliced = glaurung.source.backward_slice(SUM, "f", last)
    assert last in sliced
    assert sliced == sorted(sliced)
    assert len(sliced) <= len(flow["nodes"])


@pytest.mark.core
def test_slicing_an_unknown_function_raises():
    with pytest.raises(KeyError):
        glaurung.source.backward_slice(SUM, "nosuchfunction", 0)


@pytest.mark.core
def test_the_pdg_tags_every_edge_as_control_or_data():
    body = dict(glaurung.source.export_graphs(SUM, repr="pdg", format="json"))["f"]
    graph = json.loads(body)
    kinds = {edge.get("dependence") for edge in graph["edges"]}
    assert kinds == {"control", "data"}, kinds


@pytest.mark.core
def test_spans_are_byte_offsets_not_character_offsets():
    """The trap documented on `control_dependence`, pinned.

    A file with a non-ASCII byte before the code shifts every character index,
    so slicing `str` gives the wrong text while slicing bytes gives the right
    one. This caught a real hour of chasing a CFG bug that did not exist.
    """
    text = "/* a — b */\nint f(void) { int x = 1; return x; }"
    raw = text.encode()
    flow = glaurung.source.data_flow(text)[0]
    definition = flow["definitions"][0]
    assert raw[definition["start"] : definition["end"]].decode() == "x"
    # And the naive character slice is wrong, which is why the warning exists.
    assert text[definition["start"] : definition["end"]] != "x"


# --- declared types (phase 1 of the source-semantics plan) -------------------

TYPED = (
    "int f(const char *name, int n) { unsigned long total = 0; "
    "struct point *p; int m[4][4]; return (int)total; }"
)


@pytest.mark.core
def test_every_binding_carries_the_type_the_source_spells():
    flow = glaurung.source.data_flow(TYPED)[0]
    by_name = {b["name"]: b for b in flow["bindings"]}
    assert by_name["name"]["type"] == "const char *"
    assert by_name["name"]["pointer_depth"] == 1
    assert by_name["name"]["is_const"] is True
    assert by_name["n"]["type"] == "int"
    assert by_name["total"]["type"] == "unsigned long"
    assert by_name["p"]["type"] == "struct point *"
    assert by_name["m"]["array_rank"] == 2


@pytest.mark.core
def test_a_typedef_from_a_header_stays_an_opaque_name():
    """No `#include` resolution, so the spelling is recorded and not resolved.

    Storing `uint32_t` and being unable to say it is four bytes is honest;
    claiming to know would not be.
    """
    flow = glaurung.source.data_flow("int f(void) { uint32_t n = 0; return (int)n; }")[
        0
    ]
    binding = next(b for b in flow["bindings"] if b["name"] == "n")
    assert binding["specifiers"] == "uint32_t"


@pytest.mark.core
def test_definitions_and_uses_join_to_bindings():
    flow = glaurung.source.data_flow(TYPED)[0]
    count = len(flow["bindings"])
    for definition in flow["definitions"]:
        assert 0 <= definition["binding"] < count or definition["binding"] == 2**32 - 1
    for use in flow["uses"]:
        assert 0 <= use["binding"] < count or use["binding"] == 2**32 - 1


@pytest.mark.core
def test_a_declaration_site_records_the_type_it_declared():
    flow = glaurung.source.data_flow(TYPED)[0]
    declared = {
        d["name"]: d["declared_type"] for d in flow["definitions"] if d["declared_type"]
    }
    assert declared["total"] == "unsigned long"
    assert declared["name"] == "const char *"
    # An assignment declares nothing.
    flow2 = glaurung.source.data_flow("int f(void) { int x = 1; x = 2; return x; }")[0]
    assignment = next(d for d in flow2["definitions"] if d["kind"] == "assignment")
    assert assignment["declared_type"] is None


@pytest.mark.core
def test_an_unused_declaration_is_reported_and_is_not_a_dead_store():
    """`int *b;` is not a store, so it cannot be a dead one -- but it is unused.

    The two counts answer different questions and a caller wants both.
    """
    flow = glaurung.source.data_flow(
        "int f(int p) { int used = 1; int *never; return used; }"
    )[0]
    unused = [flow["bindings"][i]["name"] for i in flow["unused_bindings"]]
    assert unused == ["never"], unused
    assert flow["dead_stores"] == []


@pytest.mark.core
def test_well_typed_source_has_no_type_conflicts():
    flow = glaurung.source.data_flow(TYPED)[0]
    assert flow["type_conflicts"] == []


@pytest.mark.slow
def test_the_corpus_types_every_binding_and_declares_nothing_it_does_not_use():
    """Both baselines the decompiler comparison is measured against.

    Hand-written C types everything it binds and declares nothing it does not
    use. A drop in either means the reader is losing declarations, not that
    the corpus changed.
    """
    root = Path(__file__).resolve().parents[2] / "tests" / "decompiler_fixtures" / "src"
    bindings = typed = conflicts = unused = 0
    for path in sorted(root.glob("*.c")):
        for flow in glaurung.source.data_flow(path.read_text(errors="replace")):
            bindings += len(flow["bindings"])
            typed += sum(1 for b in flow["bindings"] if b["type"])
            conflicts += len(flow["type_conflicts"])
            unused += len(flow["unused_bindings"])
    assert bindings > 1000, bindings
    assert typed == bindings, f"{bindings - typed} bindings carry no type"
    assert conflicts == 0, f"{conflicts} type conflicts in hand-written C"
    assert unused == 0, f"{unused} unused bindings in hand-written C"


# --- interprocedural summaries (phase 2 of the source-semantics plan) --------

CALLS = """int strip(int x) { return 0; }
int carry(int y) { return y; }
int outer(int n) { return carry(n); }
"""


@pytest.mark.core
def test_every_function_gets_a_summary():
    summaries = {s["name"]: s for s in glaurung.source.call_summaries(CALLS)}
    assert set(summaries) == {"strip", "carry", "outer"}
    assert summaries["carry"]["parameters"] == 1


@pytest.mark.core
def test_a_parameter_that_is_returned_flows_and_one_that_is_dropped_does_not():
    """The test that separates an analysis from a rubber stamp."""
    summaries = {s["name"]: s for s in glaurung.source.call_summaries(CALLS)}
    assert summaries["carry"]["flows"] == [
        {"parameter": 0, "sink": "return", "sink_parameter": None}
    ]
    assert summaries["strip"]["flows"] == []


@pytest.mark.core
def test_a_flow_crosses_a_call():
    """`outer` propagates only because `carry` returns what it is given.

    This is the whole point of the module: with no call-site rule the answer
    would be the same for a callee that drops its argument, which is right by
    accident and wrong in general.
    """
    summaries = {s["name"]: s for s in glaurung.source.call_summaries(CALLS)}
    assert summaries["outer"]["flows"], "outer should propagate through carry"

    dropped = """int strip(int x) { return 0; }
int outer(int n) { return strip(n); }
"""
    summaries = {s["name"]: s for s in glaurung.source.call_summaries(dropped)}
    assert summaries["outer"]["flows"] == [], "strip drops its argument"


@pytest.mark.core
def test_reaches_answers_yes_no_and_unknown():
    assert glaurung.source.reaches(CALLS, "carry", 0, "carry") == "yes"
    # A function this unit does not define cannot be summarized.
    assert glaurung.source.reaches(CALLS, "nosuch", 0, "outer") == "unknown"
    # A parameter position the function does not have.
    assert glaurung.source.reaches(CALLS, "carry", 9, "outer") == "no"


@pytest.mark.core
def test_an_indirect_call_makes_a_summary_incomplete():
    """An indirect call names no callee, so no summary can be applied.

    Reporting `no` here would be a claim rather than an analysis, so the
    summary is marked incomplete and a caller inherits `unknown`.
    """
    code = "int f(int (*p)(int), int n) { return p(n); }"
    summaries = {s["name"]: s for s in glaurung.source.call_summaries(code)}
    assert summaries["f"]["complete"] is False


@pytest.mark.core
def test_recursion_and_mutual_recursion_terminate():
    for code in [
        "int f(int n) { if (n > 0) { return f(n - 1); } return n; }",
        "int a(int n) { return b(n); }\nint b(int n) { if (n > 0) { return a(n - 1); } return n; }",
    ]:
        assert glaurung.source.call_summaries(code)


@pytest.mark.core
def test_summarizing_is_total_on_input_that_is_not_c():
    for junk in ["", "\x00\x01", "int f(", "}}}"]:
        assert isinstance(glaurung.source.call_summaries(junk), list)


@pytest.mark.slow
def test_the_corpus_summarizes_every_function():
    root = Path(__file__).resolve().parents[2] / "tests" / "decompiler_fixtures" / "src"
    functions = flows = incomplete = 0
    for path in sorted(root.glob("*.c")):
        code = path.read_text(errors="replace")
        summaries = glaurung.source.call_summaries(code)
        functions += len(summaries)
        for summary in summaries:
            flows += len(summary["flows"])
            incomplete += 0 if summary["complete"] else 1
            for flow in summary["flows"]:
                assert flow["parameter"] < summary["parameters"], summary
    assert functions > 500, functions
    assert flows > 100, f"only {flows} parameter flows over {functions} functions"
