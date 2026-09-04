"""The `glaurung.source_cfg` provider that `tools/source_cfg_parity.py` resolves.

Two layers are covered separately because they fail differently:

* the PyO3 binding (`glaurung._native.csource`), which needs nothing but the
  built extension and is therefore `core`;
* the `networkx` adaptation, which needs a graph library the project itself does
  not depend on.

The second layer would otherwise be a silent skip on every developer machine,
which reads exactly like a passing test. `GLAURUNG_REQUIRE_NETWORKX=1` turns
that skip into a failure so the parity lane -- which runs under DecBench's venv,
where `networkx` is present -- cannot lose these assertions without going red.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

import glaurung
from glaurung.source_cfg import (
    SourceCfgNode,
    cfgs_from_decompiled,
    graph_from_serialized,
    parity_cfgs,
)

#: A branch and a loop, so the CFG is neither a single block nor a chain.
BRANCH_AND_LOOP = """
int classify(int n) {
    int total = 0;
    while (n > 0) {
        if (n % 2) {
            total += n;
        } else {
            total -= n;
        }
        n--;
    }
    return total;
}
"""


def _require_networkx() -> Any:
    """Import `networkx`, skipping unless the caller demanded it be present."""
    if os.environ.get("GLAURUNG_REQUIRE_NETWORKX") == "1":
        import networkx

        return networkx
    return pytest.importorskip(
        "networkx",
        reason="networkx is a DecBench dependency, not a Glaurung one; "
        "set GLAURUNG_REQUIRE_NETWORKX=1 to make this a failure instead",
    )


@pytest.mark.core
def test_provider_entry_point_is_reachable_the_way_the_harness_resolves_it() -> None:
    """`GlaurungProvider._resolve` does exactly this getattr chain."""
    module = getattr(glaurung, "source_cfg", None)
    assert module is not None, "glaurung.source_cfg must be imported by the package"
    entry = getattr(module, "cfgs_from_decompiled", None)
    assert callable(entry), "the harness calls cfgs_from_decompiled(text)"


@pytest.mark.core
def test_native_submodule_returns_the_serialized_decbench_shape() -> None:
    cfgs = parity_cfgs(BRANCH_AND_LOOP)
    assert set(cfgs) == {"classify"}
    cfg = cfgs["classify"]
    assert set(cfg) == {"nodes", "edges", "entry", "exit", "degenerate"}
    assert cfg["nodes"] == sorted(cfg["nodes"]), "node ids are dense and ascending"
    assert cfg["nodes"][0] == 0
    assert len(cfg["entry"]) == 1
    assert cfg["exit"], "a returning function has at least one exit block"
    assert cfg["degenerate"] is False
    reachable = {node for edge in cfg["edges"] for node in edge}
    assert reachable <= set(cfg["nodes"]), "every edge endpoint is a declared node"
    # A loop means some block is reached from more than one predecessor; a plain
    # chain would make the whole GED comparison vacuous.
    targets = [dst for _, dst in cfg["edges"]]
    assert any(targets.count(dst) > 1 for dst in set(targets)), "the loop back edge"


@pytest.mark.core
def test_unparseable_text_loses_only_the_function_it_cannot_recover() -> None:
    """A total front end: one broken body must not erase its neighbours.

    That is the ambiguity `tools/source_cfg_parity.py` exists to remove -- a
    provider returning nothing looks identical to one that lost every function.
    """
    text = "int good(void) { return 1; } int broken(void) { if ( ; }"
    assert "good" in parity_cfgs(text)


@pytest.mark.core
def test_synthetic_names_are_filtered_from_the_scored_set() -> None:
    assert glaurung._native.csource.is_scoreable_name("main")
    assert not glaurung._native.csource.is_scoreable_name("<global>")
    assert not glaurung._native.csource.is_scoreable_name("JUMPOUT")


@pytest.mark.core
def test_the_projection_is_deterministic() -> None:
    assert parity_cfgs(BRANCH_AND_LOOP) == parity_cfgs(BRANCH_AND_LOOP)


def test_graphs_carry_the_two_flags_the_metric_reads() -> None:
    _require_networkx()
    graphs = cfgs_from_decompiled(BRANCH_AND_LOOP)
    graph = graphs["classify"]
    nodes = list(graph.nodes)
    assert all(isinstance(node, SourceCfgNode) for node in nodes)
    assert sum(node.is_entrypoint for node in nodes) == 1
    assert sum(node.is_exitpoint for node in nodes) >= 1
    entry = next(node for node in nodes if node.is_entrypoint)
    assert graph.in_degree(entry) == 0, "nothing branches back into the entry block"


def test_the_graph_matches_the_serialized_form_node_for_node() -> None:
    """The adaptation is lossless: same node set, same edge set, same flags."""
    _require_networkx()
    serialized = parity_cfgs(BRANCH_AND_LOOP)["classify"]
    graph = cfgs_from_decompiled(BRANCH_AND_LOOP)["classify"]
    assert sorted(node.id for node in graph.nodes) == serialized["nodes"]
    assert sorted((u.id, v.id) for u, v in graph.edges) == sorted(
        tuple(edge) for edge in serialized["edges"]
    )
    assert sorted(n.id for n in graph.nodes if n.is_entrypoint) == serialized["entry"]
    assert sorted(n.id for n in graph.nodes if n.is_exitpoint) == serialized["exit"]


def test_isolated_blocks_survive_the_conversion() -> None:
    """A block named by no edge still reaches the graph.

    Deriving the node set from the edge list would drop it, shrinking the cost
    matrix `vj_ged` builds and cheapening the distance. The front end happens
    not to emit an unreachable block today (dead code is pruned before the
    projection), so the invariant is asserted against the serialized shape
    directly -- otherwise this test would pass no matter what the conversion
    did, which is how a regression gets through.
    """
    nx = _require_networkx()
    serialized = {
        "nodes": [0, 1, 2],
        "edges": [[0, 1]],
        "entry": [0],
        "exit": [1],
        "degenerate": False,
    }
    graph = graph_from_serialized(serialized)
    assert isinstance(graph, nx.DiGraph)
    assert sorted(node.id for node in graph.nodes) == [0, 1, 2]
    orphan = next(node for node in graph.nodes if node.id == 2)
    assert graph.in_degree(orphan) == 0 and graph.out_degree(orphan) == 0


def test_a_real_function_round_trips_through_the_serialized_form() -> None:
    """`cfgs_from_decompiled` is exactly `graph_from_serialized` per function."""
    _require_networkx()
    direct = cfgs_from_decompiled(BRANCH_AND_LOOP)["classify"]
    staged = graph_from_serialized(parity_cfgs(BRANCH_AND_LOOP)["classify"])
    assert sorted(n.id for n in direct.nodes) == sorted(n.id for n in staged.nodes)
    assert sorted((u.id, v.id) for u, v in direct.edges) == sorted(
        (u.id, v.id) for u, v in staged.edges
    )


def test_two_conversions_agree_on_every_input_the_metric_reads() -> None:
    """Everything `vj_ged` looks at is stable across conversions.

    The metric reads in-degree, out-degree and the two role flags, and nothing
    else; if all four agree per block then a self-comparison costs zero, which
    is the floor the parity harness measures against. Checked directly so the
    test needs no DecBench checkout.
    """
    _require_networkx()
    graph = cfgs_from_decompiled(BRANCH_AND_LOOP)["classify"]
    other = cfgs_from_decompiled(BRANCH_AND_LOOP)["classify"]
    by_id = {node.id: node for node in other.nodes}
    assert set(by_id) == {node.id for node in graph.nodes}
    for node in graph.nodes:
        twin = by_id[node.id]
        assert graph.in_degree(node) == other.in_degree(twin)
        assert graph.out_degree(node) == other.out_degree(twin)
        assert (node.is_entrypoint, node.is_exitpoint) == (
            twin.is_entrypoint,
            twin.is_exitpoint,
        )
