"""Glaurung's C source CFGs, adapted to what DecBench's GED metric reads.

`decbench.metrics.vj_ged.vj_ged` compares two `networkx.DiGraph` objects using
only ``list(g.nodes)``, ``g.in_degree(n)``, ``g.out_degree(n)`` and each node's
``is_entrypoint`` / ``is_exitpoint`` attributes. Nothing else about a node
reaches the distance -- no statements, no types, no labels. So the adaptation
from :func:`glaurung._native.csource.parity_cfgs` is purely mechanical, and the
node class below carries exactly those two flags and an identity.

`networkx` is imported inside the function rather than at module scope: it is a
DecBench dependency, not a Glaurung one, and `glaurung/__init__.py` imports this
module so that ``glaurung.source_cfg`` resolves without a separate import. A
module-level import would make the whole package unimportable wherever the graph
library is absent.

Entry point for `tools/source_cfg_parity.py --provider glaurung`; the plan it
gates is `docs/design/static-c-analysis/parity-plan.md`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from glaurung import _native

if TYPE_CHECKING:  # pragma: no cover - typing only
    import networkx

__all__ = [
    "SourceCfgNode",
    "cfgs_from_decompiled",
    "graph_from_serialized",
    "parity_cfgs",
]


class SourceCfgNode:
    """A CFG basic block reduced to the two role flags GED inspects.

    Identity is the block id, so two nodes of the same graph are distinct
    dictionary keys and `networkx` keeps them apart. The shape deliberately
    mirrors `decbench.publish.cfg_export.CfgNode`, which is what the published
    side of every comparison is rebuilt from.

    Attributes:
        id: Dense block id, ``0..n-1`` within its function.
        is_entrypoint: Whether the block is the function's entry.
        is_exitpoint: Whether the block leaves the function.
    """

    __slots__ = ("id", "is_entrypoint", "is_exitpoint")

    def __init__(
        self, id: int, is_entrypoint: bool = False, is_exitpoint: bool = False
    ) -> None:
        """Build a node.

        Args:
            id: Dense block id within the function.
            is_entrypoint: Whether the block is the function's entry.
            is_exitpoint: Whether the block leaves the function.
        """
        self.id = id
        self.is_entrypoint = is_entrypoint
        self.is_exitpoint = is_exitpoint

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SourceCfgNode) and other.id == self.id

    def __repr__(self) -> str:
        return f"n{self.id}"


def parity_cfgs(text: str) -> dict[str, dict[str, Any]]:
    """Raw per-function CFGs for one translation unit of C.

    Args:
        text: C source text, typically a decompiler's whole output file.

    Returns:
        ``{function name: {"nodes", "edges", "entry", "exit", "degenerate"}}``,
        the serialized shape DecBench stores its published source CFGs in.
    """
    return _native.csource.parity_cfgs(text)


def graph_from_serialized(cfg: dict[str, Any]) -> networkx.DiGraph:
    """Build one GED-ready graph from a serialized CFG.

    The mirror of `decbench.publish.cfg_export.rebuild_cfg`, which does this for
    the published side of every comparison. ``degenerate`` is read but not
    represented: it drives DecBench's offline translation-unit resolution, and
    `vj_ged` never sees it.

    Args:
        cfg: One function's ``{"nodes", "edges", "entry", "exit", "degenerate"}``
            mapping, as :func:`parity_cfgs` returns it.

    Returns:
        A `networkx.DiGraph` over :class:`SourceCfgNode`.

    Raises:
        ImportError: If `networkx` is not installed in the running environment.
        KeyError: If an edge names a node the ``nodes`` list does not declare.
    """
    import networkx as nx

    entries = set(cfg["entry"])
    exits = set(cfg["exit"])
    by_id = {
        node_id: SourceCfgNode(node_id, node_id in entries, node_id in exits)
        for node_id in cfg["nodes"]
    }
    graph: networkx.DiGraph = nx.DiGraph()
    # Add nodes first: a block with no edges still occupies a row of the cost
    # matrix `vj_ged` builds, and inferring nodes from the edge list alone would
    # silently drop it -- shrinking the matrix and cheapening the distance.
    graph.add_nodes_from(by_id.values())
    for src, dst in cfg["edges"]:
        graph.add_edge(by_id[src], by_id[dst])
    return graph


def cfgs_from_decompiled(text: str) -> dict[str, networkx.DiGraph]:
    """GED-ready CFGs for every scoreable function in decompiled C.

    This is the provider entry point `tools/source_cfg_parity.py` resolves.

    Args:
        text: Decompiled C source text. May be partly unparseable; the front end
            is total, so the functions it did recover are still returned.

    Returns:
        ``{function name: DiGraph}`` whose nodes are :class:`SourceCfgNode`.

    Raises:
        ImportError: If `networkx` is not installed in the running environment.
    """
    return {name: graph_from_serialized(cfg) for name, cfg in parity_cfgs(text).items()}
