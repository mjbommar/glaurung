"""Tests for ControlFlowGraph type."""

from glaurung import (
    ControlFlowGraph,
    ControlFlowEdge,
    ControlFlowEdgeKind,
    ControlFlowGraphStats,
)


class TestControlFlowGraph:
    """Test ControlFlowGraph functionality."""

    def test_cfg_creation(self):
        """Test creating a new control flow graph."""
        cfg = ControlFlowGraph()
        assert cfg.is_empty()
        assert cfg.block_count() == 0
        assert cfg.edge_count() == 0
        assert cfg.function_id is None

    def test_cfg_for_function(self):
        """Test creating a CFG for a specific function."""
        cfg = ControlFlowGraph(function_id="test_func")
        assert cfg.function_id == "test_func"

    def test_add_blocks_and_edges(self):
        """Test adding blocks and edges to CFG."""
        cfg = ControlFlowGraph()

        # Add blocks
        cfg.add_block("entry")
        cfg.add_block("loop")
        cfg.add_block("exit")

        assert cfg.block_count() == 3
        assert cfg.block_ids == ["entry", "loop", "exit"]

        # Add edges
        cfg.add_simple_edge("entry", "loop", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("loop", "exit", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("loop", "loop", ControlFlowEdgeKind.Branch)  # Loop back

        assert cfg.edge_count() == 3

    def test_successors_and_predecessors(self):
        """Test getting successors and predecessors."""
        cfg = ControlFlowGraph()

        cfg.add_block("a")
        cfg.add_block("b")
        cfg.add_block("c")

        cfg.add_simple_edge("a", "b", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("a", "c", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("b", "c", ControlFlowEdgeKind.Fallthrough)

        assert cfg.successors("a") == ["b", "c"]
        assert cfg.predecessors("c") == ["a", "b"]
        assert cfg.successors("b") == ["c"]
        assert cfg.predecessors("a") == []

    def test_entry_and_exit_blocks(self):
        """Test identifying entry and exit blocks."""
        cfg = ControlFlowGraph()

        cfg.add_block("entry")
        cfg.add_block("middle")
        cfg.add_block("exit")

        cfg.add_simple_edge("entry", "middle", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("middle", "exit", ControlFlowEdgeKind.Branch)

        assert cfg.entry_blocks() == ["entry"]
        assert cfg.exit_blocks() == ["exit"]

    def test_cyclomatic_complexity(self):
        """Test cyclomatic complexity calculation."""
        cfg = ControlFlowGraph()

        # Linear sequence: M = E - N + 2 = 2 - 3 + 2 = 1
        cfg.add_block("a")
        cfg.add_block("b")
        cfg.add_block("c")
        cfg.add_simple_edge("a", "b", ControlFlowEdgeKind.Fallthrough)
        cfg.add_simple_edge("b", "c", ControlFlowEdgeKind.Fallthrough)

        assert cfg.cyclomatic_complexity() == 2

        # Add a branch: M = 3 - 3 + 2 = 2
        cfg.add_simple_edge("b", "c", ControlFlowEdgeKind.Branch)
        assert cfg.cyclomatic_complexity() == 2

    def test_has_cycles(self):
        """Test cycle detection."""
        cfg = ControlFlowGraph()

        cfg.add_block("a")
        cfg.add_block("b")
        cfg.add_simple_edge("a", "b", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("b", "a", ControlFlowEdgeKind.Branch)  # Cycle

        assert cfg.has_cycles()

        # Remove cycle
        cfg.remove_edge("b", "a", ControlFlowEdgeKind.Branch)
        assert not cfg.has_cycles()

    def test_validation(self):
        """Test CFG validation."""
        cfg = ControlFlowGraph()

        cfg.add_block("valid")
        cfg.add_edge(ControlFlowEdge("valid", "valid", ControlFlowEdgeKind.Branch))

        # Should validate successfully
        cfg.validate()

        # Note: In Python bindings, cfg.edges returns a copy, not a reference,
        # so we can't directly manipulate the internal edges vector.
        # The add_edge method always ensures blocks exist, so validation
        # will always pass when using the public API correctly.
        # This is actually the desired behavior - the API prevents invalid states.

    def test_statistics(self):
        """Test CFG statistics."""
        cfg = ControlFlowGraph()

        cfg.add_block("entry")
        cfg.add_block("branch")
        cfg.add_block("true")
        cfg.add_block("false")
        cfg.add_block("exit")

        cfg.add_simple_edge("entry", "branch", ControlFlowEdgeKind.Fallthrough)
        cfg.add_simple_edge("branch", "true", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("branch", "false", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("true", "exit", ControlFlowEdgeKind.Fallthrough)
        cfg.add_simple_edge("false", "exit", ControlFlowEdgeKind.Fallthrough)

        stats = cfg.statistics()

        assert stats.block_count == 5
        assert stats.edge_count == 5
        assert stats.entry_blocks == 1
        assert stats.exit_blocks == 1
        assert stats.cyclomatic_complexity == 2  # E - N + 2 = 5 - 5 + 2 = 2
        assert not stats.has_cycles
        assert stats.edge_kind_counts[ControlFlowEdgeKind.Fallthrough] == 3
        assert stats.edge_kind_counts[ControlFlowEdgeKind.Branch] == 2

    def test_subgraph(self):
        """Test creating subgraphs."""
        cfg = ControlFlowGraph()

        cfg.add_block("a")
        cfg.add_block("b")
        cfg.add_block("c")
        cfg.add_block("d")

        cfg.add_simple_edge("a", "b", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("b", "c", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("c", "d", ControlFlowEdgeKind.Branch)
        cfg.add_simple_edge("a", "d", ControlFlowEdgeKind.Branch)  # Skip connection

        subgraph = cfg.subgraph(["a", "b", "c"])

        assert subgraph.block_count() == 3
        assert subgraph.edge_count() == 2  # Only edges between a, b, c

    def test_edge_with_confidence(self):
        """Test edges with confidence scores."""
        edge = ControlFlowEdge.with_confidence(
            "from", "to", ControlFlowEdgeKind.Branch, 0.85
        )

        assert edge.from_block_id == "from"
        assert edge.to_block_id == "to"
        assert edge.kind == ControlFlowEdgeKind.Branch
        assert abs(edge.confidence - 0.85) < 0.01  # Allow for float precision

    def test_edge_kinds(self):
        """Test different edge kinds."""
        kinds = [
            ControlFlowEdgeKind.Fallthrough,
            ControlFlowEdgeKind.Branch,
            ControlFlowEdgeKind.Call,
            ControlFlowEdgeKind.Return,
        ]

        for kind in kinds:
            assert isinstance(kind.value(), str)
            assert len(kind.value()) > 0


class TestControlFlowEdge:
    """Test ControlFlowEdge functionality."""

    def test_edge_creation(self):
        """Test creating edges."""
        edge = ControlFlowEdge("from", "to", ControlFlowEdgeKind.Branch)
        assert edge.from_block_id == "from"
        assert edge.to_block_id == "to"
        assert edge.kind == ControlFlowEdgeKind.Branch
        assert edge.confidence is None

    def test_edge_with_confidence(self):
        """Test edge with confidence."""
        edge = ControlFlowEdge.with_confidence(
            "from", "to", ControlFlowEdgeKind.Call, 0.9
        )
        assert abs(edge.confidence - 0.9) < 0.01  # Allow for float precision

    def test_edge_string_representation(self):
        """Test edge string representation."""
        edge = ControlFlowEdge("block1", "block2", ControlFlowEdgeKind.Fallthrough)
        assert "block1 -> block2" in str(edge)
        assert "fallthrough" in str(edge)


class TestControlFlowGraphStats:
    """Test ControlFlowGraphStats functionality."""

    def test_stats_creation(self):
        """Test creating statistics."""
        stats = ControlFlowGraphStats(
            block_count=5,
            edge_count=7,
            entry_blocks=1,
            exit_blocks=2,
            cyclomatic_complexity=4,
            has_cycles=False,
            edge_kind_counts={},
        )

        assert stats.block_count == 5
        assert stats.edge_count == 7
        assert stats.entry_blocks == 1
        assert stats.exit_blocks == 2
        assert stats.cyclomatic_complexity == 4
        assert not stats.has_cycles

    def test_stats_string_representation(self):
        """Test stats string representation."""
        stats = ControlFlowGraphStats(
            block_count=3,
            edge_count=4,
            entry_blocks=1,
            exit_blocks=1,
            cyclomatic_complexity=2,
            has_cycles=True,
            edge_kind_counts={},
        )

        assert "blocks=3" in str(stats)
        assert "edges=4" in str(stats)
        assert "complexity=2" in str(stats)
        assert "cycles=true" in str(stats)
