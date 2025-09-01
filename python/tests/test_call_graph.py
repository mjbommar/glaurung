"""Tests for CallGraph type."""

import pytest
from glaurung import (
    Address,
    AddressKind,
    CallGraph,
    CallGraphEdge,
    CallType,
    CallGraphStats,
)


class TestCallGraph:
    """Test CallGraph functionality."""

    def test_call_graph_creation(self):
        """Test creating a new call graph."""
        cg = CallGraph()
        assert cg.is_empty()
        assert cg.function_count() == 0
        assert cg.edge_count() == 0

    def test_add_functions_and_edges(self):
        """Test adding functions and call edges."""
        cg = CallGraph()

        # Add functions
        cg.add_node("main")
        cg.add_node("func1")
        cg.add_node("func2")

        assert cg.function_count() == 3
        assert cg.nodes == ["main", "func1", "func2"]

        # Add call edges
        cg.add_simple_edge("main", "func1", CallType.Direct)
        cg.add_simple_edge("main", "func2", CallType.Direct)
        cg.add_simple_edge("func1", "func2", CallType.Indirect)

        assert cg.edge_count() == 3

    def test_callers_and_callees(self):
        """Test getting callers and callees."""
        cg = CallGraph()

        cg.add_node("caller1")
        cg.add_node("caller2")
        cg.add_node("callee")

        cg.add_simple_edge("caller1", "callee", CallType.Direct)
        cg.add_simple_edge("caller2", "callee", CallType.Direct)

        assert cg.callees("caller1") == ["callee"]
        assert cg.callers("callee") == ["caller1", "caller2"]
        assert cg.callees("callee") == []

    def test_root_and_leaf_functions(self):
        """Test identifying root and leaf functions."""
        cg = CallGraph()

        cg.add_node("main")
        cg.add_node("lib_func")
        cg.add_node("user_func")
        cg.add_node("helper")

        cg.add_simple_edge("main", "user_func", CallType.Direct)
        cg.add_simple_edge("user_func", "helper", CallType.Direct)
        cg.add_simple_edge("user_func", "lib_func", CallType.Direct)

        assert cg.root_functions() == ["main"]
        assert cg.leaf_functions() == ["lib_func", "helper"]

    def test_has_cycles(self):
        """Test cycle detection in call graphs."""
        cg = CallGraph()

        cg.add_node("a")
        cg.add_node("b")
        cg.add_node("c")

        cg.add_simple_edge("a", "b", CallType.Direct)
        cg.add_simple_edge("b", "c", CallType.Direct)
        cg.add_simple_edge("c", "a", CallType.Direct)  # Creates cycle

        assert cg.has_cycles()

        # Remove cycle
        cg.remove_edge("c", "a", CallType.Direct)
        assert not cg.has_cycles()

    def test_call_depth(self):
        """Test calculating call depth."""
        cg = CallGraph()

        cg.add_node("main")
        cg.add_node("func1")
        cg.add_node("func2")
        cg.add_node("deep_func")

        cg.add_simple_edge("main", "func1", CallType.Direct)
        cg.add_simple_edge("main", "func2", CallType.Direct)
        cg.add_simple_edge("func1", "deep_func", CallType.Direct)

        assert cg.call_depth("main") == 0  # Root
        assert cg.call_depth("func1") == 1  # Called by main
        assert cg.call_depth("deep_func") == 2  # Called by func1

    def test_validation(self):
        """Test call graph validation."""
        cg = CallGraph()

        cg.add_node("valid")
        cg.add_edge(CallGraphEdge("valid", "valid", CallType.Direct))

        # Should validate successfully
        cg.validate()

        # Add invalid edge
        cg.add_edge(CallGraphEdge("valid", "invalid", CallType.Direct))

        with pytest.raises(ValueError):
            cg.validate()

    def test_statistics(self):
        """Test call graph statistics."""
        cg = CallGraph()

        cg.add_node("main")
        cg.add_node("func1")
        cg.add_node("func2")
        cg.add_node("func3")
        cg.add_node("helper")

        cg.add_simple_edge("main", "func1", CallType.Direct)
        cg.add_simple_edge("main", "func2", CallType.Direct)
        cg.add_simple_edge("func1", "helper", CallType.Direct)
        cg.add_simple_edge("func2", "helper", CallType.Direct)
        cg.add_simple_edge("func2", "func3", CallType.Direct)
        cg.add_simple_edge("helper", "func3", CallType.Direct)
        cg.add_simple_edge("func3", "func1", CallType.Direct)  # Creates cycle

        stats = cg.statistics()

        assert stats.function_count == 5
        assert stats.edge_count == 7
        assert stats.root_functions == 1
        assert stats.leaf_functions == 0  # cycle removes leaves
        assert stats.has_cycles
        assert stats.call_type_counts["Direct"] == 7
        assert stats.total_call_sites == 0  # No call sites specified
        assert stats.average_call_sites_per_edge == 0.0

    def test_subgraph(self):
        """Test creating subgraphs."""
        cg = CallGraph()

        cg.add_node("main")
        cg.add_node("func1")
        cg.add_node("func2")
        cg.add_node("func3")

        cg.add_simple_edge("main", "func1", CallType.Direct)
        cg.add_simple_edge("main", "func2", CallType.Direct)
        cg.add_simple_edge("func1", "func3", CallType.Direct)
        cg.add_simple_edge("func2", "func3", CallType.Direct)

        subgraph = cg.subgraph(["main", "func1", "func3"])

        assert subgraph.function_count() == 3
        assert subgraph.edge_count() == 2  # main->func1, func1->func3

    def test_edge_with_call_sites(self):
        """Test edges with call sites."""
        addr1 = Address(AddressKind.VA, 0x401000, 32)
        addr2 = Address(AddressKind.VA, 0x401010, 32)

        edge = CallGraphEdge.with_call_sites(
            "caller", "callee", CallType.Direct, [addr1, addr2]
        )

        assert edge.caller == "caller"
        assert edge.callee == "callee"
        assert len(edge.call_sites) == 2
        assert edge.call_sites[0] == addr1
        assert edge.call_sites[1] == addr2

    def test_edge_with_confidence(self):
        """Test edges with confidence scores."""
        edge = CallGraphEdge("caller", "callee", CallType.Direct)
        edge.confidence = 0.85

        assert edge.confidence == pytest.approx(0.85, rel=1e-6)

    def test_call_types(self):
        """Test different call types."""
        types = [
            CallType.Direct,
            CallType.Indirect,
            CallType.Virtual,
            CallType.Tail,
        ]

        for call_type in types:
            assert isinstance(call_type.value(), str)
            assert len(call_type.value()) > 0


class TestCallGraphEdge:
    """Test CallGraphEdge functionality."""

    def test_edge_creation(self):
        """Test creating call graph edges."""
        edge = CallGraphEdge("caller", "callee", CallType.Direct)
        assert edge.caller == "caller"
        assert edge.callee == "callee"
        assert edge.call_type == CallType.Direct
        assert edge.call_sites == []
        assert edge.confidence is None

    def test_edge_with_call_sites(self):
        """Test edge with call sites."""
        addr = Address(AddressKind.VA, 0x401000, 32)
        edge = CallGraphEdge.with_call_sites(
            "caller", "callee", CallType.Direct, [addr]
        )

        assert len(edge.call_sites) == 1
        assert edge.call_sites[0] == addr

    def test_add_remove_call_sites(self):
        """Test adding and removing call sites."""
        edge = CallGraphEdge("caller", "callee", CallType.Direct)
        addr1 = Address(AddressKind.VA, 0x401000, 32)
        addr2 = Address(AddressKind.VA, 0x401010, 32)

        edge.add_call_site(addr1)
        edge.add_call_site(addr2)

        assert len(edge.call_sites) == 2

        edge.remove_call_site(addr1)
        assert len(edge.call_sites) == 1
        assert edge.call_sites[0] == addr2

    def test_edge_string_representation(self):
        """Test edge string representation."""
        edge = CallGraphEdge("func1", "func2", CallType.Direct)
        assert "func1 -> func2" in str(edge)
        assert "direct" in str(edge)


class TestCallGraphStats:
    """Test CallGraphStats functionality."""

    def test_stats_creation(self):
        """Test creating call graph statistics."""
        stats = CallGraphStats(
            function_count=4,
            edge_count=5,
            root_functions=1,
            leaf_functions=2,
            has_cycles=False,
            call_type_counts={},
            total_call_sites=3,
            average_call_sites_per_edge=0.6,
        )

        assert stats.function_count == 4
        assert stats.edge_count == 5
        assert stats.root_functions == 1
        assert stats.leaf_functions == 2
        assert not stats.has_cycles
        assert stats.total_call_sites == 3
        assert stats.average_call_sites_per_edge == 0.6

    def test_stats_string_representation(self):
        """Test stats string representation."""
        stats = CallGraphStats(
            function_count=3,
            edge_count=4,
            root_functions=1,
            leaf_functions=1,
            has_cycles=True,
            call_type_counts={},
            total_call_sites=2,
            average_call_sites_per_edge=0.5,
        )

        assert "functions=3" in str(stats)
        assert "edges=4" in str(stats)
        assert "roots=1" in str(stats)
        assert "leaves=1" in str(stats)
        assert "cycles=true" in str(stats)
