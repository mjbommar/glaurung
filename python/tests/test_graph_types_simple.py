"""Simple tests to verify graph types are exposed to Python."""

import glaurung


def test_control_flow_graph_types_exist():
    """Test that ControlFlowGraph types are exposed."""
    # Enums
    assert hasattr(glaurung, "ControlFlowEdgeKind")
    assert glaurung.ControlFlowEdgeKind.Fallthrough
    assert glaurung.ControlFlowEdgeKind.Branch
    assert glaurung.ControlFlowEdgeKind.Call
    assert glaurung.ControlFlowEdgeKind.Return

    # Classes
    assert hasattr(glaurung, "ControlFlowEdge")
    assert hasattr(glaurung, "ControlFlowGraph")
    assert hasattr(glaurung, "ControlFlowGraphStats")

    # Create basic instances
    cfg = glaurung.ControlFlowGraph()
    assert cfg is not None
    assert cfg.block_count() == 0
    assert cfg.edge_count() == 0


def test_call_graph_types_exist():
    """Test that CallGraph types are exposed."""
    # Enums
    assert hasattr(glaurung, "CallType")
    assert glaurung.CallType.Direct
    assert glaurung.CallType.Indirect
    assert glaurung.CallType.Tail
    assert glaurung.CallType.Virtual

    # Classes
    assert hasattr(glaurung, "CallGraphEdge")
    assert hasattr(glaurung, "CallGraph")
    assert hasattr(glaurung, "CallGraphStats")

    # Create basic instance
    cg = glaurung.CallGraph()
    assert cg is not None
    assert cg.function_count() == 0
    assert cg.edge_count() == 0


def test_function_types_exist():
    """Test that Function types are exposed."""
    # Enums
    assert hasattr(glaurung, "FunctionKind")
    assert glaurung.FunctionKind.Normal
    assert glaurung.FunctionKind.Imported
    assert glaurung.FunctionKind.Exported
    assert glaurung.FunctionKind.Thunk
    assert glaurung.FunctionKind.Library
    assert glaurung.FunctionKind.Unknown

    # Classes
    assert hasattr(glaurung, "Function")
    assert hasattr(glaurung, "FunctionFlags")

    # Test flags
    assert glaurung.FunctionFlags.NONE == 0
    assert glaurung.FunctionFlags.NO_RETURN == 1
    assert glaurung.FunctionFlags.HAS_SEH == 2

    # Create basic instance
    addr = glaurung.Address(glaurung.AddressKind.VA, 0x401000, 64)
    func = glaurung.Function("test", addr, glaurung.FunctionKind.Normal)
    assert func.name == "test"
    assert func.entry_point.value == 0x401000


def test_reference_types_exist():
    """Test that Reference types are exposed."""
    # Enums
    assert hasattr(glaurung, "ReferenceKind")
    assert glaurung.ReferenceKind.Call
    assert glaurung.ReferenceKind.Jump
    assert glaurung.ReferenceKind.Branch
    assert glaurung.ReferenceKind.Return
    assert glaurung.ReferenceKind.Read
    assert glaurung.ReferenceKind.Write

    assert hasattr(glaurung, "UnresolvedReferenceKind")
    assert glaurung.UnresolvedReferenceKind.Dynamic
    assert glaurung.UnresolvedReferenceKind.Indirect
    assert glaurung.UnresolvedReferenceKind.External
    assert glaurung.UnresolvedReferenceKind.Unknown

    # Classes
    assert hasattr(glaurung, "ReferenceTarget")
    assert hasattr(glaurung, "Reference")

    # ReferenceTarget enum variants
    assert hasattr(glaurung.ReferenceTarget, "Resolved")
    assert hasattr(glaurung.ReferenceTarget, "Unresolved")


def test_control_flow_graph_basic_operations():
    """Test basic CFG operations that are available."""
    cfg = glaurung.ControlFlowGraph("test_func")
    assert cfg.function_id == "test_func"

    # Add blocks
    cfg.add_block("entry")
    cfg.add_block("exit")
    assert cfg.block_count() == 2

    # Add edge
    cfg.add_simple_edge("entry", "exit", glaurung.ControlFlowEdgeKind.Fallthrough)
    assert cfg.edge_count() == 1

    # Check properties
    assert not cfg.is_empty()
    assert not cfg.has_cycles()


def test_call_graph_basic_operations():
    """Test basic CallGraph operations that are available."""
    cg = glaurung.CallGraph()

    # Add nodes
    cg.add_node("main")
    cg.add_node("helper")
    assert cg.function_count() == 2

    # Note: Adding edges requires proper call site format
    # which may be a list or other structure


def test_function_serialization():
    """Test that Function can be serialized."""
    addr = glaurung.Address(glaurung.AddressKind.VA, 0x401000, 64)
    func = glaurung.Function("test_func", addr, glaurung.FunctionKind.Normal)

    # Test JSON serialization
    json_str = func.to_json()
    assert json_str is not None
    assert "test_func" in json_str

    # Test deserialization
    func2 = glaurung.Function.from_json(json_str)
    assert func2.name == func.name
