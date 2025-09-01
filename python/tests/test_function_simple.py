"""Simple test to verify Function type is now implemented."""


def test_function_is_implemented():
    """Test that Function is now available."""
    from glaurung import Function, FunctionKind, Address, AddressKind

    # Function should be importable and usable
    entry = Address(AddressKind.VA, 0x401000, bits=32)
    func = Function(
        name="test_func",
        entry_point=entry,
        kind=FunctionKind.Normal,
    )
    assert func.name == "test_func"
    assert func.entry_point == entry
    assert func.kind == FunctionKind.Normal
