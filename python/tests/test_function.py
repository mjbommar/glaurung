"""Tests for Function and related types."""

import json
import glaurung


def test_function_kind():
    """Test FunctionKind enum."""
    assert hasattr(glaurung, "FunctionKind")

    # Test enum values
    assert glaurung.FunctionKind.Normal
    assert glaurung.FunctionKind.Imported
    assert glaurung.FunctionKind.Exported
    assert glaurung.FunctionKind.Thunk
    assert glaurung.FunctionKind.Library
    assert glaurung.FunctionKind.Unknown

    # Test value property
    func_kind = glaurung.FunctionKind.Imported
    assert func_kind.value == "imported"

    # Test equality
    assert glaurung.FunctionKind.Normal == glaurung.FunctionKind.Normal
    assert glaurung.FunctionKind.Normal != glaurung.FunctionKind.Imported


def test_function_flags():
    """Test FunctionFlags constants."""
    assert hasattr(glaurung, "FunctionFlags")

    # Test flag constants
    assert glaurung.FunctionFlags.NONE == 0
    assert glaurung.FunctionFlags.NO_RETURN == 1
    assert glaurung.FunctionFlags.HAS_SEH == 2
    assert glaurung.FunctionFlags.HAS_EH == 4
    assert glaurung.FunctionFlags.IS_VARIADIC == 8
    assert glaurung.FunctionFlags.IS_INLINE == 16
    assert glaurung.FunctionFlags.IS_NAKED == 32
    assert glaurung.FunctionFlags.IS_CONSTRUCTOR == 64
    assert glaurung.FunctionFlags.IS_DESTRUCTOR == 128

    # Test combining flags
    combined = glaurung.FunctionFlags.NO_RETURN | glaurung.FunctionFlags.IS_INLINE
    assert combined == 17  # 1 | 16


def test_function_basic():
    """Test basic Function creation."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x401000, 64)

    # Minimal function
    func = glaurung.Function("main", entry, glaurung.FunctionKind.Normal)
    assert func.name == "main"
    assert func.entry_point.value == 0x401000
    assert func.kind == glaurung.FunctionKind.Normal
    assert func.range is None
    assert func.flags == glaurung.FunctionFlags.NONE
    assert func.module is None
    assert func.ordinal is None


def test_function_with_range():
    """Test Function with address range."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x401000, 64)
    func_range = glaurung.AddressRange(entry, 0x100)

    func = glaurung.Function(
        "process_data", entry, glaurung.FunctionKind.Normal, range=func_range
    )
    assert func.name == "process_data"
    assert func.range is not None
    assert func.size == 0x100


def test_function_imported():
    """Test imported function."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x402000, 64)

    func = glaurung.Function(
        "MessageBoxA",
        entry,
        glaurung.FunctionKind.Imported,
        module="user32.dll",
        ordinal=283,
    )
    assert func.name == "MessageBoxA"
    assert func.kind == glaurung.FunctionKind.Imported
    assert func.module == "user32.dll"
    assert func.ordinal == 283


def test_function_with_flags():
    """Test Function with various flags."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x403000, 64)

    # Function that doesn't return
    flags = glaurung.FunctionFlags.NO_RETURN | glaurung.FunctionFlags.IS_NAKED
    func = glaurung.Function(
        "exit_handler", entry, glaurung.FunctionKind.Normal, flags=flags
    )
    assert func.flags == 33  # 1 | 32
    assert func.has_flag(glaurung.FunctionFlags.NO_RETURN)
    assert func.has_flag(glaurung.FunctionFlags.IS_NAKED)
    assert not func.has_flag(glaurung.FunctionFlags.IS_INLINE)


def test_function_thunk():
    """Test thunk function."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x404000, 64)
    target = glaurung.Address(glaurung.AddressKind.VA, 0x405000, 64)

    func = glaurung.Function(
        "_malloc", entry, glaurung.FunctionKind.Thunk, thunk_target=target
    )
    assert func.name == "_malloc"
    assert func.kind == glaurung.FunctionKind.Thunk
    assert func.thunk_target is not None
    assert func.thunk_target.value == 0x405000


def test_function_with_metadata():
    """Test Function with various metadata."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x406000, 64)

    func = glaurung.Function(
        "complex_function",
        entry,
        glaurung.FunctionKind.Exported,
        calling_convention="stdcall",
        signature="int complex_function(int, char*)",
        stack_frame_size=0x40,
        local_vars_size=0x20,
        saved_regs_size=0x10,
        max_call_depth=5,
    )
    assert func.calling_convention == "stdcall"
    assert func.signature == "int complex_function(int, char*)"
    assert func.stack_frame_size == 0x40
    assert func.local_vars_size == 0x20
    assert func.saved_regs_size == 0x10
    assert func.max_call_depth == 5


def test_function_serialization():
    """Test Function JSON serialization."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x407000, 64)
    func_range = glaurung.AddressRange(entry, 0x200)

    func = glaurung.Function(
        "serialize_test",
        entry,
        glaurung.FunctionKind.Exported,
        range=func_range,
        flags=glaurung.FunctionFlags.IS_CONSTRUCTOR,
        module="test.dll",
    )

    # Serialize to JSON
    json_str = func.to_json()
    data = json.loads(json_str)

    assert data["name"] == "serialize_test"
    assert data["kind"] == "Exported"
    assert data["module"] == "test.dll"

    # Deserialize from JSON
    func2 = glaurung.Function.from_json(json_str)
    assert func2.name == func.name
    assert func2.kind == func.kind
    assert func2.module == func.module


def test_function_equality():
    """Test Function equality comparison."""
    entry1 = glaurung.Address(glaurung.AddressKind.VA, 0x408000, 64)
    entry2 = glaurung.Address(glaurung.AddressKind.VA, 0x409000, 64)

    func1 = glaurung.Function("test", entry1, glaurung.FunctionKind.Normal)
    func2 = glaurung.Function("test", entry1, glaurung.FunctionKind.Normal)
    func3 = glaurung.Function("test", entry2, glaurung.FunctionKind.Normal)

    assert func1 == func2
    assert func1 != func3
    assert hash(func1) == hash(func2)
    assert hash(func1) != hash(func3)


def test_function_str_repr():
    """Test Function string representations."""
    entry = glaurung.Address(glaurung.AddressKind.VA, 0x40A000, 64)

    func = glaurung.Function("display_func", entry, glaurung.FunctionKind.Library)

    str_repr = str(func)
    assert "display_func" in str_repr
    assert "0x40a000" in str_repr.lower() or "0x40A000" in str_repr

    repr_str = repr(func)
    assert "Function" in repr_str
    assert "display_func" in repr_str
