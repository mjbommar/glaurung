"""Tests for Function type - represents a function in binary analysis."""

import pytest
from glaurung import (
    Address,
    AddressKind,
    AddressRange,
    BasicBlock,
    Function,
    FunctionKind,
    FunctionFlags,
)


class TestFunctionCreation:
    """Test Function creation and validation."""

    def test_create_basic_function(self):
        """Test creating a basic function."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="main",
            entry_point=entry,
            kind=FunctionKind.Normal,
        )
        assert func.name == "main"
        assert func.entry_point == entry
        assert func.kind == FunctionKind.Normal
        assert func.size is None
        assert func.flags == FunctionFlags.NONE

    def test_create_function_with_range(self):
        """Test creating a function with address range."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        range_ = AddressRange(entry, 0x100)
        func = Function(
            name="process_data",
            entry_point=entry,
            range=range_,
            kind=FunctionKind.Normal,
        )
        assert func.name == "process_data"
        assert func.entry_point == entry
        assert func.range == range_
        assert func.size == 0x100

    def test_create_imported_function(self):
        """Test creating an imported function."""
        entry = Address(AddressKind.VA, 0x402000, bits=32)
        func = Function(
            name="CreateFileW",
            entry_point=entry,
            kind=FunctionKind.Imported,
            module="kernel32.dll",
        )
        assert func.name == "CreateFileW"
        assert func.kind == FunctionKind.Imported
        assert func.module == "kernel32.dll"

    def test_create_exported_function(self):
        """Test creating an exported function."""
        entry = Address(AddressKind.VA, 0x403000, bits=32)
        func = Function(
            name="DllMain",
            entry_point=entry,
            kind=FunctionKind.Exported,
            ordinal=1,
        )
        assert func.name == "DllMain"
        assert func.kind == FunctionKind.Exported
        assert func.ordinal == 1

    def test_create_thunk_function(self):
        """Test creating a thunk function."""
        entry = Address(AddressKind.VA, 0x404000, bits=32)
        target = Address(AddressKind.VA, 0x500000, bits=32)
        func = Function(
            name="malloc_thunk",
            entry_point=entry,
            kind=FunctionKind.Thunk,
            thunk_target=target,
        )
        assert func.name == "malloc_thunk"
        assert func.kind == FunctionKind.Thunk
        assert func.thunk_target == target

    def test_invalid_thunk_without_target(self):
        """Test that thunk functions require a target."""
        entry = Address(AddressKind.VA, 0x404000, bits=32)
        with pytest.raises(ValueError, match="Thunk functions must have a target"):
            Function(
                name="bad_thunk",
                entry_point=entry,
                kind=FunctionKind.Thunk,
            )

    def test_function_with_basic_blocks(self):
        """Test adding basic blocks to a function."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="complex_func",
            entry_point=entry,
            kind=FunctionKind.Normal,
        )

        # Add basic blocks
        bb1 = BasicBlock(
            "bb1",
            Address(AddressKind.VA, 0x401000, bits=32),
            Address(AddressKind.VA, 0x401010, bits=32),
            5,  # instruction count
        )
        bb2 = BasicBlock(
            "bb2",
            Address(AddressKind.VA, 0x401010, bits=32),
            Address(AddressKind.VA, 0x401030, bits=32),
            8,  # instruction count
        )
        bb3 = BasicBlock(
            "bb3",
            Address(AddressKind.VA, 0x401030, bits=32),
            Address(AddressKind.VA, 0x401045, bits=32),
            6,  # instruction count
        )

        func.add_basic_block(bb1)
        func.add_basic_block(bb2)
        func.add_basic_block(bb3)

        assert len(func.basic_blocks) == 3
        assert func.basic_blocks[0] == bb1
        assert func.basic_blocks[1] == bb2
        assert func.basic_blocks[2] == bb3

        # Function size should be calculated from blocks
        assert func.calculate_size() == 0x45

    def test_function_flags(self):
        """Test function flags."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="secure_func",
            entry_point=entry,
            kind=FunctionKind.Normal,
            flags=FunctionFlags.NO_RETURN | FunctionFlags.HAS_SEH,
        )
        assert func.has_flag(FunctionFlags.NO_RETURN)
        assert func.has_flag(FunctionFlags.HAS_SEH)
        assert not func.has_flag(FunctionFlags.IS_VARIADIC)

        # Add a flag
        func.add_flag(FunctionFlags.IS_VARIADIC)
        assert func.has_flag(FunctionFlags.IS_VARIADIC)

        # Remove a flag
        func.remove_flag(FunctionFlags.NO_RETURN)
        assert not func.has_flag(FunctionFlags.NO_RETURN)

    def test_function_calling_convention(self):
        """Test function calling conventions."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="api_func",
            entry_point=entry,
            kind=FunctionKind.Normal,
            calling_convention="stdcall",
        )
        assert func.calling_convention == "stdcall"

    def test_function_signature(self):
        """Test function signature."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="add",
            entry_point=entry,
            kind=FunctionKind.Normal,
            signature="int add(int a, int b)",
        )
        assert func.signature == "int add(int a, int b)"

    def test_function_callers_and_callees(self):
        """Test tracking function calls."""
        entry1 = Address(AddressKind.VA, 0x401000, bits=32)
        entry2 = Address(AddressKind.VA, 0x402000, bits=32)
        entry3 = Address(AddressKind.VA, 0x403000, bits=32)

        func = Function(
            name="middle_func",
            entry_point=entry2,
            kind=FunctionKind.Normal,
        )

        # Add callers and callees
        func.add_caller(entry1)
        func.add_callee(entry3)

        assert len(func.callers) == 1
        assert entry1 in func.callers
        assert len(func.callees) == 1
        assert entry3 in func.callees


class TestFunctionSerialization:
    """Test Function serialization/deserialization."""

    def test_json_serialization(self):
        """Test JSON serialization round-trip."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        range_ = AddressRange(entry, 0x100)
        func = Function(
            name="test_func",
            entry_point=entry,
            range=range_,
            kind=FunctionKind.Normal,
            flags=FunctionFlags.NO_RETURN | FunctionFlags.HAS_SEH,
            calling_convention="cdecl",
            signature="void test_func(int x)",
        )

        # Add some callers/callees
        func.add_caller(Address(AddressKind.VA, 0x400000, bits=32))
        func.add_callee(Address(AddressKind.VA, 0x402000, bits=32))

        # Serialize to JSON
        json_str = func.to_json()

        # Deserialize from JSON
        func2 = Function.from_json(json_str)

        assert func2.name == func.name
        assert func2.entry_point == func.entry_point
        assert func2.range == func.range
        assert func2.kind == func.kind
        assert func2.flags == func.flags
        assert func2.calling_convention == func.calling_convention
        assert func2.signature == func.signature
        assert func2.callers == func.callers
        assert func2.callees == func.callees

    def test_binary_serialization(self):
        """Test binary serialization round-trip."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="bin_func",
            entry_point=entry,
            kind=FunctionKind.Exported,
            ordinal=42,
        )

        # Serialize to binary
        bin_data = func.to_binary()

        # Deserialize from binary
        func2 = Function.from_binary(bin_data)

        assert func2.name == func.name
        assert func2.entry_point == func.entry_point
        assert func2.kind == func.kind
        assert func2.ordinal == func.ordinal


class TestFunctionKind:
    """Test FunctionKind enum."""

    def test_function_kinds(self):
        """Test all function kinds."""
        assert FunctionKind.Normal.value == "normal"
        assert FunctionKind.Imported.value == "imported"
        assert FunctionKind.Exported.value == "exported"
        assert FunctionKind.Thunk.value == "thunk"
        assert FunctionKind.Library.value == "library"
        assert FunctionKind.Unknown.value == "unknown"


class TestFunctionFlags:
    """Test FunctionFlags bitflags."""

    def test_function_flags(self):
        """Test function flag values and operations."""
        assert FunctionFlags.NONE == 0
        assert FunctionFlags.NO_RETURN == 1
        assert FunctionFlags.HAS_SEH == 2
        assert FunctionFlags.HAS_EH == 4
        assert FunctionFlags.IS_VARIADIC == 8
        assert FunctionFlags.IS_INLINE == 16
        assert FunctionFlags.IS_NAKED == 32
        assert FunctionFlags.IS_CONSTRUCTOR == 64
        assert FunctionFlags.IS_DESTRUCTOR == 128

        # Test bitwise operations
        flags = FunctionFlags.NO_RETURN | FunctionFlags.HAS_SEH
        assert flags & FunctionFlags.NO_RETURN
        assert flags & FunctionFlags.HAS_SEH
        assert not (flags & FunctionFlags.IS_VARIADIC)


class TestFunctionAnalysis:
    """Test function analysis features."""

    def test_function_complexity(self):
        """Test calculating cyclomatic complexity."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="complex_func",
            entry_point=entry,
            kind=FunctionKind.Normal,
        )

        # Add basic blocks with edges to create complexity
        bb1 = BasicBlock(
            "bb1",
            Address(AddressKind.VA, 0x401000, bits=32),
            Address(AddressKind.VA, 0x401010, bits=32),
            5,  # instruction count
        )
        bb2 = BasicBlock(
            "bb2",
            Address(AddressKind.VA, 0x401010, bits=32),
            Address(AddressKind.VA, 0x401030, bits=32),
            8,  # instruction count
        )
        bb3 = BasicBlock(
            "bb3",
            Address(AddressKind.VA, 0x401030, bits=32),
            Address(AddressKind.VA, 0x401045, bits=32),
            6,  # instruction count
        )
        bb4 = BasicBlock(
            "bb4",
            Address(AddressKind.VA, 0x401045, bits=32),
            Address(AddressKind.VA, 0x401055, bits=32),
            4,  # instruction count
        )

        func.add_basic_block(bb1)
        func.add_basic_block(bb2)
        func.add_basic_block(bb3)
        func.add_basic_block(bb4)

        # Add edges: bb1 -> bb2, bb1 -> bb3, bb2 -> bb4, bb3 -> bb4
        func.add_edge(bb1.start_address, bb2.start_address)
        func.add_edge(bb1.start_address, bb3.start_address)
        func.add_edge(bb2.start_address, bb4.start_address)
        func.add_edge(bb3.start_address, bb4.start_address)

        # Cyclomatic complexity = E - N + 2 = 4 - 4 + 2 = 2
        assert func.cyclomatic_complexity() == 2

    def test_function_stack_frame(self):
        """Test function stack frame information."""
        entry = Address(AddressKind.VA, 0x401000, bits=32)
        func = Function(
            name="stack_func",
            entry_point=entry,
            kind=FunctionKind.Normal,
            stack_frame_size=0x48,
            local_vars_size=0x20,
            saved_regs_size=0x18,
            max_call_depth=3,
        )
        assert func.stack_frame_size == 0x48
        assert func.local_vars_size == 0x20
        assert func.saved_regs_size == 0x18
        assert func.max_call_depth == 3
