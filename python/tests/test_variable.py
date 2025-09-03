"""Tests for Variable and StorageLocation types."""

import json
import pytest
import glaurung


def test_variable_register():
    """Test creating a register variable."""
    var = glaurung.Variable.register(
        "var1", "local_i", "int32", "rax", None, "decompiler"
    )

    assert var.id == "var1"
    assert var.name == "local_i"
    assert var.type_id == "int32"
    assert var.source == "decompiler"
    assert var.is_register_py()
    assert not var.is_stack_py()
    assert not var.is_heap_py()
    assert not var.is_global_py()
    assert var.register_name_py() == "rax"
    assert var.is_valid_py()


def test_variable_stack():
    """Test creating a stack variable."""
    var = glaurung.Variable.stack(
        "var2", "stack_var", "int64", -8, "rbp", None, "debug"
    )

    assert var.id == "var2"
    assert var.name == "stack_var"
    assert var.type_id == "int64"
    assert var.is_stack_py()
    assert var.stack_offset_py() == -8
    assert var.frame_base_py() == "rbp"
    assert var.is_valid_py()


def test_variable_heap():
    """Test creating a heap variable."""
    address = glaurung.Address(glaurung.AddressKind.VA, 0x1000, 64)
    var = glaurung.Variable.heap(
        "var3", "heap_obj", "ptr_void", address, None, "runtime"
    )

    assert var.id == "var3"
    assert var.name == "heap_obj"
    assert var.type_id == "ptr_void"
    assert var.is_heap_py()
    assert var.address_py().value == 0x1000
    assert var.is_valid_py()


def test_variable_global():
    """Test creating a global variable."""
    address = glaurung.Address(glaurung.AddressKind.VA, 0x404000, 64)
    # Use getattr because 'global' is a Python keyword
    global_method = getattr(glaurung.Variable, "global")
    var = global_method("var4", "global_data", "int32", address, None, "symbols")

    assert var.id == "var4"
    assert var.name == "global_data"
    assert var.type_id == "int32"
    assert var.is_global_py()
    assert var.address_py().value == 0x404000
    assert var.is_valid_py()


def test_variable_with_liveness():
    """Test variable with liveness range."""
    start_addr = glaurung.Address(glaurung.AddressKind.VA, 0x1000, 64)
    liveness = glaurung.AddressRange(start_addr, 0x100)

    var = glaurung.Variable.register(
        "var5", "temp", "int32", "rcx", liveness, "decompiler"
    )

    assert var.liveness_range is not None
    assert var.liveness_size_py() == 0x100

    # Test liveness checks
    test_addr = glaurung.Address(glaurung.AddressKind.VA, 0x1050, 64)
    assert var.is_live_at_py(test_addr)

    outside_addr = glaurung.Address(glaurung.AddressKind.VA, 0x2000, 64)
    assert not var.is_live_at_py(outside_addr)


def test_storage_location_register():
    """Test StorageLocation.Register creation."""
    storage = glaurung.StorageLocation.register("xmm0")
    var = glaurung.Variable("var1", "float64", storage)

    assert var.storage is not None
    assert var.is_register_py()
    assert str(storage) == "Register(xmm0)"
    assert "StorageLocation.Register" in repr(storage)


def test_storage_location_stack():
    """Test StorageLocation.Stack creation."""
    storage = glaurung.StorageLocation.stack(-16, "rbp")
    var = glaurung.Variable("var2", "int64", storage)

    assert var.is_stack_py()
    assert str(storage) == "Stack(-16@rbp)"
    assert "StorageLocation.Stack" in repr(storage)

    # Test without frame base
    storage2 = glaurung.StorageLocation.stack(8, None)
    assert str(storage2) == "Stack(8)"


def test_storage_location_heap():
    """Test StorageLocation.Heap creation."""
    address = glaurung.Address(glaurung.AddressKind.VA, 0x7000, 64)
    storage = glaurung.StorageLocation.heap(address)
    var = glaurung.Variable("var3", "ptr_struct", storage)

    assert var.is_heap_py()
    assert "Heap(" in str(storage)
    assert "StorageLocation.Heap" in repr(storage)


def test_storage_location_global():
    """Test StorageLocation.Global creation."""
    address = glaurung.Address(glaurung.AddressKind.VA, 0x405000, 64)
    # Use getattr because 'global' is a Python keyword
    global_method = getattr(glaurung.StorageLocation, "global")
    storage = global_method(address)
    var = glaurung.Variable("var4", "int32", storage)

    assert var.is_global_py()
    assert "Global(" in str(storage)
    assert "StorageLocation.Global" in repr(storage)


def test_variable_constructor():
    """Test Variable constructor with all parameters."""
    storage = glaurung.StorageLocation.register("r8")
    start_addr = glaurung.Address(glaurung.AddressKind.VA, 0x1000, 64)
    liveness = glaurung.AddressRange(start_addr, 0x50)

    var = glaurung.Variable(
        "var_test",
        "int64",
        storage,
        name="loop_counter",
        liveness_range=liveness,
        source="decompiler",
    )

    assert var.id == "var_test"
    assert var.name == "loop_counter"
    assert var.type_id == "int64"
    assert var.source == "decompiler"
    assert var.liveness_range is not None
    assert var.is_valid_py()


def test_variable_serialization():
    """Test Variable JSON serialization."""
    var = glaurung.Variable.register("var1", "test_var", "int32", "rax", None, "debug")

    # Serialize to JSON
    json_str = var.to_json()
    data = json.loads(json_str)

    assert data["id"] == "var1"
    assert data["name"] == "test_var"
    assert data["type_id"] == "int32"

    # Deserialize from JSON
    var2 = glaurung.Variable.from_json(json_str)
    assert var2.id == var.id
    assert var2.name == var.name
    assert var2.type_id == var.type_id


def test_variable_equality():
    """Test Variable equality comparison."""
    var1 = glaurung.Variable.register("var1", "test", "int32", "rax", None, "debug")
    var2 = glaurung.Variable.register("var1", "test", "int32", "rax", None, "debug")
    var3 = glaurung.Variable.register("var2", "test", "int32", "rbx", None, "debug")

    assert var1 == var2
    assert var1 != var3
    assert hash(var1) == hash(var2)
    assert hash(var1) != hash(var3)


def test_variable_invalid():
    """Test invalid Variable creation."""
    storage = glaurung.StorageLocation.register("rax")

    # Empty ID should fail validation
    with pytest.raises(ValueError, match="Invalid"):
        glaurung.Variable("", "int32", storage)

    # Empty type_id should fail validation
    with pytest.raises(ValueError, match="Invalid"):
        glaurung.Variable("var1", "", storage)

    # Empty register name should fail validation
    with pytest.raises(ValueError, match="Invalid"):
        bad_storage = glaurung.StorageLocation.register("")
        glaurung.Variable("var1", "int32", bad_storage)


def test_variable_str_repr():
    """Test Variable string representations."""
    var = glaurung.Variable.register("var1", "local_var", "int32", "rax", None, "debug")

    assert str(var) == "Variable(id=var1, name='local_var', type_id=int32)"
    assert "Variable(id=" in repr(var)

    # Test without name
    var2 = glaurung.Variable.register("var2", None, "int64", "rbx", None, None)
    assert "name=None" in str(var2)


def test_complex_variable():
    """Test creating a complex variable with all features."""
    # Create a stack variable for a struct with liveness info
    start_addr = glaurung.Address(glaurung.AddressKind.VA, 0x401000, 64)
    _end_addr = glaurung.Address(glaurung.AddressKind.VA, 0x401200, 64)
    liveness = glaurung.AddressRange(start_addr, 0x200)

    var = glaurung.Variable.stack(
        "local_struct", "user_data", "struct_user", -48, "rbp", liveness, "decompiler"
    )

    assert var.id == "local_struct"
    assert var.name == "user_data"
    assert var.type_id == "struct_user"
    assert var.is_stack_py()
    assert var.stack_offset_py() == -48
    assert var.frame_base_py() == "rbp"
    assert var.liveness_size_py() == 0x200

    # Check liveness at various points
    assert var.is_live_at_py(start_addr)
    assert var.is_live_at_py(glaurung.Address(glaurung.AddressKind.VA, 0x401100, 64))
    assert not var.is_live_at_py(
        glaurung.Address(glaurung.AddressKind.VA, 0x402000, 64)
    )

    # Test serialization of complex variable
    json_str = var.to_json()
    var2 = glaurung.Variable.from_json(json_str)
    assert var2 == var
