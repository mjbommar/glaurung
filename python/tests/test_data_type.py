"""Tests for DataType and related types."""

import json
import pytest
import glaurung


def test_data_type_primitive():
    """Test creating a primitive data type."""
    dt = glaurung.DataType.primitive("int32", "int32_t", 4, 4, "debug")

    assert dt.id == "int32"
    assert dt.name == "int32_t"
    assert dt.size == 4
    assert dt.alignment == 4
    assert dt.source == "debug"
    assert dt.kind == glaurung.DataTypeKind.Primitive
    assert dt.is_valid_py()
    assert not dt.is_pointer_py()
    assert not dt.is_array_py()
    assert not dt.is_function_py()
    assert not dt.is_composite_py()


def test_data_type_pointer():
    """Test creating a pointer data type."""
    dt = glaurung.DataType.pointer(
        "ptr_int32", "*int32_t", 8, 8, "int32", ["const"], "debug"
    )

    assert dt.id == "ptr_int32"
    assert dt.name == "*int32_t"
    assert dt.size == 8
    assert dt.kind == glaurung.DataTypeKind.Pointer
    assert dt.is_pointer_py()
    assert dt.base_type_id_py() == "int32"
    assert dt.is_valid_py()


def test_data_type_array():
    """Test creating an array data type."""
    dt = glaurung.DataType.array(
        "arr_int32", "int32_t[10]", 40, 4, "int32", 10, "debug"
    )

    assert dt.id == "arr_int32"
    assert dt.name == "int32_t[10]"
    assert dt.size == 40
    assert dt.kind == glaurung.DataTypeKind.Array
    assert dt.is_array_py()
    assert dt.base_type_id_py() == "int32"
    assert dt.is_valid_py()


def test_data_type_struct():
    """Test creating a struct data type."""
    fields = [
        glaurung.Field("x", "int32", 0),
        glaurung.Field("y", "int32", 4),
        glaurung.Field("z", "float64", 8),
    ]

    dt = glaurung.DataType.struct_("point3d", "struct Point3D", 16, 8, fields, "debug")

    assert dt.id == "point3d"
    assert dt.name == "struct Point3D"
    assert dt.size == 16
    assert dt.kind == glaurung.DataTypeKind.Struct
    assert dt.is_composite_py()
    assert dt.is_valid_py()


def test_data_type_union():
    """Test creating a union data type."""
    fields = [
        glaurung.Field("i", "int32", 0),
        glaurung.Field("f", "float32", 0),
    ]

    dt = glaurung.DataType.union(
        "int_or_float", "union IntOrFloat", 4, 4, fields, "debug"
    )

    assert dt.id == "int_or_float"
    assert dt.name == "union IntOrFloat"
    assert dt.size == 4
    assert dt.kind == glaurung.DataTypeKind.Union
    assert dt.is_composite_py()
    assert dt.is_valid_py()


def test_data_type_enum():
    """Test creating an enum data type."""
    members = [
        glaurung.EnumMember("RED", 0),
        glaurung.EnumMember("GREEN", 1),
        glaurung.EnumMember("BLUE", 2),
    ]

    dt = glaurung.DataType.enum_("color", "enum Color", 4, 4, "int32", members, "debug")

    assert dt.id == "color"
    assert dt.name == "enum Color"
    assert dt.size == 4
    assert dt.kind == glaurung.DataTypeKind.Enum
    assert dt.is_valid_py()


def test_data_type_function():
    """Test creating a function data type."""
    dt = glaurung.DataType.function(
        "func_add",
        "int32_t add(int32_t, int32_t)",
        0,
        None,
        "int32",
        ["int32", "int32"],
        False,
        "debug",
    )

    assert dt.id == "func_add"
    assert dt.name == "int32_t add(int32_t, int32_t)"
    assert dt.size == 0
    assert dt.kind == glaurung.DataTypeKind.Function
    assert dt.is_function_py()
    assert dt.return_type_py() == "int32"
    assert dt.is_valid_py()


def test_data_type_typedef():
    """Test creating a typedef data type."""
    dt = glaurung.DataType.typedef("size_t", "size_t", 8, 8, "uint64", "debug")

    assert dt.id == "size_t"
    assert dt.name == "size_t"
    assert dt.size == 8
    assert dt.kind == glaurung.DataTypeKind.Typedef
    assert dt.base_type_id_py() == "uint64"
    assert dt.is_valid_py()


def test_field():
    """Test Field creation and properties."""
    field = glaurung.Field("member_name", "int32", 16)

    assert field.name == "member_name"
    assert field.type_id == "int32"
    assert field.offset == 16
    assert str(field) == "Field(name=member_name, type_id=int32, offset=16)"
    assert "Field(name=" in repr(field)


def test_enum_member():
    """Test EnumMember creation and properties."""
    member = glaurung.EnumMember("CONSTANT", 42)

    assert member.name == "CONSTANT"
    assert member.value == 42
    assert str(member) == "EnumMember(name=CONSTANT, value=42)"
    assert "EnumMember(name=" in repr(member)


def test_data_type_serialization():
    """Test DataType JSON serialization."""
    dt = glaurung.DataType.primitive("int32", "int32_t", 4, 4, "debug")

    # Serialize to JSON
    json_str = dt.to_json()
    data = json.loads(json_str)

    assert data["id"] == "int32"
    assert data["name"] == "int32_t"
    assert data["size"] == 4
    assert data["alignment"] == 4

    # Deserialize from JSON
    dt2 = glaurung.DataType.from_json(json_str)
    assert dt2.id == dt.id
    assert dt2.name == dt.name
    assert dt2.size == dt.size


def test_data_type_equality():
    """Test DataType equality comparison."""
    dt1 = glaurung.DataType.primitive("int32", "int32_t", 4, 4, "debug")
    dt2 = glaurung.DataType.primitive("int32", "int32_t", 4, 4, "debug")
    dt3 = glaurung.DataType.primitive("int64", "int64_t", 8, 8, "debug")

    assert dt1 == dt2
    assert dt1 != dt3
    assert hash(dt1) == hash(dt2)
    assert hash(dt1) != hash(dt3)


def test_data_type_invalid():
    """Test invalid DataType creation."""
    # Empty ID should fail validation
    with pytest.raises(ValueError, match="Invalid"):
        glaurung.DataType.primitive("", "test", 4, None, None)

    # Empty name should fail validation
    with pytest.raises(ValueError, match="Invalid"):
        glaurung.DataType.primitive("test", "", 4, None, None)

    # Invalid alignment (not power of 2)
    with pytest.raises(ValueError, match="Invalid"):
        glaurung.DataType.primitive("test", "test", 4, 3, None)


def test_data_type_kind_enum():
    """Test DataTypeKind enum."""
    assert str(glaurung.DataTypeKind.Primitive) == "Primitive"
    assert str(glaurung.DataTypeKind.Pointer) == "Pointer"
    assert str(glaurung.DataTypeKind.Array) == "Array"
    assert str(glaurung.DataTypeKind.Struct) == "Struct"
    assert str(glaurung.DataTypeKind.Union) == "Union"
    assert str(glaurung.DataTypeKind.Enum) == "Enum"
    assert str(glaurung.DataTypeKind.Function) == "Function"
    assert str(glaurung.DataTypeKind.Typedef) == "Typedef"


def test_complex_struct():
    """Test creating a complex nested struct."""
    # Create nested struct with various field types
    fields = [
        glaurung.Field("id", "uint32", 0),
        glaurung.Field("name_ptr", "ptr_char", 8),
        glaurung.Field("coords", "point3d", 16),
        glaurung.Field("flags", "uint32", 32),
    ]

    dt = glaurung.DataType.struct_(
        "entity", "struct Entity", 40, 8, fields, "decompiler"
    )

    assert dt.id == "entity"
    assert dt.size == 40
    assert dt.alignment == 8
    assert dt.is_composite_py()
    assert dt.is_valid_py()

    # Test serialization of complex struct
    json_str = dt.to_json()
    dt2 = glaurung.DataType.from_json(json_str)
    assert dt2 == dt
