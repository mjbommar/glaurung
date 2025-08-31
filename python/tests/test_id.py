from glaurung import Id, IdKind, IdGenerator


class TestIdCreation:
    """Test Id creation and basic functionality."""

    def test_create_id(self):
        """Test creating a basic ID."""
        id_obj = Id("test_id", IdKind.Binary)
        assert id_obj.value == "test_id"
        assert id_obj.kind == IdKind.Binary
        assert id_obj.is_valid()

    def test_create_id_with_different_kinds(self):
        """Test creating IDs with different kinds."""
        test_cases = [
            (IdKind.Binary, "bin_123"),
            (IdKind.Function, "func_main"),
            (IdKind.BasicBlock, "bb_001"),
            (IdKind.Symbol, "sym_foo"),
            (IdKind.Section, "sect_text"),
            (IdKind.Segment, "seg_code"),
            (IdKind.Instruction, "insn_0x1000"),
            (IdKind.Variable, "var_local"),
            (IdKind.DataType, "type_int32"),
            (IdKind.Entity, "entity_ref"),
        ]

        for kind, value in test_cases:
            id_obj = Id(value, kind)
            assert id_obj.value == value
            assert id_obj.kind == kind

    def test_id_equality(self):
        """Test ID equality comparison."""
        id1 = Id("test", IdKind.Binary)
        id2 = Id("test", IdKind.Binary)
        id3 = Id("different", IdKind.Binary)
        id4 = Id("test", IdKind.Function)

        assert id1 == id2
        assert id1 != id3
        assert id1 != id4

    def test_id_string_representation(self):
        """Test ID string representations."""
        id_obj = Id("test_id", IdKind.Binary)

        assert str(id_obj) == "test_id"
        repr_str = repr(id_obj)
        assert "Id(" in repr_str
        assert "test_id" in repr_str
        assert "Binary" in repr_str

    def test_empty_id_not_valid(self):
        """Test that empty IDs are not valid."""
        id_obj = Id("", IdKind.Binary)
        assert not id_obj.is_valid()


class TestIdKind:
    """Test IdKind enum functionality."""

    def test_id_kind_string_representation(self):
        """Test IdKind string representations."""
        assert str(IdKind.Binary) == "Binary"
        assert str(IdKind.Function) == "Function"
        assert str(IdKind.BasicBlock) == "BasicBlock"
        assert str(IdKind.Symbol) == "Symbol"
        assert str(IdKind.Section) == "Section"
        assert str(IdKind.Segment) == "Segment"
        assert str(IdKind.Instruction) == "Instruction"
        assert str(IdKind.Variable) == "Variable"
        assert str(IdKind.DataType) == "DataType"
        assert str(IdKind.Entity) == "Entity"

    def test_id_kind_repr(self):
        """Test IdKind repr."""
        assert repr(IdKind.Binary) == "IdKind.Binary"
        assert repr(IdKind.Function) == "IdKind.Function"


class TestIdGeneratorBinary:
    """Test binary ID generation."""

    def test_binary_from_content_without_path(self):
        """Test generating binary ID from content without path."""
        content = b"test binary content"
        id_obj = IdGenerator.binary_from_content(content, None)

        assert id_obj.kind == IdKind.Binary
        assert id_obj.value.startswith("bin:sha256:")
        assert len(id_obj.value) > 20  # Should have hash
        assert id_obj.is_valid()

    def test_binary_from_content_with_path(self):
        """Test generating binary ID from content with path."""
        content = b"test binary content"
        path = "test.exe"
        id_obj = IdGenerator.binary_from_content(content, path)

        assert id_obj.kind == IdKind.Binary
        assert id_obj.value.startswith("bin:sha256:")
        # Path is used in hash calculation but not stored in final ID

    def test_binary_from_uuid(self):
        """Test generating binary ID from UUID."""
        uuid_str = "12345678-1234-1234-1234-123456789abc"
        id_obj = IdGenerator.binary_from_uuid(uuid_str)

        assert id_obj.kind == IdKind.Binary
        assert id_obj.value == f"bin:uuid:{uuid_str}"
        assert id_obj.is_valid()

    def test_binary_id_deterministic(self):
        """Test that same content produces same binary ID."""
        content = b"deterministic test content"

        id1 = IdGenerator.binary_from_content(content, None)
        id2 = IdGenerator.binary_from_content(content, None)

        assert id1 == id2


class TestIdGeneratorFunction:
    """Test function ID generation."""

    def test_function_id_generation(self):
        """Test generating function IDs."""
        binary_id = "bin:sha256:abcd1234"
        address = "0x401000"

        id_obj = IdGenerator.function(binary_id, address)

        assert id_obj.kind == IdKind.Function
        assert id_obj.value == f"func:{binary_id}:{address}"
        assert id_obj.is_valid()

    def test_function_id_deterministic(self):
        """Test that function IDs are deterministic."""
        binary_id = "bin:123"
        address = "0x401000"

        id1 = IdGenerator.function(binary_id, address)
        id2 = IdGenerator.function(binary_id, address)

        assert id1 == id2

    def test_function_id_different_inputs(self):
        """Test that different inputs produce different function IDs."""
        id1 = IdGenerator.function("bin:123", "0x401000")
        id2 = IdGenerator.function("bin:456", "0x401000")
        id3 = IdGenerator.function("bin:123", "0x402000")

        assert id1 != id2
        assert id1 != id3
        assert id2 != id3


class TestIdGeneratorBasicBlock:
    """Test basic block ID generation."""

    def test_basic_block_id_generation(self):
        """Test generating basic block IDs."""
        binary_id = "bin:sha256:abcd1234"
        address = "0x401000"

        id_obj = IdGenerator.basic_block(binary_id, address)

        assert id_obj.kind == IdKind.BasicBlock
        assert id_obj.value == f"bb:{binary_id}:{address}"
        assert id_obj.is_valid()

    def test_basic_block_id_deterministic(self):
        """Test that basic block IDs are deterministic."""
        binary_id = "bin:123"
        address = "0x401000"

        id1 = IdGenerator.basic_block(binary_id, address)
        id2 = IdGenerator.basic_block(binary_id, address)

        assert id1 == id2


class TestIdGeneratorSymbol:
    """Test symbol ID generation."""

    def test_symbol_id_with_address(self):
        """Test generating symbol ID with address."""
        name = "CreateFileW"
        address = "0x401000"

        id_obj = IdGenerator.symbol(name, address)

        assert id_obj.kind == IdKind.Symbol
        assert id_obj.value == f"sym:{name}:{address}"
        assert id_obj.is_valid()

    def test_symbol_id_without_address(self):
        """Test generating symbol ID without address."""
        name = "kernel32.dll"

        id_obj = IdGenerator.symbol(name, None)

        assert id_obj.kind == IdKind.Symbol
        assert id_obj.value == f"sym:{name}"
        assert id_obj.is_valid()

    def test_symbol_id_deterministic(self):
        """Test that symbol IDs are deterministic."""
        name = "CreateFileW"
        address = "0x401000"

        id1 = IdGenerator.symbol(name, address)
        id2 = IdGenerator.symbol(name, address)

        assert id1 == id2


class TestIdGeneratorSection:
    """Test section ID generation."""

    def test_section_id_with_name_and_index(self):
        """Test generating section ID with name and index."""
        name = ".text"
        index = 1

        id_obj = IdGenerator.section(name, index)

        assert id_obj.kind == IdKind.Section
        assert id_obj.value == f"sect:{name}:{index}"
        assert id_obj.is_valid()

    def test_section_id_with_name_only(self):
        """Test generating section ID with name only."""
        name = ".data"

        id_obj = IdGenerator.section(name, None)

        assert id_obj.kind == IdKind.Section
        assert id_obj.value == f"sect:{name}"
        assert id_obj.is_valid()

    def test_section_id_with_index_only(self):
        """Test generating section ID with index only."""
        index = 5

        id_obj = IdGenerator.section(None, index)

        assert id_obj.kind == IdKind.Section
        assert id_obj.value == f"sect:idx:{index}"
        assert id_obj.is_valid()

    def test_section_id_unknown(self):
        """Test generating section ID with no name or index."""
        id_obj = IdGenerator.section(None, None)

        assert id_obj.kind == IdKind.Section
        assert id_obj.value == "sect:unknown"
        assert id_obj.is_valid()


class TestIdGeneratorSegment:
    """Test segment ID generation."""

    def test_segment_id_with_name_and_index(self):
        """Test generating segment ID with name and index."""
        name = "CODE"
        index = 0

        id_obj = IdGenerator.segment(name, index)

        assert id_obj.kind == IdKind.Segment
        assert id_obj.value == f"seg:{name}:{index}"
        assert id_obj.is_valid()

    def test_segment_id_with_name_only(self):
        """Test generating segment ID with name only."""
        name = "DATA"

        id_obj = IdGenerator.segment(name, None)

        assert id_obj.kind == IdKind.Segment
        assert id_obj.value == f"seg:{name}"
        assert id_obj.is_valid()


class TestIdGeneratorInstruction:
    """Test instruction ID generation."""

    def test_instruction_id_generation(self):
        """Test generating instruction ID."""
        address = "0x401000"

        id_obj = IdGenerator.instruction(address)

        assert id_obj.kind == IdKind.Instruction
        assert id_obj.value == f"insn:{address}"
        assert id_obj.is_valid()

    def test_instruction_id_deterministic(self):
        """Test that instruction IDs are deterministic."""
        address = "0x401000"

        id1 = IdGenerator.instruction(address)
        id2 = IdGenerator.instruction(address)

        assert id1 == id2


class TestIdGeneratorVariable:
    """Test variable ID generation."""

    def test_variable_id_with_name_and_offset(self):
        """Test generating variable ID with name and offset."""
        context = "func:main"
        name = "local_var"
        offset = 8

        id_obj = IdGenerator.variable(context, name, offset)

        assert id_obj.kind == IdKind.Variable
        assert id_obj.value == f"var:{context}:{name}:{offset}"
        assert id_obj.is_valid()

    def test_variable_id_with_name_only(self):
        """Test generating variable ID with name only."""
        context = "func:main"
        name = "local_var"

        id_obj = IdGenerator.variable(context, name, None)

        assert id_obj.kind == IdKind.Variable
        assert id_obj.value == f"var:{context}:{name}"
        assert id_obj.is_valid()

    def test_variable_id_with_offset_only(self):
        """Test generating variable ID with offset only."""
        context = "func:main"
        offset = 16

        id_obj = IdGenerator.variable(context, None, offset)

        assert id_obj.kind == IdKind.Variable
        assert id_obj.value == f"var:{context}:offset:{offset}"
        assert id_obj.is_valid()

    def test_variable_id_minimal(self):
        """Test generating variable ID with minimal information."""
        context = "func:main"

        id_obj = IdGenerator.variable(context, None, None)

        assert id_obj.kind == IdKind.Variable
        assert id_obj.value == f"var:{context}:unnamed"
        assert id_obj.is_valid()


class TestIdGeneratorDataType:
    """Test data type ID generation."""

    def test_data_type_id_with_name_and_hash(self):
        """Test generating data type ID with name and content hash."""
        name = "int32"
        content_hash = "hash123"

        id_obj = IdGenerator.data_type(name, content_hash)

        assert id_obj.kind == IdKind.DataType
        assert id_obj.value == f"type:{name}:{content_hash}"
        assert id_obj.is_valid()

    def test_data_type_id_with_name_only(self):
        """Test generating data type ID with name only."""
        name = "void"

        id_obj = IdGenerator.data_type(name, None)

        assert id_obj.kind == IdKind.DataType
        assert id_obj.value == f"type:{name}"
        assert id_obj.is_valid()

    def test_data_type_id_with_hash_only(self):
        """Test generating data type ID with hash only."""
        content_hash = "abc123"

        id_obj = IdGenerator.data_type(None, content_hash)

        assert id_obj.kind == IdKind.DataType
        assert id_obj.value == f"type:anon:{content_hash}"
        assert id_obj.is_valid()

    def test_data_type_id_unknown(self):
        """Test generating data type ID with no information."""
        id_obj = IdGenerator.data_type(None, None)

        assert id_obj.kind == IdKind.DataType
        assert id_obj.value == "type:unknown"
        assert id_obj.is_valid()


class TestIdGeneratorEntity:
    """Test generic entity ID generation."""

    def test_entity_id_generation(self):
        """Test generating generic entity ID."""
        entity_type = "reference"
        identifier = "xref_123"

        id_obj = IdGenerator.entity(entity_type, identifier)

        assert id_obj.kind == IdKind.Entity
        assert id_obj.value == f"{entity_type}:{identifier}"
        assert id_obj.is_valid()

    def test_entity_id_deterministic(self):
        """Test that entity IDs are deterministic."""
        entity_type = "reference"
        identifier = "xref_123"

        id1 = IdGenerator.entity(entity_type, identifier)
        id2 = IdGenerator.entity(entity_type, identifier)

        assert id1 == id2


class TestIdGeneratorHash:
    """Test hash-based ID generation."""

    def test_hash_id_generation(self):
        """Test generating hash-based ID."""
        content = "test content for hashing"

        id_obj = IdGenerator.hash(IdKind.Function, content)

        assert id_obj.kind == IdKind.Function
        assert id_obj.value.startswith("function:hash:")
        assert len(id_obj.value) > 20  # Should have hash
        assert id_obj.is_valid()

    def test_hash_id_deterministic(self):
        """Test that hash-based IDs are deterministic."""
        content = "deterministic content"

        id1 = IdGenerator.hash(IdKind.Binary, content)
        id2 = IdGenerator.hash(IdKind.Binary, content)

        assert id1 == id2

    def test_hash_id_different_content(self):
        """Test that different content produces different hash IDs."""
        id1 = IdGenerator.hash(IdKind.Binary, "content1")
        id2 = IdGenerator.hash(IdKind.Binary, "content2")

        assert id1 != id2


class TestIdGeneratorIntegration:
    """Test ID generator integration scenarios."""

    def test_cross_entity_references(self):
        """Test generating IDs that reference each other."""
        # Generate binary ID
        binary_content = b"test binary"
        binary_id = IdGenerator.binary_from_content(binary_content, None)

        # Generate function ID that references the binary
        func_id = IdGenerator.function(binary_id.value, "0x401000")

        # Generate basic block ID that references the binary
        bb_id = IdGenerator.basic_block(binary_id.value, "0x401000")

        # Verify relationships
        assert binary_id.value in func_id.value
        assert binary_id.value in bb_id.value
        assert func_id != bb_id

    def test_symbol_resolution_chain(self):
        """Test a chain of symbol-related IDs."""
        # Import symbol
        import_sym = IdGenerator.symbol("CreateFileW", None)

        # Resolved symbol with address
        resolved_sym = IdGenerator.symbol("CreateFileW", "0x401000")

        # Function that implements the symbol
        func_id = IdGenerator.function("bin:123", "0x401000")

        # They should be different but related
        assert import_sym != resolved_sym
        assert "CreateFileW" in resolved_sym.value
        assert "0x401000" in func_id.value

    def test_complex_entity_hierarchy(self):
        """Test complex hierarchical ID relationships."""
        # Binary
        binary_id = IdGenerator.binary_from_uuid("uuid-123")

        # Section in binary
        section_id = IdGenerator.section(".text", 1)

        # Function in section
        func_id = IdGenerator.function(binary_id.value, "0x401000")

        # Basic block in function
        bb_id = IdGenerator.basic_block(binary_id.value, "0x401000")

        # Instruction in basic block
        insn_id = IdGenerator.instruction("0x401000")

        # Variable in function
        var_id = IdGenerator.variable(func_id.value, "local_var", 8)

        # Verify hierarchy
        assert binary_id.value in func_id.value
        assert binary_id.value in bb_id.value
        assert func_id.value in var_id.value

        # All should be different
        ids = [binary_id, section_id, func_id, bb_id, insn_id, var_id]
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                assert ids[i] != ids[j], f"IDs {i} and {j} should be different"
