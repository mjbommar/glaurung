import pytest
from glaurung import Address, AddressKind


class TestAddressCreation:
    """Test Address creation and validation."""

    def test_create_va_address(self):
        """Test creating a virtual address."""
        addr = Address(AddressKind.VA, 0x401000, 32)
        assert addr.kind == AddressKind.VA
        assert addr.value == 0x401000
        assert addr.bits == 32
        assert addr.space is None
        assert addr.symbol_ref is None
        assert addr.is_valid_py()

    def test_create_rva_address(self):
        """Test creating a relative virtual address."""
        addr = Address(AddressKind.RVA, 0x1000, 32)
        assert addr.kind == AddressKind.RVA
        assert addr.value == 0x1000
        assert addr.bits == 32

    def test_create_file_offset_address(self):
        """Test creating a file offset address."""
        addr = Address(AddressKind.FileOffset, 0x200, 32)
        assert addr.kind == AddressKind.FileOffset
        assert addr.value == 0x200

    def test_create_symbolic_address(self):
        """Test creating a symbolic address."""
        addr = Address(
            AddressKind.Symbolic, 0, 64, symbol_ref="kernel32.dll!CreateFileW"
        )
        assert addr.kind == AddressKind.Symbolic
        assert addr.value == 0
        assert addr.symbol_ref == "kernel32.dll!CreateFileW"

    def test_create_with_address_space(self):
        """Test creating an address with a custom address space."""
        addr = Address(AddressKind.VA, 0x1000, 32, space="mmio")
        assert addr.space == "mmio"

    def test_invalid_bits_rejected(self):
        """Test that invalid bit widths are rejected."""
        with pytest.raises(ValueError, match="bits must be 16, 32, or 64"):
            Address(AddressKind.VA, 0x1000, 24)

    def test_symbolic_without_symbol_ref_rejected(self):
        """Test that symbolic addresses require symbol_ref."""
        with pytest.raises(
            ValueError, match="symbol_ref is required when kind=Symbolic"
        ):
            Address(AddressKind.Symbolic, 0, 64)

    def test_value_overflow_rejected(self):
        """Test that values exceeding bit width are rejected."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            Address(AddressKind.VA, 0x10000, 16)


class TestAddressArithmetic:
    """Test Address arithmetic operations."""

    def test_add_offset(self):
        """Test adding an offset to an address."""
        addr = Address(AddressKind.VA, 0x401000, 32)
        result = addr + 0x10
        assert result.value == 0x401010
        assert result.kind == AddressKind.VA
        assert result.bits == 32

    def test_subtract_offset(self):
        """Test subtracting an offset from an address."""
        addr = Address(AddressKind.VA, 0x401010, 32)
        result = addr - 0x10
        assert result.value == 0x401000
        assert result.kind == AddressKind.VA

    def test_add_overflow_error(self):
        """Test that addition overflow raises an error."""
        addr = Address(AddressKind.VA, 0xFFFF_FFFF, 32)
        with pytest.raises(ValueError, match="exceeds maximum for 32-bit address"):
            addr + 1

    def test_subtract_underflow_error(self):
        """Test that subtraction underflow raises an error."""
        addr = Address(AddressKind.VA, 0x0, 32)
        with pytest.raises(ValueError, match="subtraction underflow"):
            addr - 1


class TestAddressConversions:
    """Test address kind conversions."""

    def test_va_to_rva_conversion(self):
        """Test converting VA to RVA."""
        va = Address(AddressKind.VA, 0x401000, 32)
        rva = va.to_rva_py(0x400000)
        assert rva is not None
        assert rva.kind == AddressKind.RVA
        assert rva.value == 0x1000

    def test_rva_to_va_conversion(self):
        """Test converting RVA to VA."""
        rva = Address(AddressKind.RVA, 0x1000, 32)
        va = rva.to_va_py(0x400000)
        assert va is not None
        assert va.kind == AddressKind.VA
        assert va.value == 0x401000

    def test_va_to_rva_below_base_error(self):
        """Test VA to RVA conversion when VA is below image base."""
        va = Address(AddressKind.VA, 0x300000, 32)
        with pytest.raises(ValueError, match="VA below image base"):
            va.to_rva_py(0x400000)

    def test_non_va_to_rva_returns_none(self):
        """Test that non-VA addresses return None for to_rva."""
        rva = Address(AddressKind.RVA, 0x1000, 32)
        result = rva.to_rva_py(0x400000)
        assert result is None


class TestAddressRepresentation:
    """Test address string representations."""

    def test_str_representation(self):
        """Test string representation of addresses."""
        va = Address(AddressKind.VA, 0x401000, 32)
        assert str(va) == "VA:401000"

        rva = Address(AddressKind.RVA, 0x1000, 32)
        assert str(rva) == "RVA:1000"

        fo = Address(AddressKind.FileOffset, 0x200, 32)
        assert str(fo) == "FO:200"

    def test_repr_representation(self):
        """Test repr representation of addresses."""
        addr = Address(AddressKind.VA, 0x401000, 32)
        expected = "Address(AddressKind.VA, 0x401000, 32)"
        assert repr(addr) == expected

    def test_str_with_space(self):
        """Test string representation with address space."""
        addr = Address(AddressKind.VA, 0x1000, 32, space="mmio")
        assert str(addr) == "VA:1000@mmio"

    def test_str_symbolic(self):
        """Test string representation of symbolic addresses."""
        addr = Address(
            AddressKind.Symbolic, 0, 64, symbol_ref="kernel32.dll!CreateFileW"
        )
        assert str(addr) == "SYM:kernel32.dll!CreateFileW"


class TestAddressValidation:
    """Test address validation."""

    def test_valid_addresses(self):
        """Test that valid addresses pass validation."""
        test_cases = [
            (AddressKind.VA, 0x401000, 32),
            (AddressKind.RVA, 0x1000, 32),
            (AddressKind.FileOffset, 0x200, 32),
            (AddressKind.Physical, 0x1000, 64),
            (AddressKind.Relative, 0x10, 32),
            (AddressKind.Symbolic, 0, 64, "test.dll!func"),
        ]

        for case in test_cases:
            if len(case) == 3:
                addr = Address(case[0], case[1], case[2])
            else:
                addr = Address(case[0], case[1], case[2], symbol_ref=case[3])
            assert addr.is_valid_py(), f"Address should be valid: {addr}"

    def test_constructor_validation(self):
        """Test that the constructor properly validates inputs."""
        # This is already tested in other test methods
        # The constructor prevents creating invalid addresses
        pass

    def test_16_bit_max_value(self):
        """Test maximum value for 16-bit addresses."""
        addr = Address(AddressKind.VA, 0xFFFF, 16)
        assert addr.is_valid_py()

        with pytest.raises(ValueError):
            Address(AddressKind.VA, 0x10000, 16)

    def test_32_bit_max_value(self):
        """Test maximum value for 32-bit addresses."""
        addr = Address(AddressKind.VA, 0xFFFF_FFFF, 32)
        assert addr.is_valid_py()

        with pytest.raises(ValueError):
            Address(AddressKind.VA, 0x1_0000_0000, 32)

    def test_64_bit_max_value(self):
        """Test that 64-bit addresses accept large values."""
        addr = Address(AddressKind.VA, 0xFFFF_FFFF_FFFF_FFFF, 64)
        assert addr.is_valid_py()


class TestAddressKind:
    """Test AddressKind enum."""

    def test_address_kind_str(self):
        """Test string representation of AddressKind."""
        assert str(AddressKind.VA) == "VA"
        assert str(AddressKind.RVA) == "RVA"
        assert str(AddressKind.FileOffset) == "FileOffset"
        assert str(AddressKind.Physical) == "Physical"
        assert str(AddressKind.Relative) == "Relative"
        assert str(AddressKind.Symbolic) == "Symbolic"

    def test_address_kind_repr(self):
        """Test repr representation of AddressKind."""
        assert repr(AddressKind.VA) == "AddressKind.VA"
        assert repr(AddressKind.RVA) == "AddressKind.RVA"


class TestAddressSerialization:
    """Test Address serialization features."""

    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        addr = Address(AddressKind.VA, 0x401000, 32, space="default")
        json_str = addr.to_json_py()
        assert isinstance(json_str, str)

        # Deserialize
        restored = Address.from_json_py(json_str)
        assert restored == addr
        assert restored.kind == addr.kind
        assert restored.value == addr.value
        assert restored.bits == addr.bits
        assert restored.space == addr.space

    def test_binary_serialization(self):
        """Test binary serialization and deserialization."""
        addr = Address(AddressKind.RVA, 0x1000, 64, symbol_ref="test.dll!func")
        binary_data = addr.to_binary_py()
        assert isinstance(binary_data, bytes)

        # Deserialize
        restored = Address.from_binary_py(binary_data)
        assert restored == addr
        assert restored.symbol_ref == addr.symbol_ref

    def test_serialization_round_trip(self):
        """Test that serialization preserves all data."""
        test_cases = [
            Address(AddressKind.VA, 0x401000, 32),
            Address(AddressKind.Symbolic, 0, 64, symbol_ref="kernel32.dll!CreateFileW"),
            Address(AddressKind.FileOffset, 0x200, 32, space="overlay"),
        ]

        for addr in test_cases:
            # JSON round trip
            json_str = addr.to_json_py()
            json_restored = Address.from_json_py(json_str)
            assert json_restored == addr

            # Binary round trip
            binary_data = addr.to_binary_py()
            binary_restored = Address.from_binary_py(binary_data)
            assert binary_restored == addr


class TestAddressConversionsExtended:
    """Test extended address conversion methods."""

    def test_file_offset_to_va_conversion(self):
        """Test converting FileOffset to VA with section mapping."""
        file_offset = Address(AddressKind.FileOffset, 0x1000, 32)
        va = file_offset.file_offset_to_va_py(
            0x1000, 0x400000
        )  # section_rva=0x1000, image_base=0x400000
        assert va is not None
        assert va.kind == AddressKind.VA
        assert va.value == 0x401000

    def test_va_to_file_offset_conversion(self):
        """Test converting VA to FileOffset with section mapping."""
        va = Address(AddressKind.VA, 0x401000, 32)
        file_offset = va.va_to_file_offset_py(
            0x400000, 0x1000
        )  # section_va=0x400000, section_file_offset=0x1000
        assert file_offset is not None
        assert file_offset.kind == AddressKind.FileOffset
        assert file_offset.value == 0x2000

    def test_file_offset_to_va_invalid(self):
        """Test FileOffset to VA conversion with invalid parameters."""
        file_offset = Address(AddressKind.FileOffset, 0x1000, 32)
        result = file_offset.file_offset_to_va_py(
            0x2000, 0x400000
        )  # file_offset < section_rva
        assert result is None

    def test_va_to_file_offset_invalid(self):
        """Test VA to FileOffset conversion with VA below section."""
        va = Address(AddressKind.VA, 0x300000, 32)
        with pytest.raises(ValueError, match="VA below section start"):
            va.va_to_file_offset_py(0x400000, 0x1000)


class TestAddressComparison:
    """Test Address comparison operations."""

    def test_address_ordering_by_value(self):
        """Test that addresses are ordered primarily by value."""
        addr1 = Address(AddressKind.VA, 0x1000, 32)
        addr2 = Address(AddressKind.VA, 0x2000, 32)
        addr3 = Address(AddressKind.VA, 0x1000, 32)

        assert addr1 < addr2
        assert addr2 > addr1
        assert addr1 == addr3

    def test_address_ordering_by_kind(self):
        """Test that addresses with same value are ordered by kind."""
        va_addr = Address(AddressKind.VA, 0x1000, 32)
        rva_addr = Address(AddressKind.RVA, 0x1000, 32)

        # VA comes before RVA in enum ordering
        assert va_addr < rva_addr

    def test_address_ordering_by_space(self):
        """Test that addresses are ordered by space when value and kind are equal."""
        addr1 = Address(AddressKind.VA, 0x1000, 32)
        addr2 = Address(AddressKind.VA, 0x1000, 32, space="default")
        addr3 = Address(AddressKind.VA, 0x1000, 32, space="overlay")

        assert addr1 < addr2  # None < Some
        assert addr2 < addr3  # "default" < "overlay"

    def test_address_sorting(self):
        """Test that addresses can be sorted."""
        addresses = [
            Address(AddressKind.RVA, 0x1000, 32, space="overlay"),
            Address(AddressKind.VA, 0x500, 32),
            Address(AddressKind.VA, 0x1000, 32),
            Address(AddressKind.FileOffset, 0x1000, 32),
        ]

        sorted_addresses = sorted(addresses)

        # Should be sorted by value, then kind, then space
        assert sorted_addresses[0].value == 0x500
        assert (
            sorted_addresses[1].value == 0x1000
            and sorted_addresses[1].kind == AddressKind.VA
        )
        assert (
            sorted_addresses[2].value == 0x1000
            and sorted_addresses[2].kind == AddressKind.FileOffset
        )
        assert (
            sorted_addresses[3].value == 0x1000
            and sorted_addresses[3].kind == AddressKind.RVA
        )
