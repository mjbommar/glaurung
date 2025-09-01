"""Tests for the Relocation type."""

from glaurung import Relocation, RelocationType, Address, AddressKind


class TestRelocationType:
    """Test the RelocationType enum."""

    def test_relocation_type_values(self):
        """Test all RelocationType enum values."""
        assert RelocationType.Absolute
        assert RelocationType.PcRelative
        assert RelocationType.Got
        assert RelocationType.Plt
        assert RelocationType.Tls
        assert RelocationType.Copy
        assert RelocationType.JumpSlot
        assert RelocationType.Relative
        assert RelocationType.Abs32
        assert RelocationType.Abs64
        assert RelocationType.Pc32
        assert RelocationType.Pc64
        assert RelocationType.GotPc
        assert RelocationType.PltPc
        assert RelocationType.TlsOffset
        assert RelocationType.TlsModule
        assert RelocationType.TlsModuleOffset
        assert RelocationType.Unknown

    def test_relocation_type_display(self):
        """Test string representation of RelocationType."""
        assert str(RelocationType.Absolute) == "Absolute"
        assert str(RelocationType.PcRelative) == "PcRelative"
        assert str(RelocationType.Got) == "Got"
        assert str(RelocationType.Plt) == "Plt"
        assert str(RelocationType.Tls) == "Tls"
        assert str(RelocationType.Unknown) == "Unknown"


class TestRelocationCreation:
    """Test Relocation creation and basic functionality."""

    def test_relocation_creation_minimal(self):
        """Test creating a minimal Relocation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation("reloc_1", address, RelocationType.Absolute)

        assert relocation.id == "reloc_1"
        assert str(relocation.kind) == "Absolute"
        assert relocation.address.value == 0x400000
        assert relocation.value is None
        assert relocation.symbol is None
        assert relocation.addend is None
        assert relocation.size is None
        assert relocation.effective_size() == 4
        assert not relocation.is_resolved()
        assert not relocation.has_symbol()
        assert not relocation.has_addend()

    def test_relocation_creation_full(self):
        """Test creating a Relocation with all fields."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "reloc_2",
            address,
            RelocationType.PcRelative,
            value=0x1000,
            symbol="target_function",
            addend=8,
            size=8,
        )

        assert relocation.id == "reloc_2"
        assert str(relocation.kind) == "PcRelative"
        assert relocation.value == 0x1000
        assert relocation.symbol == "target_function"
        assert relocation.addend == 8
        assert relocation.size == 8
        assert relocation.effective_size() == 8
        assert relocation.is_resolved()
        assert relocation.has_symbol()
        assert relocation.has_addend()

    def test_relocation_creation_with_symbol_only(self):
        """Test creating a Relocation with symbol but no value."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "reloc_3", address, RelocationType.Plt, symbol="external_func"
        )

        assert str(relocation.kind) == "Plt"
        assert relocation.symbol == "external_func"
        assert relocation.value is None
        assert not relocation.is_resolved()
        assert relocation.has_symbol()

    def test_relocation_creation_with_value_only(self):
        """Test creating a Relocation with value but no symbol."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "reloc_4", address, RelocationType.Absolute, value=0x2000
        )

        assert str(relocation.kind) == "Absolute"
        assert relocation.value == 0x2000
        assert relocation.symbol is None
        assert relocation.is_resolved()
        assert not relocation.has_symbol()


class TestRelocationTypeChecks:
    """Test Relocation type checking methods."""

    def test_absolute_relocation_types(self):
        """Test absolute relocation type detection."""
        abs_reloc = Relocation(
            "abs", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Absolute
        )
        abs32_reloc = Relocation(
            "abs32", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Abs32
        )
        abs64_reloc = Relocation(
            "abs64", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Abs64
        )

        assert abs_reloc.is_absolute()
        assert abs32_reloc.is_absolute()
        assert abs64_reloc.is_absolute()

    def test_pc_relative_relocation_types(self):
        """Test PC-relative relocation type detection."""
        pc_reloc = Relocation(
            "pc", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.PcRelative
        )
        pc32_reloc = Relocation(
            "pc32", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Pc32
        )
        pc64_reloc = Relocation(
            "pc64", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Pc64
        )

        assert pc_reloc.is_pc_relative()
        assert pc32_reloc.is_pc_relative()
        assert pc64_reloc.is_pc_relative()

    def test_got_related_relocation_types(self):
        """Test GOT-related relocation type detection."""
        got_reloc = Relocation(
            "got", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Got
        )
        gotpc_reloc = Relocation(
            "gotpc", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.GotPc
        )

        assert got_reloc.is_got_related()
        assert gotpc_reloc.is_got_related()

    def test_plt_related_relocation_types(self):
        """Test PLT-related relocation type detection."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        plt_reloc = Relocation("plt", address, RelocationType.Plt)
        pltpc_reloc = Relocation(
            "pltpc", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.PltPc
        )
        jumpslot_reloc = Relocation(
            "jumpslot",
            Address(AddressKind.VA, 0x400000, bits=64),
            RelocationType.JumpSlot,
        )

        assert plt_reloc.is_plt_related()
        assert pltpc_reloc.is_plt_related()
        assert jumpslot_reloc.is_plt_related()

    def test_tls_related_relocation_types(self):
        """Test TLS-related relocation type detection."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        tls_reloc = Relocation("tls", address, RelocationType.Tls)
        tls_offset_reloc = Relocation(
            "tls_offset",
            Address(AddressKind.VA, 0x400000, bits=64),
            RelocationType.TlsOffset,
        )
        tls_module_reloc = Relocation(
            "tls_module",
            Address(AddressKind.VA, 0x400000, bits=64),
            RelocationType.TlsModule,
        )
        tls_module_offset_reloc = Relocation(
            "tls_module_offset",
            Address(AddressKind.VA, 0x400000, bits=64),
            RelocationType.TlsModuleOffset,
        )

        assert tls_reloc.is_tls_related()
        assert tls_offset_reloc.is_tls_related()
        assert tls_module_reloc.is_tls_related()
        assert tls_module_offset_reloc.is_tls_related()

    def test_non_matching_relocation_types(self):
        """Test that relocation types don't match incorrect categories."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        abs_reloc = Relocation("abs", address, RelocationType.Absolute)
        pc_reloc = Relocation(
            "pc", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.PcRelative
        )
        got_reloc = Relocation(
            "got", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Got
        )
        plt_reloc = Relocation(
            "plt", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Plt
        )
        tls_reloc = Relocation(
            "tls", Address(AddressKind.VA, 0x400000, bits=64), RelocationType.Tls
        )

        # Test negative cases
        assert not abs_reloc.is_pc_relative()
        assert not pc_reloc.is_absolute()
        assert not got_reloc.is_plt_related()
        assert not plt_reloc.is_got_related()
        assert not tls_reloc.is_absolute()


class TestRelocationAddressCalculation:
    """Test Relocation address calculation methods."""

    def test_calculate_absolute_relocation(self):
        """Test calculating address for absolute relocation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "abs_calc", address, RelocationType.Absolute, value=0x1000, addend=0x10
        )

        result = relocation.calculate_relocated_address(0)
        assert result is not None and result == 0x1010

    def test_calculate_pc_relative_relocation(self):
        """Test calculating address for PC-relative relocation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "pc_calc", address, RelocationType.PcRelative, value=0x100, addend=4
        )

        result = relocation.calculate_relocated_address(0)
        assert result == 0x400104

    def test_calculate_relative_relocation(self):
        """Test calculating address for relative relocation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "rel_calc", address, RelocationType.Relative, value=0x200, addend=8
        )

        result = relocation.calculate_relocated_address(0x1000)
        assert result == 0x1208

    def test_calculate_without_value(self):
        """Test calculating address when no value is set."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation("no_value", address, RelocationType.Absolute)

        result = relocation.calculate_relocated_address(0)
        assert result is None

    def test_calculate_unknown_relocation_type(self):
        """Test calculating address for unknown relocation type."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "unknown", address, RelocationType.Unknown, value=0x1000
        )

        result = relocation.calculate_relocated_address(0)
        assert result == 0x1000  # Should use fallback calculation


class TestRelocationDescription:
    """Test Relocation description generation."""

    def test_description_minimal(self):
        """Test description for minimal relocation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation("minimal", address, RelocationType.Absolute)

        desc = relocation.description()
        assert "minimal" in desc
        assert "VA:400000" in desc
        assert "Absolute" in desc

    def test_description_with_symbol(self):
        """Test description for relocation with symbol."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "with_symbol", address, RelocationType.Plt, symbol="external_function"
        )

        desc = relocation.description()
        assert "with_symbol" in desc
        assert "Plt" in desc
        assert "external_function" in desc

    def test_description_with_value(self):
        """Test description for relocation with value."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "with_value", address, RelocationType.Absolute, value=0x1000
        )

        desc = relocation.description()
        assert "with_value" in desc
        assert "Absolute" in desc
        assert "value: 0x1000" in desc

    def test_description_with_addend(self):
        """Test description for relocation with addend."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "with_addend", address, RelocationType.PcRelative, value=0x100, addend=8
        )

        desc = relocation.description()
        assert "with_addend" in desc
        assert "PcRelative" in desc
        assert "value: 0x100" in desc
        assert "addend: 8" in desc

    def test_description_zero_addend_omitted(self):
        """Test that zero addend is omitted from description."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "zero_addend", address, RelocationType.Absolute, value=0x1000, addend=0
        )

        desc = relocation.description()
        assert "addend:" not in desc

    def test_description_complete(self):
        """Test description for relocation with all fields."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "complete",
            address,
            RelocationType.Got,
            value=0x2000,
            symbol="global_var",
            addend=16,
        )

        desc = relocation.description()
        assert "complete" in desc
        assert "Got" in desc
        assert "global_var" in desc
        assert "value: 0x2000" in desc
        assert "addend: 16" in desc


class TestRelocationDisplay:
    """Test Relocation string representation."""

    def test_display_without_symbol(self):
        """Test display for relocation without symbol."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation("no_symbol", address, RelocationType.Absolute)

        display = str(relocation)
        assert display == "Relocation 'no_symbol' (Absolute)"

    def test_display_with_symbol(self):
        """Test display for relocation with symbol."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        relocation = Relocation(
            "with_symbol", address, RelocationType.Plt, symbol="external_func"
        )

        display = str(relocation)
        assert display == "Relocation 'with_symbol' (Plt -> external_func)"

    def test_display_different_relocation_types(self):
        """Test display for different relocation types."""
        base_address = Address(AddressKind.VA, 0x400000, bits=64)

        types_and_symbols = [
            (RelocationType.Absolute, "abs_func"),
            (RelocationType.PcRelative, "pc_func"),
            (RelocationType.Got, "got_var"),
            (RelocationType.Plt, "plt_func"),
            (RelocationType.Tls, "tls_var"),
        ]

        for reloc_type, symbol in types_and_symbols:
            # Create a new address instance for each relocation
            address = Address(
                base_address.kind, base_address.value, bits=base_address.bits
            )
            relocation = Relocation(
                f"test_{reloc_type}", address, reloc_type, symbol=symbol
            )

            display = str(relocation)
            assert f"({reloc_type} -> {symbol})" in display


class TestRelocationEdgeCases:
    """Test edge cases and special scenarios."""

    def test_relocation_different_address_kinds(self):
        """Test relocation with different address kinds."""
        va_address = Address(AddressKind.VA, 0x400000, bits=64)
        rva_address = Address(AddressKind.RVA, 0x1000, bits=32)
        file_address = Address(AddressKind.FileOffset, 0x2000, bits=64)

        va_reloc = Relocation("va_reloc", va_address, RelocationType.Absolute)
        rva_reloc = Relocation("rva_reloc", rva_address, RelocationType.PcRelative)
        file_reloc = Relocation("file_reloc", file_address, RelocationType.Got)

        assert va_reloc.address.kind == AddressKind.VA
        assert rva_reloc.address.kind == AddressKind.RVA
        assert file_reloc.address.kind == AddressKind.FileOffset

    def test_relocation_large_values(self):
        """Test relocation with large values."""
        base_address = Address(AddressKind.VA, 0x400000, bits=64)

        large_value_reloc = Relocation(
            "large_value",
            Address(base_address.kind, base_address.value, bits=base_address.bits),
            RelocationType.Absolute,
            value=0xFFFFFFFFFFFFFFFF,  # Max u64
        )

        large_addend_reloc = Relocation(
            "large_addend",
            Address(base_address.kind, base_address.value, bits=base_address.bits),
            RelocationType.PcRelative,
            value=0x1000,
            addend=0x7FFFFFFFFFFFFFFF,  # Large positive addend
        )

        assert large_value_reloc.value == 0xFFFFFFFFFFFFFFFF
        assert large_addend_reloc.addend == 0x7FFFFFFFFFFFFFFF

    def test_relocation_negative_addend(self):
        """Test relocation with negative addend."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        neg_addend_reloc = Relocation(
            "neg_addend", address, RelocationType.Absolute, value=0x1000, addend=-8
        )

        assert neg_addend_reloc.addend == -8

    def test_relocation_all_sizes(self):
        """Test relocation with different sizes."""
        base_address = Address(AddressKind.VA, 0x400000, bits=64)

        sizes = [1, 2, 4, 8, 16]
        for size in sizes:
            address = Address(
                base_address.kind, base_address.value, bits=base_address.bits
            )
            relocation = Relocation(
                f"size_{size}", address, RelocationType.Absolute, size=size
            )
            assert relocation.effective_size() == size

    def test_relocation_default_size(self):
        """Test relocation default size when not specified."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        default_size_reloc = Relocation(
            "default_size", address, RelocationType.Absolute
        )

        assert default_size_reloc.size is None
        assert default_size_reloc.effective_size() == 4

    def test_relocation_symbol_edge_cases(self):
        """Test relocation with edge case symbol names."""
        base_address = Address(AddressKind.VA, 0x400000, bits=64)

        # Empty symbol name
        empty_symbol_reloc = Relocation(
            "empty_symbol",
            Address(base_address.kind, base_address.value, bits=base_address.bits),
            RelocationType.Plt,
            symbol="",
        )
        assert empty_symbol_reloc.symbol == ""
        assert empty_symbol_reloc.has_symbol()

        # Very long symbol name
        long_symbol = "a" * 1000
        long_symbol_reloc = Relocation(
            "long_symbol",
            Address(base_address.kind, base_address.value, bits=base_address.bits),
            RelocationType.Got,
            symbol=long_symbol,
        )
        assert len(long_symbol_reloc.symbol) == 1000
        assert long_symbol_reloc.symbol == long_symbol

    def test_relocation_calculate_edge_cases(self):
        """Test address calculation edge cases."""
        base_address = Address(AddressKind.VA, 0x400000, bits=64)

        # Test with None addend (should default to 0)
        no_addend_reloc = Relocation(
            "no_addend",
            Address(base_address.kind, base_address.value, bits=base_address.bits),
            RelocationType.Absolute,
            value=0x1000,
        )

        result = no_addend_reloc.calculate_relocated_address(0)
        assert result == 0x1000

        # Test with very large address values
        large_address = Address(AddressKind.VA, 0xFFFFFFFFFFFFFFFF, bits=64)
        large_addr_reloc = Relocation(
            "large_addr", large_address, RelocationType.PcRelative, value=0x100
        )

        result = large_addr_reloc.calculate_relocated_address(0)
        assert result == (0xFFFFFFFFFFFFFFFF + 0x100) % (2**64)  # wrapping addition
