import pytest
from glaurung import Address, AddressKind, AddressRange


class TestAddressRangeCreation:
    """Test AddressRange creation and validation."""

    def test_create_address_range(self):
        """Test creating a basic address range."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        assert range_obj.start == start
        assert range_obj.size == 0x1000
        assert range_obj.end.value == 0x402000
        assert range_obj.is_valid_py()

    def test_create_address_range_with_alignment(self):
        """Test creating an address range with alignment."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000, alignment=0x1000)

        assert range_obj.alignment == 0x1000

    def test_zero_size_rejected(self):
        """Test that zero size is rejected."""
        start = Address(AddressKind.VA, 0x401000, 32)
        with pytest.raises(ValueError, match="size cannot be 0"):
            AddressRange(start, 0)

    def test_invalid_alignment_rejected(self):
        """Test that invalid alignment values are rejected."""
        start = Address(AddressKind.VA, 0x401000, 32)

        # Zero alignment
        with pytest.raises(ValueError, match="alignment must be a positive power of 2"):
            AddressRange(start, 0x1000, alignment=0)

        # Non-power-of-2 alignment
        with pytest.raises(ValueError, match="alignment must be a positive power of 2"):
            AddressRange(start, 0x1000, alignment=24)

    def test_overflow_rejected(self):
        """Test that size causing overflow is rejected."""
        start = Address(AddressKind.VA, 0xFFFF_FFFF, 32)
        with pytest.raises(ValueError, match="overflow"):
            AddressRange(start, 2)


class TestAddressRangeProperties:
    """Test AddressRange properties and string representations."""

    def test_end_property(self):
        """Test the end property."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        end = range_obj.end
        assert end.value == 0x402000
        assert end.kind == AddressKind.VA

    def test_string_representation(self):
        """Test string representation of address ranges."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        assert str(range_obj) == "[VA:401000, VA:402000)"

    def test_repr_representation(self):
        """Test repr representation of address ranges."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        repr_str = repr(range_obj)
        assert "AddressRange" in repr_str
        assert "4198400" in repr_str  # Decimal representation
        assert "4096" in repr_str

    def test_repr_with_alignment(self):
        """Test repr with alignment."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000, alignment=0x1000)

        repr_str = repr(range_obj)
        assert "alignment=4096" in repr_str


class TestAddressRangeOperations:
    """Test AddressRange operations like contains, overlaps, intersection."""

    def test_contains_address_within_range(self):
        """Test contains_address with address inside range."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        # Address in middle of range
        test_addr = Address(AddressKind.VA, 0x401500, 32)
        assert range_obj.contains_address(test_addr)

    def test_contains_address_at_start(self):
        """Test contains_address with address at range start (inclusive)."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        assert range_obj.contains_address(start)

    def test_contains_address_at_end(self):
        """Test contains_address with address at range end (exclusive)."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        end_addr = Address(AddressKind.VA, 0x402000, 32)
        assert not range_obj.contains_address(end_addr)

    def test_contains_address_outside_range(self):
        """Test contains_address with address outside range."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        outside_addr = Address(AddressKind.VA, 0x403000, 32)
        assert not range_obj.contains_address(outside_addr)

    def test_contains_address_different_kind(self):
        """Test contains_address with incompatible address kind."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        rva_addr = Address(AddressKind.RVA, 0x1500, 32)
        assert not range_obj.contains_address(rva_addr)

    def test_contains_address_different_bits(self):
        """Test contains_address with different bit width."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        addr_64 = Address(AddressKind.VA, 0x401500, 64)
        assert not range_obj.contains_address(addr_64)


class TestAddressRangeComparisons:
    """Test AddressRange comparison operations."""

    def test_contains_range_completely_contained(self):
        """Test contains_range with completely contained range."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        inner_start = Address(AddressKind.VA, 0x401200, 32)
        inner_range = AddressRange(inner_start, 0x800)

        assert range_obj.contains_range_py(inner_range)

    def test_contains_range_overlapping_not_contained(self):
        """Test contains_range with overlapping but not contained range."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        overlap_start = Address(AddressKind.VA, 0x400800, 32)
        overlap_range = AddressRange(overlap_start, 0x1000)

        assert not range_obj.contains_range_py(overlap_range)

    def test_contains_range_outside(self):
        """Test contains_range with completely outside range."""
        start = Address(AddressKind.VA, 0x401000, 32)
        range_obj = AddressRange(start, 0x1000)

        outside_start = Address(AddressKind.VA, 0x403000, 32)
        outside_range = AddressRange(outside_start, 0x1000)

        assert not range_obj.contains_range_py(outside_range)

    def test_overlaps_overlapping_ranges(self):
        """Test overlaps with overlapping ranges."""
        start1 = Address(AddressKind.VA, 0x401000, 32)
        range1 = AddressRange(start1, 0x1000)

        start2 = Address(AddressKind.VA, 0x400800, 32)
        range2 = AddressRange(start2, 0x1000)

        assert range1.overlaps_py(range2)
        assert range2.overlaps_py(range1)

    def test_overlaps_adjacent_ranges(self):
        """Test overlaps with adjacent (touching) ranges."""
        start1 = Address(AddressKind.VA, 0x401000, 32)
        range1 = AddressRange(start1, 0x1000)

        start2 = Address(AddressKind.VA, 0x402000, 32)
        range2 = AddressRange(start2, 0x1000)

        assert not range1.overlaps_py(range2)
        assert not range2.overlaps_py(range1)

    def test_overlaps_separate_ranges(self):
        """Test overlaps with completely separate ranges."""
        start1 = Address(AddressKind.VA, 0x401000, 32)
        range1 = AddressRange(start1, 0x1000)

        start2 = Address(AddressKind.VA, 0x403000, 32)
        range2 = AddressRange(start2, 0x1000)

        assert not range1.overlaps_py(range2)
        assert not range2.overlaps_py(range1)

    def test_intersection_overlapping(self):
        """Test intersection with overlapping ranges."""
        start1 = Address(AddressKind.VA, 0x401000, 32)
        range1 = AddressRange(start1, 0x1000)

        start2 = Address(AddressKind.VA, 0x400800, 32)
        range2 = AddressRange(start2, 0x1000)

        intersection = range1.intersection_py(range2)
        assert intersection is not None
        assert intersection.start.value == 0x401000
        assert intersection.size == 0x800

    def test_intersection_no_overlap(self):
        """Test intersection with non-overlapping ranges."""
        start1 = Address(AddressKind.VA, 0x401000, 32)
        range1 = AddressRange(start1, 0x1000)

        start2 = Address(AddressKind.VA, 0x403000, 32)
        range2 = AddressRange(start2, 0x1000)

        intersection = range1.intersection_py(range2)
        assert intersection is None


class TestAddressRangeValidation:
    """Test AddressRange validation."""

    def test_valid_ranges(self):
        """Test that valid ranges pass validation."""
        test_cases = [
            (AddressKind.VA, 0x401000, 32, 0x1000),
            (AddressKind.RVA, 0x1000, 32, 0x800),
            (AddressKind.FileOffset, 0x200, 32, 0x1000),
        ]

        for kind, start_val, bits, size in test_cases:
            start = Address(kind, start_val, bits)
            range_obj = AddressRange(start, size)
            assert range_obj.is_valid_py()

    def test_invalid_ranges(self):
        """Test that invalid ranges fail validation."""
        # This is tested through constructor validation
        # Invalid ranges cannot be created through the constructor
        pass


class TestAddressRangeEdgeCases:
    """Test AddressRange edge cases."""

    def test_large_ranges(self):
        """Test with large address ranges."""
        start = Address(AddressKind.VA, 0x1000_0000, 64)
        range_obj = AddressRange(start, 0x1000_0000)  # 256MB range

        assert range_obj.is_valid_py()
        assert range_obj.end.value == 0x2000_0000

    def test_16_bit_addresses(self):
        """Test with 16-bit addresses."""
        start = Address(AddressKind.VA, 0x1000, 16)
        range_obj = AddressRange(start, 0x1000)

        assert range_obj.is_valid_py()
        assert range_obj.end.value == 0x2000

    def test_64_bit_addresses(self):
        """Test with 64-bit addresses."""
        start = Address(AddressKind.VA, 0xFFFF_FFFF_FFFF_0000, 64)
        range_obj = AddressRange(start, 0x10000)

        assert range_obj.is_valid_py()
        # 0xFFFF_FFFF_FFFF_0000 + 0x10000 = 0xFFFF_FFFF_FFFF_FFFF + 1 = 0 (wrap around)
        assert range_obj.end.value == 0

    def test_max_64_bit_range(self):
        """Test maximum possible 64-bit range."""
        start = Address(AddressKind.VA, 0xFFFF_FFFF_FFFF_FFFF, 64)
        range_obj = AddressRange(start, 1)

        assert range_obj.is_valid_py()
        assert range_obj.end.value == 0  # Wraps around but still valid
