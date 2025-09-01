"""Tests for the Segment type."""

import pytest
from glaurung import Segment, Perms, Address, AddressKind, AddressRange


class TestSegmentCreation:
    """Test segment creation and basic functionality."""

    def test_segment_creation_minimal(self):
        """Test creating a minimal segment."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000, alignment=0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=True)

        segment = Segment(
            "text_segment",
            range_obj,
            perms,
            file_offset,
            name=".text",
            alignment=0x1000,
        )

        assert segment.id == "text_segment"
        assert segment.name == ".text"
        assert segment.size() == 0x1000
        assert segment.is_code_segment()
        assert not segment.is_data_segment()
        assert not segment.is_readonly()

    def test_segment_creation_with_all_fields(self):
        """Test creating a segment with all optional fields."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x2000, alignment=0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=True, execute=False)

        segment = Segment(
            "data_segment",
            range_obj,
            perms,
            file_offset,
            name=".data",
            alignment=0x1000,
        )

        assert segment.id == "data_segment"
        assert segment.name == ".data"
        assert segment.size() == 0x2000
        assert segment.is_data_segment()

    def test_segment_validation_file_offset_kind(self):
        """Test that file_offset must have correct AddressKind."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        invalid_file_offset = Address(AddressKind.VA, 0x1000, bits=64)  # Wrong kind
        perms = Perms(read=True, write=False, execute=True)

        with pytest.raises(
            ValueError, match="file_offset must have AddressKind::FileOffset"
        ):
            Segment(
                "test",
                range_obj,
                perms,
                invalid_file_offset,
                name=".test",
            )

    def test_segment_validation_range_kind(self):
        """Test that range addresses must have correct AddressKind."""
        start = Address(AddressKind.Physical, 0x400000, bits=64)  # Wrong kind
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=True)

        with pytest.raises(
            ValueError, match="range addresses must have AddressKind::VA for segments"
        ):
            Segment(
                "test",
                range_obj,
                perms,
                file_offset,
                name=".test",
            )


class TestSegmentPermissions:
    """Test segment permission handling."""

    def test_code_segment_permissions(self):
        """Test code segment permission detection."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=True)

        segment = Segment(
            "code",
            range_obj,
            perms,
            file_offset,
            name=".text",
        )

        assert segment.is_code_segment()
        assert not segment.is_data_segment()
        assert not segment.is_readonly()

    def test_data_segment_permissions(self):
        """Test data segment permission detection."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=True, execute=False)

        segment = Segment(
            "data",
            range_obj,
            perms,
            file_offset,
            name=".data",
        )

        assert not segment.is_code_segment()
        assert segment.is_data_segment()
        assert not segment.is_readonly()

    def test_readonly_segment_permissions(self):
        """Test readonly segment permission detection."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=False)

        segment = Segment(
            "rodata",
            range_obj,
            perms,
            file_offset,
            name=".rodata",
        )

        assert not segment.is_code_segment()
        assert not segment.is_data_segment()
        assert segment.is_readonly()


class TestPerms:
    """Test the Perms type."""

    def test_perms_creation(self):
        """Test creating permission objects."""
        perms = Perms(read=True, write=False, execute=True)
        assert perms.has_read()
        assert not perms.has_write()
        assert perms.has_execute()

    def test_perms_display(self):
        """Test permission string representation."""
        perms = Perms(read=True, write=False, execute=True)
        assert str(perms) == "r-x"

        perms_all = Perms(read=True, write=True, execute=True)
        assert str(perms_all) == "rwx"

        perms_none = Perms(read=False, write=False, execute=False)
        assert str(perms_none) == "---"

    def test_perms_methods(self):
        """Test permission checking methods."""
        code_perms = Perms(read=True, write=False, execute=True)
        assert code_perms.is_code()
        assert not code_perms.is_data()
        assert not code_perms.is_readonly()

        data_perms = Perms(read=True, write=True, execute=False)
        assert not data_perms.is_code()
        assert data_perms.is_data()
        assert not data_perms.is_readonly()

        ro_perms = Perms(read=True, write=False, execute=False)
        assert not ro_perms.is_code()
        assert not ro_perms.is_data()
        assert ro_perms.is_readonly()


class TestSegmentOperations:
    """Test segment operations and properties."""

    def test_segment_size(self):
        """Test segment size calculation."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x2000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=True)

        segment = Segment(
            "test",
            range_obj,
            perms,
            file_offset,
            name=".test",
        )

        assert segment.size() == 0x2000

    def test_segment_description(self):
        """Test segment description generation."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=True)

        segment = Segment(
            "text_seg",
            range_obj,
            perms,
            file_offset,
            name=".text",
        )

        desc = segment.description()
        assert ".text" in desc
        assert "text_seg" in desc
        assert "r-x" in desc

    def test_segment_display(self):
        """Test segment string representation."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = Perms(read=True, write=False, execute=True)

        segment = Segment(
            "text_seg",
            range_obj,
            perms,
            file_offset,
            name=".text",
        )

        assert str(segment) == "Segment '.text' (text_seg)"
