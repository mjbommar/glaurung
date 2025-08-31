"""Tests for the Section type."""

import pytest
from glaurung import (
    Section, SectionPerms, Address, AddressKind, AddressRange
)


class TestSectionCreation:
    """Test section creation and basic functionality."""

    def test_section_creation_minimal(self):
        """Test creating a minimal section."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000, alignment=0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "text_section",
            ".text",
            range_obj,
            file_offset,
            perms=perms,
            flags=0x6,  # ALLOC | EXEC
            section_type="PROGBITS",
        )

        assert section.id == "text_section"
        assert section.name == ".text"
        assert section.size() == 0x1000
        assert section.is_code_section()
        assert not section.is_data_section()
        assert not section.is_readonly()
        assert section.is_executable()
        assert not section.is_writable()

    def test_section_creation_with_optional_fields(self):
        """Test creating a section with optional fields."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x2000, alignment=0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)

        section = Section(
            "data_section",
            ".data",
            range_obj,
            file_offset,
            perms=None,
            flags=0x3,  # ALLOC | WRITE
            section_type="PROGBITS",
        )

        assert section.id == "data_section"
        assert section.name == ".data"
        assert section.size() == 0x2000
        assert not section.is_code_section()
        assert not section.is_data_section()
        assert not section.is_readonly()
        assert not section.is_executable()
        assert not section.is_writable()

    def test_section_creation_rva_range(self):
        """Test creating a section with RVA range (for PE files)."""
        start = Address(AddressKind.RVA, 0x1000, bits=32)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x200, bits=32)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "text_section",
            ".text",
            range_obj,
            file_offset,
            perms=perms,
            flags=0x60000020,  # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
        )

        assert section.id == "text_section"
        assert section.name == ".text"
        assert section.range.start.kind == AddressKind.RVA

    def test_section_validation_file_offset_kind(self):
        """Test that file_offset must have correct AddressKind."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        invalid_file_offset = Address(AddressKind.VA, 0x1000, bits=64)  # Wrong kind

        with pytest.raises(ValueError, match="file_offset must have AddressKind::FileOffset"):
            Section(
                "test",
                ".test",
                range_obj,
                invalid_file_offset,
            )

    def test_section_validation_range_kind(self):
        """Test that range addresses must have correct AddressKind."""
        start = Address(AddressKind.Physical, 0x400000, bits=64)  # Wrong kind
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)

        with pytest.raises(ValueError, match="range addresses must have AddressKind::VA or AddressKind::RVA for sections"):
            Section(
                "test",
                ".test",
                range_obj,
                file_offset,
            )


class TestSectionPermissions:
    """Test section permission handling."""

    def test_code_section_permissions(self):
        """Test code section permission detection."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "code",
            ".text",
            range_obj,
            file_offset,
            perms=perms,
        )

        assert section.is_code_section()
        assert not section.is_data_section()
        assert not section.is_readonly()
        assert section.is_executable()
        assert not section.is_writable()

    def test_data_section_permissions(self):
        """Test data section permission detection."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=True, execute=False)

        section = Section(
            "data",
            ".data",
            range_obj,
            file_offset,
            perms=perms,
        )

        assert not section.is_code_section()
        assert section.is_data_section()
        assert not section.is_readonly()
        assert not section.is_executable()
        assert section.is_writable()

    def test_readonly_section_permissions(self):
        """Test readonly section permission detection."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=False)

        section = Section(
            "rodata",
            ".rodata",
            range_obj,
            file_offset,
            perms=perms,
        )

        assert not section.is_code_section()
        assert not section.is_data_section()
        assert section.is_readonly()
        assert not section.is_executable()
        assert not section.is_writable()

    def test_section_without_permissions(self):
        """Test section behavior when no permissions are set."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)

        section = Section(
            "unknown",
            ".unknown",
            range_obj,
            file_offset,
            perms=None,
        )

        assert not section.is_code_section()
        assert not section.is_data_section()
        assert not section.is_readonly()
        assert not section.is_executable()
        assert not section.is_writable()


class TestSectionPerms:
    """Test the SectionPerms type."""

    def test_section_perms_creation(self):
        """Test creating section permission objects."""
        perms = SectionPerms(read=True, write=False, execute=True)
        assert perms.has_read()
        assert not perms.has_write()
        assert perms.has_execute()

    def test_section_perms_display(self):
        """Test section permission string representation."""
        perms = SectionPerms(read=True, write=False, execute=True)
        assert str(perms) == "r-x"

        perms_all = SectionPerms(read=True, write=True, execute=True)
        assert str(perms_all) == "rwx"

        perms_none = SectionPerms(read=False, write=False, execute=False)
        assert str(perms_none) == "---"

    def test_section_perms_methods(self):
        """Test section permission checking methods."""
        code_perms = SectionPerms(read=True, write=False, execute=True)
        assert code_perms.is_code()
        assert not code_perms.is_data()
        assert not code_perms.is_readonly()

        data_perms = SectionPerms(read=True, write=True, execute=False)
        assert not data_perms.is_code()
        assert data_perms.is_data()
        assert not data_perms.is_readonly()

        ro_perms = SectionPerms(read=True, write=False, execute=False)
        assert not ro_perms.is_code()
        assert not ro_perms.is_data()
        assert ro_perms.is_readonly()


class TestSectionOperations:
    """Test section operations and properties."""

    def test_section_size(self):
        """Test section size calculation."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x2000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "test",
            ".test",
            range_obj,
            file_offset,
            perms=perms,
        )

        assert section.size() == 0x2000

    def test_section_description(self):
        """Test section description generation."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "text_sec",
            ".text",
            range_obj,
            file_offset,
            perms=perms,
            section_type="PROGBITS",
        )

        desc = section.description()
        assert ".text" in desc
        assert "text_sec" in desc
        assert "r-x" in desc
        assert "PROGBITS" in desc

    def test_section_description_no_perms(self):
        """Test section description when no permissions are set."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)

        section = Section(
            "text_sec",
            ".text",
            range_obj,
            file_offset,
            perms=None,
            section_type="PROGBITS",
        )

        desc = section.description()
        assert ".text" in desc
        assert "text_sec" in desc
        assert "---" in desc
        assert "PROGBITS" in desc

    def test_section_description_no_type(self):
        """Test section description when no section type is set."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "text_sec",
            ".text",
            range_obj,
            file_offset,
            perms=perms,
            section_type=None,
        )

        desc = section.description()
        assert ".text" in desc
        assert "text_sec" in desc
        assert "r-x" in desc
        assert "unknown" in desc

    def test_section_display(self):
        """Test section string representation."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)
        perms = SectionPerms(read=True, write=False, execute=True)

        section = Section(
            "text_sec",
            ".text",
            range_obj,
            file_offset,
            perms=perms,
        )

        assert str(section) == "Section '.text' (text_sec)"


class TestSectionFlags:
    """Test section flags handling."""

    def test_section_flags_storage(self):
        """Test that section flags are properly stored."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)

        section = Section(
            "test",
            ".test",
            range_obj,
            file_offset,
            flags=0x60000020,  # Common PE flags
        )

        assert section.flags == 0x60000020

    def test_section_flags_default(self):
        """Test default flags value."""
        start = Address(AddressKind.VA, 0x400000, bits=64)
        range_obj = AddressRange(start, 0x1000)
        file_offset = Address(AddressKind.FileOffset, 0x1000, bits=64)

        section = Section(
            "test",
            ".test",
            range_obj,
            file_offset,
        )

        assert section.flags == 0