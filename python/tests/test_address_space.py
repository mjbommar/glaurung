import pytest
from glaurung import AddressSpace, AddressSpaceKind


class TestAddressSpaceCreation:
    """Test AddressSpace creation and validation."""

    def test_create_default_address_space(self):
        """Test creating a default address space."""
        space = AddressSpace("default", AddressSpaceKind.Default, size=0x1000000)
        assert space.name == "default"
        assert space.kind == AddressSpaceKind.Default
        assert space.size == 0x1000000
        assert space.base_space is None
        assert space.is_valid_py()

    def test_create_overlay_address_space(self):
        """Test creating an overlay address space."""
        space = AddressSpace(
            "overlay1", AddressSpaceKind.Overlay, size=0x1000, base_space="default"
        )
        assert space.name == "overlay1"
        assert space.kind == AddressSpaceKind.Overlay
        assert space.size == 0x1000
        assert space.base_space == "default"
        assert space.is_valid_py()
        assert space.is_overlay()
        assert space.has_base_space()

    def test_create_stack_address_space(self):
        """Test creating a stack address space."""
        space = AddressSpace("stack", AddressSpaceKind.Stack, size=0x100000)
        assert space.name == "stack"
        assert space.kind == AddressSpaceKind.Stack
        assert space.size == 0x100000
        assert not space.is_overlay()
        assert not space.has_base_space()

    def test_create_heap_address_space(self):
        """Test creating a heap address space."""
        space = AddressSpace("heap", AddressSpaceKind.Heap)
        assert space.name == "heap"
        assert space.kind == AddressSpaceKind.Heap
        assert space.size is None
        assert space.effective_size is None

    def test_create_mmio_address_space(self):
        """Test creating an MMIO address space."""
        space = AddressSpace("mmio", AddressSpaceKind.MMIO, size=0x1000)
        assert space.name == "mmio"
        assert space.kind == AddressSpaceKind.MMIO
        assert space.size == 0x1000

    def test_create_other_address_space(self):
        """Test creating a custom/other address space."""
        space = AddressSpace("custom", AddressSpaceKind.Other, size=0x2000)
        assert space.name == "custom"
        assert space.kind == AddressSpaceKind.Other
        assert space.size == 0x2000

    def test_empty_name_rejected(self):
        """Test that empty names are rejected."""
        with pytest.raises(ValueError, match="name cannot be empty"):
            AddressSpace("", AddressSpaceKind.Default)

    def test_whitespace_name_rejected(self):
        """Test that whitespace-only names are rejected."""
        with pytest.raises(ValueError, match="name cannot be empty"):
            AddressSpace("   ", AddressSpaceKind.Default)

    def test_zero_size_rejected(self):
        """Test that zero size is rejected."""
        with pytest.raises(ValueError, match="size cannot be 0"):
            AddressSpace("test", AddressSpaceKind.Default, size=0)

    def test_overlay_without_base_space_rejected(self):
        """Test that overlay spaces require base_space."""
        with pytest.raises(
            ValueError, match="overlay address spaces must have a base_space"
        ):
            AddressSpace("overlay1", AddressSpaceKind.Overlay)


class TestAddressSpaceValidation:
    """Test AddressSpace validation."""

    def test_valid_address_spaces(self):
        """Test that valid address spaces pass validation."""
        test_cases = [
            ("default", AddressSpaceKind.Default, 0x1000000, None),
            ("overlay1", AddressSpaceKind.Overlay, 0x1000, "default"),
            ("stack", AddressSpaceKind.Stack, 0x100000, None),
            ("heap", AddressSpaceKind.Heap, None, None),
            ("mmio", AddressSpaceKind.MMIO, 0x1000, None),
            ("custom", AddressSpaceKind.Other, 0x2000, None),
        ]

        for name, kind, size, base_space in test_cases:
            space = AddressSpace(name, kind, size=size, base_space=base_space)
            assert space.is_valid_py(), f"AddressSpace should be valid: {space}"

    def test_overlay_validation(self):
        """Test overlay-specific validation."""
        # Valid overlay
        space = AddressSpace("overlay1", AddressSpaceKind.Overlay, base_space="default")
        assert space.is_overlay()
        assert space.has_base_space()

        # Invalid overlay without base_space
        with pytest.raises(ValueError):
            AddressSpace("overlay2", AddressSpaceKind.Overlay)

    def test_size_validation(self):
        """Test size validation."""
        # Valid sizes
        space1 = AddressSpace("test1", AddressSpaceKind.Default, size=1)
        assert space1.is_valid_py()

        space2 = AddressSpace(
            "test2", AddressSpaceKind.Default, size=0xFFFF_FFFF_FFFF_FFFF
        )
        assert space2.is_valid_py()

        # Invalid sizes
        with pytest.raises(ValueError):
            AddressSpace("test3", AddressSpaceKind.Default, size=0)


class TestAddressSpaceMethods:
    """Test AddressSpace methods."""

    def test_is_overlay_method(self):
        """Test the is_overlay method."""
        default_space = AddressSpace("default", AddressSpaceKind.Default)
        assert not default_space.is_overlay()

        overlay_space = AddressSpace(
            "overlay1", AddressSpaceKind.Overlay, base_space="default"
        )
        assert overlay_space.is_overlay()

    def test_has_base_space_method(self):
        """Test the has_base_space method."""
        space_without_base = AddressSpace("default", AddressSpaceKind.Default)
        assert not space_without_base.has_base_space()

        space_with_base = AddressSpace(
            "overlay1", AddressSpaceKind.Overlay, base_space="default"
        )
        assert space_with_base.has_base_space()

    def test_effective_size_method(self):
        """Test the effective_size method."""
        space_with_size = AddressSpace("test1", AddressSpaceKind.Default, size=0x1000)
        assert space_with_size.effective_size == 0x1000

        space_without_size = AddressSpace("test2", AddressSpaceKind.Heap)
        assert space_without_size.effective_size is None


class TestAddressSpaceRepresentation:
    """Test AddressSpace string representations."""

    def test_str_representation(self):
        """Test string representation of address spaces."""
        space = AddressSpace("default", AddressSpaceKind.Default, size=0x1000000)
        assert str(space) == "default:Default (size: 16777216)"

    def test_str_overlay_representation(self):
        """Test string representation of overlay spaces."""
        space = AddressSpace(
            "overlay1", AddressSpaceKind.Overlay, size=0x1000, base_space="default"
        )
        assert str(space) == "overlay1:Overlay (size: 4096) -> default"

    def test_str_without_size(self):
        """Test string representation without size."""
        space = AddressSpace("heap", AddressSpaceKind.Heap)
        assert str(space) == "heap:Heap"

    def test_repr_representation(self):
        """Test repr representation of address spaces."""
        space = AddressSpace("default", AddressSpaceKind.Default, size=0x1000000)
        expected = (
            "AddressSpace(name='default', kind=AddressSpaceKind.Default, size=16777216)"
        )
        assert repr(space) == expected

    def test_repr_with_base_space(self):
        """Test repr representation with base_space."""
        space = AddressSpace("overlay1", AddressSpaceKind.Overlay, base_space="default")
        expected = "AddressSpace(name='overlay1', kind=AddressSpaceKind.Overlay, base_space='default')"
        assert repr(space) == expected

    def test_repr_minimal(self):
        """Test repr representation with minimal fields."""
        space = AddressSpace("heap", AddressSpaceKind.Heap)
        expected = "AddressSpace(name='heap', kind=AddressSpaceKind.Heap)"
        assert repr(space) == expected


class TestAddressSpaceKind:
    """Test AddressSpaceKind enum."""

    def test_address_space_kind_str(self):
        """Test string representation of AddressSpaceKind."""
        assert str(AddressSpaceKind.Default) == "Default"
        assert str(AddressSpaceKind.Overlay) == "Overlay"
        assert str(AddressSpaceKind.Stack) == "Stack"
        assert str(AddressSpaceKind.Heap) == "Heap"
        assert str(AddressSpaceKind.MMIO) == "MMIO"
        assert str(AddressSpaceKind.Other) == "Other"

    def test_address_space_kind_repr(self):
        """Test repr representation of AddressSpaceKind."""
        assert repr(AddressSpaceKind.Default) == "AddressSpaceKind.Default"
        assert repr(AddressSpaceKind.Overlay) == "AddressSpaceKind.Overlay"
        assert repr(AddressSpaceKind.Stack) == "AddressSpaceKind.Stack"
        assert repr(AddressSpaceKind.Heap) == "AddressSpaceKind.Heap"
        assert repr(AddressSpaceKind.MMIO) == "AddressSpaceKind.MMIO"
        assert repr(AddressSpaceKind.Other) == "AddressSpaceKind.Other"


class TestAddressSpaceEdgeCases:
    """Test AddressSpace edge cases."""

    def test_large_size_values(self):
        """Test address spaces with large size values."""
        space = AddressSpace(
            "large", AddressSpaceKind.Default, size=0xFFFF_FFFF_FFFF_FFFF
        )
        assert space.size == 0xFFFF_FFFF_FFFF_FFFF
        assert space.is_valid_py()

    def test_unicode_names(self):
        """Test address spaces with Unicode names."""
        space = AddressSpace("тест", AddressSpaceKind.Default)
        assert space.name == "тест"
        assert space.is_valid_py()

    def test_long_names(self):
        """Test address spaces with long names."""
        long_name = "a" * 1000
        space = AddressSpace(long_name, AddressSpaceKind.Default)
        assert space.name == long_name
        assert space.is_valid_py()

    def test_special_characters_in_names(self):
        """Test address spaces with special characters in names."""
        space = AddressSpace("space.with.dots", AddressSpaceKind.Default)
        assert space.name == "space.with.dots"
        assert space.is_valid_py()

    def test_base_space_references(self):
        """Test various base_space reference patterns."""
        test_cases = [
            "default",
            "ram",
            "rom",
            "segment_1",
            "overlay_base",
        ]

        for base in test_cases:
            space = AddressSpace(
                f"overlay_{base}", AddressSpaceKind.Overlay, base_space=base
            )
            assert space.base_space == base
            assert space.is_valid_py()
