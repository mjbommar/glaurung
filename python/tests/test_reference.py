"""Tests for Reference type - represents cross-references in binary analysis."""

from glaurung import (
    Address,
    AddressKind,
    Reference,
    ReferenceKind,
    ReferenceTarget,
    UnresolvedReferenceKind,
)


class TestReferenceCreation:
    """Test Reference creation and validation."""

    def test_create_resolved_reference(self):
        """Test creating a resolved reference."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)
        to_addr = Address(AddressKind.VA, 0x402000, bits=32)

        ref = Reference.resolved(
            id="ref_1",
            from_addr=from_addr,
            to=to_addr,
            kind=ReferenceKind.Call,
            source="test_tool",
        )

        assert ref.id == "ref_1"
        assert ref.from_addr.value == 0x401000
        assert "Resolved" in type(ref.to).__name__
        assert ref.source == "test_tool"
        # Test that we can access the reference without errors
        assert ref is not None

    def test_create_unresolved_reference(self):
        """Test creating an unresolved reference."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)

        ref = Reference.unresolved(
            id="ref_2",
            from_addr=from_addr,
            unresolved_kind=UnresolvedReferenceKind.Indirect,
            expression="eax + 8",
            ref_kind=ReferenceKind.Read,
            source="test_tool",
        )

        assert ref.id == "ref_2"
        assert ref.from_addr.value == 0x401000
        assert "Unresolved" in type(ref.to).__name__
        assert ref.source == "test_tool"
        # Test that we can access the reference without errors
        assert ref is not None

    def test_create_reference_with_full_parameters(self):
        """Test creating a reference with all parameters."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)
        to_addr = Address(AddressKind.VA, 0x402000, bits=32)
        target = ReferenceTarget.Resolved(to_addr)

        ref = Reference(
            id="ref_3",
            from_addr=from_addr,
            to=target,
            kind=ReferenceKind.Jump,
            width=32,
            confidence=0.95,
            source="disassembler",
        )

        assert ref.id == "ref_3"
        assert ref.width == 32
        assert abs(ref.confidence - 0.95) < 0.01  # Allow for floating point precision
        assert ref.source == "disassembler"


class TestReferenceSerialization:
    """Test Reference serialization/deserialization."""

    def test_json_serialization_round_trip(self):
        """Test JSON serialization round-trip."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)
        to_addr = Address(AddressKind.VA, 0x402000, bits=32)

        original_ref = Reference.resolved(
            id="ref_json",
            from_addr=from_addr,
            to=to_addr,
            kind=ReferenceKind.Call,
            source="test_tool",
        )

        # Serialize to JSON
        json_str = original_ref.to_json()

        # Deserialize from JSON
        restored_ref = Reference.from_json(json_str)

        assert restored_ref.id == original_ref.id
        assert restored_ref.from_addr.value == original_ref.from_addr.value
        assert type(restored_ref.to).__name__ == type(original_ref.to).__name__
        assert restored_ref.source == original_ref.source

    def test_binary_serialization_round_trip(self):
        """Test binary serialization round-trip."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)

        original_ref = Reference.unresolved(
            id="ref_bin",
            from_addr=from_addr,
            unresolved_kind=UnresolvedReferenceKind.Dynamic,
            expression="runtime_resolve",
            ref_kind=ReferenceKind.Jump,
            source="test_tool",
        )

        # Serialize to binary
        bin_data = original_ref.to_binary()

        # Deserialize from binary
        restored_ref = Reference.from_binary(bin_data)

        assert restored_ref.id == original_ref.id
        assert restored_ref.from_addr.value == original_ref.from_addr.value
        assert type(restored_ref.to).__name__ == type(original_ref.to).__name__
        assert restored_ref.source == original_ref.source


class TestReferenceTarget:
    """Test ReferenceTarget enum."""

    def test_resolved_target(self):
        """Test resolved reference target."""
        addr = Address(AddressKind.VA, 0x402000, bits=32)
        target = ReferenceTarget.Resolved(addr)

        assert "Resolved" in type(target).__name__

    def test_unresolved_target(self):
        """Test unresolved reference target."""
        target = ReferenceTarget.Unresolved(
            UnresolvedReferenceKind.Indirect, "eax + offset"
        )

        assert "Unresolved" in type(target).__name__


class TestReferenceKind:
    """Test ReferenceKind enum."""

    def test_reference_kind_values(self):
        """Test all reference kind values."""
        # Just test that we can access the enum variants
        assert ReferenceKind.Call is not None
        assert ReferenceKind.Jump is not None
        assert ReferenceKind.Branch is not None
        assert ReferenceKind.Return is not None
        assert ReferenceKind.Read is not None
        assert ReferenceKind.Write is not None
        assert ReferenceKind.Reloc is not None
        assert ReferenceKind.DataRef is not None
        assert ReferenceKind.Tail is not None


class TestUnresolvedReferenceKind:
    """Test UnresolvedReferenceKind enum."""

    def test_unresolved_reference_kind_values(self):
        """Test all unresolved reference kind values."""
        # Just test that we can access the enum variants
        assert UnresolvedReferenceKind.Dynamic is not None
        assert UnresolvedReferenceKind.Indirect is not None
        assert UnresolvedReferenceKind.External is not None
        assert UnresolvedReferenceKind.Unknown is not None


class TestReferenceStringRepresentation:
    """Test string representations of Reference."""

    def test_resolved_reference_str(self):
        """Test string representation of resolved reference."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)
        to_addr = Address(AddressKind.VA, 0x402000, bits=32)

        ref = Reference.resolved(
            id="ref_str",
            from_addr=from_addr,
            to=to_addr,
            kind=ReferenceKind.Call,
            source="test_tool",
        )

        str_repr = str(ref)
        assert "ref_str@0x401000 -> 0x402000" in str_repr

    def test_unresolved_reference_str(self):
        """Test string representation of unresolved reference."""
        from_addr = Address(AddressKind.VA, 0x401000, bits=32)

        ref = Reference.unresolved(
            id="ref_str2",
            from_addr=from_addr,
            unresolved_kind=UnresolvedReferenceKind.Indirect,
            expression=None,
            ref_kind=ReferenceKind.Read,
            source="test_tool",
        )

        str_repr = str(ref)
        assert "ref_str2@0x401000 -> indirect" in str_repr
