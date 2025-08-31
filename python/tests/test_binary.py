import pytest
from glaurung import (
    Binary, Format, Arch, Endianness, Hashes,
    Address, AddressKind
)


class TestFormat:
    """Test Format enum."""

    def test_format_values(self):
        """Test all format enum values."""
        assert Format.ELF == Format.ELF
        assert Format.PE == Format.PE
        assert Format.MachO == Format.MachO
        assert Format.Wasm == Format.Wasm
        assert Format.COFF == Format.COFF
        assert Format.Raw == Format.Raw
        assert Format.Unknown == Format.Unknown

    def test_format_string_representation(self):
        """Test string representations of formats."""
        assert str(Format.ELF) == "ELF"
        assert str(Format.PE) == "PE"
        assert str(Format.MachO) == "MachO"
        assert str(Format.Wasm) == "Wasm"
        assert str(Format.COFF) == "COFF"
        assert str(Format.Raw) == "Raw"
        assert str(Format.Unknown) == "Unknown"

    def test_format_repr(self):
        """Test repr representations of formats."""
        assert repr(Format.ELF) == "Format.ELF"
        assert repr(Format.PE) == "Format.PE"


class TestArch:
    """Test Arch enum."""

    def test_arch_values(self):
        """Test all architecture enum values."""
        assert Arch.X86 == Arch.X86
        assert Arch.X86_64 == Arch.X86_64
        assert Arch.ARM == Arch.ARM
        assert Arch.AArch64 == Arch.AArch64
        assert Arch.MIPS == Arch.MIPS
        assert Arch.MIPS64 == Arch.MIPS64
        assert Arch.PPC == Arch.PPC
        assert Arch.PPC64 == Arch.PPC64
        assert Arch.RISCV == Arch.RISCV
        assert Arch.RISCV64 == Arch.RISCV64
        assert Arch.Unknown == Arch.Unknown

    def test_arch_string_representation(self):
        """Test string representations of architectures."""
        assert str(Arch.X86) == "x86"
        assert str(Arch.X86_64) == "x86_64"
        assert str(Arch.ARM) == "arm"
        assert str(Arch.AArch64) == "aarch64"
        assert str(Arch.Unknown) == "unknown"

    def test_arch_bits(self):
        """Test bit width methods."""
        assert Arch.X86.bits() == 32
        assert Arch.X86_64.bits() == 64
        assert Arch.ARM.bits() == 32
        assert Arch.AArch64.bits() == 64

    def test_arch_is_64_bit(self):
        """Test 64-bit detection."""
        assert not Arch.X86.is_64_bit()
        assert Arch.X86_64.is_64_bit()
        assert not Arch.ARM.is_64_bit()
        assert Arch.AArch64.is_64_bit()


class TestEndianness:
    """Test Endianness enum."""

    def test_endianness_values(self):
        """Test endianness enum values."""
        assert Endianness.Little == Endianness.Little
        assert Endianness.Big == Endianness.Big

    def test_endianness_string_representation(self):
        """Test string representations of endianness."""
        assert str(Endianness.Little) == "Little"
        assert str(Endianness.Big) == "Big"

    def test_endianness_repr(self):
        """Test repr representations of endianness."""
        assert repr(Endianness.Little) == "Endianness.Little"
        assert repr(Endianness.Big) == "Endianness.Big"


class TestHashes:
    """Test Hashes type."""

    def test_hashes_creation_minimal(self):
        """Test creating hashes with minimal data."""
        hashes = Hashes()
        assert not hashes.has_sha256()
        assert not hashes.has_any_hash()
        assert hashes.is_valid_py()

    def test_hashes_creation_full(self):
        """Test creating hashes with all fields."""
        sha256 = "a" * 64
        md5 = "b" * 32
        sha1 = "c" * 40

        hashes = Hashes(sha256=sha256, md5=md5, sha1=sha1)
        assert hashes.has_sha256()
        assert hashes.has_any_hash()
        assert hashes.get_hash("sha256") == sha256
        assert hashes.get_hash("md5") == md5
        assert hashes.get_hash("sha1") == sha1
        assert hashes.is_valid_py()

    def test_hashes_with_additional(self):
        """Test hashes with additional hash types."""
        additional = {"blake2b": "d" * 128}
        hashes = Hashes(additional=additional)
        assert hashes.get_hash("blake2b") == "d" * 128
        assert hashes.has_any_hash()

    def test_hashes_operations(self):
        """Test hash operations."""
        hashes = Hashes()

        # Set hashes
        hashes.set_hash("sha256", "a" * 64)
        hashes.set_hash("custom", "b" * 32)

        assert hashes.get_hash("sha256") == "a" * 64
        assert hashes.get_hash("custom") == "b" * 32
        assert hashes.get_hash("nonexistent") is None

    def test_hashes_validation(self):
        """Test hash validation."""
        # Valid hashes
        valid = Hashes(sha256="a" * 64, md5="b" * 32, sha1="c" * 40)
        assert valid.is_valid_py()

        # Invalid: wrong length
        with pytest.raises(ValueError):
            Hashes(sha256="short")

        # Invalid: non-hex characters
        with pytest.raises(ValueError):
            Hashes(sha256="g" * 64)

    def test_hashes_string_representation(self):
        """Test string representations of hashes."""
        hashes = Hashes(sha256="a" * 64)
        assert "SHA256:" in str(hashes)
        assert "a" * 16 in str(hashes)  # First 16 chars

        empty_hashes = Hashes()
        assert str(empty_hashes) == "No hashes"


class TestBinaryCreation:
    """Test Binary creation and validation."""

    def test_binary_creation_minimal(self):
        """Test creating a minimal binary."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        binary = Binary(
            id="test-binary",
            path="/path/to/binary",
            format=Format.ELF,
            arch=Arch.X86,
            bits=32,
            endianness=Endianness.Little,
            entry_points=[entry_point],
            size_bytes=1024,
        )

        assert binary.id == "test-binary"
        assert binary.path == "/path/to/binary"
        assert binary.format == Format.ELF
        assert binary.arch == Arch.X86
        assert binary.bits == 32
        assert binary.endianness == Endianness.Little
        assert len(binary.entry_points) == 1
        assert binary.size_bytes == 1024
        assert binary.hashes is None
        assert binary.uuid is None
        assert binary.timestamps is None
        assert binary.is_valid_py()
        assert not binary.is_64_bit()
        assert binary.has_entry_points()
        assert binary.entry_point_count() == 1

    def test_binary_creation_full(self):
        """Test creating a binary with all optional fields."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)
        hashes = Hashes(sha256="a" * 64)
        timestamps = {"TimeDateStamp": 1234567890}

        binary = Binary(
            id="full-binary",
            path="/full/path/binary.exe",
            format=Format.PE,
            arch=Arch.X86_64,
            bits=64,
            endianness=Endianness.Little,
            entry_points=[entry_point],
            size_bytes=2048,
            hashes=hashes,
            uuid="uuid-123",
            timestamps=timestamps,
        )

        assert binary.id == "full-binary"
        assert binary.format == Format.PE
        assert binary.arch == Arch.X86_64
        assert binary.bits == 64
        assert binary.is_64_bit()
        assert binary.has_hashes()
        assert binary.uuid == "uuid-123"
        assert binary.get_timestamp("TimeDateStamp") == 1234567890
        assert binary.is_valid_py()

    def test_binary_multiple_entry_points(self):
        """Test binary with multiple entry points."""
        ep1 = Address(AddressKind.VA, 0x401000, 32)
        ep2 = Address(AddressKind.VA, 0x402000, 32)

        binary = Binary(
            id="multi-ep",
            path="/path",
            format=Format.ELF,
            arch=Arch.X86,
            bits=32,
            endianness=Endianness.Little,
            entry_points=[ep1, ep2],
            size_bytes=1024,
        )

        assert binary.entry_point_count() == 2
        assert binary.has_entry_points()
        assert binary.primary_entry_point() is not None

    def test_binary_validation(self):
        """Test binary validation."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        # Valid binary
        valid = Binary(
            id="valid",
            path="/valid/path",
            format=Format.ELF,
            arch=Arch.X86,
            bits=32,
            endianness=Endianness.Little,
            entry_points=[entry_point],
            size_bytes=1024,
        )
        assert valid.is_valid_py()

        # Invalid: empty ID
        with pytest.raises(ValueError):
            Binary(
                id="",
                path="/path",
                format=Format.ELF,
                arch=Arch.X86,
                bits=32,
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=1024,
            )

        # Invalid: empty path
        with pytest.raises(ValueError):
            Binary(
                id="test",
                path="",
                format=Format.ELF,
                arch=Arch.X86,
                bits=32,
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=1024,
            )

        # Invalid: zero size
        with pytest.raises(ValueError):
            Binary(
                id="test",
                path="/path",
                format=Format.ELF,
                arch=Arch.X86,
                bits=32,
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=0,
            )

        # Invalid: architecture/bits mismatch
        with pytest.raises(ValueError):
            Binary(
                id="test",
                path="/path",
                format=Format.ELF,
                arch=Arch.X86_64,
                bits=32,  # Should be 64
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=1024,
            )


class TestBinaryOperations:
    """Test Binary operations."""

    def test_binary_timestamp_operations(self):
        """Test timestamp operations."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        binary = Binary(
            id="test",
            path="/path",
            format=Format.PE,
            arch=Arch.X86,
            bits=32,
            endianness=Endianness.Little,
            entry_points=[entry_point],
            size_bytes=1024,
        )

        # Initially no timestamps
        assert binary.get_timestamp("TimeDateStamp") is None

        # Set timestamp
        binary.set_timestamp("TimeDateStamp", 1234567890)
        assert binary.get_timestamp("TimeDateStamp") == 1234567890

        # Set another timestamp
        binary.set_timestamp("LinkTime", 987654321)
        assert binary.get_timestamp("LinkTime") == 987654321

    def test_binary_string_representations(self):
        """Test string representations."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        binary = Binary(
            id="test-binary",
            path="/path/to/binary",
            format=Format.ELF,
            arch=Arch.X86_64,
            bits=64,
            endianness=Endianness.Little,
            entry_points=[entry_point],
            size_bytes=1024,
        )

        str_repr = str(binary)
        assert "test-binary" in str_repr
        assert "ELF" in str_repr
        assert "x86_64" in str_repr
        assert "64" in str_repr

        repr_str = repr(binary)
        assert "Binary" in repr_str
        assert "test-binary" in repr_str


class TestBinarySerialization:
    """Test Binary serialization."""

    def test_binary_json_serialization(self):
        """Test JSON serialization and deserialization."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)
        hashes = Hashes(sha256="a" * 64)

        original = Binary(
            id="test-binary",
            path="/path/to/binary",
            format=Format.ELF,
            arch=Arch.X86,
            bits=32,
            endianness=Endianness.Little,
            entry_points=[entry_point],
            size_bytes=1024,
            hashes=hashes,
            uuid="test-uuid",
        )

        # Serialize to JSON
        json_str = original.to_json_py()
        assert isinstance(json_str, str)

        # Deserialize from JSON
        restored = Binary.from_json_py(json_str)

        # Compare key fields (created_at will differ)
        assert restored.id == original.id
        assert restored.path == original.path
        assert restored.format == original.format
        assert restored.arch == original.arch
        assert restored.bits == original.bits
        assert restored.endianness == original.endianness
        assert len(restored.entry_points) == len(original.entry_points)
        assert restored.size_bytes == original.size_bytes
        assert restored.uuid == original.uuid


class TestBinaryEdgeCases:
    """Test Binary edge cases."""

    def test_binary_64_bit_architectures(self):
        """Test 64-bit architectures."""
        entry_point = Address(AddressKind.VA, 0x140000000, 64)

        architectures = [Arch.X86_64, Arch.AArch64, Arch.MIPS64, Arch.PPC64, Arch.RISCV64]

        for arch in architectures:
            binary = Binary(
                id=f"test-{arch}",
                path="/path",
                format=Format.ELF,
                arch=arch,
                bits=64,
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=1024,
            )

            assert binary.is_64_bit()
            assert binary.arch.bits() == 64
            assert binary.is_valid_py()

    def test_binary_32_bit_architectures(self):
        """Test 32-bit architectures."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        architectures = [Arch.X86, Arch.ARM, Arch.MIPS, Arch.PPC, Arch.RISCV]

        for arch in architectures:
            binary = Binary(
                id=f"test-{arch}",
                path="/path",
                format=Format.ELF,
                arch=arch,
                bits=32,
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=1024,
            )

            assert not binary.is_64_bit()
            assert binary.arch.bits() == 32
            assert binary.is_valid_py()

    def test_binary_different_formats(self):
        """Test different binary formats."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        formats = [Format.ELF, Format.PE, Format.MachO, Format.COFF, Format.Raw]

        for fmt in formats:
            binary = Binary(
                id=f"test-{fmt}",
                path="/path",
                format=fmt,
                arch=Arch.X86,
                bits=32,
                endianness=Endianness.Little,
                entry_points=[entry_point],
                size_bytes=1024,
            )

            assert binary.format == fmt
            assert binary.is_valid_py()

    def test_binary_endianness_variations(self):
        """Test different endianness values."""
        entry_point = Address(AddressKind.VA, 0x401000, 32)

        for endianness in [Endianness.Little, Endianness.Big]:
            binary = Binary(
                id=f"test-{endianness}",
                path="/path",
                format=Format.ELF,
                arch=Arch.MIPS,  # MIPS commonly uses big-endian
                bits=32,
                endianness=endianness,
                entry_points=[entry_point],
                size_bytes=1024,
            )

            assert binary.endianness == endianness
            assert binary.is_valid_py()