"""Tests for the Disassembler types and error handling."""

from glaurung import (
    DisassemblerError,
    Architecture,
    Endianness,
    DisassemblerConfig,
    Address,
    AddressKind,
)
import pytest


class TestDisassemblerEnums:
    """Test disassembler-related enums."""

    def test_architecture_values(self):
        """Test all Architecture enum values."""
        assert Architecture.X86
        assert Architecture.X86_64
        assert Architecture.ARM
        assert Architecture.ARM64
        assert Architecture.MIPS
        assert Architecture.MIPS64
        assert Architecture.PPC
        assert Architecture.PPC64
        assert Architecture.RISCV
        assert Architecture.RISCV64
        assert Architecture.Unknown

    def test_architecture_display(self):
        """Test string representation of Architecture."""
        assert str(Architecture.X86) == "x86"
        assert str(Architecture.X86_64) == "x86_64"
        assert str(Architecture.ARM) == "arm"
        assert str(Architecture.ARM64) == "arm64"
        assert str(Architecture.Unknown) == "unknown"

    def test_architecture_address_bits(self):
        """Test address bit width for architectures."""
        assert Architecture.X86.address_bits() == 32
        assert Architecture.X86_64.address_bits() == 64
        assert Architecture.ARM.address_bits() == 32
        assert Architecture.ARM64.address_bits() == 64
        assert Architecture.MIPS.address_bits() == 32
        assert Architecture.MIPS64.address_bits() == 64
        assert Architecture.Unknown.address_bits() == 64

    def test_architecture_is_64_bit(self):
        """Test 64-bit architecture detection."""
        assert not Architecture.X86.is_64_bit()
        assert Architecture.X86_64.is_64_bit()
        assert not Architecture.ARM.is_64_bit()
        assert Architecture.ARM64.is_64_bit()
        assert Architecture.Unknown.is_64_bit()  # Defaults to 64-bit

    def test_endianness_values(self):
        """Test all Endianness enum values."""
        assert Endianness.Little
        assert Endianness.Big

    def test_endianness_display(self):
        """Test string representation of Endianness."""
        assert str(Endianness.Little) == "Little"
        assert str(Endianness.Big) == "Big"


class TestDisassemblerError:
    """Test disassembler error types."""

    def test_disassembler_error_values(self):
        """Test all DisassemblerError enum values."""
        assert DisassemblerError.InvalidInstruction
        assert DisassemblerError.InvalidAddress
        assert DisassemblerError.InsufficientBytes
        assert DisassemblerError.UnsupportedInstruction
        # InternalError requires a string parameter, so we can't test it directly

    def test_disassembler_error_display(self):
        """Test string representation of DisassemblerError."""
        assert str(DisassemblerError.InvalidInstruction) == "InvalidInstruction"
        assert str(DisassemblerError.InvalidAddress) == "InvalidAddress"
        assert str(DisassemblerError.InsufficientBytes) == "InsufficientBytes"
        assert str(DisassemblerError.UnsupportedInstruction) == "UnsupportedInstruction"


class TestDisassemblerConfig:
    """Test disassembler configuration."""

    def test_disassembler_config_creation_minimal(self):
        """Test creating a minimal disassembler configuration."""
        config = DisassemblerConfig(Architecture.X86_64, Endianness.Little)
        assert config.architecture == Architecture.X86_64
        assert config.endianness == Endianness.Little
        assert config.options == {}

    def test_disassembler_config_creation_with_options(self):
        """Test creating a disassembler configuration with options."""
        options = {"syntax": "intel", "detail": "true"}
        config = DisassemblerConfig(Architecture.X86_64, Endianness.Little, options)
        assert config.architecture == Architecture.X86_64
        assert config.endianness == Endianness.Little
        assert config.options == options
        assert config.options["syntax"] == "intel"
        assert config.options["detail"] == "true"

    def test_engine_override_rejects_incompatible_arch(self):
        """Requesting iced for ARM64 should raise ValueError (unsupported arch)."""
        with pytest.raises(ValueError):
            _ = __import__("glaurung").glaurung.disasm.PyDisassembler(
                DisassemblerConfig(
                    Architecture.ARM64, Endianness.Little, {"engine": "iced"}
                )
            )

    def test_disassembler_config_display(self):
        """Test string representation of DisassemblerConfig."""
        config = DisassemblerConfig(Architecture.X86_64, Endianness.Little)
        config_str = str(config)
        assert "DisassemblerConfig" in config_str
        assert "x86_64" in config_str
        assert "Little" in config_str


class TestArchitectureCompatibility:
    """Test architecture compatibility with addresses."""

    def test_x86_architecture_compatibility(self):
        """Test X86 architecture compatibility with addresses."""
        # Valid addresses for X86
        va32 = Address(AddressKind.VA, 0x1000, bits=32)
        rva32 = Address(AddressKind.RVA, 0x2000, bits=32)
        file_offset32 = Address(AddressKind.FileOffset, 0x3000, bits=32)

        # These should be valid for X86 (32-bit addresses)
        # Note: We can't directly test is_valid_address without a concrete disassembler
        # but we can test the address properties
        assert va32.bits == 32
        assert rva32.bits == 32
        assert file_offset32.bits == 32

    def test_x86_64_architecture_compatibility(self):
        """Test X86_64 architecture compatibility with addresses."""
        # Valid addresses for X86_64
        va64 = Address(AddressKind.VA, 0x1000, bits=64)
        rva64 = Address(AddressKind.RVA, 0x2000, bits=64)
        file_offset64 = Address(AddressKind.FileOffset, 0x3000, bits=64)

        # These should be valid for X86_64 (64-bit addresses)
        assert va64.bits == 64
        assert rva64.bits == 64
        assert file_offset64.bits == 64

    def test_arm_architecture_compatibility(self):
        """Test ARM architecture compatibility with addresses."""
        # Valid addresses for ARM
        va32 = Address(AddressKind.VA, 0x1000, bits=32)

        assert va32.bits == 32

    def test_arm64_architecture_compatibility(self):
        """Test ARM64 architecture compatibility with addresses."""
        # Valid addresses for ARM64
        va64 = Address(AddressKind.VA, 0x1000, bits=64)

        assert va64.bits == 64


class TestDisassemblerConfigEdgeCases:
    """Test edge cases for disassembler configuration."""

    def test_disassembler_config_empty_options(self):
        """Test disassembler config with explicitly empty options."""
        config = DisassemblerConfig(Architecture.X86, Endianness.Big, {})
        assert config.architecture == Architecture.X86
        assert config.endianness == Endianness.Big
        assert config.options == {}

    def test_disassembler_config_none_options(self):
        """Test disassembler config with None options (should default to empty dict)."""
        config = DisassemblerConfig(Architecture.MIPS, Endianness.Big, None)
        assert config.architecture == Architecture.MIPS
        assert config.endianness == Endianness.Big
        assert config.options == {}

    def test_disassembler_config_unknown_architecture(self):
        """Test disassembler config with unknown architecture."""
        config = DisassemblerConfig(Architecture.Unknown, Endianness.Little)
        assert config.architecture == Architecture.Unknown
        assert config.endianness == Endianness.Little
        assert config.options == {}

    def test_disassembler_config_all_architectures(self):
        """Test disassembler config with all supported architectures."""
        architectures = [
            Architecture.X86,
            Architecture.X86_64,
            Architecture.ARM,
            Architecture.ARM64,
            Architecture.MIPS,
            Architecture.MIPS64,
            Architecture.PPC,
            Architecture.PPC64,
            Architecture.RISCV,
            Architecture.RISCV64,
            Architecture.Unknown,
        ]

        for arch in architectures:
            config = DisassemblerConfig(arch, Endianness.Little)
            assert config.architecture == arch
            assert config.endianness == Endianness.Little


class TestDisassemblerErrorEdgeCases:
    """Test edge cases for disassembler errors."""

    def test_disassembler_error_equality(self):
        """Test equality of disassembler errors."""
        err1 = DisassemblerError.InvalidInstruction
        err2 = DisassemblerError.InvalidInstruction
        err3 = DisassemblerError.InvalidAddress

        assert err1 == err2
        assert err1 != err3
        assert err2 != err3

    def test_disassembler_error_string_conversion(self):
        """Test that disassembler errors can be converted to strings."""
        errors = [
            DisassemblerError.InvalidInstruction,
            DisassemblerError.InvalidAddress,
            DisassemblerError.InsufficientBytes,
            DisassemblerError.UnsupportedInstruction,
        ]

        for error in errors:
            error_str = str(error)
            assert isinstance(error_str, str)
            assert len(error_str) > 0


class TestAddressArchitectureValidation:
    """Test address validation for different architectures."""

    def test_address_bits_match_architecture(self):
        """Test that address bits should match architecture requirements."""
        # 32-bit architectures should use 32-bit addresses
        x86_addr = Address(AddressKind.VA, 0x1000, bits=32)
        arm_addr = Address(AddressKind.VA, 0x1000, bits=32)
        mips_addr = Address(AddressKind.VA, 0x1000, bits=32)

        assert x86_addr.bits == 32
        assert arm_addr.bits == 32
        assert mips_addr.bits == 32

        # 64-bit architectures should use 64-bit addresses
        x64_addr = Address(AddressKind.VA, 0x1000, bits=64)
        arm64_addr = Address(AddressKind.VA, 0x1000, bits=64)
        mips64_addr = Address(AddressKind.VA, 0x1000, bits=64)

        assert x64_addr.bits == 64
        assert arm64_addr.bits == 64
        assert mips64_addr.bits == 64

    def test_address_kinds_for_architectures(self):
        """Test appropriate address kinds for different architectures."""
        # Most architectures use VA for runtime addresses
        va_addr = Address(AddressKind.VA, 0x400000, bits=64)

        # RVA is primarily for PE/COFF files
        rva_addr = Address(AddressKind.RVA, 0x1000, bits=32)

        # File offsets are used for raw binary analysis
        file_addr = Address(AddressKind.FileOffset, 0x2000, bits=64)

        assert va_addr.kind == AddressKind.VA
        assert rva_addr.kind == AddressKind.RVA
        assert file_addr.kind == AddressKind.FileOffset
