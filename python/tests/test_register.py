"""Tests for the Register type."""

from glaurung import (
    Register,
    RegisterKind,
    Address,
    AddressKind,
)


class TestRegisterEnums:
    """Test register-related enums."""

    def test_register_kind_values(self):
        """Test all RegisterKind enum values."""
        assert RegisterKind.General
        assert RegisterKind.Float
        assert RegisterKind.Vector
        assert RegisterKind.Flags
        assert RegisterKind.Segment
        assert RegisterKind.Control
        assert RegisterKind.Debug

    def test_register_kind_display(self):
        """Test string representation of RegisterKind."""
        assert str(RegisterKind.General) == "General"
        assert str(RegisterKind.Float) == "Float"
        assert str(RegisterKind.Vector) == "Vector"
        assert str(RegisterKind.Flags) == "Flags"
        assert str(RegisterKind.Segment) == "Segment"
        assert str(RegisterKind.Control) == "Control"
        assert str(RegisterKind.Debug) == "Debug"


class TestRegisterCreation:
    """Test Register creation and basic functionality."""

    def test_register_general_creation(self):
        """Test creating a general purpose register."""
        reg = Register.general("rax", 64)

        assert reg.name == "rax"
        assert reg.size == 64
        assert str(reg.kind) == "General"
        assert reg.is_general()
        assert not reg.has_parent()
        assert not reg.is_memory_mapped()
        assert reg.size_bytes() == 8
        assert reg.can_contain(32)
        assert reg.can_contain(64)
        assert not reg.can_contain(128)

    def test_register_float_creation(self):
        """Test creating a floating point register."""
        reg = Register.float("xmm0", 128)

        assert reg.name == "xmm0"
        assert reg.size == 128
        assert str(reg.kind) == "Float"
        assert reg.is_float()
        assert reg.size_bytes() == 16

    def test_register_vector_creation(self):
        """Test creating a vector/SIMD register."""
        reg = Register.vector("ymm0", 255)  # Use max u8 value

        assert reg.name == "ymm0"
        assert reg.size == 255
        assert str(reg.kind) == "Vector"
        assert reg.is_vector()
        assert reg.size_bytes() == 32  # 255 bits rounds up to 32 bytes

    def test_register_flags_creation(self):
        """Test creating a flags register."""
        reg = Register.flags("eflags", 32)

        assert reg.name == "eflags"
        assert reg.size == 32
        assert str(reg.kind) == "Flags"
        assert reg.is_flags()

    def test_register_segment_creation(self):
        """Test creating a segment register."""
        reg = Register.segment("cs", 16)

        assert reg.name == "cs"
        assert reg.size == 16
        assert str(reg.kind) == "Segment"
        assert reg.is_segment()

    def test_register_control_creation(self):
        """Test creating a control register."""
        reg = Register.control("cr0", 64)

        assert reg.name == "cr0"
        assert reg.size == 64
        assert str(reg.kind) == "Control"
        assert reg.is_control()

    def test_register_debug_creation(self):
        """Test creating a debug register."""
        reg = Register.debug("dr0", 64)

        assert reg.name == "dr0"
        assert reg.size == 64
        assert str(reg.kind) == "Debug"
        assert reg.is_debug()

    def test_register_sub_register_creation(self):
        """Test creating a sub-register with parent relationship."""
        reg = Register.sub_register("al", 8, RegisterKind.General, "rax", 0)

        assert reg.name == "al"
        assert reg.size == 8
        assert str(reg.kind) == "General"
        assert reg.parent_register == "rax"
        assert reg.offset_in_parent == 0
        assert reg.has_parent()
        assert not reg.is_memory_mapped()

    def test_register_memory_mapped(self):
        """Test creating a memory-mapped register."""
        address = Address(AddressKind.VA, 0x1000, bits=64)
        reg = Register("mmio_reg", 32, RegisterKind.General, address, None, None)

        assert reg.name == "mmio_reg"
        assert reg.size == 32
        assert reg.is_memory_mapped()
        assert reg.address.value == 0x1000

    def test_register_manual_creation(self):
        """Test manual Register creation with all parameters."""
        address = Address(AddressKind.VA, 0x2000, bits=32)
        reg = Register("custom_reg", 16, RegisterKind.Flags, address, "parent_reg", 8)

        assert reg.name == "custom_reg"
        assert reg.size == 16
        assert str(reg.kind) == "Flags"
        assert reg.is_memory_mapped()
        assert reg.has_parent()
        assert reg.parent_register == "parent_reg"
        assert reg.offset_in_parent == 8


class TestRegisterProperties:
    """Test Register properties and methods."""

    def test_register_kind_checks(self):
        """Test register kind checking methods."""
        general_reg = Register.general("rax", 64)
        float_reg = Register.float("xmm0", 128)
        vector_reg = Register.vector("ymm0", 255)  # Use max u8 value
        flags_reg = Register.flags("eflags", 32)
        segment_reg = Register.segment("cs", 16)
        control_reg = Register.control("cr0", 64)
        debug_reg = Register.debug("dr0", 64)

        # Test each register type
        assert general_reg.is_general()
        assert float_reg.is_float()
        assert vector_reg.is_vector()
        assert flags_reg.is_flags()
        assert segment_reg.is_segment()
        assert control_reg.is_control()
        assert debug_reg.is_debug()

        # Test that each is NOT the other types
        assert not general_reg.is_float()
        assert not float_reg.is_general()
        assert not vector_reg.is_flags()
        assert not flags_reg.is_segment()
        assert not segment_reg.is_control()
        assert not control_reg.is_debug()
        assert not debug_reg.is_vector()

    def test_register_size_calculations(self):
        """Test register size calculations."""
        reg8 = Register.general("al", 8)
        reg16 = Register.general("ax", 16)
        reg32 = Register.general("eax", 32)
        reg64 = Register.general("rax", 64)
        reg128 = Register.float("xmm0", 128)
        reg256 = Register.vector("ymm0", 255)  # Use max u8 value

        assert reg8.size_bytes() == 1
        assert reg16.size_bytes() == 2
        assert reg32.size_bytes() == 4
        assert reg64.size_bytes() == 8
        assert reg128.size_bytes() == 16
        assert reg256.size_bytes() == 32

    def test_register_can_contain(self):
        """Test value containment checking."""
        reg64 = Register.general("rax", 64)
        reg32 = Register.general("eax", 32)
        reg16 = Register.general("ax", 16)
        reg8 = Register.general("al", 8)

        # 64-bit register can contain smaller values
        assert reg64.can_contain(8)
        assert reg64.can_contain(16)
        assert reg64.can_contain(32)
        assert reg64.can_contain(64)
        assert not reg64.can_contain(128)

        # 32-bit register can contain smaller values
        assert reg32.can_contain(8)
        assert reg32.can_contain(16)
        assert reg32.can_contain(32)
        assert not reg32.can_contain(64)

        # Smaller registers cannot contain larger values
        assert not reg16.can_contain(32)
        assert not reg8.can_contain(16)

    def test_register_parent_relationships(self):
        """Test parent register relationships."""
        # Test sub-registers
        al = Register.sub_register("al", 8, RegisterKind.General, "rax", 0)
        ah = Register.sub_register("ah", 8, RegisterKind.General, "rax", 8)
        ax = Register.sub_register("ax", 16, RegisterKind.General, "rax", 0)
        eax = Register.sub_register("eax", 32, RegisterKind.General, "rax", 0)

        assert al.has_parent()
        assert ah.has_parent()
        assert ax.has_parent()
        assert eax.has_parent()

        assert al.parent_register == "rax"
        assert ah.parent_register == "rax"
        assert ax.parent_register == "rax"
        assert eax.parent_register == "rax"

        assert al.offset_in_parent == 0
        assert ah.offset_in_parent == 8
        assert ax.offset_in_parent == 0
        assert eax.offset_in_parent == 0

        # Test standalone register
        standalone = Register.general("rbx", 64)
        assert not standalone.has_parent()
        assert standalone.parent_register is None
        assert standalone.offset_in_parent is None

    def test_register_memory_mapping(self):
        """Test memory-mapped register detection."""
        # Memory-mapped register
        address = Address(AddressKind.VA, 0x1000, bits=64)
        mmio_reg = Register("mmio", 32, RegisterKind.General, address, None, None)

        assert mmio_reg.is_memory_mapped()
        assert mmio_reg.address.value == 0x1000
        assert mmio_reg.address.kind == AddressKind.VA

        # Regular register
        regular_reg = Register.general("rax", 64)
        assert not regular_reg.is_memory_mapped()
        assert regular_reg.address is None


class TestRegisterDisplay:
    """Test Register display and string representation."""

    def test_register_display(self):
        """Test register string representation."""
        reg = Register.general("rax", 64)
        assert str(reg) == "rax"

        xmm = Register.float("xmm0", 128)
        assert str(xmm) == "xmm0"

        cs = Register.segment("cs", 16)
        assert str(cs) == "cs"

    def test_register_summary(self):
        """Test register summary generation."""
        # Simple register
        reg = Register.general("rax", 64)
        summary = reg.summary()
        assert "rax" in summary
        assert "64bit" in summary
        assert "General" in summary

        # Sub-register
        al = Register.sub_register("al", 8, RegisterKind.General, "rax", 0)
        summary = al.summary()
        assert "al" in summary
        assert "8bit" in summary
        assert "General" in summary
        assert "parent:rax" in summary
        assert "offset:0" in summary

        # Memory-mapped register
        address = Address(AddressKind.VA, 0x1000, bits=64)
        mmio = Register("mmio", 32, RegisterKind.Control, address, None, None)
        summary = mmio.summary()
        assert "mmio" in summary
        assert "32bit" in summary
        assert "Control" in summary
        assert "memory-mapped" in summary

        # Complex register
        complex = Register.sub_register("xmm0", 128, RegisterKind.Vector, "zmm0", 0)
        summary = complex.summary()
        assert "xmm0" in summary
        assert "128bit" in summary
        assert "Vector" in summary
        assert "parent:zmm0" in summary
        assert "offset:0" in summary


class TestRegisterEdgeCases:
    """Test edge cases and special scenarios."""

    def test_register_minimum_size(self):
        """Test register with minimum size."""
        reg = Register.general("reg8", 8)
        assert reg.size == 8
        assert reg.size_bytes() == 1
        assert reg.can_contain(8)
        assert not reg.can_contain(16)

    def test_register_maximum_size(self):
        """Test register with maximum size."""
        reg = Register.vector("zmm0", 512)  # AVX-512 register
        assert reg.size == 512
        assert reg.size_bytes() == 64  # 512 bits / 8 = 64 bytes
        assert reg.can_contain(512)  # Can contain itself
        assert not reg.can_contain(1024)

    def test_register_odd_sizes(self):
        """Test register with odd sizes."""
        reg12 = Register.general("reg12", 12)
        assert reg12.size == 12
        assert reg12.size_bytes() == 2  # Rounded up
        assert reg12.can_contain(12)
        assert not reg12.can_contain(13)

    def test_register_empty_name(self):
        """Test register with empty name."""
        reg = Register("", 64, RegisterKind.General, None, None, None)
        assert reg.name == ""
        assert str(reg) == ""

    def test_register_zero_offset(self):
        """Test sub-register with zero offset."""
        reg = Register.sub_register("low", 32, RegisterKind.General, "high", 0)
        assert reg.offset_in_parent == 0
        assert reg.has_parent()

    def test_register_large_offset(self):
        """Test sub-register with large offset."""
        reg = Register.sub_register("high", 32, RegisterKind.General, "full", 32)
        assert reg.offset_in_parent == 32

    def test_register_different_address_kinds(self):
        """Test memory-mapped registers with different address kinds."""
        va_addr = Address(AddressKind.VA, 0x1000, bits=64)
        file_addr = Address(AddressKind.FileOffset, 0x2000, bits=64)
        physical_addr = Address(AddressKind.Physical, 0x3000, bits=64)

        va_reg = Register("va_reg", 32, RegisterKind.General, va_addr, None, None)
        file_reg = Register("file_reg", 32, RegisterKind.General, file_addr, None, None)
        physical_reg = Register(
            "phys_reg", 32, RegisterKind.General, physical_addr, None, None
        )

        assert va_reg.address.kind == AddressKind.VA
        assert file_reg.address.kind == AddressKind.FileOffset
        assert physical_reg.address.kind == AddressKind.Physical

    def test_register_complex_hierarchy(self):
        """Test complex register hierarchy."""
        # Simulate x86 register hierarchy
        rax = Register.general("rax", 64)
        assert not rax.has_parent()

        # EAX is low 32 bits of RAX
        eax = Register.sub_register("eax", 32, RegisterKind.General, "rax", 0)

        # AX is low 16 bits of EAX/RAX
        ax = Register.sub_register("ax", 16, RegisterKind.General, "rax", 0)

        # AH and AL are high/low 8 bits of AX
        ah = Register.sub_register("ah", 8, RegisterKind.General, "rax", 8)
        al = Register.sub_register("al", 8, RegisterKind.General, "rax", 0)

        # Verify hierarchy
        assert eax.parent_register == "rax"
        assert ax.parent_register == "rax"
        assert ah.parent_register == "rax"
        assert al.parent_register == "rax"

        assert eax.offset_in_parent == 0
        assert ax.offset_in_parent == 0
        assert ah.offset_in_parent == 8
        assert al.offset_in_parent == 0

    def test_register_architectural_variants(self):
        """Test registers from different architectures."""
        # x86-64 registers
        rax = Register.general("rax", 64)
        assert rax.size == 64

        # ARM64 registers
        x0 = Register.general("x0", 64)
        assert x0.size == 64

        # x86-32 registers
        eax = Register.general("eax", 32)
        assert eax.size == 32

        # ARM32 registers
        r0 = Register.general("r0", 32)
        assert r0.size == 32

        # MIPS registers
        zero = Register.general("$zero", 64)
        assert zero.size == 64

    def test_register_special_names(self):
        """Test registers with special characters in names."""
        # Registers with numbers
        xmm15 = Register.float("xmm15", 128)
        assert xmm15.name == "xmm15"

        # Registers with special characters
        pc = Register.general("$pc", 64)  # MIPS program counter
        assert pc.name == "$pc"

        sp = Register.general("$sp", 64)  # Stack pointer
        assert sp.name == "$sp"
