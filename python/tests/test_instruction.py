"""Tests for the Instruction type."""

from glaurung import (
    Instruction,
    Operand,
    OperandKind,
    Access,
    SideEffect,
    Address,
    AddressKind,
)


class TestOperandEnums:
    """Test operand-related enums."""

    def test_operand_kind_values(self):
        """Test all OperandKind enum values."""
        assert OperandKind.Register
        assert OperandKind.Immediate
        assert OperandKind.Memory
        assert OperandKind.Displacement
        assert OperandKind.Relative

    def test_operand_kind_display(self):
        """Test string representation of OperandKind."""
        assert str(OperandKind.Register) == "Register"
        assert str(OperandKind.Immediate) == "Immediate"
        assert str(OperandKind.Memory) == "Memory"
        assert str(OperandKind.Displacement) == "Displacement"
        assert str(OperandKind.Relative) == "Relative"

    def test_access_values(self):
        """Test all Access enum values."""
        assert Access.Read
        assert Access.Write
        assert Access.ReadWrite

    def test_access_display(self):
        """Test string representation of Access."""
        assert str(Access.Read) == "Read"
        assert str(Access.Write) == "Write"
        assert str(Access.ReadWrite) == "ReadWrite"

    def test_side_effect_values(self):
        """Test all SideEffect enum values."""
        assert SideEffect.MemoryWrite
        assert SideEffect.RegisterModify
        assert SideEffect.StackOperation
        assert SideEffect.ControlFlow
        assert SideEffect.SystemCall
        assert SideEffect.IoOperation

    def test_side_effect_display(self):
        """Test string representation of SideEffect."""
        assert str(SideEffect.MemoryWrite) == "MemoryWrite"
        assert str(SideEffect.RegisterModify) == "RegisterModify"
        assert str(SideEffect.ControlFlow) == "ControlFlow"
        assert str(SideEffect.SystemCall) == "SystemCall"
        assert str(SideEffect.IoOperation) == "IoOperation"


class TestOperandCreation:
    """Test Operand creation and basic functionality."""

    def test_operand_register_creation(self):
        """Test creating a register operand."""
        reg = Operand.register("rax", 64, Access.ReadWrite)

        assert str(reg.kind) == "Register"
        assert reg.size == 64
        assert str(reg.access) == "ReadWrite"
        assert reg.text == "rax"  # Test the text representation instead
        assert reg.is_register()
        assert reg.is_read()
        assert reg.is_write()
        assert not reg.is_immediate()
        assert not reg.is_memory()
        assert reg.size_bytes() == 8

    def test_operand_immediate_creation(self):
        """Test creating an immediate operand."""
        imm = Operand.immediate(0x1000, 32)

        assert str(imm.kind) == "Immediate"
        assert imm.size == 32
        assert str(imm.access) == "Read"
        assert imm.text == "0x1000"  # Test the text representation instead
        assert imm.is_immediate()
        assert imm.is_read()
        assert not imm.is_write()
        assert not imm.is_register()
        assert not imm.is_memory()
        assert imm.size_bytes() == 4

    def test_operand_memory_creation_simple(self):
        """Test creating a simple memory operand."""
        mem = Operand.memory(32, Access.Read, 0x100, None, None, None)

        assert str(mem.kind) == "Memory"
        assert mem.size == 32
        assert str(mem.access) == "Read"
        assert mem.displacement == 0x100
        assert mem.base is None
        assert mem.index is None
        assert mem.scale is None
        assert mem.is_memory()
        assert mem.is_read()
        assert not mem.is_write()
        assert mem.size_bytes() == 4

    def test_operand_memory_creation_complex(self):
        """Test creating a complex memory operand."""
        mem = Operand.memory(64, Access.ReadWrite, 0x100, "rbx", "rcx", 4)

        assert str(mem.kind) == "Memory"
        assert mem.size == 64
        assert str(mem.access) == "ReadWrite"
        assert mem.displacement == 0x100
        assert mem.base == "rbx"
        assert mem.index == "rcx"
        assert mem.scale == 4
        assert mem.is_memory()
        assert mem.is_read()
        assert mem.is_write()
        assert mem.size_bytes() == 8

    def test_operand_memory_negative_displacement(self):
        """Test memory operand with negative displacement."""
        mem = Operand.memory(32, Access.Read, -8, "rsp", None, None)

        assert mem.displacement == -8
        assert mem.base == "rsp"

    def test_operand_display(self):
        """Test operand string representation."""
        reg = Operand.register("eax", 32, Access.Read)
        assert str(reg) == "eax"

        imm = Operand.immediate(42, 32)
        assert str(imm) == "0x2a"

        mem = Operand.memory(64, Access.Read, 0x100, "rbx", None, None)
        mem_str = str(mem)
        assert "rbx" in mem_str
        assert "100" in mem_str


class TestInstructionCreation:
    """Test Instruction creation and basic functionality."""

    def test_instruction_creation_minimal(self):
        """Test creating a minimal instruction."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        bytes_data = [0x90]  # NOP

        instr = Instruction(address, bytes_data, "nop", [], 1, "x86_64")

        assert instr.address.value == 0x400000
        assert instr.bytes == bytes(bytes_data)  # PyO3 converts Vec<u8> to bytes
        assert instr.mnemonic == "nop"
        assert instr.operand_count() == 0
        assert instr.length == 1
        assert instr.arch == "x86_64"
        assert not instr.has_operands()
        assert instr.semantics is None
        assert instr.side_effects is None
        assert instr.prefixes is None
        assert instr.groups is None

    def test_instruction_creation_with_operands(self):
        """Test creating an instruction with operands."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        bytes_data = [0x48, 0x89, 0xC7]  # mov rdi, rax
        operands = [
            Operand.register("rdi", 64, Access.Write),
            Operand.register("rax", 64, Access.Read),
        ]

        instr = Instruction(
            address,
            bytes_data,
            "mov",
            operands,
            3,
            "x86_64",
            semantics="move register to register",
            side_effects=[SideEffect.RegisterModify],
            prefixes=None,
            groups=["general", "move"],
        )

        assert instr.mnemonic == "mov"
        assert instr.operand_count() == 2
        assert instr.has_operands()
        assert instr.semantics == "move register to register"
        assert len(instr.side_effects) == 1
        assert str(instr.side_effects[0]) == "RegisterModify"
        assert instr.groups == ["general", "move"]

    def test_instruction_creation_jump(self):
        """Test creating a jump instruction."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        bytes_data = [0xEB, 0x10]  # jmp +0x10
        operands = [Operand.immediate(0x10, 8)]

        instr = Instruction(
            address,
            bytes_data,
            "jmp",
            operands,
            2,
            "x86_64",
            side_effects=[SideEffect.ControlFlow],
            groups=["branch", "unconditional"],
        )

        assert instr.mnemonic == "jmp"
        assert instr.operand_count() == 1
        assert instr.changes_control_flow()
        assert instr.is_branch()
        assert not instr.is_call()
        assert not instr.is_return()

    def test_instruction_creation_call(self):
        """Test creating a call instruction."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        bytes_data = [0xE8, 0x00, 0x00, 0x00, 0x00]  # call 0x400010
        operands = [Operand.immediate(0x400010, 32)]

        instr = Instruction(
            address,
            bytes_data,
            "call",
            operands,
            5,
            "x86_64",
            side_effects=[SideEffect.ControlFlow, SideEffect.StackOperation],
            groups=["call"],
        )

        assert instr.mnemonic == "call"
        assert instr.is_call()
        assert instr.changes_control_flow()
        assert not instr.is_branch()
        assert not instr.is_return()

    def test_instruction_creation_return(self):
        """Test creating a return instruction."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        bytes_data = [0xC3]  # ret

        instr = Instruction(
            address,
            bytes_data,
            "ret",
            [],
            1,
            "x86_64",
            side_effects=[SideEffect.ControlFlow, SideEffect.StackOperation],
            groups=["return"],
        )

        assert instr.mnemonic == "ret"
        assert instr.is_return()
        assert instr.changes_control_flow()
        assert not instr.is_call()
        assert not instr.is_branch()


class TestInstructionProperties:
    """Test Instruction properties and methods."""

    def test_instruction_modifies_memory(self):
        """Test memory modification detection."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        # Instruction with memory write side effect
        mem_write_instr = Instruction(
            Address(AddressKind.VA, 0x400000, bits=64),
            [0x89, 0x07],  # mov [rdi], eax
            "mov",
            [
                Operand.memory(32, Access.Write, None, "rdi", None, None),
                Operand.register("eax", 32, Access.Read),
            ],
            2,
            "x86_64",
            side_effects=[SideEffect.MemoryWrite],
        )

        assert mem_write_instr.modifies_memory()

        # Instruction without memory write side effect
        reg_instr = Instruction(
            address,
            [0x89, 0xC7],  # mov edi, eax
            "mov",
            [
                Operand.register("edi", 32, Access.Write),
                Operand.register("eax", 32, Access.Read),
            ],
            2,
            "x86_64",
        )

        assert not reg_instr.modifies_memory()

    def test_instruction_modifies_registers(self):
        """Test register modification detection."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        # Instruction with register modify side effect
        reg_mod_instr = Instruction(
            Address(AddressKind.VA, 0x400000, bits=64),
            [0x89, 0xC7],  # mov edi, eax
            "mov",
            [
                Operand.register("edi", 32, Access.Write),
                Operand.register("eax", 32, Access.Read),
            ],
            2,
            "x86_64",
            side_effects=[SideEffect.RegisterModify],
        )

        assert reg_mod_instr.modifies_registers()

        # Instruction without register modify side effect
        nop_instr = Instruction(
            address,
            [0x90],  # nop
            "nop",
            [],
            1,
            "x86_64",
        )

        assert not nop_instr.modifies_registers()

    def test_instruction_system_call_detection(self):
        """Test system call detection."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        # Instruction with system call side effect
        syscall_instr = Instruction(
            Address(AddressKind.VA, 0x400000, bits=64),
            [0x0F, 0x05],  # syscall
            "syscall",
            [],
            2,
            "x86_64",
            side_effects=[SideEffect.SystemCall],
        )

        assert syscall_instr.is_system_call()

        # Instruction without system call side effect
        mov_instr = Instruction(
            address,
            [0x89, 0xC7],  # mov edi, eax
            "mov",
            [
                Operand.register("edi", 32, Access.Write),
                Operand.register("eax", 32, Access.Read),
            ],
            2,
            "x86_64",
        )

        assert not mov_instr.is_system_call()

    def test_instruction_end_address(self):
        """Test end address calculation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(
            address,
            [0x90, 0x90, 0x90],  # 3-byte NOP
            "nop",
            [],
            3,
            "x86_64",
        )

        end_addr = instr.end_address()
        assert end_addr.value == 0x400003
        assert end_addr.kind == AddressKind.VA
        assert end_addr.bits == 64

    def test_instruction_disassembly(self):
        """Test disassembly string generation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(
            address,
            [0x48, 0x89, 0xC7],  # mov rdi, rax
            "mov",
            [
                Operand.register("rdi", 64, Access.Write),
                Operand.register("rax", 64, Access.Read),
            ],
            3,
            "x86_64",
        )

        disasm = instr.disassembly()
        assert "400000:" in disasm
        assert "48 89 c7" in disasm
        assert "mov" in disasm
        assert "rdi" in disasm
        assert "rax" in disasm

    def test_instruction_summary(self):
        """Test instruction summary generation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(
            address,
            [0x48, 0x89, 0xC7],  # mov rdi, rax
            "mov",
            [
                Operand.register("rdi", 64, Access.Write),
                Operand.register("rax", 64, Access.Read),
            ],
            3,
            "x86_64",
            groups=["general", "move"],
        )

        summary = instr.summary()
        assert "mov" in summary
        assert "rdi" in summary
        assert "rax" in summary
        assert "general" in summary
        assert "move" in summary

    def test_instruction_display(self):
        """Test instruction string representation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        # Instruction without operands
        nop_instr = Instruction(
            Address(AddressKind.VA, 0x400000, bits=64), [0x90], "nop", [], 1, "x86_64"
        )

        assert str(nop_instr) == "nop"

        # Instruction with operands
        mov_instr = Instruction(
            address,
            [0x48, 0x89, 0xC7],
            "mov",
            [
                Operand.register("rdi", 64, Access.Write),
                Operand.register("rax", 64, Access.Read),
            ],
            3,
            "x86_64",
        )

        mov_str = str(mov_instr)
        assert "mov" in mov_str
        assert "rdi" in mov_str
        assert "rax" in mov_str


class TestInstructionEdgeCases:
    """Test edge cases and special scenarios."""

    def test_instruction_empty_bytes(self):
        """Test instruction with empty byte sequence."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(address, [], "invalid", [], 0, "unknown")

        assert instr.bytes == b""  # PyO3 converts empty Vec<u8> to empty bytes
        assert instr.length == 0
        assert not instr.has_operands()

    def test_instruction_large_byte_sequence(self):
        """Test instruction with large byte sequence."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        large_bytes = [0x90] * 16  # 16 NOP bytes

        instr = Instruction(address, large_bytes, "nop_sequence", [], 16, "x86_64")

        assert len(instr.bytes) == 16
        assert instr.length == 16

    def test_instruction_many_operands(self):
        """Test instruction with many operands."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        operands = [
            Operand.register("rax", 64, Access.Read),
            Operand.register("rbx", 64, Access.Read),
            Operand.register("rcx", 64, Access.Read),
            Operand.register("rdx", 64, Access.Write),
        ]

        instr = Instruction(
            address,
            [0x48, 0x01, 0xDA],  # add rdx, rbx (simplified)
            "add",
            operands,
            3,
            "x86_64",
        )

        assert instr.operand_count() == 4
        assert instr.has_operands()

    def test_instruction_different_architectures(self):
        """Test instructions from different architectures."""
        arches = ["x86", "x86_64", "arm", "aarch64", "mips", "ppc"]
        for arch in arches:
            instr = Instruction(
                Address(AddressKind.VA, 0x400000, bits=64),
                [0x00],  # Generic byte
                "nop",
                [],
                1,
                arch,
            )
            assert instr.arch == arch

    def test_instruction_complex_side_effects(self):
        """Test instruction with multiple side effects."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(
            address,
            [0xCD, 0x80],  # int 0x80 (Linux syscall)
            "int",
            [Operand.immediate(0x80, 8)],
            2,
            "x86",
            side_effects=[
                SideEffect.SystemCall,
                SideEffect.ControlFlow,
                SideEffect.RegisterModify,
                SideEffect.StackOperation,
            ],
        )

        assert len(instr.side_effects) == 4
        side_effect_strs = [str(se) for se in instr.side_effects]
        assert "SystemCall" in side_effect_strs
        assert "ControlFlow" in side_effect_strs
        assert instr.is_system_call()
        assert instr.changes_control_flow()

    def test_instruction_with_prefixes(self):
        """Test instruction with prefixes."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(
            address,
            [0x66, 0x90],  # 16-bit NOP prefix
            "nop",
            [],
            2,
            "x86_64",
            prefixes=["operand-size"],
        )

        assert instr.prefixes == ["operand-size"]

    def test_instruction_max_length(self):
        """Test instruction with maximum length."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        # x86_64 instructions can be up to 15 bytes
        max_bytes = [0x90] * 15

        instr = Instruction(address, max_bytes, "complex_instruction", [], 15, "x86_64")

        assert len(instr.bytes) == 15
        assert instr.length == 15

    def test_instruction_zero_length(self):
        """Test instruction with zero length."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        instr = Instruction(address, [], "pseudo", [], 0, "unknown")

        assert instr.length == 0
        end_addr = instr.end_address()
        assert end_addr.value == address.value  # Should not advance

    def test_instruction_different_address_kinds(self):
        """Test instruction with different address kinds."""
        va_address = Address(AddressKind.VA, 0x400000, bits=64)
        rva_address = Address(AddressKind.RVA, 0x1000, bits=32)
        file_address = Address(AddressKind.FileOffset, 0x2000, bits=64)

        va_instr = Instruction(va_address, [0x90], "nop", [], 1, "x86_64")
        rva_instr = Instruction(rva_address, [0x90], "nop", [], 1, "x86")
        file_instr = Instruction(file_address, [0x90], "nop", [], 1, "x86_64")

        assert va_instr.address.kind == AddressKind.VA
        assert rva_instr.address.kind == AddressKind.RVA
        assert file_instr.address.kind == AddressKind.FileOffset
