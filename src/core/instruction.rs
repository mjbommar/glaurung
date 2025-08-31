//! Instruction and Operand types for decoded assembly instructions.
//!
//! Instruction represents a decoded assembly instruction at a specific address,
//! including its mnemonic, operands, and various metadata for analysis.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;

/// Types of operands that can appear in instructions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum OperandKind {
    /// Register operand
    Register,
    /// Immediate value operand
    Immediate,
    /// Memory reference operand
    Memory,
    /// Displacement operand
    Displacement,
    /// Relative operand
    Relative,
}

#[pymethods]
impl OperandKind {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for OperandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandKind::Register => write!(f, "Register"),
            OperandKind::Immediate => write!(f, "Immediate"),
            OperandKind::Memory => write!(f, "Memory"),
            OperandKind::Displacement => write!(f, "Displacement"),
            OperandKind::Relative => write!(f, "Relative"),
        }
    }
}

/// Access types for operands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum Access {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Read and write access
    ReadWrite,
}

#[pymethods]
impl Access {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Access::Read => write!(f, "Read"),
            Access::Write => write!(f, "Write"),
            Access::ReadWrite => write!(f, "ReadWrite"),
        }
    }
}

/// Side effects that instructions can have
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum SideEffect {
    /// Memory write operation
    MemoryWrite,
    /// Register modification
    RegisterModify,
    /// Stack operation
    StackOperation,
    /// Control flow change
    ControlFlow,
    /// System call
    SystemCall,
    /// I/O operation
    IoOperation,
}

#[pymethods]
impl SideEffect {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for SideEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SideEffect::MemoryWrite => write!(f, "MemoryWrite"),
            SideEffect::RegisterModify => write!(f, "RegisterModify"),
            SideEffect::StackOperation => write!(f, "StackOperation"),
            SideEffect::ControlFlow => write!(f, "ControlFlow"),
            SideEffect::SystemCall => write!(f, "SystemCall"),
            SideEffect::IoOperation => write!(f, "IoOperation"),
        }
    }
}

/// Structured operand representation for instructions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[pyclass]
pub struct Operand {
    /// Type of operand
    #[pyo3(get, set)]
    pub kind: OperandKind,
    /// Size in bits
    #[pyo3(get, set)]
    pub size: u8,
    /// Access type
    #[pyo3(get, set)]
    pub access: Access,
    /// String representation of the operand (fallback)
    #[pyo3(get, set)]
    pub text: String,
    /// Register name (for Register operands)
    #[pyo3(get, set)]
    pub register: Option<String>,
    /// Immediate value (for Immediate operands)
    #[pyo3(get, set)]
    pub immediate: Option<i64>,
    /// Memory displacement (for Memory operands)
    #[pyo3(get, set)]
    pub displacement: Option<i64>,
    /// Memory segment register (for Memory operands)
    #[pyo3(get, set)]
    pub segment: Option<String>,
    /// Memory scale factor (for Memory operands)
    #[pyo3(get, set)]
    pub scale: Option<u8>,
    /// Memory base register (for Memory operands)
    #[pyo3(get, set)]
    pub base: Option<String>,
    /// Memory index register (for Memory operands)
    #[pyo3(get, set)]
    pub index: Option<String>,
}

#[pymethods]
impl Operand {
    /// Create a new register operand
    #[staticmethod]
    pub fn register(name: String, size: u8, access: Access) -> Self {
        Self {
            kind: OperandKind::Register,
            size,
            access,
            text: name.clone(),
            register: Some(name),
            immediate: None,
            displacement: None,
            segment: None,
            scale: None,
            base: None,
            index: None,
        }
    }

    /// Create a new immediate operand
    #[staticmethod]
    pub fn immediate(value: i64, size: u8) -> Self {
        Self {
            kind: OperandKind::Immediate,
            size,
            access: Access::Read,
            text: format!("0x{:x}", value),
            register: None,
            immediate: Some(value),
            displacement: None,
            segment: None,
            scale: None,
            base: None,
            index: None,
        }
    }

    /// Create a new memory operand
    #[staticmethod]
    pub fn memory(
        size: u8,
        access: Access,
        displacement: Option<i64>,
        base: Option<String>,
        index: Option<String>,
        scale: Option<u8>,
    ) -> Self {
        let mut text = String::new();

        if let Some(seg) = &base {
            if seg != "ds" {
                // Don't show default segment
                text.push_str(&format!("{}:", seg));
            }
        }

        text.push('[');

        if let Some(base) = &base {
            text.push_str(base);
        }

        if let Some(index) = &index {
            if base.is_some() {
                text.push_str(" + ");
            }
            text.push_str(index);
            if let Some(scale) = scale {
                if scale > 1 {
                    text.push_str(&format!(" * {}", scale));
                }
            }
        }

        if let Some(disp) = displacement {
            if base.is_some() || index.is_some() {
                if disp >= 0 {
                    text.push_str(&format!(" + 0x{:x}", disp));
                } else {
                    text.push_str(&format!(" - 0x{:x}", -disp));
                }
            } else {
                text.push_str(&format!("0x{:x}", disp));
            }
        }

        text.push(']');

        Self {
            kind: OperandKind::Memory,
            size,
            access,
            text,
            register: None,
            immediate: None,
            displacement,
            segment: None,
            scale,
            base,
            index,
        }
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Check if this operand is a register
    pub fn is_register(&self) -> bool {
        self.kind == OperandKind::Register
    }

    /// Check if this operand is an immediate
    pub fn is_immediate(&self) -> bool {
        self.kind == OperandKind::Immediate
    }

    /// Check if this operand is a memory reference
    pub fn is_memory(&self) -> bool {
        self.kind == OperandKind::Memory
    }

    /// Check if this operand reads from the operand
    pub fn is_read(&self) -> bool {
        matches!(self.access, Access::Read | Access::ReadWrite)
    }

    /// Check if this operand writes to the operand
    pub fn is_write(&self) -> bool {
        matches!(self.access, Access::Write | Access::ReadWrite)
    }

    /// Get the effective size in bytes
    pub fn size_bytes(&self) -> usize {
        (self.size as usize).div_ceil(8) // Round up to bytes
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

/// Decoded instruction at a specific address
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[pyclass]
pub struct Instruction {
    /// Address where this instruction is located
    #[pyo3(get, set)]
    pub address: Address,
    /// Raw bytes of the instruction
    #[pyo3(get, set)]
    pub bytes: Vec<u8>,
    /// Instruction mnemonic (e.g., "mov", "add", "jmp")
    #[pyo3(get, set)]
    pub mnemonic: String,
    /// Structured operands
    #[pyo3(get, set)]
    pub operands: Vec<Operand>,
    /// Length of the instruction in bytes
    #[pyo3(get, set)]
    pub length: u16,
    /// Architecture this instruction belongs to
    #[pyo3(get, set)]
    pub arch: String,
    /// Optional semantic descriptor (for future IR/SSA integrations)
    #[pyo3(get, set)]
    pub semantics: Option<String>,
    /// Optional side effects of this instruction
    #[pyo3(get, set)]
    pub side_effects: Option<Vec<SideEffect>>,
    /// Optional instruction prefixes
    #[pyo3(get, set)]
    pub prefixes: Option<Vec<String>>,
    /// Optional instruction groups/categories
    #[pyo3(get, set)]
    pub groups: Option<Vec<String>>,
}

#[pymethods]
impl Instruction {
    /// Create a new Instruction instance
    #[new]
    #[pyo3(signature = (
        address,
        bytes,
        mnemonic,
        operands,
        length,
        arch,
        semantics=None,
        side_effects=None,
        prefixes=None,
        groups=None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        bytes: Vec<u8>,
        mnemonic: String,
        operands: Vec<Operand>,
        length: u16,
        arch: String,
        semantics: Option<String>,
        side_effects: Option<Vec<SideEffect>>,
        prefixes: Option<Vec<String>>,
        groups: Option<Vec<String>>,
    ) -> Self {
        Self {
            address,
            bytes,
            mnemonic,
            operands,
            length,
            arch,
            semantics,
            side_effects,
            prefixes,
            groups,
        }
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Get the number of operands
    pub fn operand_count(&self) -> usize {
        self.operands.len()
    }

    /// Check if this instruction has operands
    pub fn has_operands(&self) -> bool {
        !self.operands.is_empty()
    }

    /// Check if this instruction modifies memory
    pub fn modifies_memory(&self) -> bool {
        if let Some(effects) = &self.side_effects {
            effects.contains(&SideEffect::MemoryWrite)
        } else {
            // Fallback: check operands for write access to memory
            self.operands
                .iter()
                .any(|op| op.is_memory() && op.is_write())
        }
    }

    /// Check if this instruction modifies registers
    pub fn modifies_registers(&self) -> bool {
        if let Some(effects) = &self.side_effects {
            effects.contains(&SideEffect::RegisterModify)
        } else {
            // Fallback: check operands for write access to registers
            self.operands
                .iter()
                .any(|op| op.is_register() && op.is_write())
        }
    }

    /// Check if this instruction changes control flow
    pub fn changes_control_flow(&self) -> bool {
        if let Some(effects) = &self.side_effects {
            effects.contains(&SideEffect::ControlFlow)
        } else {
            // Fallback: check for control flow mnemonics
            matches!(
                self.mnemonic.as_str(),
                "jmp" | "je" | "jne" | "jg" | "jl" | "ja" | "jb" | "call" | "ret" | "iret"
            )
        }
    }

    /// Check if this instruction is a branch
    pub fn is_branch(&self) -> bool {
        if let Some(groups) = &self.groups {
            groups.contains(&"branch".to_string())
        } else {
            // Fallback: check mnemonic
            matches!(
                self.mnemonic.as_str(),
                "jmp" | "je" | "jne" | "jg" | "jl" | "ja" | "jb" | "jbe" | "jae" | "js" | "jns"
            )
        }
    }

    /// Check if this instruction is a call
    pub fn is_call(&self) -> bool {
        self.mnemonic == "call"
    }

    /// Check if this instruction is a return
    pub fn is_return(&self) -> bool {
        matches!(self.mnemonic.as_str(), "ret" | "iret" | "retf")
    }

    /// Check if this instruction is a system call
    pub fn is_system_call(&self) -> bool {
        if let Some(effects) = &self.side_effects {
            effects.contains(&SideEffect::SystemCall)
        } else {
            // Fallback: check for syscall instructions
            matches!(
                self.mnemonic.as_str(),
                "syscall" | "sysenter" | "int" | "svc"
            )
        }
    }

    /// Get the end address of this instruction
    pub fn end_address(&self) -> Address {
        // Note: This is a simplified calculation. In reality, addresses might not be
        // simply additive depending on the architecture and addressing mode.
        let end_value = self.address.value + self.length as u64;
        Address::new(
            self.address.kind,
            end_value,
            self.address.bits,
            self.address.space.clone(),
            None,
        )
        .unwrap_or_else(|_| Address {
            kind: self.address.kind,
            value: self.address.value,
            space: self.address.space.clone(),
            bits: self.address.bits,
            symbol_ref: self.address.symbol_ref.clone(),
        })
    }

    /// Get a human-readable disassembly string
    pub fn disassembly(&self) -> String {
        let mut result = format!("{:08x}: ", self.address.value);

        // Add hex bytes
        for (i, byte) in self.bytes.iter().enumerate() {
            if i > 0 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x}", byte));
        }

        // Pad to align mnemonics
        while result.len() < 30 {
            result.push(' ');
        }

        // Add mnemonic and operands
        result.push_str(&self.mnemonic);

        if !self.operands.is_empty() {
            result.push(' ');
            for (i, operand) in self.operands.iter().enumerate() {
                if i > 0 {
                    result.push_str(", ");
                }
                result.push_str(&operand.text);
            }
        }

        result
    }

    /// Get a summary of the instruction
    pub fn summary(&self) -> String {
        let mut parts = vec![self.mnemonic.clone()];

        if !self.operands.is_empty() {
            let operand_texts: Vec<String> =
                self.operands.iter().map(|op| op.text.clone()).collect();
            parts.push(operand_texts.join(", "));
        }

        if let Some(groups) = &self.groups {
            if !groups.is_empty() {
                parts.push(format!("({})", groups.join(", ")));
            }
        }

        parts.join(" ")
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operand_str = if self.operands.is_empty() {
            String::new()
        } else {
            let ops: Vec<String> = self.operands.iter().map(|op| op.to_string()).collect();
            format!(" {}", ops.join(", "))
        };

        write!(f, "{}{}", self.mnemonic, operand_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_operand_kind_display() {
        assert_eq!(format!("{}", OperandKind::Register), "Register");
        assert_eq!(format!("{}", OperandKind::Immediate), "Immediate");
        assert_eq!(format!("{}", OperandKind::Memory), "Memory");
        assert_eq!(format!("{}", OperandKind::Displacement), "Displacement");
        assert_eq!(format!("{}", OperandKind::Relative), "Relative");
    }

    #[test]
    fn test_access_display() {
        assert_eq!(format!("{}", Access::Read), "Read");
        assert_eq!(format!("{}", Access::Write), "Write");
        assert_eq!(format!("{}", Access::ReadWrite), "ReadWrite");
    }

    #[test]
    fn test_side_effect_display() {
        assert_eq!(format!("{}", SideEffect::MemoryWrite), "MemoryWrite");
        assert_eq!(format!("{}", SideEffect::RegisterModify), "RegisterModify");
        assert_eq!(format!("{}", SideEffect::ControlFlow), "ControlFlow");
        assert_eq!(format!("{}", SideEffect::SystemCall), "SystemCall");
    }

    #[test]
    fn test_operand_register_creation() {
        let reg = Operand::register("rax".to_string(), 64, Access::ReadWrite);
        assert_eq!(reg.kind, OperandKind::Register);
        assert_eq!(reg.size, 64);
        assert_eq!(reg.access, Access::ReadWrite);
        assert_eq!(reg.register, Some("rax".to_string()));
        assert!(reg.is_register());
        assert!(reg.is_read());
        assert!(reg.is_write());
        assert_eq!(reg.size_bytes(), 8);
    }

    #[test]
    fn test_operand_immediate_creation() {
        let imm = Operand::immediate(0x1000, 32);
        assert_eq!(imm.kind, OperandKind::Immediate);
        assert_eq!(imm.size, 32);
        assert_eq!(imm.access, Access::Read);
        assert_eq!(imm.immediate, Some(0x1000));
        assert!(imm.is_immediate());
        assert!(imm.is_read());
        assert!(!imm.is_write());
        assert_eq!(imm.size_bytes(), 4);
    }

    #[test]
    fn test_operand_memory_creation() {
        let mem = Operand::memory(
            32,
            Access::Read,
            Some(0x100),
            Some("rbx".to_string()),
            Some("rcx".to_string()),
            Some(4),
        );
        assert_eq!(mem.kind, OperandKind::Memory);
        assert_eq!(mem.size, 32);
        assert_eq!(mem.access, Access::Read);
        assert_eq!(mem.displacement, Some(0x100));
        assert_eq!(mem.base, Some("rbx".to_string()));
        assert_eq!(mem.index, Some("rcx".to_string()));
        assert_eq!(mem.scale, Some(4));
        assert!(mem.is_memory());
        assert!(mem.is_read());
        assert!(!mem.is_write());
        assert_eq!(mem.size_bytes(), 4);
    }

    #[test]
    fn test_operand_display() {
        let reg = Operand::register("eax".to_string(), 32, Access::Read);
        assert_eq!(format!("{}", reg), "eax");

        let imm = Operand::immediate(42, 32);
        assert_eq!(format!("{}", imm), "0x2a");

        let mem = Operand::memory(
            64,
            Access::Read,
            Some(0x100),
            Some("rbx".to_string()),
            None,
            None,
        );
        assert!(format!("{}", mem).contains("rbx"));
        assert!(format!("{}", mem).contains("100"));
    }

    #[test]
    fn test_instruction_creation_minimal() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let bytes = vec![0x90]; // NOP
        let operands = vec![];

        let instr = Instruction::new(
            address,
            bytes,
            "nop".to_string(),
            operands,
            1,
            "x86_64".to_string(),
            None,
            None,
            None,
            None,
        );

        assert_eq!(instr.address.value, 0x400000);
        assert_eq!(instr.bytes, vec![0x90]);
        assert_eq!(instr.mnemonic, "nop");
        assert_eq!(instr.operand_count(), 0);
        assert_eq!(instr.length, 1);
        assert_eq!(instr.arch, "x86_64");
        assert!(!instr.has_operands());
    }

    #[test]
    fn test_instruction_creation_with_operands() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let bytes = vec![0x48, 0x89, 0xc7]; // mov rdi, rax
        let operands = vec![
            Operand::register("rdi".to_string(), 64, Access::Write),
            Operand::register("rax".to_string(), 64, Access::Read),
        ];

        let instr = Instruction::new(
            address,
            bytes,
            "mov".to_string(),
            operands,
            3,
            "x86_64".to_string(),
            None,
            Some(vec![SideEffect::RegisterModify]),
            None,
            Some(vec!["general".to_string(), "move".to_string()]),
        );

        assert_eq!(instr.mnemonic, "mov");
        assert_eq!(instr.operand_count(), 2);
        assert!(instr.has_operands());
        assert!(instr.modifies_registers());
        assert!(!instr.changes_control_flow());
        assert!(!instr.is_branch());
        assert!(!instr.is_call());
        assert!(!instr.is_return());
    }

    #[test]
    fn test_instruction_control_flow_detection() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        // Test jump instruction
        let jmp_instr = Instruction::new(
            address.clone(),
            vec![0xeb, 0x10],
            "jmp".to_string(),
            vec![Operand::immediate(0x10, 8)],
            2,
            "x86_64".to_string(),
            None,
            Some(vec![SideEffect::ControlFlow]),
            None,
            Some(vec!["branch".to_string(), "unconditional".to_string()]),
        );

        assert!(jmp_instr.changes_control_flow());
        assert!(jmp_instr.is_branch());

        // Test call instruction
        let call_instr = Instruction::new(
            address.clone(),
            vec![0xe8, 0x00, 0x00, 0x00, 0x00],
            "call".to_string(),
            vec![Operand::immediate(0x400010, 32)],
            5,
            "x86_64".to_string(),
            None,
            Some(vec![SideEffect::ControlFlow, SideEffect::StackOperation]),
            None,
            Some(vec!["call".to_string()]),
        );

        assert!(call_instr.changes_control_flow());
        assert!(call_instr.is_call());
        assert!(!call_instr.is_branch());
        assert!(!call_instr.is_return());

        // Test return instruction
        let ret_instr = Instruction::new(
            address,
            vec![0xc3],
            "ret".to_string(),
            vec![],
            1,
            "x86_64".to_string(),
            None,
            Some(vec![SideEffect::ControlFlow, SideEffect::StackOperation]),
            None,
            Some(vec!["return".to_string()]),
        );

        assert!(ret_instr.changes_control_flow());
        assert!(ret_instr.is_return());
        assert!(!ret_instr.is_call());
        assert!(!ret_instr.is_branch());
    }

    #[test]
    fn test_instruction_end_address() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let instr = Instruction::new(
            address,
            vec![0x90, 0x90, 0x90],
            "nop".to_string(),
            vec![],
            3,
            "x86_64".to_string(),
            None,
            None,
            None,
            None,
        );

        let end_addr = instr.end_address();
        assert_eq!(end_addr.value, 0x400003);
        assert_eq!(end_addr.kind, AddressKind::VA);
        assert_eq!(end_addr.bits, 64);
    }

    #[test]
    fn test_instruction_disassembly() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let instr = Instruction::new(
            address,
            vec![0x48, 0x89, 0xc7],
            "mov".to_string(),
            vec![
                Operand::register("rdi".to_string(), 64, Access::Write),
                Operand::register("rax".to_string(), 64, Access::Read),
            ],
            3,
            "x86_64".to_string(),
            None,
            None,
            None,
            None,
        );

        let disasm = instr.disassembly();
        assert!(disasm.contains("400000:"));
        assert!(disasm.contains("48 89 c7"));
        assert!(disasm.contains("mov"));
        assert!(disasm.contains("rdi"));
        assert!(disasm.contains("rax"));
    }

    #[test]
    fn test_instruction_summary() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let instr = Instruction::new(
            address,
            vec![0x48, 0x89, 0xc7],
            "mov".to_string(),
            vec![
                Operand::register("rdi".to_string(), 64, Access::Write),
                Operand::register("rax".to_string(), 64, Access::Read),
            ],
            3,
            "x86_64".to_string(),
            None,
            None,
            None,
            Some(vec!["general".to_string(), "move".to_string()]),
        );

        let summary = instr.summary();
        assert!(summary.contains("mov"));
        assert!(summary.contains("rdi"));
        assert!(summary.contains("rax"));
        assert!(summary.contains("general"));
        assert!(summary.contains("move"));
    }

    #[test]
    fn test_instruction_display() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let instr = Instruction::new(
            address,
            vec![0x90],
            "nop".to_string(),
            vec![],
            1,
            "x86_64".to_string(),
            None,
            None,
            None,
            None,
        );

        assert_eq!(format!("{}", instr), "nop");

        let instr_with_ops = Instruction::new(
            Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap(),
            vec![0x48, 0x89, 0xc7],
            "mov".to_string(),
            vec![
                Operand::register("rdi".to_string(), 64, Access::Write),
                Operand::register("rax".to_string(), 64, Access::Read),
            ],
            3,
            "x86_64".to_string(),
            None,
            None,
            None,
            None,
        );

        let display = format!("{}", instr_with_ops);
        assert!(display.contains("mov"));
        assert!(display.contains("rdi"));
        assert!(display.contains("rax"));
    }
}
