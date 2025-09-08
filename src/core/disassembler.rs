//! Disassembler trait and error types for instruction decoding.
//!
//! This module defines the Disassembler trait that provides a common interface
//! for different disassembler backends (Capstone, Zydis, custom implementations, etc.).
//! It also includes error types for disassembly operations.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;
use crate::core::binary::Endianness;
use crate::core::instruction::Instruction;

/// Errors that can occur during disassembly operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum DisassemblerError {
    /// Invalid instruction bytes
    InvalidInstruction(),
    /// Address is not valid for disassembly
    InvalidAddress(),
    /// Insufficient bytes for complete instruction
    InsufficientBytes(),
    /// Unsupported architecture or instruction
    UnsupportedInstruction(),
    /// Unsupported architecture for the selected backend
    UnsupportedArchitecture(),
    /// Internal disassembler error with message
    InternalError(String),
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl DisassemblerError {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for DisassemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DisassemblerError::InvalidInstruction() => write!(f, "InvalidInstruction"),
            DisassemblerError::InvalidAddress() => write!(f, "InvalidAddress"),
            DisassemblerError::InsufficientBytes() => write!(f, "InsufficientBytes"),
            DisassemblerError::UnsupportedInstruction() => write!(f, "UnsupportedInstruction"),
            DisassemblerError::UnsupportedArchitecture() => write!(f, "UnsupportedArchitecture"),
            DisassemblerError::InternalError(msg) => write!(f, "InternalError: {}", msg),
        }
    }
}

impl std::error::Error for DisassemblerError {}

/// Result type for disassembly operations
pub type DisassemblerResult<T> = Result<T, DisassemblerError>;

/// Architecture types supported by disassemblers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum Architecture {
    /// x86 (32-bit)
    X86,
    /// x86-64 (64-bit)
    X86_64,
    /// ARM (32-bit)
    ARM,
    /// ARM64/AArch64 (64-bit)
    ARM64,
    /// MIPS (32-bit)
    MIPS,
    /// MIPS64 (64-bit)
    MIPS64,
    /// PowerPC (32-bit)
    PPC,
    /// PowerPC64 (64-bit)
    PPC64,
    /// RISC-V (32-bit)
    RISCV,
    /// RISC-V (64-bit)
    RISCV64,
    /// Unknown/unsupported architecture
    Unknown,
}

impl Architecture {
    /// Get the address size in bits for this architecture (pure Rust)
    pub fn address_bits(&self) -> u8 {
        match self {
            Architecture::X86 => 32,
            Architecture::X86_64 => 64,
            Architecture::ARM => 32,
            Architecture::ARM64 => 64,
            Architecture::MIPS => 32,
            Architecture::MIPS64 => 64,
            Architecture::PPC => 32,
            Architecture::PPC64 => 64,
            Architecture::RISCV => 32,
            Architecture::RISCV64 => 64,
            Architecture::Unknown => 64, // Default to 64-bit
        }
    }

    /// Check if this is a 64-bit architecture (pure Rust)
    pub fn is_64_bit(&self) -> bool {
        self.address_bits() == 64
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Architecture {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Address size in bits
    #[pyo3(name = "address_bits")]
    fn address_bits_py(&self) -> u8 {
        self.address_bits()
    }

    /// True if this is a 64-bit architecture
    #[pyo3(name = "is_64_bit")]
    fn is_64_bit_py(&self) -> bool {
        self.is_64_bit()
    }

    /// Enable hashing in Python so `Architecture` can be used as dict keys.
    fn __hash__(&self) -> isize {
        use Architecture::*;
        match self {
            X86 => 1,
            X86_64 => 2,
            ARM => 3,
            ARM64 => 4,
            MIPS => 5,
            MIPS64 => 6,
            PPC => 7,
            PPC64 => 8,
            RISCV => 9,
            RISCV64 => 10,
            Unknown => 0,
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X86_64 => write!(f, "x86_64"),
            Architecture::ARM => write!(f, "arm"),
            Architecture::ARM64 => write!(f, "arm64"),
            Architecture::MIPS => write!(f, "mips"),
            Architecture::MIPS64 => write!(f, "mips64"),
            Architecture::PPC => write!(f, "ppc"),
            Architecture::PPC64 => write!(f, "ppc64"),
            Architecture::RISCV => write!(f, "riscv"),
            Architecture::RISCV64 => write!(f, "riscv64"),
            Architecture::Unknown => write!(f, "unknown"),
        }
    }
}

// Endianness type is unified from core::binary::Endianness

// Bridge types between `core::binary::Arch` and disassembler `Architecture`.
impl From<crate::core::binary::Arch> for Architecture {
    fn from(a: crate::core::binary::Arch) -> Self {
        use crate::core::binary::Arch as B;
        match a {
            B::X86 => Architecture::X86,
            B::X86_64 => Architecture::X86_64,
            B::ARM => Architecture::ARM,
            B::AArch64 => Architecture::ARM64,
            B::MIPS => Architecture::MIPS,
            B::MIPS64 => Architecture::MIPS64,
            B::PPC => Architecture::PPC,
            B::PPC64 => Architecture::PPC64,
            B::RISCV => Architecture::RISCV,
            B::RISCV64 => Architecture::RISCV64,
            B::Unknown => Architecture::Unknown,
        }
    }
}

impl From<Architecture> for crate::core::binary::Arch {
    fn from(a: Architecture) -> Self {
        use crate::core::binary::Arch as B;
        match a {
            Architecture::X86 => B::X86,
            Architecture::X86_64 => B::X86_64,
            Architecture::ARM => B::ARM,
            Architecture::ARM64 => B::AArch64,
            Architecture::MIPS => B::MIPS,
            Architecture::MIPS64 => B::MIPS64,
            Architecture::PPC => B::PPC,
            Architecture::PPC64 => B::PPC64,
            Architecture::RISCV => B::RISCV,
            Architecture::RISCV64 => B::RISCV64,
            Architecture::Unknown => B::Unknown,
        }
    }
}

/// Core disassembler trait that provides a common interface for instruction decoding
pub trait Disassembler {
    /// Disassemble a single instruction at the given address
    ///
    /// # Arguments
    /// * `address` - The address where the instruction is located
    /// * `bytes` - The raw bytes to disassemble
    ///
    /// # Returns
    /// A result containing the decoded Instruction or a DisassemblerError
    fn disassemble_instruction(
        &self,
        address: &Address,
        bytes: &[u8],
    ) -> DisassemblerResult<Instruction>;

    /// Get the maximum instruction length for this architecture in bytes
    fn max_instruction_length(&self) -> usize;

    /// Get the architecture this disassembler supports
    fn architecture(&self) -> Architecture;

    /// Get the endianness this disassembler uses
    fn endianness(&self) -> Endianness;

    /// Check if an address is valid for disassembly
    ///
    /// This can be used to validate addresses before attempting disassembly
    fn is_valid_address(&self, address: &Address) -> bool {
        // Default implementation: check if address kind is appropriate for the architecture
        match (self.architecture(), address.kind) {
            (Architecture::X86 | Architecture::X86_64, crate::core::address::AddressKind::VA)
            | (Architecture::X86 | Architecture::X86_64, crate::core::address::AddressKind::RVA)
            | (
                Architecture::X86 | Architecture::X86_64,
                crate::core::address::AddressKind::FileOffset,
            )
            | (Architecture::ARM | Architecture::ARM64, crate::core::address::AddressKind::VA)
            | (Architecture::MIPS | Architecture::MIPS64, crate::core::address::AddressKind::VA)
            | (Architecture::PPC | Architecture::PPC64, crate::core::address::AddressKind::VA)
            | (
                Architecture::RISCV | Architecture::RISCV64,
                crate::core::address::AddressKind::VA,
            ) => {
                // Check if address bits match architecture
                address.bits == self.architecture().address_bits()
            }
            _ => false,
        }
    }

    /// Get a human-readable name for this disassembler
    fn name(&self) -> &str {
        "Generic Disassembler"
    }

    /// Get version information for this disassembler
    fn version(&self) -> &str {
        "1.0.0"
    }
}

/// Configuration options for disassembler creation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct DisassemblerConfig {
    /// Architecture to disassemble
    pub architecture: Architecture,
    /// Endianness to use
    pub endianness: Endianness,
    /// Additional configuration options as key-value pairs
    pub options: std::collections::HashMap<String, String>,
}

impl DisassemblerConfig {
    /// Create a new disassembler configuration (pure Rust)
    pub fn new(
        architecture: Architecture,
        endianness: Endianness,
        options: Option<std::collections::HashMap<String, String>>,
    ) -> Self {
        Self {
            architecture,
            endianness,
            options: options.unwrap_or_default(),
        }
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl DisassemblerConfig {
    /// Python constructor
    #[new]
    #[pyo3(signature = (architecture, endianness=Endianness::Little, options=None))]
    pub fn new_py(
        architecture: Architecture,
        endianness: Endianness,
        options: Option<std::collections::HashMap<String, String>>,
    ) -> Self {
        Self::new(architecture, endianness, options)
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!(
            "DisassemblerConfig(arch={}, endian={})",
            self.architecture, self.endianness
        )
    }

    // Property getters for Python
    #[getter]
    fn architecture(&self) -> Architecture {
        self.architecture
    }
    #[getter]
    fn endianness(&self) -> Endianness {
        self.endianness
    }
    #[getter]
    fn options(&self) -> std::collections::HashMap<String, String> {
        self.options.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_disassembler_error_display() {
        assert_eq!(
            format!("{}", DisassemblerError::InvalidInstruction()),
            "InvalidInstruction"
        );
        assert_eq!(
            format!("{}", DisassemblerError::InvalidAddress()),
            "InvalidAddress"
        );
        assert_eq!(
            format!("{}", DisassemblerError::InsufficientBytes()),
            "InsufficientBytes"
        );
        assert_eq!(
            format!("{}", DisassemblerError::UnsupportedInstruction()),
            "UnsupportedInstruction"
        );
        assert_eq!(
            format!("{}", DisassemblerError::InternalError("test".to_string())),
            "InternalError: test"
        );
    }

    #[test]
    fn test_architecture_display() {
        assert_eq!(format!("{}", Architecture::X86), "x86");
        assert_eq!(format!("{}", Architecture::X86_64), "x86_64");
        assert_eq!(format!("{}", Architecture::ARM), "arm");
        assert_eq!(format!("{}", Architecture::ARM64), "arm64");
        assert_eq!(format!("{}", Architecture::Unknown), "unknown");
    }

    #[test]
    fn test_architecture_address_bits() {
        assert_eq!(Architecture::X86.address_bits(), 32);
        assert_eq!(Architecture::X86_64.address_bits(), 64);
        assert_eq!(Architecture::ARM.address_bits(), 32);
        assert_eq!(Architecture::ARM64.address_bits(), 64);
        assert_eq!(Architecture::Unknown.address_bits(), 64);
    }

    #[test]
    fn test_architecture_is_64_bit() {
        assert!(!Architecture::X86.is_64_bit());
        assert!(Architecture::X86_64.is_64_bit());
        assert!(!Architecture::ARM.is_64_bit());
        assert!(Architecture::ARM64.is_64_bit());
    }

    #[test]
    fn test_endianness_display() {
        assert_eq!(format!("{}", Endianness::Little), "Little");
        assert_eq!(format!("{}", Endianness::Big), "Big");
    }

    #[test]
    fn test_disassembler_config_creation() {
        let config = DisassemblerConfig::new(Architecture::X86_64, Endianness::Little, None);
        assert_eq!(config.architecture, Architecture::X86_64);
        assert_eq!(config.endianness, Endianness::Little);
        assert!(config.options.is_empty());
    }

    #[test]
    fn test_disassembler_config_with_options() {
        let mut options = std::collections::HashMap::new();
        options.insert("syntax".to_string(), "intel".to_string());

        let config =
            DisassemblerConfig::new(Architecture::X86_64, Endianness::Little, Some(options));
        assert_eq!(config.architecture, Architecture::X86_64);
        assert_eq!(config.endianness, Endianness::Little);
        assert_eq!(config.options.get("syntax"), Some(&"intel".to_string()));
    }

    #[test]
    fn test_default_is_valid_address() {
        // Create a mock disassembler for testing
        struct MockDisassembler {
            arch: Architecture,
        }

        impl Disassembler for MockDisassembler {
            fn disassemble_instruction(
                &self,
                _address: &Address,
                _bytes: &[u8],
            ) -> DisassemblerResult<Instruction> {
                Err(DisassemblerError::UnsupportedInstruction())
            }

            fn max_instruction_length(&self) -> usize {
                15
            }

            fn architecture(&self) -> Architecture {
                self.arch
            }

            fn endianness(&self) -> Endianness {
                Endianness::Little
            }
        }

        let x86_disasm = MockDisassembler {
            arch: Architecture::X86,
        };
        let x64_disasm = MockDisassembler {
            arch: Architecture::X86_64,
        };

        // Test valid addresses
        let va32 = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let va64 = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();

        assert!(x86_disasm.is_valid_address(&va32));
        assert!(x64_disasm.is_valid_address(&va64));

        // Test invalid addresses (wrong bit width)
        assert!(!x86_disasm.is_valid_address(&va64));
        assert!(!x64_disasm.is_valid_address(&va32));
    }
}
