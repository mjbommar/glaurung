use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler, DisassemblerError};

pub enum Backend {
    Iced(super::iced::IcedDisassembler),
    Cap(super::capstone::CapstoneDisassembler),
}

impl Disassembler for Backend {
    fn disassemble_instruction(
        &self,
        address: &crate::core::address::Address,
        bytes: &[u8],
    ) -> crate::core::disassembler::DisassemblerResult<crate::core::instruction::Instruction> {
        match self {
            Backend::Iced(d) => d.disassemble_instruction(address, bytes),
            Backend::Cap(d) => d.disassemble_instruction(address, bytes),
        }
    }

    fn max_instruction_length(&self) -> usize {
        match self {
            Backend::Iced(d) => d.max_instruction_length(),
            Backend::Cap(d) => d.max_instruction_length(),
        }
    }

    fn architecture(&self) -> Architecture {
        match self {
            Backend::Iced(d) => d.architecture(),
            Backend::Cap(d) => d.architecture(),
        }
    }

    fn endianness(&self) -> Endianness {
        match self {
            Backend::Iced(d) => d.endianness(),
            Backend::Cap(d) => d.endianness(),
        }
    }

    fn name(&self) -> &str {
        match self {
            Backend::Iced(d) => d.name(),
            Backend::Cap(d) => d.name(),
        }
    }
}

/// Select a disassembler backend for the given architecture.
pub fn for_arch(arch: Architecture, endianness: Endianness) -> Option<Backend> {
    match arch {
        Architecture::X86 | Architecture::X86_64 => Some(Backend::Iced(
            super::iced::IcedDisassembler::new(arch, endianness),
        )),
        Architecture::ARM
        | Architecture::ARM64
        | Architecture::MIPS
        | Architecture::MIPS64
        | Architecture::PPC
        | Architecture::PPC64
        | Architecture::RISCV
        | Architecture::RISCV64 => {
            super::capstone::CapstoneDisassembler::new(arch, endianness).map(Backend::Cap)
        }
        Architecture::Unknown => None,
    }
}

/// Preferred backend kind for explicit selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Iced,
    Capstone,
}

/// Explicit backend selector. Returns an error if the backend cannot support the arch.
pub fn for_arch_with(
    arch: Architecture,
    endianness: Endianness,
    prefer: Option<BackendKind>,
) -> Result<Backend, DisassemblerError> {
    match prefer {
        Some(BackendKind::Iced) => match arch {
            Architecture::X86 | Architecture::X86_64 => Ok(Backend::Iced(
                super::iced::IcedDisassembler::new(arch, endianness),
            )),
            _ => Err(DisassemblerError::UnsupportedArchitecture()),
        },
        Some(BackendKind::Capstone) => super::capstone::CapstoneDisassembler::new(arch, endianness)
            .map(Backend::Cap)
            .ok_or(DisassemblerError::UnsupportedArchitecture()),
        None => for_arch(arch, endianness).ok_or(DisassemblerError::UnsupportedArchitecture()),
    }
}
