use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler, DisassemblerError};

pub enum Backend {
    Iced(super::iced::IcedDisassembler),
    Cap(super::capstone::CapstoneDisassembler),
    /// Migration backend: Glaurung's decoder is authoritative for implemented
    /// families and Capstone covers the remaining AArch64 surface.
    Aarch64Hybrid {
        native: super::native_aarch64::NativeAarch64Disassembler,
        fallback: super::capstone::CapstoneDisassembler,
    },
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
            Backend::Aarch64Hybrid { native, fallback } => native
                .disassemble_instruction(address, bytes)
                .or_else(|error| match error {
                    DisassemblerError::UnsupportedInstruction() => {
                        fallback.disassemble_instruction(address, bytes)
                    }
                    _ => Err(error),
                }),
        }
    }

    fn max_instruction_length(&self) -> usize {
        match self {
            Backend::Iced(d) => d.max_instruction_length(),
            Backend::Cap(d) => d.max_instruction_length(),
            Backend::Aarch64Hybrid { native, fallback } => native
                .max_instruction_length()
                .max(fallback.max_instruction_length()),
        }
    }

    fn architecture(&self) -> Architecture {
        match self {
            Backend::Iced(d) => d.architecture(),
            Backend::Cap(d) => d.architecture(),
            Backend::Aarch64Hybrid { native, .. } => native.architecture(),
        }
    }

    fn endianness(&self) -> Endianness {
        match self {
            Backend::Iced(d) => d.endianness(),
            Backend::Cap(d) => d.endianness(),
            Backend::Aarch64Hybrid { native, .. } => native.endianness(),
        }
    }

    fn name(&self) -> &str {
        match self {
            Backend::Iced(d) => d.name(),
            Backend::Cap(d) => d.name(),
            Backend::Aarch64Hybrid { .. } => "glaurung-aarch64+capstone",
        }
    }
}

impl Backend {
    /// Switch to/from Thumb mode on ARM backends. No-op on other arches/backends.
    pub fn set_thumb_mode(&mut self, thumb: bool) -> Result<(), DisassemblerError> {
        match self {
            Backend::Cap(d) => d.set_thumb_mode(thumb),
            Backend::Aarch64Hybrid { .. } => Ok(()),
            Backend::Iced(_) => Ok(()),
        }
    }
}

/// Select a disassembler backend for the given architecture.
pub fn for_arch(arch: Architecture, endianness: Endianness) -> Option<Backend> {
    match arch {
        Architecture::X86 | Architecture::X86_64 => Some(Backend::Iced(
            super::iced::IcedDisassembler::new(arch, endianness),
        )),
        Architecture::ARM64 => Some(Backend::Aarch64Hybrid {
            native: super::native_aarch64::NativeAarch64Disassembler::new(endianness),
            fallback: super::capstone::CapstoneDisassembler::new(arch, endianness)?,
        }),
        Architecture::ARM
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
    Native,
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
        Some(BackendKind::Native) => match arch {
            Architecture::ARM64 => Ok(Backend::Aarch64Hybrid {
                native: super::native_aarch64::NativeAarch64Disassembler::new(endianness),
                fallback: super::capstone::CapstoneDisassembler::new(arch, endianness)
                    .ok_or(DisassemblerError::UnsupportedArchitecture())?,
            }),
            _ => Err(DisassemblerError::UnsupportedArchitecture()),
        },
        None => for_arch(arch, endianness).ok_or(DisassemblerError::UnsupportedArchitecture()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    fn va(value: u64) -> Address {
        Address::new(AddressKind::VA, value, 64, None, None).unwrap()
    }

    #[test]
    fn default_aarch64_backend_is_native_first_and_capstone_complete() {
        let backend = for_arch(Architecture::ARM64, Endianness::Little).unwrap();
        assert_eq!(backend.name(), "glaurung-aarch64+capstone");

        // Native family: B +4.
        let branch = backend
            .disassemble_instruction(&va(0x1000), &[0x01, 0x00, 0x00, 0x14])
            .unwrap();
        assert_eq!(branch.mnemonic, "b");
        assert_eq!(branch.operands[0].immediate, Some(0x1004));

        // Not native yet: NOP must remain available through the migration
        // fallback so making the native decoder a production caller is not a
        // capability regression.
        let nop = backend
            .disassemble_instruction(&va(0x1000), &[0x1f, 0x20, 0x03, 0xd5])
            .unwrap();
        assert_eq!(nop.mnemonic, "nop");
    }
}
