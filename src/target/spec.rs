//! Validated target identity, data layout, ABI, and instruction-mode facts.

use crate::core::binary::{Arch, Endianness, Format};
use crate::target::abi::CallConv;
use crate::target::register_views::{self, RegisterView};
use crate::target::registers::RegisterRoles;

/// Internal decompiler target identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetId {
    /// 32-bit x86.
    X86_32,
    /// 64-bit x86.
    X86_64,
    /// 64-bit Arm.
    AArch64,
    /// 32-bit Arm, independent of A32 versus Thumb encoding.
    Arm32,
    /// Parsed by the program layer but not supported by the LLIR decompiler.
    Unsupported(Arch),
}

/// Instruction encoding mode for one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeMode {
    /// 32-bit x86 instruction encoding.
    X86_32,
    /// 64-bit x86 instruction encoding.
    X86_64,
    /// AArch64 instruction encoding.
    AArch64,
    /// ARM32 A32 instruction encoding.
    ArmA32,
    /// ARM32 Thumb instruction encoding.
    ArmThumb,
}

/// Operating-system ABI family inferred from the object container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsAbi {
    /// ELF-family System V ABI.
    SystemV,
    /// Windows ABI.
    Windows,
    /// Darwin ABI.
    Darwin,
    /// Container metadata does not establish an OS ABI.
    Unknown,
}

/// How a lifted instruction interprets the architectural program counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcRule {
    /// PC-relative operands are based on the following instruction.
    NextInstruction,
    /// Reading PC yields the current instruction address plus this byte bias.
    CurrentPlus(u8),
    /// The ISA has no source-visible general-purpose PC value in LLIR.
    NotGeneralPurpose,
}

/// One immutable, internally consistent machine target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetSpec {
    id: TargetId,
    architecture: Arch,
    endianness: Endianness,
    format: Format,
    os_abi: OsAbi,
    address_bits: Option<u8>,
    pointer_bits: Option<u8>,
    default_code_mode: Option<CodeMode>,
    calling_convention: Option<CallConv>,
    registers: RegisterRoles,
}

impl TargetSpec {
    /// Build the canonical target from facts extracted during the image's one
    /// object parse. Unsupported ISAs remain explicit rather than being
    /// silently interpreted as x86-64.
    pub(crate) fn from_image_metadata(
        architecture: Arch,
        endianness: Endianness,
        format: Format,
        arm_hard_float: bool,
    ) -> Self {
        let id = match architecture {
            Arch::X86 => TargetId::X86_32,
            Arch::X86_64 => TargetId::X86_64,
            Arch::AArch64 => TargetId::AArch64,
            Arch::ARM => TargetId::Arm32,
            other => TargetId::Unsupported(other),
        };
        let default_code_mode = match id {
            TargetId::X86_32 => Some(CodeMode::X86_32),
            TargetId::X86_64 => Some(CodeMode::X86_64),
            TargetId::AArch64 => Some(CodeMode::AArch64),
            TargetId::Arm32 => Some(CodeMode::ArmA32),
            TargetId::Unsupported(_) => None,
        };
        let os_abi = match format {
            Format::ELF => OsAbi::SystemV,
            Format::PE => OsAbi::Windows,
            Format::MachO => OsAbi::Darwin,
            _ => OsAbi::Unknown,
        };
        let calling_convention = match id {
            TargetId::X86_32 => Some(CallConv::Cdecl32),
            TargetId::X86_64 if os_abi == OsAbi::Windows => Some(CallConv::Win64),
            TargetId::X86_64 => Some(CallConv::SysVAmd64),
            TargetId::AArch64 => Some(CallConv::Aarch64),
            TargetId::Arm32 if arm_hard_float => Some(CallConv::ArmHardFloat),
            TargetId::Arm32 => Some(CallConv::Arm),
            TargetId::Unsupported(_) => None,
        };
        let address_bits = match architecture {
            Arch::X86 | Arch::ARM | Arch::MIPS | Arch::PPC | Arch::RISCV => Some(32),
            Arch::X86_64 | Arch::AArch64 | Arch::MIPS64 | Arch::PPC64 | Arch::RISCV64 => Some(64),
            Arch::Unknown => None,
        };

        Self {
            id,
            architecture,
            endianness,
            format,
            os_abi,
            address_bits,
            pointer_bits: address_bits,
            default_code_mode,
            calling_convention,
            registers: RegisterRoles::for_target(id),
        }
    }

    /// Internal architecture identity supported by the decompiler.
    pub fn id(self) -> TargetId {
        self.id
    }

    /// Compatibility architecture for public APIs still using `core::Arch`.
    pub fn architecture(self) -> Arch {
        self.architecture
    }

    /// Target byte order.
    pub fn endianness(self) -> Endianness {
        self.endianness
    }

    /// Object-container format from which this target was derived.
    pub fn format(self) -> Format {
        self.format
    }

    /// Operating-system ABI established by the object container.
    pub fn os_abi(self) -> OsAbi {
        self.os_abi
    }

    /// Width of virtual addresses, or `None` when the parsed ISA is unknown.
    pub fn address_bits(self) -> Option<u8> {
        self.address_bits
    }

    /// Width of ordinary data pointers, or `None` when not established.
    pub fn pointer_bits(self) -> Option<u8> {
        self.pointer_bits
    }

    /// Default instruction encoding for functions without a mode marker.
    pub fn default_code_mode(self) -> Option<CodeMode> {
        self.default_code_mode
    }

    /// Select the per-function ARM encoding without changing any other target.
    /// A Thumb marker on a non-ARM target is rejected.
    pub fn code_mode_for_function(self, is_thumb: bool) -> Option<CodeMode> {
        match (self.id, is_thumb) {
            (TargetId::Arm32, true) => Some(CodeMode::ArmThumb),
            (TargetId::Arm32, false) => Some(CodeMode::ArmA32),
            (_, true) => None,
            (_, false) => self.default_code_mode,
        }
    }

    /// Default calling convention established by the target and object ABI.
    pub fn calling_convention(self) -> Option<CallConv> {
        self.calling_convention
    }

    /// Architecture-qualified special-register roles.
    pub fn registers(self) -> RegisterRoles {
        self.registers
    }

    /// Architecture-qualified view of one physical register spelling.
    ///
    /// Register-view migration is incremental. ARM32 is target-owned now;
    /// existing x86-64 and AArch64 consumers continue through the compatibility
    /// facade in `crate::ir::regview` until their fact class moves here.
    pub fn register_view(self, name: &str) -> Option<RegisterView> {
        register_views::view(self.id, name)
    }

    /// Canonical storage parent when writing `name` replaces every parent bit.
    ///
    /// Partial views deliberately return `None`: callers performing SSA
    /// definition canonicalization must not turn an `s0` or `d0` write into a
    /// complete definition of the overlapping ARM32 `q0` storage family.
    pub fn complete_register_write_parent(self, name: &str) -> Option<&'static str> {
        self.register_view(name)
            .filter(|view| view.is_complete_write())
            .map(RegisterView::parent)
    }

    /// Minimum byte alignment of an instruction start in `mode`, if the mode
    /// belongs to this target.
    pub fn instruction_alignment(self, mode: CodeMode) -> Option<u8> {
        self.supports_mode(mode).then_some(match mode {
            CodeMode::X86_32 | CodeMode::X86_64 => 1,
            CodeMode::AArch64 | CodeMode::ArmA32 => 4,
            CodeMode::ArmThumb => 2,
        })
    }

    /// Architectural PC rule in `mode`, if the mode belongs to this target.
    pub fn pc_rule(self, mode: CodeMode) -> Option<PcRule> {
        self.supports_mode(mode).then_some(match mode {
            CodeMode::X86_32 | CodeMode::X86_64 => PcRule::NextInstruction,
            CodeMode::AArch64 => PcRule::NotGeneralPurpose,
            CodeMode::ArmA32 => PcRule::CurrentPlus(8),
            CodeMode::ArmThumb => PcRule::CurrentPlus(4),
        })
    }

    fn supports_mode(self, mode: CodeMode) -> bool {
        matches!(
            (self.id, mode),
            (TargetId::X86_32, CodeMode::X86_32)
                | (TargetId::X86_64, CodeMode::X86_64)
                | (TargetId::AArch64, CodeMode::AArch64)
                | (TargetId::Arm32, CodeMode::ArmA32 | CodeMode::ArmThumb)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_coff_does_not_claim_the_windows_abi() {
        let target =
            TargetSpec::from_image_metadata(Arch::X86_64, Endianness::Little, Format::COFF, false);

        assert_eq!(target.os_abi(), OsAbi::Unknown);
        assert_eq!(target.calling_convention(), Some(CallConv::SysVAmd64));
    }
}
