use crate::core::address::Address;
use crate::core::binary::Endianness;
use crate::core::disassembler::{
    Architecture, Disassembler, DisassemblerError, DisassemblerResult,
};
use crate::core::instruction::{Access, Instruction, Operand};
use capstone::arch::arm::ArmOperandType;
use capstone::arch::arm64::Arm64OperandType;
use capstone::prelude::*;
use capstone::{Arch, Capstone, Endian, Mode, NO_EXTRA_MODE};

pub struct CapstoneDisassembler {
    cs: capstone::Capstone,
    arch: Architecture,
    endianness: Endianness,
}

fn cs_arch_mode(arch: Architecture, end: Endianness) -> Option<(Arch, Mode, Option<Endian>)> {
    match arch {
        Architecture::ARM => Some((
            Arch::ARM,
            Mode::Arm,
            Some(if matches!(end, Endianness::Big) {
                Endian::Big
            } else {
                Endian::Little
            }),
        )),
        Architecture::ARM64 => Some((
            Arch::ARM64,
            Mode::Arm,
            Some(if matches!(end, Endianness::Big) {
                Endian::Big
            } else {
                Endian::Little
            }),
        )),
        Architecture::MIPS => Some((
            Arch::MIPS,
            Mode::Mips32,
            Some(if matches!(end, Endianness::Big) {
                Endian::Big
            } else {
                Endian::Little
            }),
        )),
        Architecture::MIPS64 => Some((
            Arch::MIPS,
            Mode::Mips64,
            Some(if matches!(end, Endianness::Big) {
                Endian::Big
            } else {
                Endian::Little
            }),
        )),
        Architecture::PPC => Some((
            Arch::PPC,
            Mode::Mode32,
            Some(if matches!(end, Endianness::Big) {
                Endian::Big
            } else {
                Endian::Little
            }),
        )),
        Architecture::PPC64 => Some((
            Arch::PPC,
            Mode::Mode64,
            Some(if matches!(end, Endianness::Big) {
                Endian::Big
            } else {
                Endian::Little
            }),
        )),
        Architecture::RISCV => Some((Arch::RISCV, Mode::RiscV32, None)),
        Architecture::RISCV64 => Some((Arch::RISCV, Mode::RiscV64, None)),
        Architecture::X86 | Architecture::X86_64 | Architecture::Unknown => None,
    }
}

impl CapstoneDisassembler {
    pub fn new(arch: Architecture, endianness: Endianness) -> Option<Self> {
        let (a, m, endian) = cs_arch_mode(arch, endianness)?;
        let mut cs = Capstone::new_raw(a, m, NO_EXTRA_MODE, endian).ok()?;
        // Enable details to recover structured operands (needed for PC-relative addressing)
        let _ = cs.set_detail(true);
        Some(Self {
            cs,
            arch,
            endianness,
        })
    }

    fn parse_operands_simple(op_str: &str) -> Vec<Operand> {
        let mut out = Vec::new();
        for tok in op_str
            .split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
        {
            let lower = tok.to_ascii_lowercase();
            // Bracket form: [base, #disp] (ARM/ARM64) or [abs]
            if let (Some(l), Some(r)) = (lower.find('['), lower.find(']')) {
                let inside = &lower[(l + 1)..r];
                let mut base: Option<String> = None;
                let mut disp: Option<i64> = None;
                for part in inside.split(',').map(|p| p.trim()) {
                    if part.is_empty() {
                        continue;
                    }
                    if base.is_none() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        base = Some(part.to_string());
                        continue;
                    }
                    // immediate like #0x10 or 0x10 or -16
                    let s = part.trim_start_matches('#');
                    if let Some(stripped) = s.strip_prefix("0x") {
                        if let Ok(v) = i64::from_str_radix(stripped, 16) {
                            disp = Some(v);
                        }
                    } else if let Ok(v) = s.parse::<i64>() {
                        disp = Some(v);
                    }
                }
                out.push(Operand::memory(0, Access::Read, disp, base, None, None));
                continue;
            }
            // Paren form: disp(base) (MIPS/RISCV/PPC)
            if let (Some(l), Some(r)) = (lower.find('('), lower.find(')')) {
                let before = lower[..l].trim();
                let inside = lower[(l + 1)..r].trim();
                let base = if !inside.is_empty() {
                    Some(inside.to_string())
                } else {
                    None
                };
                let mut disp: Option<i64> = None;
                let b = before.trim_start_matches('#');
                if let Some(stripped) = b.strip_prefix("0x") {
                    if let Ok(v) = i64::from_str_radix(stripped, 16) {
                        disp = Some(v);
                    }
                } else if let Ok(v) = b.parse::<i64>() {
                    disp = Some(v);
                }
                out.push(Operand::memory(0, Access::Read, disp, base, None, None));
                continue;
            }
            let is_imm = lower.starts_with("0x")
                || lower.starts_with('#')
                || lower
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '+');
            if is_imm {
                let val = if let Some(s) = lower.strip_prefix('#') {
                    i64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
                } else if let Some(s) = lower.strip_prefix("0x") {
                    i64::from_str_radix(s, 16).unwrap_or(0)
                } else {
                    lower.parse::<i64>().unwrap_or(0)
                };
                out.push(Operand::immediate(val, 0));
            } else {
                out.push(Operand::register(tok.to_string(), 0, Access::Read));
            }
        }
        out
    }
}

impl Disassembler for CapstoneDisassembler {
    fn disassemble_instruction(
        &self,
        address: &Address,
        bytes: &[u8],
    ) -> DisassemblerResult<Instruction> {
        // Disassemble a single instruction
        let insns = self
            .cs
            .disasm_all(bytes, address.value)
            .map_err(|_| DisassemblerError::InvalidInstruction())?;
        if insns.is_empty() {
            return Err(DisassemblerError::InvalidInstruction());
        }
        let insn = insns.iter().next().unwrap();
        let len = insn.bytes().len();
        let mnemonic = insn.mnemonic().unwrap_or("").to_string();
        // Try detailed operands when available (ARM64 focus)
        let mut operands: Vec<Operand> = Vec::new();
        if let Ok(detail) = self.cs.insn_detail(insn) {
            match self.arch {
                Architecture::ARM64 => {
                    if let Some(ad) = detail.arch_detail().arm64() {
                        for op in ad.operands() {
                            match op.op_type {
                                Arm64OperandType::Reg(r) => {
                                    let name = self.cs.reg_name(r).unwrap_or_default();
                                    operands.push(Operand::register(name, 0, Access::Read));
                                }
                                Arm64OperandType::Imm(i) => {
                                    operands.push(Operand::immediate(i, 0));
                                }
                                Arm64OperandType::Mem(m) => {
                                    let base = if m.base().0 != 0 {
                                        Some(self.cs.reg_name(m.base()).unwrap_or_default())
                                    } else {
                                        None
                                    };
                                    let index = if m.index().0 != 0 {
                                        Some(self.cs.reg_name(m.index()).unwrap_or_default())
                                    } else {
                                        None
                                    };
                                    let scale = None;
                                    let disp = if m.disp() != 0 {
                                        Some(m.disp() as i64)
                                    } else {
                                        Some(0)
                                    };
                                    operands.push(Operand::memory(
                                        0,
                                        Access::Read,
                                        disp,
                                        base,
                                        index,
                                        scale,
                                    ));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Architecture::ARM => {
                    if let Some(ad) = detail.arch_detail().arm() {
                        for op in ad.operands() {
                            match op.op_type {
                                ArmOperandType::Reg(r) => {
                                    let name = self.cs.reg_name(r).unwrap_or_default();
                                    operands.push(Operand::register(name, 0, Access::Read));
                                }
                                ArmOperandType::Imm(i) => {
                                    operands.push(Operand::immediate(i as i64, 0))
                                }
                                ArmOperandType::Mem(m) => {
                                    let base = if m.base().0 != 0 {
                                        Some(self.cs.reg_name(m.base()).unwrap_or_default())
                                    } else {
                                        None
                                    };
                                    let index = if m.index().0 != 0 {
                                        Some(self.cs.reg_name(m.index()).unwrap_or_default())
                                    } else {
                                        None
                                    };
                                    let scale = None;
                                    let disp = if m.disp() != 0 {
                                        Some(m.disp() as i64)
                                    } else {
                                        Some(0)
                                    };
                                    operands.push(Operand::memory(
                                        0,
                                        Access::Read,
                                        disp,
                                        base,
                                        index,
                                        scale,
                                    ));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                // For other arches, rely on textual parsing fallback below.
                Architecture::RISCV
                | Architecture::RISCV64
                | Architecture::MIPS
                | Architecture::MIPS64
                | Architecture::PPC
                | Architecture::PPC64 => {}
                _ => {}
            }
        }
        if operands.is_empty() {
            // Fallback to simple text parsing
            let ops = insn.op_str().unwrap_or("");
            operands = if ops.is_empty() {
                Vec::new()
            } else {
                Self::parse_operands_simple(ops)
            };
        }
        let ins = Instruction {
            address: address.clone(),
            bytes: insn.bytes().to_vec(),
            mnemonic,
            operands,
            length: len as u16,
            arch: format!("{}", self.arch),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        };
        Ok(ins)
    }

    fn max_instruction_length(&self) -> usize {
        8
    }
    fn architecture(&self) -> Architecture {
        self.arch
    }
    fn endianness(&self) -> Endianness {
        self.endianness
    }
    fn name(&self) -> &str {
        "capstone"
    }
}
