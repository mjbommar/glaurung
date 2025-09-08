use crate::core::address::Address;
use crate::core::binary::Endianness;
use crate::core::disassembler::{
    Architecture, Disassembler, DisassemblerError, DisassemblerResult,
};
use crate::core::instruction::{Access, Instruction, Operand};

pub struct IcedDisassembler {
    bits: u32,
    arch: Architecture,
    endianness: Endianness,
}

impl IcedDisassembler {
    pub fn new(arch: Architecture, endianness: Endianness) -> Self {
        let bits = match arch {
            Architecture::X86 => 32,
            Architecture::X86_64 => 64,
            _ => 64,
        };
        Self {
            bits,
            arch,
            endianness,
        }
    }

    fn iced_operands(instr: &iced_x86::Instruction, bits: u32) -> Vec<Operand> {
        use iced_x86::{OpKind, Register as IReg};
        let mut out = Vec::new();
        let op_count = instr.op_count() as usize;
        for i in 0..op_count {
            let kind = instr.op_kind(i as u32);
            match kind {
                OpKind::Register => {
                    let r = instr.op_register(i as u32);
                    let name = format!("{:?}", r).to_ascii_lowercase();
                    // Size is unknown without table; use 0 as placeholder
                    out.push(Operand::register(name, 0, Access::Read));
                }
                OpKind::Memory => {
                    let base = instr.memory_base();
                    let index = instr.memory_index();
                    let scale = instr.memory_index_scale();
                    let disp = instr.memory_displacement64() as i64;
                    let base_s = if base != IReg::None {
                        Some(format!("{:?}", base).to_ascii_lowercase())
                    } else {
                        None
                    };
                    let index_s = if index != IReg::None {
                        Some(format!("{:?}", index).to_ascii_lowercase())
                    } else {
                        None
                    };
                    let scale_u8 = if scale > 0 { Some(scale as u8) } else { None };
                    out.push(Operand::memory(
                        0,
                        Access::Read,
                        Some(disp),
                        base_s,
                        index_s,
                        scale_u8,
                    ));
                }
                OpKind::Immediate8 => {
                    out.push(Operand::immediate(instr.immediate8() as i8 as i64, 8))
                }
                OpKind::Immediate16 => {
                    out.push(Operand::immediate(instr.immediate16() as i16 as i64, 16))
                }
                OpKind::Immediate32 => {
                    out.push(Operand::immediate(instr.immediate32() as i32 as i64, 32))
                }
                OpKind::Immediate64 => out.push(Operand::immediate(instr.immediate64() as i64, 64)),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    let target = instr.near_branch_target() as i64;
                    out.push(Operand::immediate(target, if bits >= 64 { 64 } else { 32 }));
                }
                OpKind::FarBranch16 | OpKind::FarBranch32 => {
                    // Represent as immediate far target using near branch convenience (segment not modeled)
                    let target = instr.near_branch_target() as i64;
                    out.push(Operand::immediate(target, if bits >= 64 { 64 } else { 32 }));
                }
                _ => {
                    // Fallback: use formatted text operand via IntelFormatter parsing when unknown
                    // We skip here; the textual formatter still provides display, but structured operand is omitted.
                }
            }
        }
        out
    }
}

impl Disassembler for IcedDisassembler {
    fn disassemble_instruction(
        &self,
        address: &Address,
        bytes: &[u8],
    ) -> DisassemblerResult<Instruction> {
        use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

        if !matches!(self.arch, Architecture::X86 | Architecture::X86_64) {
            return Err(DisassemblerError::UnsupportedInstruction());
        }
        let mut decoder = Decoder::new(self.bits, bytes, DecoderOptions::NONE);
        decoder.set_ip(address.value as u64);

        let instr = decoder.decode();
        if instr.is_invalid() {
            return Err(DisassemblerError::InvalidInstruction());
        }
        let len = instr.len();
        let mut fmt = IntelFormatter::new();
        let mut out = String::new();
        fmt.format(&instr, &mut out);
        let (mnemonic, _ops) = if let Some((m, rest)) = out.split_once(' ') {
            (m.to_string(), rest.trim().to_string())
        } else {
            (format!("{:?}", instr.mnemonic()), String::new())
        };
        let operands = Self::iced_operands(&instr, self.bits);

        let text_bytes = &bytes[..len.min(bytes.len())];
        let ins = Instruction {
            address: address.clone(),
            bytes: text_bytes.to_vec(),
            mnemonic,
            operands,
            length: len as u16,
            arch: match self.arch {
                Architecture::X86 => "x86".to_string(),
                Architecture::X86_64 => "x86_64".to_string(),
                _ => "x86".to_string(),
            },
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        };
        Ok(ins)
    }

    fn max_instruction_length(&self) -> usize {
        15
    }

    fn architecture(&self) -> Architecture {
        self.arch
    }

    fn endianness(&self) -> Endianness {
        self.endianness
    }

    fn name(&self) -> &str {
        "iced-x86"
    }
}
