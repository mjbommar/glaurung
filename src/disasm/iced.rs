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
        use iced_x86::{InstructionInfoFactory, OpAccess, OpKind, Register as IReg};
        // Per-operand read/write access (op_access(i) aligns with op_kind(i)).
        // Without this every operand was reported Read, so the lifter could not
        // tell a destination from a source.
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(instr);
        let map_access = |a: OpAccess| -> Access {
            match a {
                OpAccess::Write | OpAccess::CondWrite => Access::Write,
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => Access::ReadWrite,
                _ => Access::Read,
            }
        };
        let mut out = Vec::new();
        let op_count = instr.op_count() as usize;
        for i in 0..op_count {
            let kind = instr.op_kind(i as u32);
            let acc = map_access(info.op_access(i as u32));
            match kind {
                OpKind::Register => {
                    let r = instr.op_register(i as u32);
                    let name = format!("{:?}", r).to_ascii_lowercase();
                    // Register width in bits (iced reports bytes). Saturate to u8:
                    // zmm (512b) exceeds u8, but gp/xmm sizes are the common case.
                    let size_bits = r.size().saturating_mul(8).min(255) as u8;
                    out.push(Operand::register(name, size_bits, acc));
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
                    // Access width in bits (0 for address-only operands like lea,
                    // where iced reports MemorySize::Unknown).
                    let mem_bits = instr.memory_size().size().saturating_mul(8).min(255) as u8;
                    out.push(Operand::memory(
                        mem_bits,
                        acc,
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
                // Sign-extended immediate encodings (e.g. `83 /7 ib` = cmp r32,imm8s
                // -> Immediate8to32). iced models these as distinct op-kinds; without
                // them the structured immediate is silently dropped.
                OpKind::Immediate8to16 => {
                    out.push(Operand::immediate(instr.immediate8to16() as i64, 16))
                }
                OpKind::Immediate8to32 => {
                    out.push(Operand::immediate(instr.immediate8to32() as i64, 32))
                }
                OpKind::Immediate8to64 => {
                    out.push(Operand::immediate(instr.immediate8to64(), 64))
                }
                OpKind::Immediate32to64 => {
                    out.push(Operand::immediate(instr.immediate32to64(), 64))
                }
                OpKind::Immediate8_2nd => {
                    out.push(Operand::immediate(instr.immediate8_2nd() as i64, 8))
                }
                // Implicit string-instruction memory operands (movs/stos/lods/
                // scas/cmps). Previously dropped by the fallback, so `rep movsb`
                // lost both of its memory operands.
                OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI => {
                    let seg_pfx = |default: &str| -> String {
                        let s = instr.segment_prefix();
                        if s != IReg::None {
                            format!("{:?}", s).to_ascii_lowercase()
                        } else {
                            default.to_string()
                        }
                    };
                    let (base, seg): (&str, String) = match kind {
                        OpKind::MemorySegSI => ("si", seg_pfx("ds")),
                        OpKind::MemorySegESI => ("esi", seg_pfx("ds")),
                        OpKind::MemorySegRSI => ("rsi", seg_pfx("ds")),
                        OpKind::MemorySegDI => ("di", seg_pfx("ds")),
                        OpKind::MemorySegEDI => ("edi", seg_pfx("ds")),
                        OpKind::MemorySegRDI => ("rdi", seg_pfx("ds")),
                        OpKind::MemoryESDI => ("di", "es".to_string()),
                        OpKind::MemoryESEDI => ("edi", "es".to_string()),
                        OpKind::MemoryESRDI => ("rdi", "es".to_string()),
                        _ => unreachable!(),
                    };
                    let mem_bits =
                        instr.memory_size().size().saturating_mul(8).min(255) as u8;
                    let mut op =
                        Operand::memory(mem_bits, acc, None, Some(base.to_string()), None, None);
                    op.segment = Some(seg);
                    out.push(op);
                }
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
        decoder.set_ip(address.value);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::AddressKind;
    use crate::core::instruction::OperandKind;

    fn dis() -> IcedDisassembler {
        IcedDisassembler::new(Architecture::X86_64, Endianness::Little)
    }
    fn va(v: u64) -> Address {
        Address::new(AddressKind::VA, v, 64, None, None).unwrap()
    }

    #[test]
    fn register_and_memory_sizes_are_extracted() {
        let d = dis();
        // mov ecx, 0x10  -> op0 = ecx (32-bit register)
        let ins = d.disassemble_instruction(&va(0x1000), &[0xb9, 0x10, 0, 0, 0]).unwrap();
        assert_eq!(ins.operands[0].size, 32, "ecx is 32-bit");
        // mov rax, [rbp - 8] -> op0 rax (64), op1 qword memory (64)
        let ins = d.disassemble_instruction(&va(0x1000), &[0x48, 0x8b, 0x45, 0xf8]).unwrap();
        assert_eq!(ins.operands[0].size, 64, "rax is 64-bit");
        assert_eq!(ins.operands[1].size, 64, "qword memory access");
        // add byte ptr [rax], 1 -> op0 byte memory (8)
        let ins = d.disassemble_instruction(&va(0x1000), &[0x80, 0x00, 0x01]).unwrap();
        assert_eq!(ins.operands[0].kind, OperandKind::Memory);
        assert_eq!(ins.operands[0].size, 8, "byte memory access");
    }

    #[test]
    fn operand_access_distinguishes_read_and_write() {
        use crate::core::instruction::Access;
        let d = dis();
        // mov [rax], rbx (48 89 18): op0 memory = Write, op1 rbx = Read
        let ins = d.disassemble_instruction(&va(0x1000), &[0x48, 0x89, 0x18]).unwrap();
        assert_eq!(ins.operands[0].access, Access::Write, "[rax] is written");
        assert_eq!(ins.operands[1].access, Access::Read, "rbx is read");
        // add rax, rbx (48 01 d8): op0 rax = ReadWrite, op1 rbx = Read
        let ins = d.disassemble_instruction(&va(0x1000), &[0x48, 0x01, 0xd8]).unwrap();
        assert_eq!(ins.operands[0].access, Access::ReadWrite, "add dest is r/w");
        assert_eq!(ins.operands[1].access, Access::Read);
    }

    #[test]
    fn sign_extended_immediate_is_not_dropped() {
        // cmp ecx, 0x15  (83 f9 15) uses Immediate8to32 -> previously dropped.
        let ins = dis().disassemble_instruction(&va(0x1000), &[0x83, 0xf9, 0x15]).unwrap();
        let imm = ins.operands.iter().find_map(|o| o.immediate);
        assert_eq!(imm, Some(0x15), "imm8-to-32 must be extracted");
    }

    /// Guard against silent operand drops (the `_ => {}` fallback class of bug).
    /// Each form lists its expected structured-operand count; a regression that
    /// stops emitting an operand kind trips here.
    #[test]
    fn no_operand_is_silently_dropped() {
        let d = dis();
        let cases: &[(&[u8], usize, &str)] = &[
            (&[0x90], 0, "nop"),
            (&[0xc3], 0, "ret"),
            (&[0x50], 1, "push rax"),
            (&[0x48, 0x89, 0x18], 2, "mov [rax], rbx"),
            (&[0x83, 0xf9, 0x15], 2, "cmp ecx, imm8s"),
            (&[0xb8, 0x10, 0, 0, 0], 2, "mov eax, imm32"),
            (&[0xa4], 2, "movsb (es:[rdi], ds:[rsi])"),
            (&[0xaa], 2, "stosb (es:[rdi], al)"),
            (&[0xac], 2, "lodsb (al, ds:[rsi])"),
            (&[0xf3, 0xa4], 2, "rep movsb"),
        ];
        for (bytes, expect, name) in cases {
            let ins = d.disassemble_instruction(&va(0x1000), bytes).unwrap();
            assert_eq!(ins.operands.len(), *expect, "{name}: operand count");
        }
    }

    #[test]
    fn string_op_operands_carry_base_and_segment() {
        // movsb: op0 = es:[rdi], op1 = ds:[rsi]
        let ins = dis().disassemble_instruction(&va(0x1000), &[0xa4]).unwrap();
        assert_eq!(ins.operands[0].base.as_deref(), Some("rdi"));
        assert_eq!(ins.operands[0].segment.as_deref(), Some("es"));
        assert_eq!(ins.operands[1].base.as_deref(), Some("rsi"));
        assert_eq!(ins.operands[1].segment.as_deref(), Some("ds"));
    }
}
