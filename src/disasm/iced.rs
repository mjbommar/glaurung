use std::cell::RefCell;
use std::sync::OnceLock;

use crate::core::address::Address;
use crate::core::binary::Endianness;
use crate::core::disassembler::{
    Architecture, Disassembler, DisassemblerError, DisassemblerResult,
};
use crate::core::instruction::{Access, Instruction, Operand};

/// Lowercased spelling of every `iced_x86::Mnemonic`, interned once per process.
///
/// The per-instruction expression this replaces was
/// `format!("{:?}", instr.mnemonic()).to_ascii_lowercase()`: two heap
/// allocations plus a trip through `core::fmt`'s `Debug` machinery on an enum
/// with 1,894 variants, paid on every decoded instruction in both the discovery
/// and lift phases. The table is *filled with that same expression*, so the
/// strings it hands out are identical by construction rather than by a
/// hand-transcribed table that could drift from iced-x86.
///
/// `Mnemonic::values()` yields the variants in discriminant order starting at
/// zero, so the index of an entry is `mnemonic as usize`; `mnemonic_name`
/// falls back to formatting if that ever stops holding.
fn mnemonic_names() -> &'static [String] {
    static NAMES: OnceLock<Box<[String]>> = OnceLock::new();
    NAMES.get_or_init(|| {
        iced_x86::Mnemonic::values()
            .map(|m| format!("{:?}", m).to_ascii_lowercase())
            .collect()
    })
}

/// Lowercased spelling of every `iced_x86::Register`, interned once per process.
///
/// Same mechanism, same guarantee as [`mnemonic_names`]. Register names are the
/// hotter of the two: an ordinary x86-64 instruction carries two register
/// operands, and a memory operand adds a base and an index on top.
fn register_names() -> &'static [String] {
    static NAMES: OnceLock<Box<[String]>> = OnceLock::new();
    NAMES.get_or_init(|| {
        iced_x86::Register::values()
            .map(|r| format!("{:?}", r).to_ascii_lowercase())
            .collect()
    })
}

/// Interned lowercase mnemonic spelling: one allocation instead of two.
fn mnemonic_name(m: iced_x86::Mnemonic) -> String {
    match mnemonic_names().get(m as usize) {
        Some(name) => name.clone(),
        None => format!("{:?}", m).to_ascii_lowercase(),
    }
}

/// Interned lowercase register spelling: one allocation instead of two.
fn register_name(r: iced_x86::Register) -> String {
    match register_names().get(r as usize) {
        Some(name) => name.clone(),
        None => format!("{:?}", r).to_ascii_lowercase(),
    }
}

/// A memory operand carrying the exact `text` [`Operand::memory`] would derive,
/// composed in one allocation instead of four.
///
/// `Operand::memory` builds its text with `String::new()` and a
/// `push_str(&format!(..))` per part. Each `format!` is a throwaway `String`,
/// and the target reallocates as it grows out of the allocator's first bucket,
/// so `[rbp - 0x8]` -- the commonest operand shape in unoptimised code -- cost
/// three allocations for its text and a fourth for the base register name.
/// Writing straight into one pre-sized `String` with `write!` removes the
/// temporaries; `write!` on a `String` is infallible and appends in place.
///
/// The rules are transcribed from `Operand::memory` exactly, *including* the one
/// that reads like a bug: the leading `seg:` prefix is emitted from the BASE
/// register rather than from a segment, so `[rbp-8]` renders as
/// `rbp:[rbp - 0x8]`. That is what the decoder has always produced and what
/// every string-keyed consumer downstream already expects, so it is preserved
/// deliberately rather than quietly corrected here.
///
/// `memory_operand_text_matches_operand_memory` below is the link that keeps the
/// two in step: it compares this against `Operand::memory` over a grid of bases,
/// indexes, scales and displacements, so a future edit to either side fails
/// loudly instead of diverging.
fn memory_operand(
    size: u8,
    access: Access,
    displacement: Option<i64>,
    base: Option<String>,
    index: Option<String>,
    scale: Option<u8>,
) -> Operand {
    use std::fmt::Write as _;
    // Enough for `rbp:[rbp + rax * 8 + 0x7fffffffffffffff]`, the widest shape
    // the rules below can produce, so the common case never reallocates.
    let mut text = String::with_capacity(48);
    if let Some(seg) = &base {
        if seg != "ds" {
            text.push_str(seg);
            text.push(':');
        }
    }
    text.push('[');
    if let Some(b) = &base {
        text.push_str(b);
    }
    if let Some(idx) = &index {
        if base.is_some() {
            text.push_str(" + ");
        }
        text.push_str(idx);
        if let Some(s) = scale {
            if s > 1 {
                let _ = write!(text, " * {}", s);
            }
        }
    }
    if let Some(disp) = displacement {
        if base.is_some() || index.is_some() {
            if disp >= 0 {
                let _ = write!(text, " + 0x{:x}", disp);
            } else {
                let _ = write!(text, " - 0x{:x}", -disp);
            }
        } else {
            let _ = write!(text, "0x{:x}", disp);
        }
    }
    text.push(']');
    Operand {
        kind: crate::core::instruction::OperandKind::Memory,
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
        vector_shape: None,
        vector_index: None,
    }
}

pub struct IcedDisassembler {
    bits: u32,
    arch: Architecture,
    endianness: Endianness,
    /// Reused across `disassemble_instruction` calls.
    ///
    /// `InstructionInfoFactory::new()` allocates two `Vec`s sized for the
    /// worst-case used-register and used-memory sets — measured at two
    /// allocations and ~850 bytes *per instruction* when built inside the decode
    /// loop, which was the single largest allocation term in the decoder. The
    /// factory is a scratch buffer: `info()` overwrites it, so one per
    /// disassembler is enough and the returned `InstructionInfo` is identical.
    ///
    /// `RefCell` rather than `&mut self` because `Disassembler::disassemble_instruction`
    /// takes `&self`. Nothing re-enters the decoder while the borrow is live, so
    /// the borrow cannot conflict.
    info_factory: RefCell<iced_x86::InstructionInfoFactory>,
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
            info_factory: RefCell::new(iced_x86::InstructionInfoFactory::new()),
        }
    }

    fn iced_operands(&self, instr: &iced_x86::Instruction, bits: u32) -> Vec<Operand> {
        use iced_x86::{OpAccess, OpKind, Register as IReg};
        // Per-operand read/write access (op_access(i) aligns with op_kind(i)).
        // Without this every operand was reported Read, so the lifter could not
        // tell a destination from a source.
        let mut factory = self.info_factory.borrow_mut();
        let info = factory.info(instr);
        let map_access = |a: OpAccess| -> Access {
            match a {
                OpAccess::Write | OpAccess::CondWrite => Access::Write,
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => Access::ReadWrite,
                _ => Access::Read,
            }
        };
        let op_count = instr.op_count() as usize;
        // Exact capacity: `Vec::new()` grew 0->1->2->4 as operands were pushed,
        // so a two-operand instruction paid two allocations for the vector alone.
        // Kinds that fall through the `_ =>` arm below leave spare capacity,
        // which is not observable in the decoded instruction.
        let mut out = Vec::with_capacity(op_count);
        for i in 0..op_count {
            let kind = instr.op_kind(i as u32);
            let acc = map_access(info.op_access(i as u32));
            match kind {
                OpKind::Register => {
                    let r = instr.op_register(i as u32);
                    let name = register_name(r);
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
                        Some(register_name(base))
                    } else {
                        None
                    };
                    let index_s = if index != IReg::None {
                        Some(register_name(index))
                    } else {
                        None
                    };
                    let scale_u8 = if scale > 0 { Some(scale as u8) } else { None };
                    // Access width in bits (0 for address-only operands like lea,
                    // where iced reports MemorySize::Unknown).
                    let mem_bits = instr.memory_size().size().saturating_mul(8).min(255) as u8;
                    out.push(memory_operand(
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
                OpKind::Immediate8to64 => out.push(Operand::immediate(instr.immediate8to64(), 64)),
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
                            register_name(s)
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
                    let mem_bits = instr.memory_size().size().saturating_mul(8).min(255) as u8;
                    let mut op =
                        memory_operand(mem_bits, acc, None, Some(base.to_string()), None, None);
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
        use iced_x86::{Decoder, DecoderOptions};

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
        // The formatter includes instruction prefixes in its text. For CET
        // indirect branches it renders `notrack jmp rdx`; taking the first
        // whitespace-delimited token therefore turned the operation into
        // `notrack` and made every control-flow consumer miss the jump. Iced's
        // decoded mnemonic is the authoritative operation and deliberately
        // excludes prefixes.
        let mnemonic = mnemonic_name(instr.mnemonic());
        let operands = self.iced_operands(&instr, self.bits);

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
        let ins = d
            .disassemble_instruction(&va(0x1000), &[0xb9, 0x10, 0, 0, 0])
            .unwrap();
        assert_eq!(ins.operands[0].size, 32, "ecx is 32-bit");
        // mov rax, [rbp - 8] -> op0 rax (64), op1 qword memory (64)
        let ins = d
            .disassemble_instruction(&va(0x1000), &[0x48, 0x8b, 0x45, 0xf8])
            .unwrap();
        assert_eq!(ins.operands[0].size, 64, "rax is 64-bit");
        assert_eq!(ins.operands[1].size, 64, "qword memory access");
        // add byte ptr [rax], 1 -> op0 byte memory (8)
        let ins = d
            .disassemble_instruction(&va(0x1000), &[0x80, 0x00, 0x01])
            .unwrap();
        assert_eq!(ins.operands[0].kind, OperandKind::Memory);
        assert_eq!(ins.operands[0].size, 8, "byte memory access");
    }

    #[test]
    fn notrack_prefix_does_not_replace_the_jump_mnemonic() {
        let d = dis();
        // GCC -O2 emits this CET-hardened indirect jump for switch tables.
        // `notrack` is a prefix, not the operation: CFG discovery must still
        // see a register-indirect `jmp` and resolve its case successors.
        let ins = d
            .disassemble_instruction(&va(0x112f), &[0x3e, 0xff, 0xe2])
            .unwrap();
        assert_eq!(ins.mnemonic.to_ascii_lowercase(), "jmp");
        assert_eq!(ins.operands[0].register.as_deref(), Some("rdx"));
        assert_eq!(ins.operands[0].access, Access::Read);
    }

    #[test]
    fn operand_access_distinguishes_read_and_write() {
        use crate::core::instruction::Access;
        let d = dis();
        // mov [rax], rbx (48 89 18): op0 memory = Write, op1 rbx = Read
        let ins = d
            .disassemble_instruction(&va(0x1000), &[0x48, 0x89, 0x18])
            .unwrap();
        assert_eq!(ins.operands[0].access, Access::Write, "[rax] is written");
        assert_eq!(ins.operands[1].access, Access::Read, "rbx is read");
        // add rax, rbx (48 01 d8): op0 rax = ReadWrite, op1 rbx = Read
        let ins = d
            .disassemble_instruction(&va(0x1000), &[0x48, 0x01, 0xd8])
            .unwrap();
        assert_eq!(ins.operands[0].access, Access::ReadWrite, "add dest is r/w");
        assert_eq!(ins.operands[1].access, Access::Read);
    }

    #[test]
    fn sign_extended_immediate_is_not_dropped() {
        // cmp ecx, 0x15  (83 f9 15) uses Immediate8to32 -> previously dropped.
        let ins = dis()
            .disassemble_instruction(&va(0x1000), &[0x83, 0xf9, 0x15])
            .unwrap();
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

    /// The interned tables must agree with the `format!` expressions they
    /// replaced for *every* variant, not just the ones a fixture happens to
    /// decode. The mnemonic and register spellings are load-bearing: the lifter
    /// dispatches on the mnemonic and every dataflow map is keyed on the
    /// register name, so a single divergent entry would silently change every
    /// emitted function.
    #[test]
    fn interned_mnemonic_names_match_the_format_they_replaced() {
        for m in iced_x86::Mnemonic::values() {
            assert_eq!(
                mnemonic_name(m),
                format!("{:?}", m).to_ascii_lowercase(),
                "mnemonic {m:?} (discriminant {})",
                m as usize
            );
        }
    }

    #[test]
    fn interned_register_names_match_the_format_they_replaced() {
        for r in iced_x86::Register::values() {
            assert_eq!(
                register_name(r),
                format!("{:?}", r).to_ascii_lowercase(),
                "register {r:?} (discriminant {})",
                r as usize
            );
        }
    }

    /// The tables are indexed by `enum as usize`, which is only correct while
    /// `values()` yields the variants in discriminant order from zero. Pin it.
    #[test]
    fn interning_tables_are_indexed_by_discriminant() {
        for (i, m) in iced_x86::Mnemonic::values().enumerate() {
            assert_eq!(
                i, m as usize,
                "Mnemonic::values() is not discriminant-ordered"
            );
        }
        for (i, r) in iced_x86::Register::values().enumerate() {
            assert_eq!(
                i, r as usize,
                "Register::values() is not discriminant-ordered"
            );
        }
        assert_eq!(mnemonic_names().len(), iced_x86::Mnemonic::values().count());
        assert_eq!(register_names().len(), iced_x86::Register::values().count());
    }

    /// `memory_operand` transcribes `Operand::memory`'s text rules to compose
    /// them in one allocation. The transcription is only safe while the two
    /// agree, so compare them over a grid that covers every branch: with and
    /// without a base, with and without an index, every scale the encoding can
    /// carry, positive, negative and absent displacements, and the `"ds"` base
    /// that suppresses the (mis-named) prefix.
    #[test]
    fn memory_operand_text_matches_operand_memory() {
        let bases = [None, Some("rbp"), Some("rax"), Some("ds"), Some("r15d")];
        let indexes = [None, Some("rcx"), Some("r9")];
        let scales = [None, Some(1u8), Some(2), Some(4), Some(8)];
        let disps = [
            None,
            Some(0i64),
            Some(1),
            Some(-1),
            Some(8),
            Some(-8),
            Some(0x7fff_ffff),
            Some(-0x8000_0000),
            Some(i64::MAX),
        ];
        let mut checked = 0usize;
        for base in bases {
            for index in indexes {
                for scale in scales {
                    for disp in disps {
                        let b = base.map(str::to_string);
                        let i = index.map(str::to_string);
                        let mine =
                            memory_operand(64, Access::Read, disp, b.clone(), i.clone(), scale);
                        let theirs = Operand::memory(64, Access::Read, disp, b, i, scale);
                        assert_eq!(
                            mine, theirs,
                            "base={base:?} index={index:?} scale={scale:?} disp={disp:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 5 * 3 * 5 * 9);
    }

    /// The shared `InstructionInfoFactory` is a scratch buffer that `info()`
    /// overwrites. Decoding a long run through one disassembler must give the
    /// same operand accesses as decoding each instruction through a fresh one.
    #[test]
    fn a_reused_info_factory_does_not_leak_state_between_instructions() {
        let shared = dis();
        // A mix whose accesses differ per position: write-dest, read-only,
        // read-modify-write, and a zero-operand form in between.
        let program: &[&[u8]] = &[
            &[0x48, 0x89, 0x18],       // mov [rax], rbx
            &[0x90],                   // nop
            &[0x48, 0x01, 0xd8],       // add rax, rbx
            &[0xa4],                   // movsb
            &[0x48, 0x8b, 0x45, 0xf8], // mov rax, [rbp-8]
            &[0xc3],                   // ret
        ];
        // Two passes over the shared decoder, so the second pass sees a factory
        // already filled by the first.
        for _ in 0..2 {
            for bytes in program {
                let fresh = dis();
                assert_eq!(
                    shared.disassemble_instruction(&va(0x1000), bytes).unwrap(),
                    fresh.disassemble_instruction(&va(0x1000), bytes).unwrap(),
                );
            }
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
