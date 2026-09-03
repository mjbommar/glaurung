use crate::core::address::Address;
use crate::core::binary::Endianness;
use crate::core::disassembler::{
    Architecture, Disassembler, DisassemblerError, DisassemblerResult,
};
use crate::core::instruction::{Access, Instruction, Operand, VectorShape};
use capstone::arch::arm::ArmOperandType;
use capstone::arch::arm64::{Arm64OperandType, Arm64Vas};
use capstone::prelude::*;
use capstone::{Arch, Capstone, Endian, ExtraMode, Mode};

pub struct CapstoneDisassembler {
    cs: capstone::Capstone,
    /// A second ARM decoder in Cortex-M (`CS_MODE_MCLASS`) mode, used **only**
    /// when the primary decoder rejects an instruction.
    ///
    /// M-profile and A-profile assign different meanings to the same Thumb
    /// system-register encodings, so no single Capstone configuration decodes
    /// both. Enabling MClass globally is not an option: `f381 8100` is
    /// `msr cpsr_c, r1` on A-profile and decodes as `msr apsr_nzcvq, r1` under
    /// MClass -- a silently WRONG answer rather than a failed one.
    ///
    /// As a fallback it is safe in the direction that matters. A-profile
    /// system instructions decode successfully on the primary, so the fallback
    /// never sees them; Cortex-M `mrs r0, BASEPRI` (`f3ef 8011`) is rejected
    /// outright by the primary, and rejection is what abandons the enclosing
    /// function. That is DecBench failure class F2a, 31 rows: an `mrs` inside
    /// an interrupt-priority critical section appears in essentially every
    /// RTOS and bare-metal image, and the whole function is lost at it.
    mclass: Option<capstone::Capstone>,
    arch: Architecture,
    endianness: Endianness,
}

/// The multiplier an ARM/AArch64 scaled-index memory operand applies to its
/// index register, or `None` when the index is unshifted.
///
/// Capstone carries the shift on the *operand* (`ArmOperand::shift` /
/// `Arm64Operand::shift`), not inside `ArmOpMem`/`Arm64OpMem`, so a reader that
/// only inspects the mem struct sees `[base, index]` for `[base, index, lsl #2]`
/// and computes an effective address four times too small — with no diagnostic
/// anywhere. Only a left shift denotes a scale; `asr`/`lsr`/`ror`/`rrx` and every
/// register-amount form are index arithmetic this operand model cannot spell, so
/// they report `None` rather than a fabricated multiplier.
///
/// `Operand::scale` is a `u8`, so shifts wider than 7 (a 256x or larger stride,
/// which no compiler emits for a table) also decline instead of truncating.
fn shift_to_scale(shift_amount: Option<u32>) -> Option<u8> {
    let amount = shift_amount?;
    if amount == 0 || amount > 7 {
        return None;
    }
    Some(1u8 << amount)
}

/// The left-shift amount of an ARM32 operand, if it has one.
fn arm_lsl_amount(shift: capstone::arch::arm::ArmShift) -> Option<u32> {
    match shift {
        capstone::arch::arm::ArmShift::Lsl(amount) => Some(amount),
        _ => None,
    }
}

/// The left-shift amount of an AArch64 operand, if it has one.
fn arm64_lsl_amount(shift: capstone::arch::arm64::Arm64Shift) -> Option<u32> {
    match shift {
        capstone::arch::arm64::Arm64Shift::Lsl(amount) => Some(amount),
        _ => None,
    }
}

fn arm64_vector_shape(arrangement: Arm64Vas) -> Option<VectorShape> {
    use Arm64Vas::*;

    let (lanes, element_bits) = match arrangement {
        ARM64_VAS_16B => (16, 8),
        ARM64_VAS_8B => (8, 8),
        ARM64_VAS_4B => (4, 8),
        ARM64_VAS_1B => (1, 8),
        ARM64_VAS_8H => (8, 16),
        ARM64_VAS_4H => (4, 16),
        ARM64_VAS_2H => (2, 16),
        ARM64_VAS_1H => (1, 16),
        ARM64_VAS_4S => (4, 32),
        ARM64_VAS_2S => (2, 32),
        ARM64_VAS_1S => (1, 32),
        ARM64_VAS_2D => (2, 64),
        ARM64_VAS_1D => (1, 64),
        ARM64_VAS_1Q => (1, 128),
        ARM64_VAS_INVALID => return None,
    };
    Some(VectorShape {
        lanes,
        element_bits,
    })
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
        // Capstone 5 rejects ARMv7 Thumb VFP encodings such as
        // `vneg.f64 d0,d0` unless CS_MODE_V8 is enabled, even though the
        // instruction itself predates ARMv8.  V8 is a decoding superset for
        // the ARM backend; enabling it keeps ordinary A32/Thumb instructions
        // valid while preventing CFG discovery from truncating at the first
        // compiler-generated VFP operation. Other architectures retain their
        // established mode exactly.
        let arm_extra_mode = matches!(arch, Architecture::ARM).then_some(ExtraMode::V8);
        let extra_modes = arm_extra_mode.into_iter();
        let mut cs = Capstone::new_raw(a, m, extra_modes, endian).ok()?;
        // Enable details to recover structured operands (needed for PC-relative addressing)
        let _ = cs.set_detail(true);
        // Cortex-M is Thumb-only, so the fallback decoder is built in Thumb
        // mode and stays there; `set_thumb_mode` does not touch it.
        let mclass = matches!(arch, Architecture::ARM)
            .then(|| {
                let mut m = Capstone::new_raw(
                    a,
                    Mode::Thumb,
                    [ExtraMode::V8, ExtraMode::MClass].into_iter(),
                    endian,
                )
                .ok()?;
                let _ = m.set_detail(true);
                Some(m)
            })
            .flatten();
        Some(Self {
            cs,
            mclass,
            arch,
            endianness,
        })
    }

    /// Switch a 32-bit ARM disassembler between classic ARM and Thumb modes.
    ///
    /// No-op and `Ok(())` for non-ARM architectures. Callers that detect a
    /// Thumb target (e.g. address with LSB set, mapping-symbol `$t`) should
    /// invoke this before disassembling a window so that 16/32-bit Thumb
    /// encodings are decoded correctly.
    pub fn set_thumb_mode(&mut self, thumb: bool) -> Result<(), DisassemblerError> {
        if !matches!(self.arch, Architecture::ARM) {
            return Ok(());
        }
        let new_mode = if thumb { Mode::Thumb } else { Mode::Arm };
        self.cs
            .set_mode(new_mode)
            .map_err(|_| DisassemblerError::UnsupportedArchitecture())
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
        // Decode exactly one instruction.
        //
        // This used to call `disasm_all`, which decodes the WHOLE slice and
        // then dropped everything but the first instruction. Callers pass the
        // rest of the image (`&data[file_offset..]`), so every single
        // instruction decoded the entire remaining binary: cost quadratic in
        // file size, paid on every architecture routed through Capstone.
        //
        // x86-64 goes through iced, which decodes one instruction, and was
        // unaffected — which is why the same `cat` took 0.1 s on x86-64 and
        // 3.7 s on AArch64 with a third as many functions, and why AArch64
        // `grep` (199 KB) never finished at all.
        //
        // The slice is additionally capped, because `disasm_count` still walks
        // its input. The cap is x86's architectural maximum rather than this
        // backend's `max_instruction_length()` (8): `for_arch_with` lets a
        // caller select Capstone for x86, where an instruction may be 15 bytes,
        // and an 8-byte window would silently fail to decode the longest ones.
        // Every other architecture here is fixed-width and far below 16.
        const MAX_INSN_BYTES: usize = 16;
        let window = &bytes[..MAX_INSN_BYTES.min(bytes.len())];
        // Decode on the primary; fall back to the Cortex-M decoder only when
        // the primary rejects the bytes. See the `mclass` field docs for why
        // the order matters: MClass-first would silently misdecode A-profile
        // system instructions, while MClass-last can only turn a rejection
        // (which costs the whole function) into a decode.
        let primary = self.cs.disasm_count(window, address.value, 1).ok();
        let (cs, insns) = match primary {
            Some(i) if !i.is_empty() => (&self.cs, i),
            _ => {
                let fallback = self
                    .mclass
                    .as_ref()
                    .and_then(|m| m.disasm_count(window, address.value, 1).ok())
                    .filter(|i| !i.is_empty());
                match (self.mclass.as_ref(), fallback) {
                    (Some(m), Some(i)) => (m, i),
                    _ => return Err(DisassemblerError::InvalidInstruction()),
                }
            }
        };
        let insn = insns.iter().next().unwrap();
        let len = insn.bytes().len();
        let mnemonic = insn.mnemonic().unwrap_or("").to_string();
        // Try detailed operands when available (ARM64 focus)
        let mut operands: Vec<Operand> = Vec::new();
        // capstone-rs 0.12 represents AArch64 MRS/MSR system-register ids as
        // an enum and uses `transmute` while constructing detailed operands.
        // Newer Capstone can return architectural encodings (for example
        // TPIDR_EL0 = 0xd53bd040's sysreg field) that are not enum variants;
        // Rust then raises a non-unwinding invalid-enum panic before we can
        // decline the instruction. The textual operand is authoritative for
        // these two mnemonics and the generic fallback below preserves it, so
        // never ask the affected binding to materialise their detail record.
        let unsafe_arm64_system_detail =
            self.arch == Architecture::ARM64 && matches!(mnemonic.as_str(), "mrs" | "msr");
        if !unsafe_arm64_system_detail {
            if let Ok(detail) = cs.insn_detail(insn) {
                match self.arch {
                    Architecture::ARM64 => {
                        if let Some(ad) = detail.arch_detail().arm64() {
                            // `s0`/`h0` are 32/16-bit lanes, `d0`/`q0` are wider.
                            // Used only to pick the precision of an FP immediate.
                            let ins_reg_width: Option<u32> =
                                ad.operands().find_map(|op| match op.op_type {
                                    Arm64OperandType::Reg(r) => cs
                                        .reg_name(r)
                                        .and_then(|n| n.chars().next())
                                        .map(|c| if c == 's' { 32 } else { 64 }),
                                    _ => None,
                                });
                            // Track writeback so pre-indexed forms (`[sp,
                            // #-0x30]!`) can be distinguished from non-
                            // writeback forms downstream. When writeback is
                            // set, we zero the memory operand's disp and
                            // append an explicit Immediate operand carrying
                            // that disp — which makes pre-indexed look exactly
                            // like post-indexed in our operand form. The
                            // ARM64 lifter then adds the base writeback in
                            // both cases.
                            let writeback = ad.writeback();
                            let mut pending_writeback: Option<i64> = None;
                            for op in ad.operands() {
                                match op.op_type {
                                    Arm64OperandType::Reg(r) => {
                                        let name = cs.reg_name(r).unwrap_or_default();
                                        let shape = arm64_vector_shape(op.vas);
                                        let mut operand = Operand::register(
                                            name,
                                            shape.and_then(VectorShape::total_bits).unwrap_or(0),
                                            Access::Read,
                                        );
                                        operand.vector_shape = shape;
                                        operand.vector_index = op.vector_index;
                                        operands.push(operand);
                                    }
                                    Arm64OperandType::Imm(i) => {
                                        operands.push(Operand::immediate(i, 0));
                                    }
                                    // A scalar FP immediate, e.g. `fmov d2, #2.0`.
                                    // This fell into the catch-all and was DROPPED,
                                    // so the instruction reached the lifter with one
                                    // operand, failed its arity check, and lifted to
                                    // nothing -- leaving the destination register
                                    // undefined. That is usually the constant feeding
                                    // the value a function returns, so the function
                                    // recovers as `void(void)`. Same shape as the
                                    // ARM32 VFP handling directly below; capstone
                                    // exposes the immediate as an `f64` regardless of
                                    // the encoded precision, so preserve the exact
                                    // IEEE payload and let the typed intrinsic supply
                                    // the interpretation.
                                    Arm64OperandType::Fp(value) => {
                                        let (bits, width) = match ins_reg_width {
                                            Some(32) => (i64::from((value as f32).to_bits()), 32),
                                            _ => (value.to_bits() as i64, 64),
                                        };
                                        operands.push(Operand::immediate(bits, width));
                                    }
                                    Arm64OperandType::Mem(m) => {
                                        let base = if m.base().0 != 0 {
                                            Some(cs.reg_name(m.base()).unwrap_or_default())
                                        } else {
                                            None
                                        };
                                        let index = if m.index().0 != 0 {
                                            Some(cs.reg_name(m.index()).unwrap_or_default())
                                        } else {
                                            None
                                        };
                                        let scale = shift_to_scale(arm64_lsl_amount(op.shift));
                                        let disp = m.disp() as i64;
                                        operands.push(Operand::memory(
                                            0,
                                            Access::Read,
                                            Some(disp),
                                            base,
                                            index,
                                            scale,
                                        ));
                                        // Pre-indexed writeback: surface the
                                        // non-zero disp as a trailing Imm so
                                        // the lifter emits a matching base-
                                        // adjust. Loads/stores themselves use
                                        // [base + disp], which is the post-
                                        // writeback effective address —
                                        // equivalent to sp_new + 0.
                                        if writeback && disp != 0 {
                                            pending_writeback = Some(disp);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            // Surface the writeback displacement as a trailing
                            // Immediate operand so the ARM64 lifter sees a
                            // uniform shape for pre- and post-indexed LDP/STP/
                            // LDR.
                            if let Some(wb) = pending_writeback {
                                operands.push(Operand::immediate(wb, 0));
                            }
                        }
                    }
                    Architecture::ARM => {
                        if let Some(ad) = detail.arch_detail().arm() {
                            for op in ad.operands() {
                                match op.op_type {
                                    ArmOperandType::Reg(r) => {
                                        let name = cs.reg_name(r).unwrap_or_default();
                                        operands.push(Operand::register(name, 0, Access::Read));
                                    }
                                    ArmOperandType::Imm(i) => {
                                        operands.push(Operand::immediate(i as i64, 0))
                                    }
                                    ArmOperandType::Fp(value) => {
                                        // Capstone exposes an ARM VFP immediate as an
                                        // `f64`, independently of the instruction's
                                        // encoded precision. Preserve its exact IEEE
                                        // payload in the ordinary immediate container;
                                        // the typed VFP intrinsic supplies the semantic
                                        // interpretation downstream.
                                        let (bits, width) = if mnemonic.contains(".f32") {
                                            (i64::from((value as f32).to_bits()), 32)
                                        } else {
                                            (value.to_bits() as i64, 64)
                                        };
                                        operands.push(Operand::immediate(bits, width));
                                    }
                                    ArmOperandType::Mem(m) => {
                                        let base = if m.base().0 != 0 {
                                            Some(cs.reg_name(m.base()).unwrap_or_default())
                                        } else {
                                            None
                                        };
                                        let index = if m.index().0 != 0 {
                                            Some(cs.reg_name(m.index()).unwrap_or_default())
                                        } else {
                                            None
                                        };
                                        let scale = shift_to_scale(arm_lsl_amount(op.shift));
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
                                    // A Cortex-M special register (BASEPRI, IPSR,
                                    // PSP, ...). It was falling into the catch-all
                                    // and being dropped, so `mrs r0, BASEPRI`
                                    // reached the lifter with ONE operand and no
                                    // indication of which system register it read.
                                    // The lifter cannot name the intrinsic without
                                    // it, and BASEPRI_MAX must stay distinct from
                                    // BASEPRI.
                                    ArmOperandType::SysReg(r) => {
                                        // `reg_name` resolves `arm_reg` ids and
                                        // returns empty for an `arm_sysreg` one,
                                        // so the printed operand text is the only
                                        // place the register's identity survives.
                                        // Losing it would collapse BASEPRI_MAX
                                        // into BASEPRI, whose update semantics
                                        // differ.
                                        let name = match cs.reg_name(r) {
                                            Some(n) if !n.is_empty() => n,
                                            _ => insn
                                                .op_str()
                                                .unwrap_or("")
                                                .split(',')
                                                .nth(operands.len())
                                                .map(|s| s.trim().to_ascii_lowercase())
                                                .unwrap_or_default(),
                                        };
                                        operands.push(Operand::register(name, 0, Access::Read));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};
    use crate::core::instruction::OperandKind;

    fn va(v: u64) -> Address {
        Address::new(AddressKind::VA, v, 32, None, None).unwrap()
    }

    #[test]
    fn arm_mode_decodes_arm_encoding() {
        // `mov r0, r0` — ARM encoding, 4 bytes, little-endian: E1 A0 00 00
        let cs = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little)
            .expect("capstone arm backend");
        let ins = cs
            .disassemble_instruction(&va(0x1000), &[0x00, 0x00, 0xa0, 0xe1])
            .expect("decode");
        assert_eq!(ins.length, 4, "ARM instruction must be 4 bytes");
        assert!(
            ins.mnemonic == "mov" || ins.mnemonic == "nop",
            "got {:?}",
            ins.mnemonic
        );
    }

    /// An ARM scaled-index memory operand must carry its shift.
    ///
    /// Capstone puts the shift on the *operand* (`ArmOperand::shift`), not on
    /// `ArmOpMem`, so reading only the mem struct loses it silently. Dropping it
    /// makes every effective address `base + index` instead of
    /// `base + index * 2^n` — for `lsl #2`, wrong by a factor of four with no
    /// diagnostic. `ldr pc, [rB, rI, lsl #2]` is the ARM A32 jump-table
    /// dispatch (321 occurrences across 34 of the 58 ARM binaries in the frozen
    /// DecBench sample-set), and it cannot be recognised at all without this.
    #[test]
    fn arm_scaled_index_memory_operand_carries_its_shift() {
        let cs = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little)
            .expect("capstone arm backend");

        // `ldr r1, [r2, r3, lsl #2]` — e7921103, little-endian byte order.
        let ins = cs
            .disassemble_instruction(&va(0x1000), &[0x03, 0x11, 0x92, 0xe7])
            .expect("decode");
        let mem = ins
            .operands
            .iter()
            .find(|operand| operand.kind == OperandKind::Memory)
            .expect("a memory operand");
        assert_eq!(mem.base.as_deref(), Some("r2"));
        assert_eq!(mem.index.as_deref(), Some("r3"));
        assert_eq!(
            mem.scale,
            Some(4),
            "lsl #2 is a scale of 4, got {:?}",
            mem.scale
        );

        // `ldrb r1, [r2, r3, lsl #1]` — e7d21083.
        let ins = cs
            .disassemble_instruction(&va(0x1000), &[0x83, 0x10, 0xd2, 0xe7])
            .expect("decode");
        let mem = ins
            .operands
            .iter()
            .find(|operand| operand.kind == OperandKind::Memory)
            .expect("a memory operand");
        assert_eq!(
            mem.scale,
            Some(2),
            "lsl #1 is a scale of 2, got {:?}",
            mem.scale
        );
    }

    /// An unshifted ARM index must report no scale, not a fabricated one.
    #[test]
    fn arm_unshifted_index_reports_no_scale() {
        let cs = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little)
            .expect("capstone arm backend");
        // `ldr r1, [r2, r3]` — e7921003.
        let ins = cs
            .disassemble_instruction(&va(0x1000), &[0x03, 0x10, 0x92, 0xe7])
            .expect("decode");
        let mem = ins
            .operands
            .iter()
            .find(|operand| operand.kind == OperandKind::Memory)
            .expect("a memory operand");
        assert_eq!(mem.index.as_deref(), Some("r3"));
        assert!(
            mem.scale.is_none() || mem.scale == Some(1),
            "an unshifted index is scale 1, got {:?}",
            mem.scale
        );
    }

    #[test]
    fn thumb_mode_decodes_thumb_encoding() {
        // `nop` — Thumb-2 encoding, 2 bytes: 00 BF
        let mut cs = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little)
            .expect("capstone arm backend");
        cs.set_thumb_mode(true).expect("enable thumb");
        let ins = cs
            .disassemble_instruction(&va(0x1000), &[0x00, 0xbf])
            .expect("decode");
        assert_eq!(ins.length, 2, "Thumb NOP must be 2 bytes");
        assert_eq!(ins.mnemonic, "nop");
    }

    #[test]
    fn thumb_mode_decodes_armv7_vfp_double_encoding() {
        // GCC 15 `-march=armv7-a -mfpu=vfpv3-d16 -mthumb`:
        // `vneg.f64 d0, d0`.  CFG discovery and the LLIR lifter share this
        // backend boundary; refusing the instruction truncates the function
        // before its result and RET even though the ARM lifter models VNEG.
        let mut cs = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little)
            .expect("capstone arm backend");
        cs.set_thumb_mode(true).expect("enable thumb");
        let ins = cs
            .disassemble_instruction(&va(0x1000), &[0xb1, 0xee, 0x40, 0x0b])
            .expect("decode Thumb VFP negation");
        assert_eq!(ins.length, 4);
        assert_eq!(ins.mnemonic, "vneg.f64");
    }

    #[test]
    fn arm64_preserves_packed_vector_arrangements() {
        // `add v30.4s, v31.4s, v30.4s` = 0x4ebe87fe.
        let cs = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little)
            .expect("capstone arm64 backend");
        let ins = cs
            .disassemble_instruction(&va(0x1000), &0x4ebe87feu32.to_le_bytes())
            .expect("decode packed add");
        assert_eq!(ins.mnemonic, "add");
        assert_eq!(ins.operands.len(), 3);
        assert!(ins.operands.iter().all(|operand| {
            operand.vector_shape
                == Some(VectorShape {
                    lanes: 4,
                    element_bits: 32,
                })
                && operand.size == 128
        }));
    }

    #[test]
    fn arm64_system_register_operand_cannot_abort_the_decoder() {
        // `mrs x0, tpidr_el0` = 0xd53bd040. capstone-rs 0.12 attempts to
        // transmute the system-register encoding while building its detailed
        // operand and can abort on values absent from its generated enum.
        let cs = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little)
            .expect("capstone arm64 backend");
        let ins = cs
            .disassemble_instruction(&va(0x1000), &0xd53bd040u32.to_le_bytes())
            .expect("decode system-register read without detailed-enum conversion");
        assert_eq!(ins.mnemonic, "mrs");
        assert_eq!(ins.operands.len(), 2);
    }

    #[test]
    fn toggling_mode_back_to_arm_works() {
        let mut cs = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little)
            .expect("capstone arm backend");
        cs.set_thumb_mode(true).expect("enable thumb");
        let t = cs
            .disassemble_instruction(&va(0), &[0x00, 0xbf])
            .expect("thumb decode");
        assert_eq!(t.length, 2);
        cs.set_thumb_mode(false).expect("disable thumb");
        let a = cs
            .disassemble_instruction(&va(0), &[0x00, 0x00, 0xa0, 0xe1])
            .expect("arm decode");
        assert_eq!(a.length, 4);
    }

    #[test]
    fn set_thumb_mode_is_noop_on_non_arm() {
        let mut cs = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little)
            .expect("capstone arm64 backend");
        // Must not error and must not affect arm64 decoding.
        cs.set_thumb_mode(true).expect("no-op on arm64");
        cs.set_thumb_mode(false).expect("no-op on arm64");
    }
}
