//! ARM32 (ARMv7, Thumb-2) → LLIR lifter.
//!
//! Decodes variable-length Thumb-2 (and A32) instructions using the existing
//! [`crate::disasm::capstone::CapstoneDisassembler`] and emits LLIR ops. It is
//! the 32-bit sibling of [`crate::ir::lift_arm64`]; the operand-reading helpers
//! and the `cmp → four flag writes` idiom mirror it exactly.
//!
//! **Thumb by default.** Every ARM target Glaurung is expected to decompile in
//! practice is Thumb: Cortex-M (ARMv7-M) has no A32 mode at all, and modern
//! `arm-linux-gnueabihf` builds default to Thumb-2. So [`lift_bytes`] sets the
//! capstone backend to Thumb mode when `thumb` is true (the pipeline default for
//! `Arch::ARM`). A32-only binaries are a documented follow-up; the same lifter
//! handles their (mostly identical) mnemonics once decoded in A32 mode.
//!
//! Coverage (v1): `nop`; `mov`/`movs`/`movw`/`mvn`; the data-processing set
//! (`add`/`sub`/`and`/`orr`/`eor`/`lsl`/`lsr`/`asr`/`mul`/`rsb`, `s`-suffixed and
//! reg/imm forms); `cmp`/`cmn` → flags; `ldr*`/`str*` (offset, indexed, and
//! PC-relative literal forms); `push`/`pop` register lists (decomposed to sp
//! adjust + loads/stores, `pop {…,pc}` recognised as a return); `b`/`b<cond>`;
//! `cbz`/`cbnz`; `bl`/`blx` (direct + indirect calls); `bx` (return via `lr`,
//! else indirect). Anything else becomes [`Op::Unknown`] carrying the mnemonic,
//! which `lift_function` rewrites to a conservative [`Op::Intrinsic`].

use crate::core::address::{Address, AddressKind};
use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler};
use crate::core::instruction::{Instruction, Operand, OperandKind};
use crate::disasm::capstone::CapstoneDisassembler;

use crate::ir::types::*;

mod flags;
mod predication;
mod shifts;
mod sysreg;
#[path = "lift_arm32/wide_multiply.rs"]
mod wide_multiply;
use flags::{
    a32_predicate, arm_carry_arithmetic, bin_for_mnem, cmp_flag_ops, cond_flag_for, flags_for_arith,
};
use predication::{
    is_it_mnemonic, it_conditions, make_conditional, mnemonic_in_it, strip_qualifier,
};
use shifts::{
    apply_shift, data_processing_shift, fold_modified_immediate, index_shift,
    is_preindexed_writeback, shifted_operand, RegShift, ShiftKind,
};
// `SHIFT_TEMP` names the temporaries `apply_shift` allocates, and the only
// reader outside `shifts` is the `packet_tests` child, which reaches the
// parent's namespace through `use super::*`. Gating the re-export keeps it out
// of the shipped build, where nothing would consume it.
#[cfg(test)]
use shifts::SHIFT_TEMP;

fn operand_reg(op: &Operand) -> Option<VReg> {
    if matches!(op.kind, OperandKind::Register) {
        op.register.clone().map(VReg::phys)
    } else {
        None
    }
}

fn operand_reg_name(op: &Operand) -> Option<String> {
    if matches!(op.kind, OperandKind::Register) {
        op.register.clone()
    } else {
        None
    }
}

fn operand_to_value(op: &Operand) -> Option<Value> {
    match op.kind {
        OperandKind::Register => op.register.clone().map(|n| Value::Reg(VReg::phys(n))),
        OperandKind::Immediate => op.immediate.map(Value::Const),
        _ => None,
    }
}

/// Memory operand with an ARM32 access width (bytes) derived from the mnemonic.
fn operand_to_memop(op: &Operand, size: u8) -> Option<MemOp> {
    if !matches!(op.kind, OperandKind::Memory) {
        return None;
    }
    Some(MemOp {
        base: op.base.clone().map(VReg::phys),
        index: op.index.clone().map(VReg::phys),
        scale: op.scale.unwrap_or(0),
        disp: op.displacement.unwrap_or(0),
        size,
        segment: None, // ARM has no segment registers
        endian: Endian::Little,
    })
}

/// Access width in bytes for a load/store mnemonic (default 4 = word).
fn mem_size_for(mnem: &str) -> u8 {
    match mnem {
        m if m.starts_with("ldrb") || m.starts_with("strb") => 1,
        m if m.starts_with("ldrsb") => 1,
        m if m.starts_with("ldrh") || m.starts_with("strh") => 2,
        m if m.starts_with("ldrsh") => 2,
        _ => 4,
    }
}

/// Extension performed by an ARM scalar load after reading memory.
///
/// `ldrb`/`ldrh` zero-extend and `ldrsb`/`ldrsh` sign-extend into the 32-bit
/// destination register. A bare [`Op::Load`] records only the memory width, so
/// preserve this distinct architectural behavior as a second IR operation.
fn load_extension_for(mnem: &str) -> Option<(bool, Width)> {
    if mnem.starts_with("ldrsb") {
        Some((true, Width::W8))
    } else if mnem.starts_with("ldrsh") {
        Some((true, Width::W16))
    } else if mnem.starts_with("ldrb") {
        Some((false, Width::W8))
    } else if mnem.starts_with("ldrh") {
        Some((false, Width::W16))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// PC reads and the literal pool
// ---------------------------------------------------------------------------

/// The window of machine code being lifted, and the state it decodes under.
///
/// ARM32 has no `adrp`. Every address, every constant wider than the encoding
/// allows, and every GOT offset is materialised by reading the *literal pool* —
/// a block of constants the assembler drops inside the function body — with
/// `ldr Rd,[pc,#imm]`, usually followed by `add Rd,pc`. The pool is therefore
/// part of the very byte window being lifted, which is what makes resolving it
/// here both possible and exact.
///
/// Modelling `pc` as an ordinary register instead left the whole family reading
/// an undefined value: the recovered `-fstack-protector` preamble became
/// `*(int *)(*(int *)((var3 + 0x118) + var3 + ...))` over an unassigned `var3`,
/// and every function with a local array took SIGSEGV when the recovered C was
/// recompiled and run.
struct LiftCtx<'a> {
    thumb: bool,
    bytes: &'a [u8],
    start_va: u64,
    /// The whole image, when the caller has it.
    ///
    /// [`crate::ir::lift_function`] lifts one BASIC BLOCK at a time, and a
    /// function's literal pool sits after its last block — so `bytes` alone
    /// resolves the pool in a unit test and essentially never in production.
    image: Option<&'a [u8]>,
}

impl LiftCtx<'_> {
    /// The value a read of `pc` yields: the instruction's own address plus 4 in
    /// Thumb state and plus 8 in ARM state (ARM DDI 0406C A2.3.1). Not "the next
    /// instruction" — in Thumb the increment is 4 even for a 2-byte instruction.
    fn pc_at(&self, ins: &Instruction) -> i64 {
        ins.address.value as i64 + if self.thumb { 4 } else { 8 }
    }

    /// Effective address of a PC-relative literal load: `Align(PC,4) + offset`.
    fn literal_va(&self, ins: &Instruction, offset: i64) -> u64 {
        ((self.pc_at(ins) & !3).wrapping_add(offset)) as u64
    }

    /// The 32-bit little-endian word at `va`, read from the image where one was
    /// supplied and otherwise from the lifted window. `None` means the address
    /// is not resolvable, and the caller must keep the load — with its exact
    /// absolute address, which a later pass can still resolve.
    ///
    /// The image lookup is restricted to EXECUTABLE sections. Reading executable
    /// memory as data is only ever a literal pool, and it is constant; a `[pc,
    /// #imm]` that resolved into `.data` would be a decode error, and freezing a
    /// mutable word into a constant is exactly the wrong answer.
    fn literal(&self, va: u64) -> Option<i64> {
        let word = self
            .image
            .and_then(|image| text_word(image, va))
            .or_else(|| {
                let offset = usize::try_from(va.checked_sub(self.start_va)?).ok()?;
                let bytes: [u8; 4] = self.bytes.get(offset..offset + 4)?.try_into().ok()?;
                Some(u32::from_le_bytes(bytes))
            })?;
        Some(i64::from(word))
    }
}

/// The little-endian word at `va` in an executable section of `image`.
fn text_word(image: &[u8], va: u64) -> Option<u32> {
    use object::read::{Object, ObjectSection};
    let obj = crate::decompile::profile::parse_object(image).ok()?;
    for section in obj.sections() {
        if section.kind() != object::SectionKind::Text || section.size() == 0 {
            continue;
        }
        let addr = section.address();
        if va < addr || va >= addr.saturating_add(section.size()) {
            continue;
        }
        let (start, _) = section.file_range()?;
        let offset = usize::try_from(start.checked_add(va - addr)?).ok()?;
        let bytes: [u8; 4] = image.get(offset..offset + 4)?.try_into().ok()?;
        return Some(u32::from_le_bytes(bytes));
    }
    None
}

/// Substitute a read of `pc` with the value the architecture defines it to be.
/// Applied to SOURCE operands only; `pc` as a destination is control flow and is
/// handled by the branch/return arms.
///
/// It is a [`Value::Addr`], not a bare constant, because that is what it is —
/// and because `const_fold` only folds an offset into a base when the base is
/// already known to be an address. `ldr Rd,[pc,#n]; add Rd,pc` would otherwise
/// fold to an anonymous integer that `name_resolve` never looks up, and the
/// GOT slot it names would stay a magic number.
fn resolve_pc(value: Value, pc: i64) -> Value {
    match value {
        Value::Reg(VReg::Phys(ref name)) if name == "pc" => Value::Addr(pc as u64),
        other => other,
    }
}

/// Architectural storage width of one ARM push/pop register-list entry.
///
/// Core and single-precision VFP registers occupy four bytes; double-precision
/// VFP registers occupy eight.  Capstone expands a register range into its
/// individual register operands, so summing these widths also handles multi-D
/// `vpush`/`vpop` lists without a separate instruction-specific path.
fn stack_register_width(reg: &str) -> i64 {
    if reg
        .strip_prefix('d')
        .is_some_and(|index| index.parse::<u8>().is_ok())
    {
        8
    } else {
        4
    }
}

/// `push {list}` — AAPCS stores the lowest-numbered register at the lowest
/// address after decrementing sp by the total register-list width. Capstone
/// lists the registers in ascending order, so each store uses the cumulative
/// width of its predecessors.
fn lift_push(regs: &[String]) -> Vec<Op> {
    if regs.is_empty() {
        return vec![Op::Nop];
    }
    let total_width: i64 = regs.iter().map(|reg| stack_register_width(reg)).sum();
    let sp = VReg::phys("sp");
    let mut out = vec![Op::Bin {
        dst: sp.clone(),
        op: BinOp::Sub,
        lhs: Value::Reg(sp.clone()),
        rhs: Value::Const(total_width),
    }];
    let mut offset = 0;
    for r in regs {
        let width = stack_register_width(r);
        out.push(Op::Store {
            addr: MemOp::plain(Some(sp.clone()), None, 0, offset, width as u8),
            src: Value::Reg(VReg::phys(r.clone())),
        });
        offset += width;
    }
    out
}

/// `pop {list}` — mirror of push: load each operand at the cumulative width of
/// its predecessors, then add the total register-list width to sp. If `pc` is
/// in the list the function returns, so the loads and sp adjust are followed by
/// [`Op::Return`].
fn lift_pop(regs: &[String]) -> Vec<Op> {
    if regs.is_empty() {
        return vec![Op::Nop];
    }
    let total_width: i64 = regs.iter().map(|reg| stack_register_width(reg)).sum();
    let sp = VReg::phys("sp");
    let mut out = Vec::new();
    let mut returns = false;
    let mut offset = 0;
    for r in regs {
        let width = stack_register_width(r);
        if r == "pc" {
            returns = true;
        } else {
            out.push(Op::Load {
                dst: VReg::phys(r.clone()),
                addr: MemOp::plain(Some(sp.clone()), None, 0, offset, width as u8),
            });
        }
        offset += width;
    }
    out.push(Op::Bin {
        dst: sp.clone(),
        op: BinOp::Add,
        lhs: Value::Reg(sp),
        rhs: Value::Const(total_width),
    });
    if returns {
        out.push(Op::Return);
    }
    out
}

/// Give a register-offset memory operand the scale its encoding specifies.
///
/// `[r1, r2, lsl #2]` and `[r1, r2]` reach the lifter identically, and the scale
/// arrived as 0, which every consumer reads as 1 — so every scaled array index
/// was off by its element size.
fn scaled_memop(ins: &Instruction, ctx: &LiftCtx, mut addr: MemOp) -> MemOp {
    if addr.index.is_some() {
        if let Some(amount) = index_shift(ins, ctx) {
            addr.scale = 1u8 << amount;
        }
    }
    // A PC-relative address is fully known at lift time: fold it to an absolute
    // displacement so nothing downstream sees a read of a register that has no
    // definition. `[pc, Rm]` is not a literal-pool form and is left alone.
    if addr.base.as_ref() == Some(&VReg::phys("pc")) && addr.index.is_none() {
        addr.disp = ctx.literal_va(ins, addr.disp) as i64;
        addr.base = None;
    }
    addr
}

/// Lift a single instruction whose base mnemonic (already lowercased, with the
/// `.w`/`.n` qualifier and any IT-block condition suffix stripped) is `mnem`.
/// Predication is applied by the caller in [`lift_bytes`].
///
/// `thumb` says which instruction set the bytes were decoded under; the shifted-
/// operand encodings differ completely between the two and cannot be recovered
/// from the operand list.
fn lift_one(ins: &Instruction, mnem: &str, ctx: &LiftCtx) -> Vec<Op> {
    // Normalise the one operand shape capstone reports unfolded, before any
    // arity check sees it. The folded list must reach the helpers that re-read
    // `ins.operands` by index — `shifted_operand` is the one that matters —
    // so this rebuilds the instruction rather than shadowing a local slice:
    // reading `#16` where the encoding means `#0x10000` is exactly the
    // confident wrong answer an opaque intrinsic is preferable to.
    match fold_modified_immediate(ins, ctx) {
        Some(operands) => {
            let mut normalized = ins.clone();
            normalized.operands = operands;
            lift_one_decoded(&normalized, mnem, ctx)
        }
        None => lift_one_decoded(ins, mnem, ctx),
    }
}

/// [`lift_one`] over an instruction whose operand list is already in the folded
/// shape every arity check below is written against.
fn lift_one_decoded(ins: &Instruction, mnem: &str, ctx: &LiftCtx) -> Vec<Op> {
    let ops = &ins.operands;

    // Scalar VFP arithmetic has IEEE semantics that integer `Op::Bin` cannot
    // represent, but its register footprint and precision are exact. Ghidra
    // and Kuna keep these values in a dedicated floating-point storage class;
    // retain that class boundary in LLIR with typed intrinsics.
    if [
        "vadd.f32", "vsub.f32", "vmul.f32", "vdiv.f32", "vadd.f64", "vsub.f64", "vmul.f64",
        "vdiv.f64",
    ]
    .iter()
    .any(|operation| mnem.starts_with(operation))
        && ops.len() == 3
    {
        if let (Some(dst), Some(lhs), Some(rhs)) = (
            operand_reg(&ops[0]),
            operand_to_value(&ops[1]),
            operand_to_value(&ops[2]),
        ) {
            let width = if mnem.contains(".f64") {
                Width::W64
            } else {
                Width::W32
            };
            return vec![Op::Intrinsic {
                name: mnem.to_string(),
                ins: vec![lhs, rhs],
                outs: vec![(dst, width)],
                reads_mem: false,
                writes_mem: false,
            }];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // Cortex-M special registers: see `sysreg`. Reaching this at all depends
    // on the MClass fallback decoder in `crate::disasm::capstone`.
    if sysreg::is_system_register_transfer(mnem, ops) {
        return sysreg::lift(mnem, ops, operand_reg);
    }

    // VFP register moves are bit-preserving operations even though the source
    // type lattice cannot yet render their floating-point value.  Keep their
    // exact input/output footprint as an intrinsic so SSA and ABI recovery can
    // see `s0`/`d0` results.  Treating them as footprint-free Unknown nodes is
    // what made real hard-float functions masquerade as `void`.
    if mnem.starts_with("vmov") && ops.len() == 2 {
        if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
            let width = match &dst {
                VReg::Phys(name) if name.starts_with('d') => Width::W64,
                _ => Width::W32,
            };
            return vec![Op::Intrinsic {
                name: mnem.to_string(),
                ins: vec![src],
                outs: vec![(dst, width)],
                reads_mem: false,
                writes_mem: false,
            }];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // Scalar VFP loads/stores use the same effective-address semantics as the
    // integer memory operations, but the destination/source register retains
    // the floating storage class for type recovery.  Keeping these as real
    // Load/Store nodes makes stack spills and object-field dataflow visible to
    // SSA instead of severing every O0 hard-float expression at memory.
    if mnem == "vldr" && ops.len() == 2 {
        if let Some(dst) = operand_reg(&ops[0]) {
            let size = match &dst {
                VReg::Phys(name) if name.starts_with('d') => 8,
                _ => 4,
            };
            if let Some(addr) = operand_to_memop(&ops[1], size) {
                return vec![Op::Load { dst, addr }];
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }
    if mnem == "vstr" && ops.len() == 2 {
        if let Some(src) = operand_to_value(&ops[0]) {
            let size = match &src {
                Value::Reg(VReg::Phys(name)) if name.starts_with('d') => 8,
                _ => 4,
            };
            if let Some(addr) = operand_to_memop(&ops[1], size) {
                return vec![Op::Store { addr, src }];
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // Float negation is a numeric unary operation, unlike the bit-preserving
    // vmov family.  Retain it as a typed intrinsic so the AST can lower it to
    // source `-x` without pretending integer two's-complement semantics.
    if (mnem.starts_with("vneg.f32") || mnem.starts_with("vneg.f64")) && ops.len() == 2 {
        if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
            let width = if mnem.contains(".f64") {
                Width::W64
            } else {
                Width::W32
            };
            return vec![Op::Intrinsic {
                name: mnem.to_string(),
                ins: vec![src],
                outs: vec![(dst, width)],
                reads_mem: false,
                writes_mem: false,
            }];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- register-list instructions (push/pop) --------------------------
    if mnem == "push" || mnem == "vpush" {
        let regs: Vec<String> = ops.iter().filter_map(operand_reg_name).collect();
        return lift_push(&regs);
    }
    if mnem == "pop" || mnem == "vpop" {
        let regs: Vec<String> = ops.iter().filter_map(operand_reg_name).collect();
        return lift_pop(&regs);
    }
    // Load/store multiple: `ldm{ia,ib,da,db} Rn{!}, {list}` and its `stm`
    // sibling. Operands[0] is the base register, the rest the register list.
    // ARM assigns registers in ascending order to ascending addresses; only
    // the first address changes with the addressing mode. Base writeback is
    // not surfaced by the decoder yet, so it remains a conservative no-op.
    // `ldm … , {…, pc}` returns.
    if mnem.starts_with("ldm") || mnem.starts_with("stm") {
        let regs: Vec<String> = ops.iter().filter_map(operand_reg_name).collect();
        if regs.len() >= 2 {
            let base = VReg::phys(regs[0].clone());
            let list = &regs[1..];
            let is_load = mnem.starts_with("ldm");
            let bytes = 4 * list.len() as i64;
            let first_disp = if mnem.ends_with("ib") {
                4
            } else if mnem.ends_with("da") {
                4 - bytes
            } else if mnem.ends_with("db") {
                -bytes
            } else {
                0
            };
            let mut out = Vec::new();
            let mut returns = false;
            for (i, r) in list.iter().enumerate() {
                let addr = MemOp::plain(Some(base.clone()), None, 0, first_disp + 4 * i as i64, 4);
                if is_load {
                    if r == "pc" {
                        returns = true;
                        continue;
                    }
                    out.push(Op::Load {
                        dst: VReg::phys(r.clone()),
                        addr,
                    });
                } else {
                    out.push(Op::Store {
                        addr,
                        src: Value::Reg(VReg::phys(r.clone())),
                    });
                }
            }
            if returns {
                out.push(Op::Return);
            }
            if out.is_empty() {
                out.push(Op::Nop);
            }
            return out;
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- load/store double: ldrd/strd Rt, Rt2, [Rn, #off] ---------------
    // Two consecutive 4-byte transfers at `[Rn+off]` and `[Rn+off+4]`. Handled
    // before the generic ldr/str arms (which would otherwise capture the
    // `ldr`/`str` prefix and mis-parse the two-register form).
    if mnem == "ldrd" || mnem == "strd" {
        if ops.len() == 3 {
            let is_load = mnem == "ldrd";
            if let Some(addr) = operand_to_memop(&ops[2], 4) {
                let addr2 = MemOp {
                    disp: addr.disp.wrapping_add(4),
                    ..addr.clone()
                };
                if is_load {
                    if let (Some(rt), Some(rt2)) = (operand_reg(&ops[0]), operand_reg(&ops[1])) {
                        return vec![
                            Op::Load { dst: rt, addr },
                            Op::Load {
                                dst: rt2,
                                addr: addr2,
                            },
                        ];
                    }
                } else if let (Some(rt), Some(rt2)) =
                    (operand_to_value(&ops[0]), operand_to_value(&ops[1]))
                {
                    return vec![
                        Op::Store { addr, src: rt },
                        Op::Store {
                            addr: addr2,
                            src: rt2,
                        },
                    ];
                }
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- bit clear: bic Rd, Rn, <reg|imm>  ==>  Rd = Rn & ~Op2 -----------
    if mnem == "bic" || mnem == "bics" {
        if ops.len() == 3 {
            if let (Some(dst), Some(lhs)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                // Immediate operand: fold ~imm at lift time.
                if let Some(imm) = ops[2].immediate {
                    return vec![Op::Bin {
                        dst,
                        op: BinOp::And,
                        lhs,
                        rhs: Value::Const(!imm),
                    }];
                }
                // Register operand: t = ~(Rm <shift>) ; Rd = Rn & t.
                let mut out = Vec::new();
                if let Some(rm) = shifted_operand(ins, ctx, 2, &mut out) {
                    let t = VReg::Temp(0);
                    out.push(Op::Un {
                        dst: t.clone(),
                        op: UnOp::Not,
                        src: rm,
                    });
                    out.push(Op::Bin {
                        dst: dst.clone(),
                        op: BinOp::And,
                        lhs,
                        rhs: Value::Reg(t),
                    });
                    // `bics` reports whether the AND-NOT RESULT is zero or
                    // negative. This arm returned before ever writing them, so
                    // the `S` suffix was recognised and then discarded — the
                    // same silent drop `flags_for_arith` exists to prevent.
                    if mnem == "bics" {
                        let (_, after) = flags_for_arith(
                            BinOp::And,
                            &dst,
                            Value::Reg(dst.clone()),
                            Value::Const(0),
                        );
                        out.extend(after);
                    }
                    return out;
                }
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- bitfield extract: ubfx/sbfx Rd, Rn, #lsb, #width ---------------
    // `Rd = (Rn >> lsb) & mask` unsigned; the signed form re-broadcasts the
    // field's top bit by shifting it to bit 31 and back arithmetically. Both are
    // exact, so they are lowered rather than left as opaque intrinsics.
    if matches!(mnem, "ubfx" | "sbfx") && ops.len() == 4 {
        if let (Some(dst), Some(src), Some(lsb), Some(width)) = (
            operand_reg(&ops[0]),
            operand_to_value(&ops[1]),
            ops[2].immediate,
            ops[3].immediate,
        ) {
            if (0..32).contains(&lsb) && (1..=32).contains(&width) && lsb + width <= 32 {
                let t = VReg::Temp(0);
                if mnem == "ubfx" {
                    let mask = ((1i64 << width) - 1) as i64;
                    return vec![
                        Op::Bin {
                            dst: t.clone(),
                            op: BinOp::Shr,
                            lhs: src,
                            rhs: Value::Const(lsb),
                        },
                        Op::Bin {
                            dst,
                            op: BinOp::And,
                            lhs: Value::Reg(t),
                            rhs: Value::Const(mask),
                        },
                    ];
                }
                return vec![
                    Op::Bin {
                        dst: t.clone(),
                        op: BinOp::Shl,
                        lhs: src,
                        rhs: Value::Const(32 - lsb - width),
                    },
                    Op::Bin {
                        dst,
                        op: BinOp::Sar,
                        lhs: Value::Reg(t),
                        rhs: Value::Const(32 - width),
                    },
                ];
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- bitfield insert: bfi Rd, Rn, #lsb, #width ---------------------
    // Preserve the destination outside the inserted lane and take the lane
    // itself from the low `width` bits of Rn.  This is a read-modify-write,
    // not an opaque side effect: GCC uses two BFIs to construct C bitfields at
    // O0, and dropping them leaves the backing byte uninitialised.
    if mnem == "bfi" && ops.len() == 4 {
        if let (Some(dst), Some(src), Some(lsb), Some(width)) = (
            operand_reg(&ops[0]),
            operand_to_value(&ops[1]),
            ops[2].immediate,
            ops[3].immediate,
        ) {
            if (0..32).contains(&lsb) && (1..=32).contains(&width) && lsb + width <= 32 {
                let lane_mask = if width == 32 {
                    u32::MAX as i64
                } else {
                    (1i64 << width) - 1
                };
                let destination_mask = (lane_mask as u64) << lsb;
                let kept_mask = (u64::from(u32::MAX) & !destination_mask) as i64;
                let lane = VReg::Temp(0);
                let mut out = vec![Op::Bin {
                    dst: lane.clone(),
                    op: BinOp::And,
                    lhs: src,
                    rhs: Value::Const(lane_mask),
                }];
                let placed = if lsb == 0 {
                    Value::Reg(lane)
                } else {
                    let placed = VReg::Temp(1);
                    out.push(Op::Bin {
                        dst: placed.clone(),
                        op: BinOp::Shl,
                        lhs: Value::Reg(lane),
                        rhs: Value::Const(lsb),
                    });
                    Value::Reg(placed)
                };
                let kept = VReg::Temp(if lsb == 0 { 1 } else { 2 });
                out.extend([
                    Op::Bin {
                        dst: kept.clone(),
                        op: BinOp::And,
                        lhs: Value::Reg(dst.clone()),
                        rhs: Value::Const(kept_mask),
                    },
                    Op::Bin {
                        dst,
                        op: BinOp::Or,
                        lhs: Value::Reg(kept),
                        rhs: placed,
                    },
                ]);
                return out;
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- or-not: orn Rd, Rn, Op2  ==>  Rd = Rn | ~Op2 -------------------
    if matches!(mnem, "orn" | "orns") && ops.len() == 3 {
        if let (Some(dst), Some(lhs)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
            if let Some(imm) = ops[2].immediate {
                return vec![Op::Bin {
                    dst,
                    op: BinOp::Or,
                    lhs,
                    rhs: Value::Const(!imm),
                }];
            }
            let mut out = Vec::new();
            if let Some(rm) = shifted_operand(ins, ctx, 2, &mut out) {
                let t = VReg::Temp(0);
                out.push(Op::Un {
                    dst: t.clone(),
                    op: UnOp::Not,
                    src: rm,
                });
                out.push(Op::Bin {
                    dst,
                    op: BinOp::Or,
                    lhs,
                    rhs: Value::Reg(t),
                });
                return out;
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- rotate right: ror Rd, Rn, #imm | Rd, Rm ------------------------
    // Expanded as `(x >> n) | (x << (32-n))` over the 32-bit register. The
    // register-amount form is left unmodelled: the complement `32-n` would need
    // a second dynamic computation this arm does not have operands for.
    if matches!(mnem, "ror" | "rors") && matches!(ops.len(), 2 | 3) {
        let decoded = match ops.len() {
            2 => data_processing_shift(ins, ctx).and_then(|shift| {
                (shift.kind == ShiftKind::Ror).then_some(i64::from(shift.amount))
            }),
            3 => ops[2].immediate,
            _ => None,
        };
        if let (Some(dst), Some(src), Some(amount)) =
            (operand_reg(&ops[0]), operand_to_value(&ops[1]), decoded)
        {
            if (1..32).contains(&amount) {
                let mut out = Vec::new();
                let rotated = apply_shift(
                    RegShift {
                        kind: ShiftKind::Ror,
                        amount: amount as u8,
                    },
                    src,
                    &mut out,
                );
                if let Some(value) = rotated {
                    out.push(Op::Assign { dst, src: value });
                    return out;
                }
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- extend-and-add: uxtab/uxtah/sxtab/sxtah Rd, Rn, Rm -------------
    // `Rd = Rn + extend(Rm)`. The extension is materialised explicitly so the
    // narrowing is visible to type recovery, exactly as `uxtb` does.
    if matches!(mnem, "uxtab" | "uxtah" | "sxtab" | "sxtah") && ops.len() == 3 {
        if let (Some(dst), Some(lhs), Some(rm)) = (
            operand_reg(&ops[0]),
            operand_to_value(&ops[1]),
            operand_to_value(&ops[2]),
        ) {
            let from = if mnem.ends_with('b') {
                Width::W8
            } else {
                Width::W16
            };
            let t = VReg::Temp(0);
            let extend = if mnem.starts_with('s') {
                Op::SExt {
                    dst: t.clone(),
                    src: rm,
                    from,
                    to: Width::W32,
                }
            } else {
                Op::ZExt {
                    dst: t.clone(),
                    src: rm,
                    from,
                    to: Width::W32,
                }
            };
            return vec![
                extend,
                Op::Bin {
                    dst,
                    op: BinOp::Add,
                    lhs,
                    rhs: Value::Reg(t),
                },
            ];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- byte reverse: rev / rev16 Rd, Rm -------------------------------
    // `rev` reverses the four bytes of the word; `rev16` reverses the bytes
    // within each halfword. Both are pure shift/mask arithmetic, so they lower
    // exactly — and a packet parser that byte-swaps its header is precisely the
    // code an opaque intrinsic here would silence.
    if matches!(mnem, "rev" | "rev16") && ops.len() == 2 {
        if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
            //: (shift-left amount, post-shift mask) per contributing byte lane.
            let lanes: &[(i64, i64)] = if mnem == "rev" {
                &[
                    (24, 0xff00_0000),
                    (8, 0x00ff_0000),
                    (-8, 0x0000_ff00),
                    (-24, 0xff),
                ]
            } else {
                &[
                    (8, 0xff00_0000),
                    (-8, 0x00ff_0000),
                    (8, 0x0000_ff00),
                    (-8, 0xff),
                ]
            };
            let mut out = Vec::new();
            let mut accumulated: Option<VReg> = None;
            for (index, (shift, mask)) in lanes.iter().enumerate() {
                let shifted = VReg::Temp(10 + index as u32 * 2);
                out.push(Op::Bin {
                    dst: shifted.clone(),
                    op: if *shift > 0 { BinOp::Shl } else { BinOp::Shr },
                    lhs: src.clone(),
                    rhs: Value::Const(shift.abs()),
                });
                let lane = VReg::Temp(11 + index as u32 * 2);
                out.push(Op::Bin {
                    dst: lane.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(shifted),
                    rhs: Value::Const(*mask),
                });
                accumulated = Some(match accumulated {
                    None => lane,
                    Some(previous) => {
                        let joined = VReg::Temp(20 + index as u32);
                        out.push(Op::Bin {
                            dst: joined.clone(),
                            op: BinOp::Or,
                            lhs: Value::Reg(previous),
                            rhs: Value::Reg(lane),
                        });
                        joined
                    }
                });
            }
            if let Some(result) = accumulated {
                out.push(Op::Assign {
                    dst,
                    src: Value::Reg(result),
                });
                return out;
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- count leading zeros: clz Rd, Rm --------------------------------
    // ARM DDI 0487 defines `clz` on the 32-bit value with `clz(0) == 32`, and
    // the AST renders that exactly (`ast::write_wide_arithmetic_dec`) as
    // `((unsigned int)x == 0 ? 32 : __builtin_clz((unsigned int)x))`.
    //
    // The `(unsigned int)` is not decoration. This IR models `r0` at its
    // canonical 64-bit width and never truncates it, so `__builtin_clzll` on the
    // raw value would count the zeros of a 64-bit quantity and return a number
    // 32 too large. Naming the operand's real width here is what makes the
    // lowering exact — and it is exact whenever the low 32 bits hold the
    // machine's value, which is all the lifter's congruent arithmetic
    // guarantees.
    //
    // Left unmodelled this was an opaque comment whose destination was never
    // defined, so `-O2` bit-scan idioms (`31 - clz(x)`, `32 - clz(x)`) read an
    // undefined local: eight armv7 `-O2` measurements in the fixture corpus.
    if mnem == "clz" && ops.len() == 2 {
        if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
            return vec![Op::Intrinsic {
                name: "arm.clz.32".to_string(),
                ins: vec![src],
                outs: vec![(dst, Width::W32)],
                reads_mem: false,
                writes_mem: false,
            }];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- zero/sign-extend byte/half: uxtb/uxth/sxtb/sxth Rd, Rn ----------
    if matches!(mnem, "uxtb" | "uxth" | "sxtb" | "sxth") && ops.len() == 2 {
        if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
            let from = if mnem.ends_with('b') {
                Width::W8
            } else {
                Width::W16
            };
            let signed = mnem.starts_with('s');
            return vec![if signed {
                Op::SExt {
                    dst,
                    src,
                    from,
                    to: Width::W32,
                }
            } else {
                Op::ZExt {
                    dst,
                    src,
                    from,
                    to: Width::W32,
                }
            }];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- movt Rd, #imm  ==>  set the top 16 bits: Rd = Rd | (imm << 16) --
    // Pairs with a preceding movw that loaded the low 16 bits.
    if mnem == "movt" && ops.len() == 2 {
        if let (Some(dst), Some(imm)) = (operand_reg(&ops[0]), ops[1].immediate) {
            return vec![Op::Bin {
                dst: dst.clone(),
                op: BinOp::Or,
                lhs: Value::Reg(dst),
                rhs: Value::Const(imm << 16),
            }];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- long multiply / multiply-accumulate (4-operand forms) ----------
    // umull/smull RdLo, RdHi, Rn, Rm : {RdHi:RdLo} = Rn * Rm. Keep the low
    // product as the ordinary width-truncated multiply and make the high half a
    // typed intrinsic, matching x86/AArch64's shared wide-arithmetic boundary.
    // The instruction itself owns signedness: reconstructing `smull` as a bare
    // product followed by `sar` lets a high-bit immediate become an unsigned C
    // operand before the later shift/cast can recover signed 32x32 semantics.
    // Emit the high half before committing RdLo because ARM permits a source to
    // overlap a destination; the temp retains the low product independently.
    if (mnem == "umull" || mnem == "smull") && ops.len() == 4 {
        if let (Some(rd_lo), Some(rd_hi), Some(rn), Some(rm)) = (
            operand_reg(&ops[0]),
            operand_reg(&ops[1]),
            operand_to_value(&ops[2]),
            operand_to_value(&ops[3]),
        ) {
            let t = VReg::Temp(0);
            let high_name = if mnem == "smull" {
                "arm.smul_hi.32"
            } else {
                "arm.umul_hi.32"
            };
            return vec![
                Op::Bin {
                    dst: t.clone(),
                    op: BinOp::Mul,
                    lhs: rn.clone(),
                    rhs: rm.clone(),
                },
                Op::Intrinsic {
                    name: high_name.to_string(),
                    ins: vec![rn, rm],
                    outs: vec![(rd_hi, Width::W32)],
                    reads_mem: false,
                    writes_mem: false,
                },
                Op::Assign {
                    dst: rd_lo,
                    src: Value::Reg(t),
                },
            ];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }
    if mnem == "smlal" {
        return wide_multiply::lift_signed_long_multiply_accumulate(&ops).unwrap_or_else(|| {
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        });
    }
    // smlabb Rd, Rn, Rm, Ra: sign-extend the bottom halfword of both
    // multiplicands, add the signed 32-bit accumulator, and keep the low 32
    // result bits.  Perform the arithmetic at 64 bits so the emitted C is
    // defined even where the architectural 32-bit addition wraps.
    if mnem == "smlabb" && ops.len() == 4 {
        if let (Some(rd), Some(rn), Some(rm), Some(ra)) = (
            operand_reg(&ops[0]),
            operand_to_value(&ops[1]),
            operand_to_value(&ops[2]),
            operand_to_value(&ops[3]),
        ) {
            let rn16 = VReg::Temp(0);
            let rn64 = VReg::Temp(1);
            let rm16 = VReg::Temp(2);
            let rm64 = VReg::Temp(3);
            let ra64 = VReg::Temp(4);
            let product = VReg::Temp(5);
            let sum = VReg::Temp(6);
            return vec![
                Op::Trunc {
                    dst: rn16.clone(),
                    src: rn,
                    from: Width::W32,
                    to: Width::W16,
                },
                Op::SExt {
                    dst: rn64.clone(),
                    src: Value::Reg(rn16),
                    from: Width::W16,
                    to: Width::W64,
                },
                Op::Trunc {
                    dst: rm16.clone(),
                    src: rm,
                    from: Width::W32,
                    to: Width::W16,
                },
                Op::SExt {
                    dst: rm64.clone(),
                    src: Value::Reg(rm16),
                    from: Width::W16,
                    to: Width::W64,
                },
                Op::SExt {
                    dst: ra64.clone(),
                    src: ra,
                    from: Width::W32,
                    to: Width::W64,
                },
                Op::Bin {
                    dst: product.clone(),
                    op: BinOp::Mul,
                    lhs: Value::Reg(rn64),
                    rhs: Value::Reg(rm64),
                },
                Op::Bin {
                    dst: sum.clone(),
                    op: BinOp::Add,
                    lhs: Value::Reg(product),
                    rhs: Value::Reg(ra64),
                },
                Op::Trunc {
                    dst: rd,
                    src: Value::Reg(sum),
                    from: Width::W64,
                    to: Width::W32,
                },
            ];
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }
    // mla Rd, Rn, Rm, Ra : Rd = Rn*Rm + Ra ; mls Rd, Rn, Rm, Ra : Rd = Ra - Rn*Rm.
    // A temp holds Rn*Rm so the accumulate operand `Ra` is read before `Rd` is
    // overwritten (the common `s += a*b` case has Ra == Rd).
    if (mnem == "mla" || mnem == "mls") && ops.len() == 4 {
        if let (Some(rd), Some(rn), Some(rm), Some(ra)) = (
            operand_reg(&ops[0]),
            operand_to_value(&ops[1]),
            operand_to_value(&ops[2]),
            operand_to_value(&ops[3]),
        ) {
            let t = VReg::Temp(0);
            let mut out = vec![Op::Bin {
                dst: t.clone(),
                op: BinOp::Mul,
                lhs: rn,
                rhs: rm,
            }];
            if mnem == "mla" {
                out.push(Op::Bin {
                    dst: rd,
                    op: BinOp::Add,
                    lhs: ra,
                    rhs: Value::Reg(t),
                });
            } else {
                out.push(Op::Bin {
                    dst: rd,
                    op: BinOp::Sub,
                    lhs: ra,
                    rhs: Value::Reg(t),
                });
            }
            return out;
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- add/sub with carry: adc/adcs/sbc/sbcs ----------------------------
    if matches!(mnem, "adc" | "adcs" | "sbc" | "sbcs") {
        let add = mnem.starts_with("adc");
        let sets_flags = mnem.ends_with('s');
        let operand = |i: usize, out: &mut Vec<Op>| shifted_operand(ins, ctx, i, out);
        if ops.len() == 3 {
            let mut prefix = Vec::new();
            if let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ops[0]),
                operand_to_value(&ops[1]).map(|value| resolve_pc(value, ctx.pc_at(ins))),
                operand(2, &mut prefix),
            ) {
                prefix.extend(arm_carry_arithmetic(dst, lhs, rhs, add, true, sets_flags));
                return prefix;
            }
        }
        if ops.len() == 2 {
            let mut prefix = Vec::new();
            if let (Some(dst), Some(rhs)) = (operand_reg(&ops[0]), operand(1, &mut prefix)) {
                prefix.extend(arm_carry_arithmetic(
                    dst.clone(),
                    Value::Reg(dst),
                    rhs,
                    add,
                    true,
                    sets_flags,
                ));
                return prefix;
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- data processing: <op>{s} Rd, Rn, <reg|imm>  (or 2-operand form) --
    if let Some(op) = bin_for_mnem(mnem) {
        // The `S` suffix means the instruction also writes the condition flags.
        // `bin_for_mnem` maps `subs` and `sub` to the same `BinOp`, so without
        // this the flag write was dropped *silently* — the mnemonic is
        // recognised, so it never even showed up as an unlifted instruction.
        // A dropped flag write leaves its later reader bound to a stale
        // definition, which is how ARMv7 output ended up carrying 6.19 leaked
        // flag temporaries per function against AArch64's 1.45.
        let sets_flags =
            mnem.ends_with('s') && mnem != "rsb" && bin_for_mnem(&mnem[..mnem.len() - 1]).is_some();
        // A shift written as its own instruction (`lsl.w Rd,Rn,#n`) is encoded
        // as `mov` WITH a shift, so it sits in the very same instruction family
        // the modifier is decoded from. Thumb exposes the distance as a third
        // operand. A32's alias can expose only `Rd,Rn`, in which case the word
        // is the sole owner of the distance and must be handled before the
        // ordinary two-operand accumulate form.
        let carries_own_shift = matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar);
        let operand = |i: usize, out: &mut Vec<Op>| {
            if carries_own_shift {
                ops.get(i).and_then(operand_to_value)
            } else {
                shifted_operand(ins, ctx, i, out)
            }
        };
        if carries_own_shift && ops.len() == 2 {
            if let (Some(dst), Some(lhs), Some(shift)) = (
                operand_reg(&ops[0]),
                operand_to_value(&ops[1]).map(|value| resolve_pc(value, ctx.pc_at(ins))),
                data_processing_shift(ins, ctx),
            ) {
                let encoded_op = match shift.kind {
                    ShiftKind::Lsl => Some(BinOp::Shl),
                    ShiftKind::Lsr => Some(BinOp::Shr),
                    ShiftKind::Asr => Some(BinOp::Sar),
                    ShiftKind::Ror | ShiftKind::Rrx => None,
                };
                if encoded_op == Some(op) {
                    let rhs = Value::Const(i64::from(shift.amount));
                    let (before, after) = if sets_flags {
                        flags_for_arith(op, &dst, lhs.clone(), rhs.clone())
                    } else {
                        (Vec::new(), Vec::new())
                    };
                    let mut out = before;
                    out.push(Op::Bin { dst, op, lhs, rhs });
                    out.extend(after);
                    return out;
                }
            }
        }
        // Three-operand: Rd, Rn, Op2
        if ops.len() == 3 {
            let mut out = Vec::new();
            if let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ops[0]),
                operand_to_value(&ops[1]).map(|v| resolve_pc(v, ctx.pc_at(ins))),
                operand(2, &mut out),
            ) {
                if sets_flags && matches!(op, BinOp::Add | BinOp::Sub) {
                    out.extend(arm_carry_arithmetic(
                        dst,
                        lhs,
                        rhs,
                        op == BinOp::Add,
                        false,
                        true,
                    ));
                    return out;
                }
                let (before, after) = if sets_flags {
                    flags_for_arith(op, &dst, lhs.clone(), rhs.clone())
                } else {
                    (Vec::new(), Vec::new())
                };
                out.extend(before);
                out.push(Op::Bin {
                    dst: dst.clone(),
                    op,
                    lhs,
                    rhs,
                });
                out.extend(after);
                return out;
            }
        }
        // Two-operand accumulate: Rd, Op2  ==>  Rd = Rd <op> Op2
        if ops.len() == 2 {
            let mut out = Vec::new();
            if let (Some(dst), Some(rhs)) = (operand_reg(&ops[0]), operand(1, &mut out)) {
                if sets_flags && matches!(op, BinOp::Add | BinOp::Sub) {
                    out.extend(arm_carry_arithmetic(
                        dst.clone(),
                        Value::Reg(dst),
                        rhs,
                        op == BinOp::Add,
                        false,
                        true,
                    ));
                    return out;
                }
                let (before, after) = if sets_flags {
                    flags_for_arith(op, &dst, Value::Reg(dst.clone()), rhs.clone())
                } else {
                    (Vec::new(), Vec::new())
                };
                out.extend(before);
                out.push(Op::Bin {
                    dst: dst.clone(),
                    op,
                    lhs: Value::Reg(dst.clone()),
                    rhs,
                });
                out.extend(after);
                return out;
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- reverse subtract: rsb Rd, Rn, #imm  ==>  Rd = imm - Rn ----------
    if mnem == "rsb" || mnem == "rsbs" || mnem == "neg" || mnem == "negs" {
        if ops.len() == 3 {
            let mut out = Vec::new();
            if let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ops[0]),
                operand_to_value(&ops[1]).map(|v| resolve_pc(v, ctx.pc_at(ins))),
                shifted_operand(ins, ctx, 2, &mut out),
            ) {
                // Rd = rhs - lhs  (reverse)
                out.push(Op::Bin {
                    dst,
                    op: BinOp::Sub,
                    lhs: rhs,
                    rhs: lhs,
                });
                return out;
            }
        }
        // neg Rd, Rn  ==>  Rd = 0 - Rn
        if ops.len() == 2 {
            if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                return vec![Op::Bin {
                    dst,
                    op: BinOp::Sub,
                    lhs: Value::Const(0),
                    rhs: src,
                }];
            }
        }
        return vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }];
    }

    // --- conditional branches: b<cond> label (bne/beq/blt/...) -----------
    if let Some(suffix) = mnem.strip_prefix('b') {
        if suffix.len() == 2 {
            if let Some((cond, inverted)) = cond_flag_for(suffix) {
                if let Some(target) = ops.first().and_then(|o| o.immediate) {
                    return vec![Op::CondJump {
                        cond,
                        target: target as u64,
                        inverted,
                    }];
                }
                return vec![Op::Unknown {
                    mnemonic: mnem.to_string(),
                }];
            }
        }
    }

    match mnem {
        "nop" | "hint" => vec![Op::Nop],

        // Moves. mov/movs/movw Rd, <reg|imm>. mvn Rd, Op2 = Rd = ~Op2.
        "mov" | "movs" | "movw" | "mov.w" => {
            if ops.len() == 2 {
                if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                    return vec![Op::Assign {
                        dst,
                        src: resolve_pc(src, ctx.pc_at(ins)),
                    }];
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }
        // adr Rd, label — PC-relative address. Capstone resolves the target
        // into the immediate; surface it as an absolute address so xref/string
        // recovery can pair it with a following load.
        "adr" => {
            if ops.len() == 2 {
                if let (Some(dst), Some(imm)) = (operand_reg(&ops[0]), ops[1].immediate) {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Addr(imm as u64),
                    }];
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }
        "mvn" | "mvns" => {
            if ops.len() == 2 {
                let mut out = Vec::new();
                if let (Some(dst), Some(src)) =
                    (operand_reg(&ops[0]), shifted_operand(ins, ctx, 1, &mut out))
                {
                    out.push(Op::Un {
                        dst,
                        op: UnOp::Not,
                        src,
                    });
                    return out;
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // `cmp Rn, Op2` is `subs` discarding its result, so it writes exactly
        // the flags `flags_for_arith` gives a subtraction.
        "cmp" => {
            if ops.len() == 2 {
                let mut out = Vec::new();
                if let (Some(lhs), Some(rhs)) = (
                    operand_to_value(&ops[0]).map(|v| resolve_pc(v, ctx.pc_at(ins))),
                    shifted_operand(ins, ctx, 1, &mut out),
                ) {
                    out.extend(cmp_flag_ops(lhs, rhs));
                    return out;
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }
        // `cmn Rn, Op2` is `adds` discarding its result: it compares Rn against
        // MINUS Op2, so only the zero and sign facts of `Rn + Op2` can be
        // claimed. Reusing the `cmp` flag set here (as this arm used to) wrote a
        // borrow-carry and a signed ordering the CPU never evaluated, and the
        // following `b<cond>` rendered that fabricated condition.
        "cmn" => {
            if ops.len() == 2 {
                let mut out = Vec::new();
                if let (Some(lhs), Some(rhs)) = (
                    operand_to_value(&ops[0]).map(|v| resolve_pc(v, ctx.pc_at(ins))),
                    shifted_operand(ins, ctx, 1, &mut out),
                ) {
                    let sum = VReg::Temp(3);
                    out.push(Op::Bin {
                        dst: sum.clone(),
                        op: BinOp::Add,
                        lhs,
                        rhs,
                    });
                    // ARM's `lt`/`le` after `cmn` are `N != V` and
                    // `Z || N != V`, which are exactly "the mathematical sum is
                    // negative / non-positive" — and this IR's `Add` does not
                    // wrap, so the sum IS the mathematical one. The unsigned
                    // pair (C, Ule) would need the 32-bit carry-out and is left
                    // undefined rather than guessed.
                    for (flag, op) in [
                        (Flag::Z, CmpOp::Eq),
                        (Flag::Slt, CmpOp::Slt),
                        (Flag::Sle, CmpOp::Sle),
                    ] {
                        out.push(Op::Cmp {
                            dst: VReg::Flag(flag),
                            op,
                            lhs: Value::Reg(sum.clone()),
                            rhs: Value::Const(0),
                        });
                    }
                    return out;
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }
        // `tst a, b` sets Z from `a & b`; `teq a, b` from `a ^ b`. The result
        // itself is discarded, so it is computed into a temporary and Z taken
        // from that.
        //
        // Reporting Z as `a == b` — which this arm used to do — is a DIFFERENT
        // predicate, and not a conservative one: `tst r0,#4` with r0 == 4 sets
        // Z=0 ("bit 2 is set"), while `4 == 4` reports Z=1. Only Z is claimed;
        // N would need the sign bit of the 32-bit result, and ARM32 registers
        // carry no width in this IR (see `flags_for_arith`).
        "tst" | "teq" => {
            if ops.len() == 2 {
                let mut out = Vec::new();
                if let (Some(lhs), Some(rhs)) = (
                    operand_to_value(&ops[0]).map(|v| resolve_pc(v, ctx.pc_at(ins))),
                    shifted_operand(ins, ctx, 1, &mut out),
                ) {
                    let result = VReg::Temp(3);
                    out.push(Op::Bin {
                        dst: result.clone(),
                        op: if mnem == "teq" {
                            BinOp::Xor
                        } else {
                            BinOp::And
                        },
                        lhs,
                        rhs,
                    });
                    out.push(Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(result),
                        rhs: Value::Const(0),
                    });
                    return out;
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Loads.
        m if m.starts_with("ldr") => {
            if ops.len() >= 2 {
                let Some(dst) = operand_reg(&ops[0]) else {
                    return vec![Op::Unknown {
                        mnemonic: mnem.to_string(),
                    }];
                };
                let size = mem_size_for(m);
                if let Some(addr) =
                    operand_to_memop(&ops[1], size).map(|a| scaled_memop(ins, ctx, a))
                {
                    if dst == VReg::phys("pc") && addr.base == Some(VReg::phys("sp")) {
                        let mut out = Vec::new();
                        if let Some(off) = ops.get(2).and_then(|operand| operand.immediate) {
                            let sp = VReg::phys("sp");
                            out.push(Op::Bin {
                                dst: sp.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(sp),
                                rhs: Value::Const(off),
                            });
                        }
                        out.push(Op::Return);
                        return out;
                    }
                    // `ldr pc, [rBase, rIdx, lsl #2]` — the ARM jump-table
                    // dispatch. Lifting it as an ordinary load into `pc` leaves
                    // the structurer with a block that writes a register and
                    // falls off the end, so the arms the CFG proved render as
                    // labels and gotos instead of a `switch`.
                    //
                    // Same shape as `tbb`/`tbh` below: load the entry, then
                    // branch through it, carrying the index straight from the
                    // addressing mode so the recovered `switch` can name it.
                    // Word stride only — that is what the encoding this
                    // recognises uses, and `analysis::dispatch` decodes nothing
                    // else for this form.
                    if dst == VReg::phys("pc") && addr.scale == 4 {
                        if let (Some(base), Some(index)) = (addr.base.clone(), addr.index.clone()) {
                            if base != VReg::phys("sp") {
                                let target = VReg::Temp(0);
                                return vec![
                                    Op::Load {
                                        dst: target.clone(),
                                        addr,
                                    },
                                    Op::IndirectJump {
                                        target: Value::Reg(target),
                                        index: Some(Value::Reg(index)),
                                    },
                                ];
                            }
                        }
                    }
                    // A whole-word load from an address `scaled_memop` resolved
                    // out of `[pc, #imm]` is a literal-pool read: the pool is
                    // constant data inside the very window being lifted, so the
                    // value is known exactly and becomes a constant. That is
                    // what turns the armhf `-fPIC` idiom
                    // (`ldr Rd,[pc,#n]; add Rd,pc`) into a real address instead
                    // of arithmetic on an undefined register.
                    if let Some(word) = (addr.base.is_none()
                        && addr.index.is_none()
                        && size == 4
                        && load_extension_for(m).is_none()
                        && ops.len() == 2)
                        .then(|| ctx.literal(addr.disp as u64))
                        .flatten()
                    {
                        return vec![Op::Assign {
                            dst,
                            src: Value::Const(word),
                        }];
                    }
                    let base_reg = addr.base.clone();
                    let writeback = addr.disp;
                    let mut out = if let Some((signed, from)) = load_extension_for(m) {
                        let loaded = VReg::Temp(0);
                        let extension = if signed {
                            Op::SExt {
                                dst,
                                src: Value::Reg(loaded.clone()),
                                from,
                                to: Width::W32,
                            }
                        } else {
                            Op::ZExt {
                                dst,
                                src: Value::Reg(loaded.clone()),
                                from,
                                to: Width::W32,
                            }
                        };
                        vec![Op::Load { dst: loaded, addr }, extension]
                    } else {
                        vec![Op::Load { dst, addr }]
                    };
                    // Post-indexed writeback: 3rd operand is the offset.
                    // Pre-indexed writeback: the base becomes the address the
                    // access just used, i.e. it advances by the displacement.
                    let update = if ops.len() == 3 {
                        ops[2].immediate
                    } else if is_preindexed_writeback(ins, ctx) {
                        Some(writeback)
                    } else {
                        None
                    };
                    if let (Some(base), Some(off)) = (base_reg, update) {
                        out.push(Op::Bin {
                            dst: base.clone(),
                            op: BinOp::Add,
                            lhs: Value::Reg(base),
                            rhs: Value::Const(off),
                        });
                    }
                    return out;
                }
                // PC-relative literal: `ldr Rd, =sym` folds to an absolute imm.
                if let Some(abs) = ops[1].immediate {
                    let addr = MemOp {
                        base: None,
                        index: None,
                        scale: 0,
                        disp: abs,
                        size,
                        segment: None,
                        endian: Endian::Little,
                    };
                    if let Some((signed, from)) = load_extension_for(m) {
                        let loaded = VReg::Temp(0);
                        let extension = if signed {
                            Op::SExt {
                                dst,
                                src: Value::Reg(loaded.clone()),
                                from,
                                to: Width::W32,
                            }
                        } else {
                            Op::ZExt {
                                dst,
                                src: Value::Reg(loaded.clone()),
                                from,
                                to: Width::W32,
                            }
                        };
                        return vec![Op::Load { dst: loaded, addr }, extension];
                    }
                    return vec![Op::Load { dst, addr }];
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Stores.
        m if m.starts_with("str") => {
            if ops.len() >= 2 {
                let Some(src) = operand_to_value(&ops[0]) else {
                    return vec![Op::Unknown {
                        mnemonic: mnem.to_string(),
                    }];
                };
                let size = mem_size_for(m);
                if let Some(addr) =
                    operand_to_memop(&ops[1], size).map(|a| scaled_memop(ins, ctx, a))
                {
                    let base_reg = addr.base.clone();
                    let writeback = addr.disp;
                    let mut out = vec![Op::Store { addr, src }];
                    // See the load arm: post-indexed carries its offset as a
                    // third operand, pre-indexed advances by the displacement.
                    let update = if ops.len() == 3 {
                        ops[2].immediate
                    } else if is_preindexed_writeback(ins, ctx) {
                        Some(writeback)
                    } else {
                        None
                    };
                    if let (Some(base), Some(off)) = (base_reg, update) {
                        out.push(Op::Bin {
                            dst: base.clone(),
                            op: BinOp::Add,
                            lhs: Value::Reg(base),
                            rhs: Value::Const(off),
                        });
                    }
                    return out;
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Compare-and-branch (Thumb): cbz/cbnz Rn, label.
        "cbz" | "cbnz" => {
            let inverted = mnem == "cbnz";
            if ops.len() == 2 {
                let Some(reg_val) = operand_to_value(&ops[0]) else {
                    return vec![Op::Unknown {
                        mnemonic: mnem.to_string(),
                    }];
                };
                if let Some(target) = ops[1].immediate {
                    return vec![
                        Op::Cmp {
                            dst: VReg::Flag(Flag::Z),
                            op: CmpOp::Eq,
                            lhs: reg_val,
                            rhs: Value::Const(0),
                        },
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: target as u64,
                            inverted,
                        },
                    ];
                }
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Unconditional branch (also the tail-call form b.w).
        "b" | "b.w" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Jump {
                    target: target as u64,
                }];
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Calls: bl label (direct); blx label|reg (direct|indirect).
        "bl" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                    effects: None,
                }];
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }
        "blx" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                    effects: None,
                }];
            }
            if let Some(reg) = ops.first().and_then(operand_reg) {
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(reg)),
                    effects: None,
                }];
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Thumb-2 table branch: `tbb [pc, Rm]` / `tbh [pc, Rm, lsl #1]`.
        //
        // `pc` reads as this instruction's address + 4 in Thumb state, and the
        // encoding is always 4 bytes, so the table starts at the byte right
        // after it and the load is `[table_va + Rm * entry_size]`. The branch
        // target is `table_va + 2 * loaded`, which the CFG has already resolved
        // into real successors (`analysis::dispatch::thumb_table_branch`); this
        // is an `IndirectJump` rather than a `Call` so the structurer recognises
        // it as the dispatch to replace with a `switch`.
        //
        // `index` carries the switch value straight from the addressing mode,
        // which is what lets the recovered `switch` name it. On x86 that has to
        // be reconstructed by `lift_function::annotate_resolved_switch_indices`
        // from a scale-four load; here the encoding states it outright.
        "tbb" | "tbh" => {
            let entry_size: u8 = if mnem == "tbb" { 1 } else { 2 };
            let table_va = ctx.pc_at(ins);
            let index = ops
                .first()
                .filter(|operand| operand.base.as_deref() == Some("pc"))
                .and_then(|operand| operand.index.as_deref())
                .map(VReg::phys);
            if let Some(index) = index {
                let offset = VReg::Temp(0);
                return vec![
                    Op::Load {
                        dst: offset.clone(),
                        addr: MemOp::plain(
                            None,
                            Some(index.clone()),
                            entry_size,
                            table_va,
                            entry_size,
                        ),
                    },
                    Op::IndirectJump {
                        target: Value::Reg(offset),
                        index: Some(Value::Reg(index)),
                    },
                ];
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        // Branch-and-exchange: `bx lr` returns; `bx reg` is an indirect
        // transfer (tail call / computed branch). `bxns` is the ARMv8-M
        // non-secure variant with the same control-flow shape.
        "bx" | "bxns" => {
            if let Some(name) = ops.first().and_then(operand_reg_name) {
                if name == "lr" {
                    return vec![Op::Return];
                }
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(VReg::phys(name))),
                    effects: None,
                }];
            }
            vec![Op::Unknown {
                mnemonic: mnem.to_string(),
            }]
        }

        _ => vec![Op::Unknown {
            mnemonic: mnem.to_string(),
        }],
    }
}

/// Lift a byte window of ARM32 machine code into LLIR.
///
/// `thumb` selects the capstone decode mode: Thumb-2 (the default for
/// `Arch::ARM` in this pipeline) when true, A32 when false. Thumb instructions
/// are 2 or 4 bytes; the loop advances by capstone's reported length rather than
/// a fixed stride. Returns an empty vector if the backend cannot be built or the
/// first instruction fails to decode.
pub fn lift_bytes(bytes: &[u8], start_va: u64, thumb: bool) -> Vec<LlirInstr> {
    lift_bytes_in_image(bytes, start_va, thumb, None)
}

/// [`lift_bytes`], additionally given the whole image the window came from.
///
/// ARM32 constants live in a literal pool that `ldr Rd,[pc,#imm]` reads, and the
/// pool sits after the function's last basic block — outside the per-block
/// window [`crate::ir::lift_function`] lifts. Passing the image is what lets
/// those loads resolve to the constants they are, instead of to synthetic
/// globals over an address the recovered C then dereferences.
pub fn lift_bytes_in_image(
    bytes: &[u8],
    start_va: u64,
    thumb: bool,
    image: Option<&[u8]>,
) -> Vec<LlirInstr> {
    let Some(mut cs) = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little) else {
        return vec![];
    };
    if cs.set_thumb_mode(thumb).is_err() {
        return vec![];
    }
    let ctx = LiftCtx {
        thumb,
        bytes,
        start_va,
        image,
    };
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_va;
    // Per-slot conditions for the instructions the current IT block still
    // predicates (front = next instruction).
    let mut it_queue: std::collections::VecDeque<(VReg, bool)> = std::collections::VecDeque::new();
    while off < bytes.len() {
        let Ok(addr) = Address::new(AddressKind::VA, va, 32, None, None) else {
            break;
        };
        let ins = match cs.disassemble_instruction(&addr, &bytes[off..]) {
            Ok(i) => i,
            Err(_) => break,
        };
        if ins.length == 0 {
            break;
        }
        let raw = ins.mnemonic.to_ascii_lowercase();
        let mnem = strip_qualifier(&raw);

        if is_it_mnemonic(mnem) {
            // The IT prefix carries no data effect; it just arms predication for
            // the following instructions. Read its condition (operand 0) + mask.
            let cond_name = ins
                .operands
                .first()
                .and_then(|o| o.register.as_deref())
                .unwrap_or("");
            it_queue = it_conditions(mnem, cond_name).into();
            out.push(LlirInstr { va, op: Op::Nop });
        } else if let Some((flag, inverted)) = it_queue.pop_front() {
            let lifted = lift_one(&ins, mnemonic_in_it(&ins, mnem), &ctx);
            for op in make_conditional(lifted, flag, inverted) {
                out.push(LlirInstr { va, op });
            }
        } else if !thumb {
            if let Some((base, flag, inverted)) = a32_predicate(&ins, mnem) {
                // A direct conditional branch already has an exact CondJump
                // representation, including its target. All other A32
                // condition-suffixed operations lift through their base
                // mnemonic and then commit their effects conditionally.
                let lifted = if base == "b" {
                    lift_one(&ins, mnem, &ctx)
                } else {
                    lift_one(&ins, &base, &ctx)
                };
                let lifted = if base == "b" {
                    lifted
                } else {
                    make_conditional(lifted, flag, inverted)
                };
                for op in lifted {
                    out.push(LlirInstr { va, op });
                }
            } else {
                for op in lift_one(&ins, mnem, &ctx) {
                    out.push(LlirInstr { va, op });
                }
            }
        } else {
            for op in lift_one(&ins, mnem, &ctx) {
                out.push(LlirInstr { va, op });
            }
        }

        off += ins.length as usize;
        va = va.saturating_add(ins.length as u64);
    }
    out
}

#[cfg(test)]
#[path = "lift_arm32/packet_tests.rs"]
mod packet_tests;

#[cfg(test)]
#[path = "lift_arm32/wide_multiply_tests.rs"]
mod wide_multiply_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every Cortex-M system-register form observed in the DecBench ARM32
    /// corpus, assembled by `arm-none-eabi-as -mcpu=cortex-m4 -mthumb`.
    ///
    /// These are machine state, not memory. Lifting them as an opaque
    /// memory-clobbering unknown (or not at all) is what makes 31 rows return
    /// no body: the whole function is abandoned at the first `mrs` in an
    /// interrupt-priority critical section, and those appear in essentially
    /// every RTOS and bare-metal image.
    const SYSREG_PACKETS: &[(&str, [u8; 4], &str)] = &[
        ("mrs r0, BASEPRI", [0xef, 0xf3, 0x11, 0x80], "r0"),
        ("msr BASEPRI, r1", [0x81, 0xf3, 0x11, 0x88], "r1"),
        ("msr BASEPRI_MAX, r2", [0x82, 0xf3, 0x12, 0x88], "r2"),
        ("mrs r3, IPSR", [0xef, 0xf3, 0x05, 0x83], "r3"),
        ("mrs r4, PSP", [0xef, 0xf3, 0x09, 0x84], "r4"),
        ("msr PSP, r5", [0x85, 0xf3, 0x09, 0x88], "r5"),
    ];

    #[test]
    fn cortex_m_system_registers_lift_to_typed_non_memory_intrinsics() {
        for (asm, bytes, reg) in SYSREG_PACKETS {
            let lifted = lift_bytes(bytes, 0x8000_0100, true);
            assert!(
                !lifted.is_empty(),
                "{asm}: lifted to nothing, so the enclosing function is \
                 abandoned at this instruction"
            );
            let is_mrs = asm.starts_with("mrs");
            match &lifted[0].op {
                Op::Intrinsic {
                    name,
                    ins,
                    outs,
                    reads_mem,
                    writes_mem,
                } => {
                    // The exact name, not just the prefix: an empty or
                    // wrong system register would still satisfy a prefix
                    // check while collapsing BASEPRI_MAX into BASEPRI.
                    let sys = asm.rsplit(&[',', ' '][..]).next().unwrap();
                    let expect = format!(
                        "arm32.{}.{}",
                        if is_mrs { "mrs" } else { "msr" },
                        if is_mrs {
                            asm.split(", ").nth(1).unwrap().to_ascii_lowercase()
                        } else {
                            asm.split(' ').nth(1).unwrap().trim_end_matches(',').to_ascii_lowercase()
                        }
                    );
                    let _ = sys;
                    assert_eq!(
                        name, &expect,
                        "{asm}: the system register must be part of the \
                         intrinsic name so BASEPRI_MAX stays distinct from \
                         BASEPRI"
                    );
                    assert!(
                        !reads_mem && !writes_mem,
                        "{asm}: special registers are machine state, not \
                         memory -- claiming memory effects here makes every \
                         surrounding load and store unorderable"
                    );
                    if is_mrs {
                        assert_eq!(
                            outs,
                            &[(VReg::phys(*reg), Width::W32)],
                            "{asm}: MRS defines its destination; without the \
                             output the register reads as undefined downstream"
                        );
                        assert!(ins.is_empty(), "{asm}: MRS takes no register input");
                    } else {
                        assert_eq!(
                            ins,
                            &[Value::Reg(VReg::phys(*reg))],
                            "{asm}: MSR consumes its source; dropping the \
                             input loses a real data dependency"
                        );
                        assert!(outs.is_empty(), "{asm}: MSR defines no GPR");
                    }
                }
                other => panic!("{asm}: expected a typed intrinsic, got {other:#?}"),
            }
        }
    }

    /// The rest of the Cortex-M special registers, same assembler.
    ///
    /// `mrs r7, XPSR` is assembled from that spelling but disassembles as
    /// `PSR`, so these assert the property that matters rather than a
    /// spelling: every form lifts to a typed non-memory intrinsic, and
    /// registers that differ get names that differ.
    #[test]
    fn the_remaining_cortex_m_special_registers_lift_distinctly() {
        let packets: &[(&str, [u8; 4], &str)] = &[
            ("mrs PRIMASK", [0xef, 0xf3, 0x10, 0x80], "r0"),
            ("msr PRIMASK", [0x81, 0xf3, 0x10, 0x88], "r1"),
            ("mrs FAULTMASK", [0xef, 0xf3, 0x13, 0x82], "r2"),
            ("mrs CONTROL", [0xef, 0xf3, 0x14, 0x83], "r3"),
            ("msr CONTROL", [0x84, 0xf3, 0x14, 0x88], "r4"),
            ("mrs MSP", [0xef, 0xf3, 0x08, 0x85], "r5"),
            ("msr MSP", [0x86, 0xf3, 0x08, 0x88], "r6"),
            ("mrs XPSR", [0xef, 0xf3, 0x03, 0x87], "r7"),
        ];
        let mut mrs_names = std::collections::BTreeSet::new();
        for (asm, bytes, reg) in packets {
            let lifted = lift_bytes(bytes, 0x8000_0300, true);
            assert!(!lifted.is_empty(), "{asm}: lifted to nothing");
            let Op::Intrinsic {
                name,
                ins,
                outs,
                reads_mem,
                writes_mem,
            } = &lifted[0].op
            else {
                panic!("{asm}: expected a typed intrinsic, got {:#?}", lifted[0].op);
            };
            assert!(!reads_mem && !writes_mem, "{asm}: not memory");
            let is_mrs = asm.starts_with("mrs");
            let prefix = if is_mrs { "arm32.mrs." } else { "arm32.msr." };
            assert!(name.starts_with(prefix), "{asm}: named {name:?}");
            assert!(
                name.len() > prefix.len(),
                "{asm}: named {name:?} -- the system register is missing, so \
                 this intrinsic is indistinguishable from every other {prefix}"
            );
            if is_mrs {
                assert_eq!(outs, &[(VReg::phys(*reg), Width::W32)], "{asm}");
                mrs_names.insert(name.clone());
            } else {
                assert_eq!(ins, &[Value::Reg(VReg::phys(*reg))], "{asm}");
            }
        }
        // PRIMASK, FAULTMASK, CONTROL, MSP, XPSR are five distinct registers.
        assert_eq!(mrs_names.len(), 5, "collapsed names: {mrs_names:?}");
    }

    /// BASEPRI_MAX is not BASEPRI: it only ever RAISES the priority ceiling,
    /// so a fix that folded the two would silently model a critical section
    /// as doing the opposite of what it does on one of the two paths.
    #[test]
    fn basepri_max_is_distinct_from_basepri() {
        let basepri = lift_bytes(&[0x81, 0xf3, 0x11, 0x88], 0x8000_0400, true);
        let basepri_max = lift_bytes(&[0x82, 0xf3, 0x12, 0x88], 0x8000_0400, true);
        let name = |v: &[LlirInstr]| match &v[0].op {
            Op::Intrinsic { name, .. } => name.clone(),
            other => panic!("expected intrinsic, got {other:#?}"),
        };
        let (a, b) = (name(&basepri), name(&basepri_max));
        assert_ne!(a, b, "BASEPRI and BASEPRI_MAX collapsed to {a:?}");
        assert_eq!(a, "arm32.msr.basepri");
        assert_eq!(b, "arm32.msr.basepri_max");
    }

    #[test]
    fn thumb_vmov_f32_preserves_the_real_s0_output_footprint() {
        // `vmov.f32 s0, s15` from the epilogue of the real DecBench
        // `pidUpdate` ARM hard-float function.
        let lifted = lift_bytes(&[0xb0, 0xee, 0x67, 0x0a], 0x8060508, true);
        assert_eq!(lifted.len(), 1, "lifted VFP move: {lifted:#?}");
        assert!(
            matches!(
                &lifted[0].op,
                Op::Intrinsic {
                    name,
                    ins,
                    outs,
                    reads_mem: false,
                    writes_mem: false,
                } if name == "vmov.f32"
                    && ins == &[Value::Reg(VReg::phys("s15"))]
                    && outs == &[(VReg::phys("s0"), Width::W32)]
            ),
            "lifted VFP move: {lifted:#?}"
        );

        // `vmov.f32 s14, s0` immediately consumes a hard-float call result in
        // the real caller fixture.  Capstone assigns a different register
        // encoding here than in the return move above; both must retain the
        // same two-operand data-flow shape.
        let consumed = lift_bytes(&[0xb0, 0xee, 0x40, 0x7a], 0x104a, true);
        assert!(
            matches!(
                consumed.as_slice(),
                [LlirInstr {
                    op: Op::Intrinsic { name, ins, outs, .. },
                    ..
                }] if name == "vmov.f32"
                    && ins == &[Value::Reg(VReg::phys("s0"))]
                    && outs == &[(VReg::phys("s14"), Width::W32)]
            ),
            "lifted call-result move: {consumed:#?}"
        );

        // The next real instruction combines that result with the caller's
        // saved input.  Keep this exact binary spelling covered as well.
        let added = lift_bytes(&[0x77, 0xee, 0x27, 0x7a], 0x1052, true);
        assert!(
            matches!(
                added.as_slice(),
                [LlirInstr {
                    op: Op::Intrinsic { name, ins, outs, .. },
                    ..
                }] if name == "vadd.f32"
                    && ins == &[
                        Value::Reg(VReg::phys("s14")),
                        Value::Reg(VReg::phys("s15")),
                    ]
                    && outs == &[(VReg::phys("s15"), Width::W32)]
            ),
            "lifted post-call addition: {added:#?}"
        );
    }

    #[test]
    fn thumb_lighthouse_vfp_sequence_has_complete_register_footprints() {
        // Exact instructions around the real DecBench lighthouse math calls.
        // These definitions feed s0 before tanf/asinf; any opaque operation
        // severs the argument dataflow even when the library prototype is known.
        let cases = [
            (
                [0x27, 0xee, 0xa7, 0x7a],
                "vmul.f32",
                vec![Value::Reg(VReg::phys("s15")), Value::Reg(VReg::phys("s15"))],
                VReg::phys("s14"),
            ),
            (
                [0x77, 0xee, 0xc7, 0x7a],
                "vsub.f32",
                vec![Value::Reg(VReg::phys("s15")), Value::Reg(VReg::phys("s14"))],
                VReg::phys("s15"),
            ),
            (
                [0xc7, 0xee, 0x27, 0x6a],
                "vdiv.f32",
                vec![Value::Reg(VReg::phys("s14")), Value::Reg(VReg::phys("s15"))],
                VReg::phys("s13"),
            ),
        ];
        for (bytes, expected_name, expected_inputs, expected_output) in cases {
            let lifted = lift_bytes(&bytes, 0x805_d062, true);
            assert!(
                matches!(
                    lifted.as_slice(),
                    [LlirInstr {
                        op: Op::Intrinsic { name, ins, outs, .. },
                        ..
                    }] if name == expected_name
                        && ins == &expected_inputs
                        && outs == &[(expected_output, Width::W32)]
                ),
                "{expected_name} footprint: {lifted:#?}"
            );
        }

        let core_move = lift_bytes(&[0x07, 0xee, 0x10, 0x3a], 0x805_d086, true);
        assert!(
            matches!(
                core_move.as_slice(),
                [LlirInstr {
                    op: Op::Intrinsic { name, ins, outs, .. },
                    ..
                }] if name == "vmov"
                    && ins == &[Value::Reg(VReg::phys("r3"))]
                    && outs == &[(VReg::phys("s14"), Width::W32)]
            ),
            "core-to-VFP move footprint: {core_move:#?}"
        );
    }

    #[test]
    fn thumb_vmov_f32_immediate_preserves_ieee_payload() {
        // `vmov.f32 s15, #8` (`3.0f`) from the real DecBench dynThrottle
        // function. Capstone reports this operand as an f64, so the decoder
        // must explicitly project it back to the instruction's f32 payload.
        let lifted = lift_bytes(&[0xf0, 0xee, 0x08, 0x7a], 0x804343c, true);
        assert_eq!(lifted.len(), 1, "lifted VFP immediate: {lifted:#?}");
        assert!(
            matches!(
                &lifted[0].op,
                Op::Intrinsic { name, ins, outs, .. }
                    if name == "vmov.f32"
                        && ins == &[Value::Const(0x4040_0000)]
                        && outs == &[(VReg::phys("s15"), Width::W32)]
            ),
            "lifted VFP immediate: {lifted:#?}"
        );
    }

    #[test]
    fn thumb_vfp_memory_and_negation_have_explicit_dataflow() {
        // Exact instructions from the real DecBench crazyflie `pidUpdate`
        // prologue/body.  These are semantic float operations, not opaque
        // comments: the spill layout identifies mixed-class parameter order,
        // while the load/negate chain must retain the value reaching s15.
        let store = lift_bytes(&[0x8d, 0xed, 0x02, 0x0a], 0x8060286, true);
        assert!(
            matches!(
                store.as_slice(),
                [LlirInstr {
                    op: Op::Store {
                        addr: MemOp {
                            base: Some(base),
                            index: None,
                            disp: 8,
                            size: 4,
                            ..
                        },
                        src: Value::Reg(src),
                    },
                    ..
                }] if base == &VReg::phys("sp") && src == &VReg::phys("s0")
            ),
            "lifted VFP store: {store:#?}"
        );

        let load = lift_bytes(&[0xdd, 0xed, 0x02, 0x7a], 0x806029c, true);
        assert!(
            matches!(
                load.as_slice(),
                [LlirInstr {
                    op: Op::Load {
                        dst,
                        addr: MemOp {
                            base: Some(base),
                            index: None,
                            disp: 8,
                            size: 4,
                            ..
                        },
                    },
                    ..
                }] if dst == &VReg::phys("s15") && base == &VReg::phys("sp")
            ),
            "lifted VFP load: {load:#?}"
        );

        let negate = lift_bytes(&[0xf1, 0xee, 0x67, 0x7a], 0x806033a, true);
        assert!(
            matches!(
                negate.as_slice(),
                [LlirInstr {
                    op: Op::Intrinsic { name, ins, outs, .. },
                    ..
                }] if name == "vneg.f32"
                    && ins == &[Value::Reg(VReg::phys("s15"))]
                    && outs == &[(VReg::phys("s15"), Width::W32)]
            ),
            "lifted VFP negate: {negate:#?}"
        );
    }

    #[test]
    fn thumb_postindexed_pc_load_lifts_as_stack_pop_return() {
        // `ldr.w pc, [sp], #4`, the exact GCC epilogue encoding exercised by
        // the DecBench `write_power_mode` function.
        let lifted = lift_bytes(&[0x5d, 0xf8, 0x04, 0xfb], 0x801da76, true);
        assert!(
            matches!(
                lifted.last().map(|instruction| &instruction.op),
                Some(Op::Return)
            ),
            "epilogue must end in semantic Return: {lifted:#?}"
        );
    }

    #[test]
    fn thumb_vpush_vpop_double_register_preserve_eight_byte_stack_width() {
        // Exact Cortex-M4 encodings from DecBench's real
        // `lighthouseCalibrationMeasurementModelLh2` frame:
        //
        //     vpush {d8}    ed2d 8b02
        //     vpop  {d8}    ecbd 8b02
        //
        // A D register is 64 bits.  Treating the VFP register list like a
        // core-register push silently undercounts the frame by four bytes.
        let pushed = ops(&[0x2d, 0xed, 0x02, 0x8b]);
        assert_eq!(
            pushed,
            vec![
                Op::Bin {
                    dst: VReg::phys("sp"),
                    op: BinOp::Sub,
                    lhs: Value::Reg(VReg::phys("sp")),
                    rhs: Value::Const(8),
                },
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("sp")), None, 0, 0, 8),
                    src: Value::Reg(VReg::phys("d8")),
                },
            ],
            "vpush must allocate and store the full d8 width"
        );

        let popped = ops(&[0xbd, 0xec, 0x02, 0x8b]);
        assert_eq!(
            popped,
            vec![
                Op::Load {
                    dst: VReg::phys("d8"),
                    addr: MemOp::plain(Some(VReg::phys("sp")), None, 0, 0, 8),
                },
                Op::Bin {
                    dst: VReg::phys("sp"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("sp")),
                    rhs: Value::Const(8),
                },
            ],
            "vpop must load and release the full d8 width"
        );
    }

    /// A real Thumb-2 (Cortex-M) function body, assembled with
    /// `arm-none-eabi-as -mcpu=cortex-m4 -mthumb` and byte-swapped to
    /// little-endian memory order:
    ///
    /// ```text
    /// push {r4, lr}        b510
    /// movs r0, #0          2000
    /// mov  r4, r1          460c
    /// adds r0, r0, r4      1900
    /// cmp  r0, r4          42a0
    /// subs r2, r3, r4      1b1a
    /// ldr  r0, [r1, #4]    6848
    /// str  r0, [r1, #8]    6088
    /// pop  {r4, pc}        bd10
    /// bx   lr              4770
    /// ```
    const THUMB_BODY: &[u8] = &[
        0x10, 0xb5, // push {r4, lr}
        0x00, 0x20, // movs r0, #0
        0x0c, 0x46, // mov r4, r1
        0x00, 0x19, // adds r0, r0, r4
        0xa0, 0x42, // cmp r0, r4
        0x1a, 0x1b, // subs r2, r3, r4
        0x48, 0x68, // ldr r0, [r1, #4]
        0x88, 0x60, // str r0, [r1, #8]
        0x10, 0xbd, // pop {r4, pc}
        0x70, 0x47, // bx lr
    ];

    fn ops(bytes: &[u8]) -> Vec<Op> {
        lift_bytes(bytes, 0x1000, true)
            .into_iter()
            .map(|i| i.op)
            .collect()
    }

    fn ops_a32(bytes: &[u8]) -> Vec<Op> {
        lift_bytes(bytes, 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect()
    }

    #[test]
    fn thumb_body_lifts_expected_ops() {
        let ops = ops(THUMB_BODY);
        assert!(!ops.is_empty(), "capstone produced no ops");

        // push {r4, lr}: sp -= 8, then two stores.
        assert!(
            ops.iter().any(|o| matches!(o,
                Op::Bin { dst, op: BinOp::Sub, rhs: Value::Const(8), .. }
                    if matches!(dst, VReg::Phys(n) if n == "sp"))),
            "push did not decrement sp by 8: {:?}",
            ops
        );
        let stores = ops.iter().filter(|o| matches!(o, Op::Store { .. })).count();
        assert!(stores >= 2, "expected >=2 stores (push + str): {:?}", ops);

        // movs r0, #0  ->  r0 = 0
        assert!(
            ops.iter().any(|o| matches!(o,
                Op::Assign { dst, src: Value::Const(0) }
                    if matches!(dst, VReg::Phys(n) if n == "r0"))),
            "movs r0,#0 missing: {:?}",
            ops
        );

        // adds r0, r0, r4  ->  Bin Add
        assert!(
            ops.iter()
                .any(|o| matches!(o, Op::Bin { op: BinOp::Add, .. })),
            "adds missing: {:?}",
            ops
        );
        // subs r2, r3, r4  ->  Bin Sub (non-sp)
        assert!(
            ops.iter().any(|o| matches!(o,
                Op::Bin { dst, op: BinOp::Sub, .. }
                    if matches!(dst, VReg::Phys(n) if n == "r2"))),
            "subs missing: {:?}",
            ops
        );

        // cmp r0, r4 -> four flag writes incl. the Z equality.
        assert!(
            ops.iter().any(|o| matches!(
                o,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    ..
                }
            )),
            "cmp flag writes missing: {:?}",
            ops
        );

        // ldr / str
        assert!(
            ops.iter().any(|o| matches!(o, Op::Load { .. })),
            "ldr missing: {:?}",
            ops
        );

        // pop {r4, pc} and bx lr both return.
        let returns = ops.iter().filter(|o| matches!(o, Op::Return)).count();
        assert!(
            returns >= 2,
            "expected >=2 returns (pop pc + bx lr): {:?}",
            ops
        );
    }

    #[test]
    fn bx_lr_is_return_but_bx_reg_is_indirect() {
        // bx lr = 4770 ; the standalone form.
        assert_eq!(ops(&[0x70, 0x47]), vec![Op::Return]);
    }

    /// ARMv7 scalar arithmetic (Cortex-M4), assembled with
    /// `arm-none-eabi-as -mcpu=cortex-m4 -mthumb`, little-endian memory order.
    #[test]
    fn scalar_arith_ops_lift() {
        // sdiv r0, r1, r2 = fb91 f0f2  ->  r0 = r1 / r2
        assert_eq!(
            ops(&[0x91, 0xfb, 0xf2, 0xf0]),
            vec![Op::Bin {
                dst: VReg::phys("r0"),
                op: BinOp::Div,
                lhs: Value::Reg(VReg::phys("r1")),
                rhs: Value::Reg(VReg::phys("r2")),
            }]
        );
        // udiv r0, r1, r2 = fbb1 f0f2  ->  also Div
        assert_eq!(
            ops(&[0xb1, 0xfb, 0xf2, 0xf0]),
            vec![Op::Bin {
                dst: VReg::phys("r0"),
                op: BinOp::Div,
                lhs: Value::Reg(VReg::phys("r1")),
                rhs: Value::Reg(VReg::phys("r2")),
            }]
        );

        // clz r0, r1 = fab1 f081 -> a typed intrinsic naming the 32-bit width,
        // not an opaque comment whose destination is never defined.
        let clz = ops(&[0xb1, 0xfa, 0x81, 0xf0]);
        assert_eq!(
            clz,
            vec![Op::Intrinsic {
                name: "arm.clz.32".to_string(),
                ins: vec![Value::Reg(VReg::phys("r1"))],
                outs: vec![(VReg::phys("r0"), Width::W32)],
                reads_mem: false,
                writes_mem: false,
            }],
            "clz must lift to an exactly-renderable 32-bit intrinsic"
        );

        // umull r0, r1, r2, r3 = fba2 0103  ->  {r1:r0} = r2*r3
        let umull = ops(&[0xa2, 0xfb, 0x03, 0x01]);
        assert!(
            umull
                .iter()
                .any(|o| matches!(o, Op::Bin { op: BinOp::Mul, .. })),
            "umull no mul: {:?}",
            umull
        );
        assert!(
            umull.iter().any(|o| matches!(o,
                Op::Assign { dst, .. } if matches!(dst, VReg::Phys(n) if n == "r0"))),
            "umull low half not assigned to r0: {:?}",
            umull
        );
        assert!(
            umull.iter().any(|o| matches!(o,
                Op::Intrinsic { name, outs, .. }
                    if name == "arm.umul_hi.32"
                        && outs == &[(VReg::phys("r1"), Width::W32)])),
            "umull high half is not the typed r1 result: {:?}",
            umull
        );

        // mla r0, r1, r2, r3 = fb01 3002  ->  t = r1*r2 ; r0 = r3 + t
        let mla = ops(&[0x01, 0xfb, 0x02, 0x30]);
        assert!(
            mla.iter()
                .any(|o| matches!(o, Op::Bin { op: BinOp::Mul, .. })),
            "mla no mul: {:?}",
            mla
        );
        assert!(
            mla.iter().any(|o| matches!(o,
                Op::Bin { dst, op: BinOp::Add, .. } if matches!(dst, VReg::Phys(n) if n == "r0"))),
            "mla no accumulate into r0: {:?}",
            mla
        );

        // mls r0, r1, r2, r3 = fb01 3012  ->  r0 = r3 - r1*r2
        let mls = ops(&[0x01, 0xfb, 0x12, 0x30]);
        assert!(
            mls.iter().any(|o| matches!(o,
                Op::Bin { dst, op: BinOp::Sub, .. } if matches!(dst, VReg::Phys(n) if n == "r0"))),
            "mls no subtract into r0: {:?}",
            mls
        );

        // subs r2, #1 = 3a01 (2-op) and subs r0, r1, r2 = 1a88 (3-op) both Sub.
        assert!(
            ops(&[0x01, 0x3a])
                .iter()
                .any(|o| matches!(o, Op::Bin { op: BinOp::Sub, .. })),
            "subs r2,#1 not a Sub"
        );
        assert!(
            ops(&[0x88, 0x1a])
                .iter()
                .any(|o| matches!(o, Op::Bin { op: BinOp::Sub, .. })),
            "subs r0,r1,r2 not a Sub"
        );
    }

    /// Memory-pair, bit-clear, extend and move-top forms (arm-none-eabi-as,
    /// little-endian). None of these must fall through to `Op::Unknown`.
    #[test]
    fn ldrd_bic_extend_movt_lift() {
        fn no_unknown(ops: &[Op]) -> bool {
            !ops.iter().any(|o| matches!(o, Op::Unknown { .. }))
        }

        // ldrd r0, r1, [r2, #8] = e9d2 0102  ->  two loads at +8 and +12.
        let ldrd = ops(&[0xd2, 0xe9, 0x02, 0x01]);
        let loads: Vec<_> = ldrd
            .iter()
            .filter_map(|o| match o {
                Op::Load { addr, .. } => Some(addr.disp),
                _ => None,
            })
            .collect();
        assert_eq!(loads, vec![8, 12], "ldrd loads: {:?}", ldrd);

        // strd r0, r1, [r2, #16] = e9c2 0104  ->  two stores at +16 and +20.
        let strd = ops(&[0xc2, 0xe9, 0x04, 0x01]);
        let stores: Vec<_> = strd
            .iter()
            .filter_map(|o| match o {
                Op::Store { addr, .. } => Some(addr.disp),
                _ => None,
            })
            .collect();
        assert_eq!(stores, vec![16, 20], "strd stores: {:?}", strd);

        // bic.w r0, r1, r2 = ea21 0002  ->  Not + And (r0 = r1 & ~r2).
        let bic = ops(&[0x21, 0xea, 0x02, 0x00]);
        assert!(
            bic.iter()
                .any(|o| matches!(o, Op::Un { op: UnOp::Not, .. }))
                && bic
                    .iter()
                    .any(|o| matches!(o, Op::Bin { op: BinOp::And, .. })),
            "bic not Not+And: {:?}",
            bic
        );

        // uxtb r0,r1=b2c8, uxth=b288 -> ZExt ; sxtb=b248, sxth=b208 -> SExt.
        assert!(
            matches!(ops(&[0xc8, 0xb2]).as_slice(), [Op::ZExt { from, .. }] if *from == Width::W8)
        );
        assert!(
            matches!(ops(&[0x88, 0xb2]).as_slice(), [Op::ZExt { from, .. }] if *from == Width::W16)
        );
        assert!(
            matches!(ops(&[0x48, 0xb2]).as_slice(), [Op::SExt { from, .. }] if *from == Width::W8)
        );
        assert!(
            matches!(ops(&[0x08, 0xb2]).as_slice(), [Op::SExt { from, .. }] if *from == Width::W16)
        );

        // movt r0, #0x1234 = f2c1 2034  ->  r0 = r0 | (0x1234 << 16).
        assert_eq!(
            ops(&[0xc1, 0xf2, 0x34, 0x20]),
            vec![Op::Bin {
                dst: VReg::phys("r0"),
                op: BinOp::Or,
                lhs: Value::Reg(VReg::phys("r0")),
                rhs: Value::Const(0x1234 << 16),
            }]
        );

        // Whole batch: nothing unknown.
        for b in [
            &[0xd2u8, 0xe9, 0x02, 0x01][..],
            &[0xc2, 0xe9, 0x04, 0x01],
            &[0x21, 0xea, 0x02, 0x00],
            &[0xc8, 0xb2],
            &[0x48, 0xb2],
            &[0xc1, 0xf2, 0x34, 0x20],
        ] {
            assert!(no_unknown(&ops(b)), "unexpected Unknown in {:x?}", b);
        }
    }

    #[test]
    fn ldrb_keeps_its_zero_extension_semantics() {
        // ldrb r1, [r7, #3] = 78f9. The architectural result is a
        // zero-extended 32-bit value, not an ambiguous one-byte load into r1.
        // Keeping the extension explicit is also the signedness evidence type
        // recovery needs for an unsigned-char parameter spilled at -O0.
        let lifted = ops(&[0xf9, 0x78]);
        assert!(
            matches!(
                lifted.as_slice(),
                [
                    Op::Load {
                        dst: VReg::Temp(0),
                        addr
                    },
                    Op::ZExt {
                        dst: VReg::Phys(dst),
                        src: Value::Reg(VReg::Temp(0)),
                        from: Width::W8,
                        to: Width::W32,
                    }
                ] if addr.size == 1 && dst == "r1"
            ),
            "ldrb lost its zero extension: {lifted:?}"
        );
    }

    /// Thumb-2 IT (if-then) blocks: the `it`/`ite` prefix must become a Nop and
    /// each predicated instruction a conditional select, never `Op::Unknown`.
    ///
    /// ```text
    /// cmp  r0, r1     4288
    /// it   lt         bfb8
    /// movlt r0, r2    4610
    /// cmp  r0, r3     4298
    /// ite  ge         bfac
    /// movge r0, r4    4620
    /// movlt r0, r5    4628
    /// bx   lr         4770
    /// ```
    #[test]
    fn it_block_predication_becomes_conditional_selects() {
        let body: &[u8] = &[
            0x88, 0x42, // cmp r0, r1
            0xb8, 0xbf, // it lt
            0x10, 0x46, // movlt r0, r2
            0x98, 0x42, // cmp r0, r3
            0xac, 0xbf, // ite ge
            0x20, 0x46, // movge r0, r4
            0x28, 0x46, // movlt r0, r5
            0x70, 0x47, // bx lr
        ];
        let out = ops(body);
        assert!(
            !out.iter().any(|o| matches!(o, Op::Unknown { .. })),
            "IT block left an Unknown: {:?}",
            out
        );
        // The three predicated `mov`s become conditional selects.
        let ites = out.iter().filter(|o| matches!(o, Op::Ite { .. })).count();
        assert_eq!(ites, 3, "expected 3 Ite selects, got {}: {:?}", ites, out);
        // Each select is gated on the signed-less-than flag from the `cmp`.
        assert!(
            out.iter().all(|o| !matches!(o,
                Op::Ite { cond, .. } if !matches!(cond, VReg::Flag(Flag::Slt)))),
            "an Ite is not gated on Slt: {:?}",
            out
        );
        // The IT prefixes themselves carry no data effect.
        assert!(out.iter().any(|o| matches!(o, Op::Nop)));
    }

    /// A32 carries the predicate in every instruction word instead of using a
    /// Thumb IT prefix.  These are the exact GCC instructions from
    /// `01_conditional_polarity.c:early_return` at `-O2`:
    ///
    /// ```text
    /// cmp   r0, #0
    /// movlt r0, #77
    /// movge r0, #88
    /// bx    lr
    /// ```
    #[test]
    fn a32_instruction_predicates_become_conditional_selects() {
        let out = ops_a32(&[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, #0
            0x4d, 0x00, 0xa0, 0xb3, // movlt r0, #77
            0x58, 0x00, 0xa0, 0xa3, // movge r0, #88
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]);

        assert!(
            !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
            "A32 predicates must not become opaque: {out:#?}"
        );
        let selects: Vec<_> = out
            .iter()
            .filter_map(|op| match op {
                Op::Ite {
                    dst, cond, t, e, ..
                } if *dst == VReg::phys("r0") => Some((cond, t, e)),
                _ => None,
            })
            .collect();
        assert_eq!(selects.len(), 2, "expected two predicated moves: {out:#?}");
        assert!(
            selects
                .iter()
                .all(|(cond, _, _)| **cond == VReg::Flag(Flag::Slt)),
            "both moves must consume the cmp signed-less predicate: {out:#?}"
        );
        assert!(matches!(out.last(), Some(Op::Return)));
    }

    #[test]
    fn a32_conditional_bx_lr_becomes_a_conditional_return() {
        let out = ops_a32(&[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, #0
            0x1e, 0xff, 0x2f, 0x01, // bxeq lr
            0x05, 0x00, 0xa0, 0xe3, // mov r0, #5 (fallthrough)
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]);

        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::CondReturn {
                    cond: VReg::Flag(Flag::Z),
                    inverted: false,
                }
            )),
            "bxeq lr must retain both return and fallthrough paths: {out:#?}"
        );
        assert!(matches!(out.last(), Some(Op::Return)));
    }

    #[test]
    fn unsupported_a32_predicated_control_effects_fail_closed() {
        let out = ops_a32(&[
            0x00, 0x00, 0x00, 0x1b, // blne 0x1008
            0x13, 0xff, 0x2f, 0x11, // bxne r3
        ]);
        assert_eq!(
            out.iter()
                .filter(|op| matches!(op, Op::Unknown { mnemonic } if mnemonic == "predicated control effect"))
                .count(),
            2,
            "conditional calls/computed branches must not become unconditional: {out:#?}"
        );
        assert!(
            !out.iter()
                .any(|op| matches!(op, Op::Call { .. } | Op::IndirectJump { .. })),
            "unsupported predicated control must fail closed: {out:#?}"
        );
    }

    #[test]
    fn a32_predicated_store_does_not_become_an_unconditional_effect() {
        // The exact optimized `cas_update` body: only the equal path stores.
        let out = ops_a32(&[
            0x00, 0x30, 0xa0, 0xe1, // mov r3, r0
            0x00, 0x00, 0x90, 0xe5, // ldr r0, [r0]
            0x01, 0x00, 0x50, 0xe1, // cmp r0, r1
            0x01, 0x00, 0xa0, 0x03, // moveq r0, #1
            0x00, 0x20, 0x83, 0x05, // streq r2, [r3]
            0x00, 0x00, 0xa0, 0x13, // movne r0, #0
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]);

        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::CondStore {
                    cond: VReg::Flag(Flag::Z),
                    inverted: false,
                    ..
                }
            )),
            "streq must retain its memory predicate: {out:#?}"
        );
        assert!(!out.iter().any(|op| matches!(op, Op::Store { .. })));
    }

    #[test]
    fn a32_predicated_load_is_lazy_and_retains_the_destination() {
        let out = ops_a32(&[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, #0
            0x04, 0x10, 0x12, 0x15, // ldrne r1, [r2, #-4]
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]);

        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::CondLoad {
                    dst,
                    cond: VReg::Flag(Flag::Z),
                    inverted: true,
                    addr,
                    fallback: Value::Reg(fallback),
                } if *dst == VReg::phys("r1")
                    && addr.base.as_ref() == Some(&VReg::phys("r2"))
                    && addr.disp == -4
                    && *fallback == VReg::phys("r1")
            )),
            "ldrne must keep both its memory guard and old r1 fallback: {out:#?}"
        );
        assert!(
            !out.iter().any(|op| matches!(op, Op::Load { .. })),
            "predicated ldr must not dereference eagerly: {out:#?}"
        );
    }

    #[test]
    fn a32_predicated_multi_register_pop_retains_fallthrough() {
        let out = ops_a32(&[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, #0
            0x70, 0x80, 0xbd, 0x18, // popne {r4, r5, r6, pc}
            0x05, 0x00, 0xa0, 0xe3, // mov r0, #5 (fallthrough)
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]);

        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::CondReturn {
                    cond: VReg::Flag(Flag::Z),
                    inverted: true,
                }
            )),
            "conditional pop-to-pc must not become an unconditional return: {out:#?}"
        );
        assert_eq!(
            out.iter().filter(|op| matches!(op, Op::Return)).count(),
            1,
            "only the final bx lr is unconditional: {out:#?}"
        );
        assert!(
            out.iter().any(|op| matches!(op, Op::CondLoad { .. })),
            "conditional pop restores must remain lazy: {out:#?}"
        );
        assert!(
            !out.iter().any(|op| matches!(op, Op::Load { .. })),
            "conditional pop must not read the stack on its false path: {out:#?}"
        );
    }

    /// A predicated flag-writing instruction must not execute unconditionally.
    #[test]
    fn a_predicated_compare_does_not_clobber_the_flags_it_is_predicated_on() {
        let body: &[u8] = &[
            0x00, 0x28, // cmp r0, #0
            0xc8, 0xbf, // it gt
            0x00, 0x29, // cmpgt r1, #0
            0x70, 0x47, // bx lr
        ];
        let out = ops(body);

        let committed: Vec<&VReg> = out
            .iter()
            .filter_map(|op| match op {
                Op::Ite { dst, .. } if matches!(dst, VReg::Flag(_)) => Some(dst),
                _ => None,
            })
            .collect();
        assert!(
            !committed.is_empty(),
            "the predicated cmp wrote its flags unconditionally: {out:#?}"
        );

        let mut last_write: Vec<(VReg, &Op)> = Vec::new();
        for op in &out {
            if let Some(dst @ VReg::Flag(_)) = crate::ir::use_def::def_uses(op).0 {
                match last_write.iter_mut().find(|(register, _)| *register == dst) {
                    Some((_, slot)) => *slot = op,
                    None => last_write.push((dst, op)),
                }
            }
        }
        assert!(
            !last_write.is_empty(),
            "the compares wrote no flags: {out:#?}"
        );
        for (flag, op) in &last_write {
            assert!(
                matches!(op, Op::Ite { .. }),
                "flag {flag:?} ends with an unconditional write ({op:?}): {out:#?}"
            );
        }
    }

    /// Predicate commits must use the flag value from before the instruction.
    #[test]
    fn a_predicate_written_by_its_own_instruction_is_snapshotted_first() {
        let body: &[u8] = &[
            0x00, 0x28, // cmp r0, #0
            0x18, 0xbf, // it ne
            0x00, 0x29, // cmpne r1, #0
            0x70, 0x47, // bx lr
        ];
        let out = ops(body);

        let gated_on_live_z = out.iter().any(|op| {
            matches!(op, Op::Ite { cond, dst, .. }
                if matches!(cond, VReg::Flag(Flag::Z)) && matches!(dst, VReg::Flag(_)))
        });
        assert!(
            !gated_on_live_z,
            "a flag select is gated on the live Z it also rewrites: {out:#?}"
        );
        assert!(
            out.iter().any(|op| matches!(op,
                Op::Assign { dst, src }
                    if matches!(dst, VReg::Temp(_))
                        && matches!(src, Value::Reg(VReg::Flag(Flag::Z))))),
            "no snapshot of the Z predicate was taken: {out:#?}"
        );
    }

    /// Thumb's narrow add/sub encodings set flags only when they execute outside
    /// an IT block.  Capstone still spells the encoded operations `subs`/`adds`,
    /// so the lifter has to apply the IT-state semantic override itself.  This
    /// is the real `dec_preserves_carry` O2 sequence: the initial `cmp` supplies
    /// carry to all three predicated slots and neither arithmetic slot may
    /// replace it.
    #[test]
    fn narrow_arithmetic_inside_it_preserves_the_incoming_flags() {
        let body: &[u8] = &[
            0x88, 0x42, // cmp r0, r1
            0x26, 0xbf, // itte cs
            0x40, 0x1a, // subcs r0, r0, r1 (encoded narrow SUBS)
            0x02, 0x30, // addcs r0, #2     (encoded narrow ADDS)
            0x02, 0x20, // movcc r0, #2
            0x70, 0x47, // bx lr
        ];
        let out = ops(body);
        let carry_writes = out
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        ..
                    } | Op::Assign {
                        dst: VReg::Flag(Flag::C),
                        ..
                    } | Op::Bin {
                        dst: VReg::Flag(Flag::C),
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            carry_writes, 1,
            "the predicated narrow arithmetic overwrote cmp carry: {out:#?}"
        );
        assert_eq!(
            out.iter().filter(|op| matches!(op, Op::Ite { .. })).count(),
            3,
            "all three IT slots must remain conditional selects: {out:#?}"
        );
    }

    /// `subs` must write the flags of `cmp`, not just the subtraction.
    ///
    /// `bin_for_mnem` maps `sub` and `subs` to the same `BinOp`, so before this
    /// the `S` suffix was recognised and then discarded — the flag write
    /// vanished without ever appearing as an unlifted instruction, and later
    /// readers bound to stale definitions.
    #[test]
    fn s_suffixed_arithmetic_writes_condition_flags() {
        // subs r0, r1, r2  (ARM, A1 encoding) = 0xe0510002
        let out = lift_bytes(&0xe0510002u32.to_le_bytes(), 0x1000, false);
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, Op::Bin { op: BinOp::Sub, .. })),
            "subs lost its subtraction"
        );
        assert!(
            out.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    ..
                }
            )),
            "subs did not write ZF: {:?}",
            out.iter().map(|i| &i.op).collect::<Vec<_>>()
        );
    }

    /// `Rm, lsl #n` must reach the operation.
    ///
    /// Capstone's operand list carries the register and drops the modifier, so
    /// `add.w r0,r0,r1,lsl #1` and `add r0,r0,r1` arrived here indistinguishable.
    /// That is a silent wrong answer, not a rendering nicety: `sum_arg2(1,1)`
    /// returned 4 where the source returns 5.
    #[test]
    fn thumb_shifted_register_operand_reaches_the_operation() {
        // The real `sum_arg2` body from the armv7 fixture build:
        //     add.w r0, r0, r1, lsl #1     eb00 0041
        let out = ops(&[0x00, 0xeb, 0x41, 0x00]);
        assert!(
            !out.iter().any(|o| matches!(o, Op::Unknown { .. })),
            "shifted add became Unknown: {out:#?}"
        );
        let shifted = out
            .iter()
            .find_map(|o| match o {
                Op::Bin {
                    dst,
                    op: BinOp::Shl,
                    lhs,
                    rhs: Value::Const(1),
                } if lhs == &Value::Reg(VReg::phys("r1")) => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("lsl #1 was dropped: {out:#?}"));
        assert!(
            out.iter().any(|o| matches!(o,
                Op::Bin { dst, op: BinOp::Add, lhs, rhs: Value::Reg(r) }
                    if dst == &VReg::phys("r0")
                        && lhs == &Value::Reg(VReg::phys("r0"))
                        && r == &shifted)),
            "the add did not consume the shifted operand: {out:#?}"
        );
    }

    /// Every shift type the encoding can express, at both instruction widths.
    /// `asr #31` is the sign-broadcast half of a divide-by-power-of-two, so
    /// dropping it does not merely lose a factor — it loses the rounding.
    #[test]
    fn thumb_and_arm_shifted_operands_use_the_encoded_shift_kind() {
        for (bytes, thumb, want_op, want_amount) in [
            // sub.w r0, r1, r2, lsr #3      eba1 00d2
            (&[0xa1u8, 0xeb, 0xd2, 0x00][..], true, BinOp::Shr, 3i64),
            // add.w r0, r1, r2, asr #31     eb01 70e2
            (&[0x01, 0xeb, 0xe2, 0x70][..], true, BinOp::Sar, 31),
            // rsb   r0, r1, r2, lsl #3      ebc1 00c2
            (&[0xc1, 0xeb, 0xc2, 0x00][..], true, BinOp::Shl, 3),
            // A32: add r0, r1, r2, lsl #3   e0810182
            (&[0x82, 0x01, 0x81, 0xe0][..], false, BinOp::Shl, 3),
            // A32: add r0, r1, r2, asr #31  e0810fc2
            (&[0xc2, 0x0f, 0x81, 0xe0][..], false, BinOp::Sar, 31),
        ] {
            let out: Vec<Op> = lift_bytes(bytes, 0x1000, thumb)
                .into_iter()
                .map(|i| i.op)
                .collect();
            assert!(
                out.iter().any(|o| matches!(o,
                    Op::Bin { op, lhs, rhs: Value::Const(n), .. }
                        if *op == want_op
                            && lhs == &Value::Reg(VReg::phys("r2"))
                            && *n == want_amount)),
                "{bytes:x?} lost its {want_op:?} #{want_amount}: {out:#?}"
            );
        }
    }

    /// A shift written as its own instruction must NOT be shifted twice.
    ///
    /// `lsl.w r0,r1,#2` is encoded as `mov` with a shift, so it lives in the very
    /// same instruction family the modifier is decoded from; applying the
    /// modifier there would square the scale.
    #[test]
    fn a_standalone_shift_instruction_is_not_shifted_again() {
        // lsl.w r0, r1, #2   ea4f 0081
        let out = ops(&[0x4f, 0xea, 0x81, 0x00]);
        assert_eq!(
            out,
            vec![Op::Bin {
                dst: VReg::phys("r0"),
                op: BinOp::Shl,
                lhs: Value::Reg(VReg::phys("r1")),
                rhs: Value::Const(2),
            }],
            "standalone lsl was re-shifted: {out:#?}"
        );
    }

    /// A32 represents the standalone immediate-shift alias in the instruction
    /// word even when Capstone exposes only `Rd, Rm` through the shared operand
    /// model. The encoded distance must remain the right-hand operand; treating
    /// the two visible registers as an accumulate form turns `i << 2` into
    /// `i << i`.
    #[test]
    fn a32_standalone_immediate_shift_uses_the_encoded_distance() {
        // lsl r3, r3, #2   e1a03103
        let out = ops_a32(&[0x03, 0x31, 0xa0, 0xe1]);
        assert_eq!(
            out,
            vec![Op::Bin {
                dst: VReg::phys("r3"),
                op: BinOp::Shl,
                lhs: Value::Reg(VReg::phys("r3")),
                rhs: Value::Const(2),
            }],
            "A32 standalone lsl lost its encoded immediate: {out:#?}"
        );
    }

    /// The high half of a signed long multiply owns signed 32x32 semantics.
    /// Keeping it as an untyped temporary product lets a high-bit constant enter
    /// C's unsigned arithmetic conversions before a later cast can recover it.
    #[test]
    fn arm32_signed_long_multiply_has_a_typed_high_half() {
        for out in [
            // smull r1, r2, r2, r3   e0c21392
            ops_a32(&[0x92, 0x13, 0xc2, 0xe0]),
            // smull r1, r2, r2, r3   fb82 1203
            ops(&[0x82, 0xfb, 0x03, 0x12]),
        ] {
            assert!(
                out.iter().any(|op| matches!(
                    op,
                    Op::Intrinsic {
                        name,
                        ins,
                        outs,
                        reads_mem: false,
                        writes_mem: false,
                    } if name == "arm.smul_hi.32"
                        && ins == &[
                            Value::Reg(VReg::phys("r2")),
                            Value::Reg(VReg::phys("r3")),
                        ]
                        && outs == &[(VReg::phys("r2"), Width::W32)]
                )),
                "signed multiply-high lost its width or signedness: {out:#?}"
            );
        }
    }

    /// A register-offset load/store scales its index by the encoded `lsl`.
    ///
    /// `[r1, r2, lsl #2]` arrived with `scale: 0`, which every consumer reads as
    /// 1 — so every scaled array index was off by its element size.
    #[test]
    fn register_offset_memory_operands_carry_their_index_scale() {
        for (bytes, thumb, want_scale) in [
            // ldr.w  r3, [r1, r2, lsl #2]   f851 3022
            (&[0x51u8, 0xf8, 0x22, 0x30][..], true, 4u8),
            // ldrb.w r0, [r1, r2, lsl #1]   f811 0012
            (&[0x11, 0xf8, 0x12, 0x00][..], true, 2),
            // A32: ldr r3, [r1, r2, lsl #2] e7913102
            (&[0x02, 0x31, 0x91, 0xe7][..], false, 4),
            // A32: ldr r3, [r4, r2, lsl #4] e7943202
            (&[0x02, 0x32, 0x94, 0xe7][..], false, 16),
        ] {
            let out: Vec<Op> = lift_bytes(bytes, 0x1000, thumb)
                .into_iter()
                .map(|i| i.op)
                .collect();
            let scale = out
                .iter()
                .find_map(|o| match o {
                    Op::Load { addr, .. } | Op::Store { addr, .. } => Some(addr.scale),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{bytes:x?} produced no memory op: {out:#?}"));
            assert_eq!(scale, want_scale, "{bytes:x?} index scale: {out:#?}");
        }

        // str.w r0, [r1, r2, lsl #2]   f841 0022
        let stored = ops(&[0x41, 0xf8, 0x22, 0x00]);
        assert!(
            matches!(stored.as_slice(), [Op::Store { addr, .. }] if addr.scale == 4
                && addr.index == Some(VReg::phys("r2"))),
            "store index scale: {stored:#?}"
        );
    }

    /// An unscaled register-offset access must stay unscaled — the fix must not
    /// invent a factor where the encoding has none.
    #[test]
    fn an_unshifted_register_offset_keeps_scale_one() {
        // ldr r3, [r1, r2]   (16-bit Thumb) = 5889
        let out = ops(&[0x89, 0x58]);
        assert!(
            matches!(out.as_slice(), [Op::Load { addr, .. }]
                if addr.index == Some(VReg::phys("r2")) && addr.scale <= 1),
            "unshifted index was scaled: {out:#?}"
        );
    }

    #[test]
    fn a32_load_multiple_honors_increment_before_addressing() {
        // ldmib r2, {r1, r2}   e9920006
        //
        // Increment-before starts at r2+4, not r2. This exact instruction
        // loads RbNode.left/right together in rb_validate.
        let out = ops_a32(&[0x06, 0x00, 0x92, 0xe9]);
        assert_eq!(
            out,
            vec![
                Op::Load {
                    dst: VReg::phys("r1"),
                    addr: MemOp::plain(Some(VReg::phys("r2")), None, 0, 4, 4),
                },
                Op::Load {
                    dst: VReg::phys("r2"),
                    addr: MemOp::plain(Some(VReg::phys("r2")), None, 0, 8, 4),
                },
            ],
            "ldmib must not be approximated as increment-after"
        );
    }

    /// A read of `pc` is a CONSTANT, not a live register.
    ///
    /// ARM32 has no `adrp`: every address, every large constant and every GOT
    /// offset is materialised as `ldr Rd,[pc,#imm]` from a literal pool, usually
    /// followed by `add Rd,pc`. Modelling `pc` as an ordinary register left
    /// those reading an undefined value, and the recovered C dereferenced it.
    #[test]
    fn a_read_of_pc_is_the_architectural_constant() {
        // add r2, pc = 447a. In Thumb state a read of PC is `addr + 4`.
        assert_eq!(
            lift_bytes(&[0x7a, 0x44], 0x44c, true)
                .into_iter()
                .map(|i| i.op)
                .collect::<Vec<_>>(),
            vec![Op::Bin {
                dst: VReg::phys("r2"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r2")),
                rhs: Value::Addr(0x450),
            }],
        );
        // A32: add r2, r2, pc = e082200f. In ARM state a read of PC is `addr+8`.
        assert_eq!(
            lift_bytes(&0xe082200fu32.to_le_bytes(), 0x1000, false)
                .into_iter()
                .map(|i| i.op)
                .collect::<Vec<_>>(),
            vec![Op::Bin {
                dst: VReg::phys("r2"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r2")),
                rhs: Value::Addr(0x1008),
            }],
        );
    }

    /// A PC-relative load reads the literal pool, which is part of the function
    /// body being lifted — so its word is known here and becomes a constant.
    #[test]
    fn pc_relative_loads_resolve_against_the_literal_pool() {
        // ldr r0, [pc, #4] = 4801, at 0x1000: Align(0x1004,4) + 4 = 0x1008.
        let window = [
            0x01, 0x48, // ldr r0, [pc, #4]
            0x00, 0xbf, // nop
            0x00, 0xbf, // nop
            0x00, 0xbf, // nop
            0xef, 0xbe, 0xad, 0xde, // the literal at 0x1008
        ];
        let out = lift_bytes(&window, 0x1000, true);
        assert_eq!(
            out.first().map(|i| i.op.clone()),
            Some(Op::Assign {
                dst: VReg::phys("r0"),
                src: Value::Const(0xdead_beef),
            }),
            "PC-relative load did not resolve: {out:#?}"
        );

        // A32: ldr r0, [pc, #4] = e59f0004, at 0x1000: 0x1008 + 4 = 0x100c.
        let mut a32 = Vec::new();
        a32.extend_from_slice(&0xe59f0004u32.to_le_bytes());
        a32.extend_from_slice(&[0x00; 8]);
        a32.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        let out = lift_bytes(&a32, 0x1000, false);
        assert_eq!(
            out.first().map(|i| i.op.clone()),
            Some(Op::Assign {
                dst: VReg::phys("r0"),
                src: Value::Const(0x1234_5678),
            }),
            "A32 PC-relative load did not resolve: {out:#?}"
        );
    }

    /// A literal outside the lifted window must become an ABSOLUTE load, never
    /// a load through an undefined `pc` register — the address is still exactly
    /// known, and a later pass can resolve it against the image.
    #[test]
    fn an_out_of_window_literal_load_keeps_its_absolute_address() {
        // ldr r3, [pc, #0x118] = 4b46 at 0x44e -> Align(0x452,4) + 0x118 = 0x568.
        let out = lift_bytes(&[0x46, 0x4b], 0x44e, true);
        assert!(
            matches!(out.as_slice(), [LlirInstr { op: Op::Load { dst, addr }, .. }]
                if dst == &VReg::phys("r3")
                    && addr.base.is_none()
                    && addr.index.is_none()
                    && addr.disp == 0x568),
            "out-of-window literal load: {out:#?}"
        );
    }

    /// The exact `-fstack-protector` preamble GCC emits for armhf `-fPIC`, from
    /// the real `20_graph_bfs` fixture build. It must reduce to a load of the
    /// guard's known GOT slot (`0x20020`), not to arithmetic on a live `pc`.
    ///
    /// Left unresolved, `canary::recognise_canary` cannot see the guard, the
    /// renderer substitutes a portable zero-filled object for the original-image
    /// address, and every `-fstack-protector` function took SIGSEGV when the
    /// recovered C was recompiled and run.
    #[test]
    fn the_armhf_pic_stack_guard_preamble_resolves_to_its_got_slot() {
        // 0x44a: ldr r2, [pc, #0x118]   4a46   -> literal at 0x564 = 0x0001fbb0
        // 0x44c: add r2, pc             447a   -> 0x1fbb0 + 0x450 = 0x20000
        // 0x44e: ldr r3, [pc, #0x118]   4b46   -> literal at 0x568 = 0x20
        // 0x450: ldr r3, [r2, r3]       58d3
        // 0x452: ldr r3, [r3]           681b
        let mut window = vec![0x46, 0x4a, 0x7a, 0x44, 0x46, 0x4b, 0xd3, 0x58, 0x1b, 0x68];
        window.resize(0x564 - 0x44a, 0x00); // pad out to the pool
        window.extend_from_slice(&0x0001_fbb0u32.to_le_bytes()); // 0x564
        window.extend_from_slice(&0x0000_0020u32.to_le_bytes()); // 0x568
        let out: Vec<Op> = lift_bytes(&window, 0x44a, true)
            .into_iter()
            .take(4)
            .map(|i| i.op)
            .collect();
        assert_eq!(
            out[0],
            Op::Assign {
                dst: VReg::phys("r2"),
                src: Value::Const(0x0001_fbb0),
            },
            "GOT-base literal: {out:#?}"
        );
        assert_eq!(
            out[1],
            Op::Bin {
                dst: VReg::phys("r2"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r2")),
                rhs: Value::Addr(0x450),
            },
            "PC add: {out:#?}"
        );
        assert_eq!(
            out[2],
            Op::Assign {
                dst: VReg::phys("r3"),
                src: Value::Const(0x20),
            },
            "GOT-offset literal: {out:#?}"
        );
    }

    /// `subs Rd, #imm` sets the flags from `Rd_OLD - imm`, so the old operands
    /// must be captured before the subtraction overwrites `Rd`.
    ///
    /// Emitting the `Op::Bin` first and then reading `Value::Reg(dst)` made the
    /// zero flag mean `Rd_new == imm`, i.e. `Rd_old == 2*imm`. The real
    /// `dec_loop` countdown `subs r3,#1; bne` therefore decompiled to
    /// `while (i != 1)` and never terminated — which is the whole reason
    /// `14_flag_effects` exists.
    #[test]
    fn s_suffixed_flags_capture_operands_before_the_result_overwrite() {
        // subs r3, #1 = 3b01, the exact latch of the real `dec_loop` fixture.
        let out = ops(&[0x01, 0x3b]);
        let subtract = out
            .iter()
            .position(|o| matches!(o, Op::Bin { op: BinOp::Sub, .. }))
            .unwrap_or_else(|| panic!("no subtraction: {out:#?}"));
        let zero = out
            .iter()
            .position(|o| {
                matches!(
                    o,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        ..
                    }
                )
            })
            .unwrap_or_else(|| panic!("no zero flag: {out:#?}"));
        let saved_lhs = out
            .iter()
            .position(|op| {
                matches!(
                    op,
                    Op::Assign {
                        dst: VReg::Temp(21),
                        src: Value::Reg(VReg::Phys(source)),
                    } if source == "r3"
                )
            })
            .unwrap_or_else(|| panic!("old lhs was not captured: {out:#?}"));
        assert!(
            saved_lhs < subtract,
            "lhs capture must precede overwrite: {out:#?}"
        );
        assert!(
            subtract < zero,
            "result-derived zero flag must follow subtraction: {out:#?}"
        );

        // The three-operand form with `Rd == Rn` has the same hazard:
        // subs r0, r0, r1 (A1) = 0xe0500001.
        let out: Vec<Op> = lift_bytes(&0xe0500001u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        let subtract = out
            .iter()
            .position(|o| matches!(o, Op::Bin { op: BinOp::Sub, .. }))
            .unwrap();
        let saved_lhs = out
            .iter()
            .position(|o| {
                matches!(
                    o,
                    Op::Assign {
                        dst: VReg::Temp(21),
                        src: Value::Reg(VReg::Phys(source)),
                    } if source == "r0"
                )
            })
            .unwrap();
        assert!(saved_lhs < subtract, "three-operand form: {out:#?}");
    }

    /// A result-derived flag is the mirror case: `adds` reports whether its
    /// RESULT is zero, so those writes must come after the operation.
    #[test]
    fn result_derived_flags_follow_the_operation_they_describe() {
        // adds r0, r1, r2 (A1) = 0xe0910002
        let out: Vec<Op> = lift_bytes(&0xe0910002u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        let add = out
            .iter()
            .position(|o| matches!(o, Op::Bin { op: BinOp::Add, .. }))
            .unwrap_or_else(|| panic!("no addition: {out:#?}"));
        let zero = out
            .iter()
            .position(|o| {
                matches!(
                    o,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        ..
                    }
                )
            })
            .unwrap_or_else(|| panic!("no zero flag: {out:#?}"));
        assert!(add < zero, "adds flags must follow the add: {out:#?}");
    }

    #[test]
    fn carry_arithmetic_uses_the_existing_borrow_polarity() {
        // A32 encodings, chosen so Capstone exposes the unqualified mnemonics:
        // adds/adcs/subs/sbcs r0, r1, r2.
        let cases = [
            (0xe0910002u32, "adds"),
            (0xe0b10002u32, "adcs"),
            (0xe0510002u32, "subs"),
            (0xe0d10002u32, "sbcs"),
        ];
        for (word, name) in cases {
            let out: Vec<Op> = lift_bytes(&word.to_le_bytes(), 0x1000, false)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            assert!(
                !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
                "{name} did not lift: {out:#?}"
            );
            assert!(
                out.iter().any(|op| matches!(
                    op,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        ..
                    } | Op::Bin {
                        dst: VReg::Flag(Flag::C),
                        ..
                    } | Op::Assign {
                        dst: VReg::Flag(Flag::C),
                        ..
                    }
                )),
                "{name} did not define the carry/borrow convention: {out:#?}"
            );
        }

        let adcs: Vec<Op> = lift_bytes(&0xe0b10002u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            adcs.iter().any(|op| matches!(
                op,
                Op::Cmp {
                    op: CmpOp::Eq,
                    lhs: Value::Reg(VReg::Flag(Flag::C)),
                    rhs: Value::Const(0),
                    ..
                }
            )),
            "ADCS must invert stored borrow/no-carry into architectural carry-in: {adcs:#?}"
        );

        let sbcs: Vec<Op> = lift_bytes(&0xe0d10002u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            sbcs.iter().any(|op| matches!(
                op,
                Op::Bin {
                    op: BinOp::Sub,
                    rhs: Value::Reg(VReg::Flag(Flag::C)),
                    ..
                }
            )),
            "SBCS must subtract the stored incoming borrow directly: {sbcs:#?}"
        );

        assert_eq!(cond_flag_for("ls"), Some((VReg::Flag(Flag::Ule), false)));
        assert_eq!(cond_flag_for("hi"), Some((VReg::Flag(Flag::Ule), true)));
        assert_eq!(cond_flag_for("lo"), Some((VReg::Flag(Flag::C), false)));
        assert_eq!(cond_flag_for("hs"), Some((VReg::Flag(Flag::C), true)));
    }

    /// `[Rn, #imm]!` advances `Rn`; `[Rn, #imm]` does not.
    ///
    /// Capstone reports both as the same two operands, so the writeback was
    /// silently lost and the induction variable of every pointer-walking `-O2`
    /// loop stood still. `for_sum`'s real latch is `ldr r1,[r3,#4]!` followed by
    /// `cmp r3,r0; bne` — without the update that is an infinite loop.
    #[test]
    fn preindexed_writeback_advances_the_base_register() {
        // ldr r1, [r3, #4]!   f853 1f04   (the real `for_sum` latch)
        let out = ops(&[0x53, 0xf8, 0x04, 0x1f]);
        assert!(
            matches!(out.as_slice(), [
                Op::Load { dst, addr },
                Op::Bin { dst: base, op: BinOp::Add, lhs, rhs: Value::Const(4) },
            ] if dst == &VReg::phys("r1")
                && addr.base == Some(VReg::phys("r3"))
                && addr.disp == 4
                && base == &VReg::phys("r3")
                && lhs == &Value::Reg(VReg::phys("r3"))),
            "pre-indexed load: {out:#?}"
        );

        // str r1, [r3, #8]!   f843 1f08
        let out = ops(&[0x43, 0xf8, 0x08, 0x1f]);
        assert!(
            matches!(out.as_slice(), [
                Op::Store { addr, .. },
                Op::Bin { dst: base, op: BinOp::Add, rhs: Value::Const(8), .. },
            ] if addr.disp == 8 && base == &VReg::phys("r3")),
            "pre-indexed store: {out:#?}"
        );

        // A32: ldr r1, [r3, #4]!  = 0xe5b31004
        let out: Vec<Op> = lift_bytes(&0xe5b31004u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(out.len(), 2, "A32 pre-indexed load: {out:#?}");
        assert!(
            matches!(&out[1], Op::Bin { dst, op: BinOp::Add, rhs: Value::Const(4), .. }
                if dst == &VReg::phys("r3")),
            "A32 pre-indexed load: {out:#?}"
        );
    }

    /// The plain offset form must NOT be given a writeback the encoding does not
    /// have — inventing one corrupts the base on every iteration.
    #[test]
    fn a_plain_offset_access_leaves_its_base_alone() {
        for (bytes, thumb) in [
            // ldr r1, [r3, #4]  (16-bit Thumb) = 6859
            (&[0x59u8, 0x68][..], true),
            // A32: ldr r1, [r3, #4] = 0xe5931004
            (&0xe5931004u32.to_le_bytes()[..], false),
        ] {
            let out: Vec<Op> = lift_bytes(bytes, 0x1000, thumb)
                .into_iter()
                .map(|i| i.op)
                .collect();
            assert!(
                matches!(out.as_slice(), [Op::Load { .. }]),
                "{bytes:x?} gained a writeback: {out:#?}"
            );
        }
    }

    /// Mnemonics whose meaning is exact arithmetic must be lowered, not left as
    /// `Op::Unknown` — an unknown is a BARRIER that stops values and flags
    /// propagating across it, so one unmodelled instruction silences the whole
    /// expression it sits in.
    #[test]
    fn exactly_lowerable_mnemonics_do_not_become_unknown() {
        for (bytes, what) in [
            (&[0xc1u8, 0xf3, 0x07, 0x10][..], "ubfx r0,r1,#4,#8"),
            (&[0x41, 0xf3, 0x07, 0x10][..], "sbfx r0,r1,#4,#8"),
            (&[0x61, 0xea, 0x02, 0x00][..], "orn r0,r1,r2"),
            (&[0x4f, 0xea, 0x71, 0x10][..], "ror.w r0,r1,#5"),
            (&[0x51, 0xfa, 0x82, 0xf0][..], "uxtab r0,r1,r2"),
            (&[0x11, 0xfa, 0x82, 0xf0][..], "uxtah r0,r1,r2"),
            (&[0x41, 0xfa, 0x82, 0xf0][..], "sxtab r0,r1,r2"),
            (&[0x08, 0xba][..], "rev r0,r1"),
            (&[0x48, 0xba][..], "rev16 r0,r1"),
        ] {
            let out = ops(bytes);
            assert!(
                !out.is_empty() && !out.iter().any(|o| matches!(o, Op::Unknown { .. })),
                "{what} did not lower: {out:#?}"
            );
        }
    }

    /// `ubfx r0, r1, #4, #8` extracts bits 4..11 zero-extended; `sbfx` the same
    /// field sign-extended.
    #[test]
    fn bitfield_extract_lowers_to_its_exact_shift_and_mask() {
        assert_eq!(
            ops(&[0xc1, 0xf3, 0x07, 0x10]),
            vec![
                Op::Bin {
                    dst: VReg::Temp(0),
                    op: BinOp::Shr,
                    lhs: Value::Reg(VReg::phys("r1")),
                    rhs: Value::Const(4),
                },
                Op::Bin {
                    dst: VReg::phys("r0"),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::Temp(0)),
                    rhs: Value::Const(0xff),
                },
            ]
        );
        // sbfx: shift the field's top bit to bit 31, then bring it back with an
        // ARITHMETIC shift so the sign is broadcast.
        assert_eq!(
            ops(&[0x41, 0xf3, 0x07, 0x10]),
            vec![
                Op::Bin {
                    dst: VReg::Temp(0),
                    op: BinOp::Shl,
                    lhs: Value::Reg(VReg::phys("r1")),
                    rhs: Value::Const(20),
                },
                Op::Bin {
                    dst: VReg::phys("r0"),
                    op: BinOp::Sar,
                    lhs: Value::Reg(VReg::Temp(0)),
                    rhs: Value::Const(24),
                },
            ]
        );
    }

    /// `uxtab Rd, Rn, Rm` is `Rn + (Rm & 0xff)`, with the narrowing explicit so
    /// type recovery can see the byte.
    #[test]
    fn extend_and_add_narrows_before_it_adds() {
        assert_eq!(
            ops(&[0x51, 0xfa, 0x82, 0xf0]),
            vec![
                Op::ZExt {
                    dst: VReg::Temp(0),
                    src: Value::Reg(VReg::phys("r2")),
                    from: Width::W8,
                    to: Width::W32,
                },
                Op::Bin {
                    dst: VReg::phys("r0"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("r1")),
                    rhs: Value::Reg(VReg::Temp(0)),
                },
            ]
        );
    }

    /// `bic`/`bics` are AND-**NOT**, and the `S` form reports whether that
    /// result is zero. The flag write was previously dropped: this arm returned
    /// before `flags_for_arith` was ever consulted, so the `S` suffix was
    /// recognised and then discarded exactly as `subs` once was.
    #[test]
    fn bics_is_and_not_and_writes_its_result_flags() {
        // bic.w r0, r1, r2 = ea21 0002 — no flags.
        let plain = ops(&[0x21, 0xea, 0x02, 0x00]);
        assert!(
            !plain.iter().any(|o| matches!(o, Op::Cmp { .. })),
            "bic fabricated flags: {plain:#?}"
        );
        // bics.w r0, r1, r2 = ea31 0002 — AND-NOT plus zero/sign of the result.
        let flagged = ops(&[0x31, 0xea, 0x02, 0x00]);
        assert!(
            flagged
                .iter()
                .any(|o| matches!(o, Op::Un { op: UnOp::Not, .. }))
                && flagged
                    .iter()
                    .any(|o| matches!(o, Op::Bin { op: BinOp::And, .. })),
            "bics is not AND-NOT: {flagged:#?}"
        );
        let zero = flagged
            .iter()
            .position(|o| {
                matches!(
                    o,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        ..
                    }
                )
            })
            .unwrap_or_else(|| panic!("bics wrote no zero flag: {flagged:#?}"));
        let and = flagged
            .iter()
            .position(|o| matches!(o, Op::Bin { op: BinOp::And, .. }))
            .unwrap();
        assert!(and < zero, "the flag must follow the result: {flagged:#?}");
        assert_eq!(
            flagged[zero],
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::phys("r0")),
                rhs: Value::Const(0),
            }
        );
    }

    /// The non-`S` form must NOT invent flags — claiming a flag the CPU did not
    /// write is worse than claiming none, because a branch will render it.
    #[test]
    fn plain_arithmetic_writes_no_flags() {
        // sub r0, r1, r2 = 0xe0410002
        let out = lift_bytes(&0xe0410002u32.to_le_bytes(), 0x1000, false);
        assert!(
            !out.iter().any(|i| matches!(&i.op, Op::Cmp { .. })),
            "plain sub fabricated condition flags"
        );
    }

    // -----------------------------------------------------------------------
    // A32 modified immediates: capstone's split `#<imm8>, #<rotation>` pair
    // -----------------------------------------------------------------------

    /// The armhf PLT stub preamble is two `add`s with a non-canonical rotated
    /// immediate, and it was 108 + 20 of the 146 opaque intrinsics in the ARM32
    /// sample corpus — every one of the 16 opaque `add`s the effect census
    /// counts. `add ip, pc, #0, #12` is a pure register computation with a
    /// completely known footprint; as an opaque intrinsic it declared that it
    /// read and wrote all memory.
    #[test]
    fn the_plt_stub_rotated_immediate_adds_lift_to_their_constants() {
        // 0x414: add ip, pc, #0, #12   e28fc600  -> ip = (0x414+8) + ROR(0,12)
        // 0x418: add ip, ip, #16, #20  e28cca10  -> ip = ip + ROR(16,20) = +0x10000
        let mut window = Vec::new();
        window.extend_from_slice(&0xe28fc600u32.to_le_bytes());
        window.extend_from_slice(&0xe28cca10u32.to_le_bytes());
        let out: Vec<Op> = lift_bytes(&window, 0x414, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
            "PLT preamble did not lift: {out:#?}"
        );
        assert_eq!(
            out[0],
            Op::Bin {
                dst: VReg::phys("ip"),
                op: BinOp::Add,
                lhs: Value::Addr(0x41c),
                rhs: Value::Const(0),
            },
            "add ip, pc, #0, #12: {out:#?}"
        );
        assert_eq!(
            out[1],
            Op::Bin {
                dst: VReg::phys("ip"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("ip")),
                rhs: Value::Const(0x1_0000),
            },
            "add ip, ip, #16, #20: {out:#?}"
        );
    }

    /// The split pair is a property of the *encoding*, not of `add`: capstone
    /// declines to fold it for every A32 data-processing mnemonic. Folding it
    /// once, before the arity checks, is what keeps the whole family out of
    /// `Op::Unknown` rather than only the one mnemonic the census happened to
    /// catch.
    #[test]
    fn every_data_processing_mnemonic_folds_its_rotated_immediate() {
        // Rd = Rn = ip, imm8 = 16, rotation = 20  ->  ROR(16, 20) = 0x10000.
        let cases: [(u32, &str, Option<BinOp>); 5] = [
            (0xe28cca10, "add", Some(BinOp::Add)),
            (0xe24cca10, "sub", Some(BinOp::Sub)),
            (0xe20cca10, "and", Some(BinOp::And)),
            (0xe22cca10, "eor", Some(BinOp::Xor)),
            (0xe38cca10, "orr", Some(BinOp::Or)),
        ];
        for (word, name, binop) in cases {
            let out: Vec<Op> = lift_bytes(&word.to_le_bytes(), 0x1000, false)
                .into_iter()
                .map(|i| i.op)
                .collect();
            assert!(
                !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
                "{name} left an unlifted instruction: {out:#?}"
            );
            assert_eq!(
                out[0],
                Op::Bin {
                    dst: VReg::phys("ip"),
                    op: binop.unwrap(),
                    lhs: Value::Reg(VReg::phys("ip")),
                    rhs: Value::Const(0x1_0000),
                },
                "{name}: {out:#?}"
            );
        }
    }

    /// The two-source-operand forms carry the same pair with one fewer register,
    /// so the fold must be written against the *tail* of the operand list rather
    /// than a fixed index.
    #[test]
    fn the_two_operand_forms_fold_their_rotated_immediate_too() {
        // mov r0, #0x40, #30  e3a00f40  ->  ROR(0x40, 30) = 0x100
        let out: Vec<Op> = lift_bytes(&0xe3a00f40u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(
            out[0],
            Op::Assign {
                dst: VReg::phys("r0"),
                src: Value::Const(0x100),
            },
            "mov r0, #0x40, #30: {out:#?}"
        );
        // cmp ip, #16, #20  e35c0a10  ->  compares against 0x10000
        let out: Vec<Op> = lift_bytes(&0xe35c0a10u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
            "cmp left an unlifted instruction: {out:#?}"
        );
        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::Cmp {
                    rhs: Value::Const(0x1_0000),
                    ..
                }
            )),
            "cmp did not compare against the folded constant: {out:#?}"
        );
    }

    /// The fold must not fire on an encoding whose trailing immediates are not
    /// that pair. `movw` puts a 16-bit literal in the same `imm12` field and is
    /// the encoding most likely to be confused with it; a canonical rotation is
    /// already folded by capstone and must pass through untouched.
    #[test]
    fn the_fold_declines_encodings_that_are_not_a_rotated_pair() {
        // movw r0, #0x1234  e3010234 : imm4:imm12, NOT a modified immediate.
        let out: Vec<Op> = lift_bytes(&0xe3010234u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(
            out[0],
            Op::Assign {
                dst: VReg::phys("r0"),
                src: Value::Const(0x1234),
            },
            "movw was rewritten: {out:#?}"
        );
        // add r0, r1, #4  e2810004 : canonical, already folded by capstone.
        let out: Vec<Op> = lift_bytes(&0xe2810004u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(
            out[0],
            Op::Bin {
                dst: VReg::phys("r0"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r1")),
                rhs: Value::Const(4),
            },
            "a canonical immediate was disturbed: {out:#?}"
        );
        // add r0, r1, r2, lsl #3  e0810182 : a shifted *register*, no immediate
        // pair at all — the shift decoding must keep working.
        let out: Vec<Op> = lift_bytes(&0xe0810182u32.to_le_bytes(), 0x1000, false)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
            "shifted-register add regressed: {out:#?}"
        );
    }
}
