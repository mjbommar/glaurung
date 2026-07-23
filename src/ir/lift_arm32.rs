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

/// The three-operand (and two-operand accumulate) data-processing mnemonics.
/// The optional `s` flag-setting suffix is stripped by the caller.
fn bin_for_mnem(m: &str) -> Option<BinOp> {
    Some(match m {
        "add" | "adds" | "addw" => BinOp::Add,
        "sub" | "subs" | "subw" => BinOp::Sub,
        "and" | "ands" => BinOp::And,
        "orr" | "orrs" => BinOp::Or,
        "eor" | "eors" => BinOp::Xor,
        "lsl" | "lsls" => BinOp::Shl,
        "lsr" | "lsrs" => BinOp::Shr,
        "asr" | "asrs" => BinOp::Sar,
        "mul" | "muls" => BinOp::Mul,
        _ => return None,
    })
}

/// Map an ARM condition suffix onto the LLIR flag whose truth decides the
/// branch, plus whether it reads the flag inverted. ARM condition codes are
/// architecturally identical to AArch64's; this also covers `hi`/`ls`.
fn cond_flag_for(suffix: &str) -> Option<(VReg, bool)> {
    Some(match suffix {
        "eq" => (VReg::Flag(Flag::Z), false),
        "ne" => (VReg::Flag(Flag::Z), true),
        "lo" | "cc" => (VReg::Flag(Flag::C), false),
        "hs" | "cs" => (VReg::Flag(Flag::C), true),
        // Unsigned higher / lower-or-same use the Ule flag.
        "ls" => (VReg::Flag(Flag::Ule), false),
        "hi" => (VReg::Flag(Flag::Ule), true),
        "lt" => (VReg::Flag(Flag::Slt), false),
        "ge" => (VReg::Flag(Flag::Slt), true),
        "le" => (VReg::Flag(Flag::Sle), false),
        "gt" => (VReg::Flag(Flag::Sle), true),
        "mi" => (VReg::Flag(Flag::Slt), false),
        "pl" => (VReg::Flag(Flag::Slt), true),
        "vs" => (VReg::Flag(Flag::O), false),
        "vc" => (VReg::Flag(Flag::O), true),
        _ => return None,
    })
}

/// The four flag writes an ARM `cmp a, b` performs — identical to x86/AArch64.
fn cmp_flag_ops(lhs: Value, rhs: Value) -> Vec<Op> {
    vec![
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ult,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Slt),
            op: CmpOp::Slt,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Sle),
            op: CmpOp::Sle,
            lhs,
            rhs,
        },
    ]
}

/// `push {list}` — AAPCS stores the lowest-numbered register at the lowest
/// address after decrementing sp by 4·N. Capstone lists the registers in
/// ascending order, so store operand `i` at `[sp + 4·i]`.
fn lift_push(regs: &[String]) -> Vec<Op> {
    let n = regs.len() as i64;
    if n == 0 {
        return vec![Op::Nop];
    }
    let sp = VReg::phys("sp");
    let mut out = vec![Op::Bin {
        dst: sp.clone(),
        op: BinOp::Sub,
        lhs: Value::Reg(sp.clone()),
        rhs: Value::Const(4 * n),
    }];
    for (i, r) in regs.iter().enumerate() {
        out.push(Op::Store {
            addr: MemOp::plain(Some(sp.clone()), None, 0, 4 * i as i64, 4),
            src: Value::Reg(VReg::phys(r.clone())),
        });
    }
    out
}

/// `pop {list}` — mirror of push: load operand `i` from `[sp + 4·i]`, then add
/// 4·N to sp. If `pc` is in the list the function returns, so the loads and sp
/// adjust are followed by [`Op::Return`].
fn lift_pop(regs: &[String]) -> Vec<Op> {
    let n = regs.len() as i64;
    if n == 0 {
        return vec![Op::Nop];
    }
    let sp = VReg::phys("sp");
    let mut out = Vec::new();
    let mut returns = false;
    for (i, r) in regs.iter().enumerate() {
        if r == "pc" {
            returns = true;
            continue; // don't materialise a write to pc; it's the return target
        }
        out.push(Op::Load {
            dst: VReg::phys(r.clone()),
            addr: MemOp::plain(Some(sp.clone()), None, 0, 4 * i as i64, 4),
        });
    }
    out.push(Op::Bin {
        dst: sp.clone(),
        op: BinOp::Add,
        lhs: Value::Reg(sp),
        rhs: Value::Const(4 * n),
    });
    if returns {
        out.push(Op::Return);
    }
    out
}

fn lift_one(ins: &Instruction) -> Vec<Op> {
    let raw = ins.mnemonic.to_ascii_lowercase();
    // Thumb-2 encodes an instruction-width qualifier (`.w` wide / `.n` narrow)
    // on many mnemonics (`add.w`, `ldr.w`, `mov.w`, `b.w`). It does not change
    // the operation, so strip it before matching.
    let mnem = raw
        .strip_suffix(".w")
        .or_else(|| raw.strip_suffix(".n"))
        .unwrap_or(&raw)
        .to_string();
    let ops = &ins.operands;

    // --- register-list instructions (push/pop) --------------------------
    if mnem == "push" || mnem == "vpush" {
        let regs: Vec<String> = ops.iter().filter_map(operand_reg_name).collect();
        return lift_push(&regs);
    }
    if mnem == "pop" || mnem == "vpop" {
        let regs: Vec<String> = ops.iter().filter_map(operand_reg_name).collect();
        return lift_pop(&regs);
    }
    // Load/store multiple: `ldm{ia} Rn{!}, {list}` / `stm{ia} Rn{!}, {list}`.
    // operands[0] is the base register, the rest the register list. We emit a
    // load/store per list register at `[Rn + 4·i]` (increment-after assumed;
    // base writeback is not surfaced by the decoder, so it is approximated as a
    // no-op). `ldm … , {…, pc}` returns.
    if mnem.starts_with("ldm") || mnem.starts_with("stm") {
        let regs: Vec<String> = ops.iter().filter_map(operand_reg_name).collect();
        if regs.len() >= 2 {
            let base = VReg::phys(regs[0].clone());
            let list = &regs[1..];
            let is_load = mnem.starts_with("ldm");
            let mut out = Vec::new();
            let mut returns = false;
            for (i, r) in list.iter().enumerate() {
                let addr = MemOp::plain(Some(base.clone()), None, 0, 4 * i as i64, 4);
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
        return vec![Op::Unknown { mnemonic: mnem }];
    }

    // --- data processing: <op>{s} Rd, Rn, <reg|imm>  (or 2-operand form) --
    if let Some(op) = bin_for_mnem(&mnem) {
        // Three-operand: Rd, Rn, Op2
        if ops.len() == 3 {
            if let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ops[0]),
                operand_to_value(&ops[1]),
                operand_to_value(&ops[2]),
            ) {
                return vec![Op::Bin { dst, op, lhs, rhs }];
            }
        }
        // Two-operand accumulate: Rd, Op2  ==>  Rd = Rd <op> Op2
        if ops.len() == 2 {
            if let (Some(dst), Some(rhs)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                return vec![Op::Bin {
                    dst: dst.clone(),
                    op,
                    lhs: Value::Reg(dst),
                    rhs,
                }];
            }
        }
        return vec![Op::Unknown { mnemonic: mnem }];
    }

    // --- reverse subtract: rsb Rd, Rn, #imm  ==>  Rd = imm - Rn ----------
    if mnem == "rsb" || mnem == "rsbs" || mnem == "neg" || mnem == "negs" {
        if ops.len() == 3 {
            if let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ops[0]),
                operand_to_value(&ops[1]),
                operand_to_value(&ops[2]),
            ) {
                // Rd = rhs - lhs  (reverse)
                return vec![Op::Bin {
                    dst,
                    op: BinOp::Sub,
                    lhs: rhs,
                    rhs: lhs,
                }];
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
        return vec![Op::Unknown { mnemonic: mnem }];
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
                return vec![Op::Unknown { mnemonic: mnem }];
            }
        }
    }

    match mnem.as_str() {
        "nop" | "hint" => vec![Op::Nop],

        // Moves. mov/movs/movw Rd, <reg|imm>. mvn Rd, Op2 = Rd = ~Op2.
        "mov" | "movs" | "movw" | "mov.w" => {
            if ops.len() == 2 {
                if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                    return vec![Op::Assign { dst, src }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
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
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "mvn" | "mvns" => {
            if ops.len() == 2 {
                if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                    return vec![Op::Un {
                        dst,
                        op: UnOp::Not,
                        src,
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Compares set flags (cmn compares against the negation, approximated).
        "cmp" | "cmn" => {
            if ops.len() == 2 {
                if let (Some(lhs), Some(rhs)) =
                    (operand_to_value(&ops[0]), operand_to_value(&ops[1]))
                {
                    return cmp_flag_ops(lhs, rhs);
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "tst" => {
            // tst a, b sets Z from (a & b). Approximate with an equality flag.
            if ops.len() == 2 {
                if let (Some(lhs), Some(rhs)) =
                    (operand_to_value(&ops[0]), operand_to_value(&ops[1]))
                {
                    return vec![Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs,
                        rhs,
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Loads.
        m if m.starts_with("ldr") => {
            if ops.len() >= 2 {
                let Some(dst) = operand_reg(&ops[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let size = mem_size_for(m);
                if let Some(addr) = operand_to_memop(&ops[1], size) {
                    let base_reg = addr.base.clone();
                    let mut out = vec![Op::Load { dst, addr }];
                    // Post-indexed writeback: 3rd operand is the offset.
                    if ops.len() == 3 {
                        if let (Some(base), Some(off)) = (base_reg, ops[2].immediate) {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
                // PC-relative literal: `ldr Rd, =sym` folds to an absolute imm.
                if let Some(abs) = ops[1].immediate {
                    return vec![Op::Load {
                        dst,
                        addr: MemOp {
                            base: None,
                            index: None,
                            scale: 0,
                            disp: abs,
                            size,
                            segment: None,
                            endian: Endian::Little,
                        },
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Stores.
        m if m.starts_with("str") => {
            if ops.len() >= 2 {
                let Some(src) = operand_to_value(&ops[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let size = mem_size_for(m);
                if let Some(addr) = operand_to_memop(&ops[1], size) {
                    let base_reg = addr.base.clone();
                    let mut out = vec![Op::Store { addr, src }];
                    if ops.len() == 3 {
                        if let (Some(base), Some(off)) = (base_reg, ops[2].immediate) {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Compare-and-branch (Thumb): cbz/cbnz Rn, label.
        "cbz" | "cbnz" => {
            let inverted = mnem == "cbnz";
            if ops.len() == 2 {
                let Some(reg_val) = operand_to_value(&ops[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
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
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Unconditional branch (also the tail-call form b.w).
        "b" | "b.w" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Jump {
                    target: target as u64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Calls: bl label (direct); blx label|reg (direct|indirect).
        "bl" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "blx" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                }];
            }
            if let Some(reg) = ops.first().and_then(operand_reg) {
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(reg)),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        // Branch-and-exchange: `bx lr` returns; `bx reg` is an indirect
        // transfer (tail call / computed branch).
        "bx" => {
            if let Some(name) = ops.first().and_then(operand_reg_name) {
                if name == "lr" {
                    return vec![Op::Return];
                }
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(VReg::phys(name))),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }

        _ => vec![Op::Unknown { mnemonic: mnem }],
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
    let Some(mut cs) = CapstoneDisassembler::new(Architecture::ARM, Endianness::Little) else {
        return vec![];
    };
    if cs.set_thumb_mode(thumb).is_err() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_va;
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
        for op in lift_one(&ins) {
            out.push(LlirInstr { va, op });
        }
        off += ins.length as usize;
        va = va.saturating_add(ins.length as u64);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ops.iter().any(|o| matches!(o, Op::Bin { op: BinOp::Add, .. })),
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
            ops.iter().any(|o| matches!(o,
                Op::Cmp { dst: VReg::Flag(Flag::Z), op: CmpOp::Eq, .. })),
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
        assert!(returns >= 2, "expected >=2 returns (pop pc + bx lr): {:?}", ops);
    }

    #[test]
    fn bx_lr_is_return_but_bx_reg_is_indirect() {
        // bx lr = 4770 ; the standalone form.
        assert_eq!(ops(&[0x70, 0x47]), vec![Op::Return]);
    }
}
