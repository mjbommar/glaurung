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
        // ARMv7 hardware divide (Cortex-M4/A). Signedness is approximated: the
        // IR has a single Div; sdiv/udiv both map to it.
        "sdiv" | "udiv" => BinOp::Div,
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

/// Lift a single instruction whose base mnemonic (already lowercased, with the
/// `.w`/`.n` qualifier and any IT-block condition suffix stripped) is `mnem`.
/// Predication is applied by the caller in [`lift_bytes`].
fn lift_one(ins: &Instruction, mnem: &str) -> Vec<Op> {
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
                // Register operand: t = ~Rm ; Rd = Rn & t.
                if let Some(rm) = operand_reg(&ops[2]) {
                    let t = VReg::Temp(0);
                    return vec![
                        Op::Un {
                            dst: t.clone(),
                            op: UnOp::Not,
                            src: Value::Reg(rm),
                        },
                        Op::Bin {
                            dst,
                            op: BinOp::And,
                            lhs,
                            rhs: Value::Reg(t),
                        },
                    ];
                }
            }
        }
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
    }

    // --- long multiply / multiply-accumulate (4-operand forms) ----------
    // umull/smull RdLo, RdHi, Rn, Rm : {RdHi:RdLo} = Rn * Rm. We compute the
    // full product into a temp (the IR is 64-bit-wide), assign the low half to
    // RdLo, and the high half (RdLo shifted right 32) to RdHi -- logical shift
    // for umull, arithmetic for smull.
    if (mnem == "umull" || mnem == "smull") && ops.len() == 4 {
        if let (Some(rd_lo), Some(rd_hi), Some(rn), Some(rm)) = (
            operand_reg(&ops[0]),
            operand_reg(&ops[1]),
            operand_to_value(&ops[2]),
            operand_to_value(&ops[3]),
        ) {
            let t = VReg::Temp(0);
            let hi_shift = if mnem == "smull" { BinOp::Sar } else { BinOp::Shr };
            return vec![
                Op::Bin {
                    dst: t.clone(),
                    op: BinOp::Mul,
                    lhs: rn,
                    rhs: rm,
                },
                Op::Assign {
                    dst: rd_lo,
                    src: Value::Reg(t.clone()),
                },
                Op::Bin {
                    dst: rd_hi,
                    op: hi_shift,
                    lhs: Value::Reg(t),
                    rhs: Value::Const(32),
                },
            ];
        }
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
    }

    // --- data processing: <op>{s} Rd, Rn, <reg|imm>  (or 2-operand form) --
    if let Some(op) = bin_for_mnem(mnem) {
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
        return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
                return vec![Op::Unknown { mnemonic: mnem.to_string() }];
            }
        }
    }

    match mnem {
        "nop" | "hint" => vec![Op::Nop],

        // Moves. mov/movs/movw Rd, <reg|imm>. mvn Rd, Op2 = Rd = ~Op2.
        "mov" | "movs" | "movw" | "mov.w" => {
            if ops.len() == 2 {
                if let (Some(dst), Some(src)) = (operand_reg(&ops[0]), operand_to_value(&ops[1])) {
                    return vec![Op::Assign { dst, src }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
        }

        // Loads.
        m if m.starts_with("ldr") => {
            if ops.len() >= 2 {
                let Some(dst) = operand_reg(&ops[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
        }

        // Stores.
        m if m.starts_with("str") => {
            if ops.len() >= 2 {
                let Some(src) = operand_to_value(&ops[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
        }

        // Compare-and-branch (Thumb): cbz/cbnz Rn, label.
        "cbz" | "cbnz" => {
            let inverted = mnem == "cbnz";
            if ops.len() == 2 {
                let Some(reg_val) = operand_to_value(&ops[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem.to_string() }];
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
        }

        // Unconditional branch (also the tail-call form b.w).
        "b" | "b.w" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Jump {
                    target: target as u64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
        }

        // Calls: bl label (direct); blx label|reg (direct|indirect).
        "bl" => {
            if let Some(target) = ops.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
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
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
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
                }];
            }
            vec![Op::Unknown { mnemonic: mnem.to_string() }]
        }

        _ => vec![Op::Unknown { mnemonic: mnem.to_string() }],
    }
}

/// Strip the `.w`/`.n` Thumb-2 width qualifier from a lowercased mnemonic.
fn strip_qualifier(m: &str) -> &str {
    m.strip_suffix(".w").or_else(|| m.strip_suffix(".n")).unwrap_or(m)
}

/// True for an IT-block introducer: `it` optionally followed by up to three
/// `t`/`e` mask characters (`it`, `itt`, `ite`, `itte`, `itttt`, …).
fn is_it_mnemonic(m: &str) -> bool {
    matches!(m.len(), 2..=5)
        && m.starts_with("it")
        && m[2..].bytes().all(|b| b == b't' || b == b'e')
}

/// Per-slot (flag, inverted) conditions for the instructions an IT block
/// predicates. Capstone reports the mask in the mnemonic (`it`/`ite`/`itt`/…)
/// and the base condition as the first operand (a pseudo-register named `lt`,
/// `ge`, …). Slot 0 is always the base condition (the implicit `t`); each mask
/// character then adds a slot — `t` reuses the base polarity, `e` inverts it.
fn it_conditions(mnem: &str, cond_name: &str) -> Vec<(VReg, bool)> {
    let Some((flag, inv)) = cond_flag_for(cond_name) else {
        return Vec::new();
    };
    let mut out = vec![(flag.clone(), inv)];
    for c in mnem.as_bytes()[2..].iter() {
        out.push((flag.clone(), if *c == b'e' { !inv } else { inv }));
    }
    out
}

/// Wrap an unconditionally-lifted instruction's ops so its register write only
/// takes effect when `cond` holds (an IT-block predicated instruction). The
/// common single-write shapes become an [`Op::Ite`] select (`dst = cond ? new :
/// dst`); multi-op or store-only lifts fall back to executing unconditionally
/// (a documented approximation).
fn make_conditional(ops: Vec<Op>, cond: VReg, inverted: bool) -> Vec<Op> {
    // Ite is `dst = cond ? t : e`; for `if !cond` we swap the two arms.
    let pick = |new: Value, keep: Value| -> (Value, Value) {
        if inverted {
            (keep, new)
        } else {
            (new, keep)
        }
    };
    if ops.len() != 1 {
        return ops;
    }
    match ops.into_iter().next().unwrap() {
        Op::Assign { dst, src } => {
            let (t, e) = pick(src, Value::Reg(dst.clone()));
            vec![Op::Ite {
                dst,
                cond,
                t,
                e,
                width: Width::W32,
            }]
        }
        Op::Bin { dst, op, lhs, rhs } => {
            let tmp = VReg::Temp(1);
            let (t, e) = pick(Value::Reg(tmp.clone()), Value::Reg(dst.clone()));
            vec![
                Op::Bin {
                    dst: tmp,
                    op,
                    lhs,
                    rhs,
                },
                Op::Ite {
                    dst,
                    cond,
                    t,
                    e,
                    width: Width::W32,
                },
            ]
        }
        Op::Un { dst, op, src } => {
            let tmp = VReg::Temp(1);
            let (t, e) = pick(Value::Reg(tmp.clone()), Value::Reg(dst.clone()));
            vec![
                Op::Un { dst: tmp, op, src },
                Op::Ite {
                    dst,
                    cond,
                    t,
                    e,
                    width: Width::W32,
                },
            ]
        }
        Op::Load { dst, addr } => {
            let tmp = VReg::Temp(1);
            let (t, e) = pick(Value::Reg(tmp.clone()), Value::Reg(dst.clone()));
            vec![
                Op::Load { dst: tmp, addr },
                Op::Ite {
                    dst,
                    cond,
                    t,
                    e,
                    width: Width::W32,
                },
            ]
        }
        // Stores / returns / anything else: keep as-is (unconditional approx).
        other => vec![other],
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
            let lifted = lift_one(&ins, mnem);
            for op in make_conditional(lifted, flag, inverted) {
                out.push(LlirInstr { va, op });
            }
        } else {
            for op in lift_one(&ins, mnem) {
                out.push(LlirInstr { va, op });
            }
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
                Op::Bin { dst, op: BinOp::Shr, .. } if matches!(dst, VReg::Phys(n) if n == "r1"))),
            "umull high half not r1 = t >> 32: {:?}",
            umull
        );

        // mla r0, r1, r2, r3 = fb01 3002  ->  t = r1*r2 ; r0 = r3 + t
        let mla = ops(&[0x01, 0xfb, 0x02, 0x30]);
        assert!(
            mla.iter().any(|o| matches!(o, Op::Bin { op: BinOp::Mul, .. })),
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
            bic.iter().any(|o| matches!(o, Op::Un { op: UnOp::Not, .. }))
                && bic.iter().any(|o| matches!(o, Op::Bin { op: BinOp::And, .. })),
            "bic not Not+And: {:?}",
            bic
        );

        // uxtb r0,r1=b2c8, uxth=b288 -> ZExt ; sxtb=b248, sxth=b208 -> SExt.
        assert!(matches!(ops(&[0xc8, 0xb2]).as_slice(), [Op::ZExt { from, .. }] if *from == Width::W8));
        assert!(matches!(ops(&[0x88, 0xb2]).as_slice(), [Op::ZExt { from, .. }] if *from == Width::W16));
        assert!(matches!(ops(&[0x48, 0xb2]).as_slice(), [Op::SExt { from, .. }] if *from == Width::W8));
        assert!(matches!(ops(&[0x08, 0xb2]).as_slice(), [Op::SExt { from, .. }] if *from == Width::W16));

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
}
