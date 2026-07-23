//! AArch64 → LLIR lifter.
//!
//! Decodes fixed-width 4-byte ARM64 instructions using the existing
//! [`crate::disasm::capstone::CapstoneDisassembler`] and emits LLIR ops.
//!
//! Coverage (v1):
//!
//! * `nop` → [`Op::Nop`]
//! * `mov`, `movz` → [`Op::Assign`]
//! * `add`, `sub`, `and`, `orr`, `eor`, `lsl`, `lsr`, `asr` → [`Op::Bin`]
//! * `cmp` → five [`Op::Cmp`] writes (Z, C, Ule, Slt, Sle) — same as x86
//! * `adrp` → [`Op::Assign`] of the resolved page address (capstone folds the
//!   PC arithmetic into the immediate operand)
//! * `ldr`/`ldrb`/`ldrh`/`ldrsw` with `[base, #disp]` → [`Op::Load`]
//! * `str`/`strb`/`strh` with `[base, #disp]` → [`Op::Store`]
//! * `b` (near target), `b.<cond>`, `cbz`/`cbnz`, `tbz`/`tbnz` →
//!   [`Op::Jump`] / [`Op::CondJump`]
//! * `bl` (direct), `blr` / `br` (indirect) → [`Op::Call`]
//! * `ret` → [`Op::Return`]
//!
//! Anything else becomes [`Op::Unknown`] carrying the capstone mnemonic so
//! downstream passes can flag unsupported instructions.

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

fn operand_to_value(op: &Operand) -> Option<Value> {
    match op.kind {
        OperandKind::Register => op.register.clone().map(|n| Value::Reg(VReg::phys(n))),
        OperandKind::Immediate => op.immediate.map(Value::Const),
        _ => None,
    }
}

fn operand_to_memop(op: &Operand, size: u8) -> Option<MemOp> {
    if !matches!(op.kind, OperandKind::Memory) {
        return None;
    }
    let base = op.base.clone().map(VReg::phys);
    let index = op.index.clone().map(VReg::phys);
    let disp = op.displacement.unwrap_or(0);
    Some(MemOp {
        base,
        index,
        scale: op.scale.unwrap_or(0),
        disp,
        size,
        segment: None, // ARM64 has no segment registers
        endian: Endian::Little,
    })
}

fn scalar_access_size(mnemonic: &str, register: &Operand) -> u8 {
    match mnemonic {
        "ldrb" | "ldrsb" | "strb" => 1,
        "ldrh" | "ldrsh" | "strh" => 2,
        "ldrsw" => 4,
        _ => match register.register.as_deref() {
            Some(name) if name.starts_with('w') || name.starts_with('s') => 4,
            Some(name) if name.starts_with('h') => 2,
            Some(name) if name.starts_with('b') => 1,
            _ => 8,
        },
    }
}

fn instruction_word(ins: &Instruction) -> Option<u32> {
    let bytes: [u8; 4] = ins.bytes.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn intrinsic(name: &str, outs: Vec<(VReg, Width)>) -> Op {
    Op::Intrinsic {
        name: name.to_string(),
        ins: Vec::new(),
        outs,
        reads_mem: false,
        writes_mem: false,
    }
}

fn semantic_intrinsic(name: &str, ins: Vec<Value>) -> Op {
    Op::Intrinsic {
        name: name.to_string(),
        ins,
        outs: Vec::new(),
        reads_mem: false,
        writes_mem: false,
    }
}

fn temp_for(ins: &Instruction, lane: u32) -> VReg {
    VReg::Temp(
        (ins.address.value as u32)
            .wrapping_mul(4)
            .wrapping_add(lane),
    )
}

fn bin_for_mnem(m: &str) -> Option<BinOp> {
    Some(match m {
        "add" => BinOp::Add,
        "sub" => BinOp::Sub,
        "and" => BinOp::And,
        "orr" => BinOp::Or,
        "eor" => BinOp::Xor,
        "lsl" => BinOp::Shl,
        "lsr" => BinOp::Shr,
        "asr" => BinOp::Sar,
        "mul" => BinOp::Mul,
        _ => return None,
    })
}

/// Map a `b.<cond>` mnemonic (e.g. "b.eq") onto the LLIR flag whose truth
/// determines whether the branch is taken. Returns `(flag, inverted)`: the
/// negated sibling (`b.ne` vs `b.eq`) reads the same flag with the inverted
/// bit set, so a downstream consumer can render the branch as `!=` vs `==`.
fn cond_flag_for_bcond(suffix: &str) -> Option<(VReg, bool)> {
    Some(match suffix {
        "eq" => (VReg::Flag(Flag::Z), false),
        "ne" => (VReg::Flag(Flag::Z), true),
        // AArch64 uses "LO" (same as CS / unsigned lower) and "HS" (HI or
        // equal) for unsigned-less-than.
        "lo" | "cc" => (VReg::Flag(Flag::C), false),
        "cs" | "hs" => (VReg::Flag(Flag::C), true),
        "lt" => (VReg::Flag(Flag::Slt), false),
        "ge" => (VReg::Flag(Flag::Slt), true),
        "le" => (VReg::Flag(Flag::Sle), false),
        "gt" => (VReg::Flag(Flag::Sle), true),
        "ls" => (VReg::Flag(Flag::Ule), false),
        "hi" => (VReg::Flag(Flag::Ule), true),
        // MI/PL read the raw sign; with cmp-driven flows this coincides with
        // signed-less-than, so we approximate similarly to x86 Js/Jns.
        "mi" => (VReg::Flag(Flag::Slt), false),
        "pl" => (VReg::Flag(Flag::Slt), true),
        "vs" => (VReg::Flag(Flag::O), false),
        "vc" => (VReg::Flag(Flag::O), true),
        _ => return None,
    })
}

fn cond_flag_for_code(code: u32) -> Option<(VReg, bool)> {
    let suffix = match code & 0xf {
        0x0 => "eq",
        0x1 => "ne",
        0x2 => "hs",
        0x3 => "lo",
        0x4 => "mi",
        0x5 => "pl",
        0x6 => "vs",
        0x7 => "vc",
        0x8 => "hi",
        0x9 => "ls",
        0xa => "ge",
        0xb => "lt",
        0xc => "gt",
        0xd => "le",
        _ => return None,
    };
    cond_flag_for_bcond(suffix)
}

fn conditional_select(dst: VReg, cond_code: u32, if_true: Value, if_false: Value) -> Option<Op> {
    let width = dst.width()?;
    let (cond, inverted) = cond_flag_for_code(cond_code)?;
    let (t, e) = if inverted {
        (if_false, if_true)
    } else {
        (if_true, if_false)
    };
    Some(Op::Ite {
        dst,
        cond,
        t,
        e,
        width,
    })
}

fn low_mask(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn bitfield_operands(ins: &Instruction) -> Option<(VReg, Value, u16, u16, Width)> {
    if ins.operands.len() != 4 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = operand_to_value(&ins.operands[1])?;
    let lsb = u16::try_from(ins.operands[2].immediate?).ok()?;
    let field = u16::try_from(ins.operands[3].immediate?).ok()?;
    let dst_width = dst.width()?;
    let src_width = match &src {
        Value::Reg(register) => register.width()?,
        _ => return None,
    };
    if field == 0 || lsb.checked_add(field)? > src_width.bits() || field > dst_width.bits() {
        return None;
    }
    Some((dst, src, lsb, field, dst_width))
}

fn lift_one(ins: &Instruction) -> Vec<Op> {
    let mnem = ins.mnemonic.to_ascii_lowercase();

    // Three-operand arithmetic: <op> Xd, Xn, <reg|imm>
    if let Some(op) = bin_for_mnem(&mnem) {
        if ins.operands.len() == 3 {
            let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ins.operands[0]),
                operand_to_value(&ins.operands[1]),
                operand_to_value(&ins.operands[2]),
            ) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            return vec![Op::Bin { dst, op, lhs, rhs }];
        }
    }

    // b.<cond> conditional branches.
    if let Some(suffix) = mnem.strip_prefix("b.") {
        if let Some((cond, inverted)) = cond_flag_for_bcond(suffix) {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::CondJump {
                    cond,
                    target: target as u64,
                    inverted,
                }];
            }
        }
        return vec![Op::Unknown { mnemonic: mnem }];
    }

    match mnem.as_str() {
        "nop" => vec![Op::Nop],
        "mov" => {
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(src) = operand_to_value(&ins.operands[1]) {
                    return vec![Op::Assign { dst, src }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "movz" => {
            // movz <Xd>, #imm — low 16-bit move-with-zero; we emit Assign for
            // the simple (no-shift) case. More general movz + movk sequences
            // are handled by a later materialization pass.
            if ins.operands.len() >= 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Const(imm),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "movk" => {
            if ins.operands.is_empty() {
                return vec![Op::Unknown { mnemonic: mnem }];
            }
            let Some(dst) = operand_reg(&ins.operands[0]) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let Some(word) = instruction_word(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let width = if word >> 31 == 0 { 32u32 } else { 64u32 };
            let shift = ((word >> 21) & 0x3) * 16;
            if shift + 16 > width {
                return vec![Op::Unknown { mnemonic: mnem }];
            }
            let imm = (word >> 5) & 0xffff;
            let width_mask = if width == 64 {
                u64::MAX
            } else {
                u64::from(u32::MAX)
            };
            let field_mask = 0xffffu64 << shift;
            let keep_mask = width_mask & !field_mask;
            let inserted = u64::from(imm) << shift;
            return vec![
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(dst.clone()),
                    rhs: Value::Const(keep_mask as i64),
                },
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::Or,
                    lhs: Value::Reg(dst),
                    rhs: Value::Const(inserted as i64),
                },
            ];
        }
        "neg" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![Op::Un {
                    dst,
                    op: UnOp::Neg,
                    src,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cmn" | "tst" => {
            if ins.operands.len() == 2 {
                let (Some(lhs), Some(rhs)) = (
                    operand_to_value(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let width = match &lhs {
                    Value::Reg(register) => register.width(),
                    _ => None,
                };
                if let Some(width) = width {
                    let name = format!("aarch64_{}{}", mnem, width.bits());
                    return vec![semantic_intrinsic(&name, vec![lhs, rhs])];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "csel" => {
            if ins.operands.len() == 3 {
                let (Some(dst), Some(if_true), Some(if_false), Some(word)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    instruction_word(ins),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(op) = conditional_select(dst, (word >> 12) & 0xf, if_true, if_false) {
                    return vec![op];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cset" => {
            if ins.operands.len() == 1 {
                let (Some(dst), Some(word)) =
                    (operand_reg(&ins.operands[0]), instruction_word(ins))
                else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let effective_cond = ((word >> 12) & 0xf) ^ 1;
                if let Some(op) =
                    conditional_select(dst, effective_cond, Value::Const(1), Value::Const(0))
                {
                    return vec![op];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cinc" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src), Some(word)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    instruction_word(ins),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let incremented = temp_for(ins, 0);
                let effective_cond = ((word >> 12) & 0xf) ^ 1;
                let Some(select) = conditional_select(
                    dst,
                    effective_cond,
                    Value::Reg(incremented.clone()),
                    src.clone(),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
                    Op::Bin {
                        dst: incremented,
                        op: BinOp::Add,
                        lhs: src,
                        rhs: Value::Const(1),
                    },
                    select,
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ngc" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let negated = temp_for(ins, 0);
                let with_borrow = temp_for(ins, 1);
                let Some(select) = conditional_select(
                    dst,
                    0x3, // synthetic C is true for the lower/borrow predicate
                    Value::Reg(with_borrow.clone()),
                    Value::Reg(negated.clone()),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
                    Op::Un {
                        dst: negated.clone(),
                        op: UnOp::Neg,
                        src,
                    },
                    Op::Bin {
                        dst: with_borrow,
                        op: BinOp::Sub,
                        lhs: Value::Reg(negated),
                        rhs: Value::Const(1),
                    },
                    select,
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "madd" => {
            if ins.operands.len() == 4 {
                let (Some(dst), Some(lhs), Some(rhs), Some(addend)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    operand_to_value(&ins.operands[3]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let product = temp_for(ins, 0);
                return vec![
                    Op::Bin {
                        dst: product.clone(),
                        op: BinOp::Mul,
                        lhs,
                        rhs,
                    },
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Reg(product),
                        rhs: addend,
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "umaddl" => {
            if ins.operands.len() == 4 {
                let (Some(dst), Some(lhs), Some(rhs), Some(addend)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    operand_to_value(&ins.operands[3]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let lhs64 = temp_for(ins, 0);
                let rhs64 = temp_for(ins, 1);
                let product = temp_for(ins, 2);
                return vec![
                    Op::ZExt {
                        dst: lhs64.clone(),
                        src: lhs,
                        from: Width::W32,
                        to: Width::W64,
                    },
                    Op::ZExt {
                        dst: rhs64.clone(),
                        src: rhs,
                        from: Width::W32,
                        to: Width::W64,
                    },
                    Op::Bin {
                        dst: product.clone(),
                        op: BinOp::Mul,
                        lhs: Value::Reg(lhs64),
                        rhs: Value::Reg(rhs64),
                    },
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Reg(product),
                        rhs: addend,
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "sxtw" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![Op::SExt {
                    dst,
                    src,
                    from: Width::W32,
                    to: Width::W64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ubfx" => {
            let Some((dst, src, lsb, field, dst_width)) = bitfield_operands(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let fragment = temp_for(ins, 0);
            vec![
                Op::Extract {
                    dst: fragment.clone(),
                    src,
                    hi: lsb + field,
                    lo: lsb,
                },
                Op::ZExt {
                    dst,
                    src: Value::Reg(fragment),
                    from: Width(field),
                    to: dst_width,
                },
            ]
        }
        "bfxil" | "bfi" => {
            let Some((dst, src, source_lsb, field, dst_width)) = bitfield_operands(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let destination_lsb = if mnem == "bfi" { source_lsb } else { 0 };
            if destination_lsb + field > dst_width.bits() {
                return vec![Op::Unknown { mnemonic: mnem }];
            }
            let extract_lsb = if mnem == "bfi" { 0 } else { source_lsb };
            let fragment = temp_for(ins, 0);
            let widened = temp_for(ins, 1);
            let placed = temp_for(ins, 2);
            let kept = temp_for(ins, 3);
            let mut out = vec![
                Op::Extract {
                    dst: fragment.clone(),
                    src,
                    hi: extract_lsb + field,
                    lo: extract_lsb,
                },
                Op::ZExt {
                    dst: widened.clone(),
                    src: Value::Reg(fragment),
                    from: Width(field),
                    to: dst_width,
                },
            ];
            let placed_value = if destination_lsb == 0 {
                Value::Reg(widened)
            } else {
                out.push(Op::Bin {
                    dst: placed.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(widened),
                    rhs: Value::Const(i64::from(destination_lsb)),
                });
                Value::Reg(placed)
            };
            let destination_mask = low_mask(field) << destination_lsb;
            let width_mask = low_mask(dst_width.bits());
            out.extend([
                Op::Bin {
                    dst: kept.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(dst.clone()),
                    rhs: Value::Const((width_mask & !destination_mask) as i64),
                },
                Op::Bin {
                    dst,
                    op: BinOp::Or,
                    lhs: Value::Reg(kept),
                    rhs: placed_value,
                },
            ]);
            out
        }
        "paciasp" | "autiasp" | "dmb" | "csdb" => vec![intrinsic(&mnem, Vec::new())],
        "mrs" => {
            // MRS Xt,SP_EL0 has fixed sysreg bits 0xd5384100; Rt is bits 4:0.
            if instruction_word(ins).is_some_and(|word| word & 0xffff_ffe0 == 0xd538_4100)
                && ins.operands.len() == 1
            {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![intrinsic("mrs_sp_el0", vec![(dst, Width::W64)])];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "adrp" => {
            // adrp <Xd>, #<page>. Capstone already resolves the page VA into
            // the immediate operand. We surface it as an absolute address so
            // xref recovery can pair it with the subsequent add/ldr.
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Addr(imm as u64),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cmp" => {
            if ins.operands.len() == 2 {
                let Some(lhs) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(rhs) = operand_to_value(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
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
                        dst: VReg::Flag(Flag::Ule),
                        op: CmpOp::Ule,
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
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "ldur" => {
            if ins.operands.len() >= 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let size = scalar_access_size(&mnem, &ins.operands[0]);
                if let Some(addr) = operand_to_memop(&ins.operands[1], size) {
                    let base_reg = addr.base.clone();
                    let mut out = vec![Op::Load { dst, addr }];
                    // Post-indexed: 3rd operand is the writeback amount.
                    if ins.operands.len() == 3 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[2].immediate) {
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
                // PC-relative literal (2-operand form).
                if ins.operands.len() == 2 {
                    if let Some(abs) = ins.operands[1].immediate {
                        let size: u8 = match mnem.as_str() {
                            "ldrb" | "ldrsb" => 1,
                            "ldrh" | "ldrsh" => 2,
                            "ldrsw" => 4,
                            _ => 8,
                        };
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
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "str" | "strb" | "strh" | "stur" => {
            if ins.operands.len() >= 2 {
                let Some(src) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let size = scalar_access_size(&mnem, &ins.operands[0]);
                if let Some(addr) = operand_to_memop(&ins.operands[1], size) {
                    let base_reg = addr.base.clone();
                    let mut out = vec![Op::Store { addr, src }];
                    if ins.operands.len() == 3 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[2].immediate) {
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
        // Load-pair / store-pair: `ldp Xt1, Xt2, [base, #disp]` transfers two
        // consecutive 8-byte words. We decompose into two ordinary
        // Load/Store ops so the rest of the pipeline (stack locals, dead
        // stores, push/pop recognition) doesn't need to know about pairs.
        "ldp" => {
            if ins.operands.len() >= 3 {
                let Some(dst1) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(dst2) = operand_reg(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(mut addr) = operand_to_memop(&ins.operands[2], 8) {
                    let base_reg = addr.base.clone();
                    let pair_off = 8i64;
                    let addr2 = MemOp {
                        disp: addr.disp.wrapping_add(pair_off),
                        ..addr.clone()
                    };
                    addr.size = 8;
                    let mut out = vec![
                        Op::Load { dst: dst1, addr },
                        Op::Load {
                            dst: dst2,
                            addr: addr2,
                        },
                    ];
                    // Post-indexed: 4th operand is the writeback amount.
                    if ins.operands.len() == 4 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[3].immediate) {
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
        "stp" => {
            if ins.operands.len() >= 3 {
                let Some(src1) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(src2) = operand_to_value(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(mut addr) = operand_to_memop(&ins.operands[2], 8) {
                    let base_reg = addr.base.clone();
                    let pair_off = 8i64;
                    let addr2 = MemOp {
                        disp: addr.disp.wrapping_add(pair_off),
                        ..addr.clone()
                    };
                    addr.size = 8;
                    let mut out = vec![
                        Op::Store { addr, src: src1 },
                        Op::Store {
                            addr: addr2,
                            src: src2,
                        },
                    ];
                    if ins.operands.len() == 4 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[3].immediate) {
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
        "cbz" | "cbnz" => {
            // cbz <Xn>, <label>: branch if <Xn> == 0.
            // cbnz <Xn>, <label>: branch if <Xn> != 0 (inverted).
            // Emit: %zf = (Xn == 0); cond_jump (!)%zf <label>
            let inverted = mnem == "cbnz";
            if ins.operands.len() == 2 {
                let Some(reg_val) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(target) = ins.operands[1].immediate {
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
        "tbz" | "tbnz" => {
            // TBZ/TBNZ do not modify NZCV. Extract the selected bit into a
            // dedicated non-architectural predicate so a later b.<cond> still
            // observes the preceding flag-setting instruction.
            if ins.operands.len() == 3 {
                let Some(reg) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(bit) = ins.operands[1].immediate else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(target) = ins.operands[2].immediate else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(width) = (match &reg {
                    Value::Reg(register) => register.width(),
                    _ => None,
                }) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if bit < 0 || bit >= i64::from(width.bits()) {
                    return vec![Op::Unknown { mnemonic: mnem }];
                }
                return vec![
                    Op::Extract {
                        dst: VReg::Flag(Flag::Bit),
                        src: reg,
                        hi: bit as u16 + 1,
                        lo: bit as u16,
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Bit),
                        target: target as u64,
                        inverted: mnem == "tbz",
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "b" => {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::Jump {
                    target: target as u64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "bl" => {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "br" | "blr" => {
            if let Some(reg) = ins.operands.first().and_then(operand_reg) {
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(reg)),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ret" => vec![Op::Return],
        _ => vec![Op::Unknown { mnemonic: mnem }],
    }
}

/// Lift a byte window of AArch64 machine code into LLIR.
///
/// Returns an empty vector if the capstone backend cannot be constructed
/// (should not happen at runtime on supported platforms) or if decoding
/// fails on the very first instruction.
pub fn lift_bytes(bytes: &[u8], start_va: u64) -> Vec<LlirInstr> {
    let Some(cs) = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_va;
    while off + 4 <= bytes.len() {
        let Ok(addr) = Address::new(AddressKind::VA, va, 64, None, None) else {
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

    // NOTE: ARM64 is 4-byte little-endian for data and wide-immediate fields.
    // The byte sequences below are hand-assembled from instruction encodings
    // in the Arm ARM (ARM DDI 0487) so tests are hermetic and don't need a
    // real binary.

    fn last_op_mnem(out: &[LlirInstr]) -> String {
        match &out.last().unwrap().op {
            Op::Unknown { mnemonic } => mnemonic.clone(),
            other => format!("{:?}", other),
        }
    }

    #[test]
    fn nop_lifts_to_nop() {
        // NOP = 0xd503201f (little-endian: 1f 20 03 d5)
        let out = lift_bytes(&[0x1f, 0x20, 0x03, 0xd5], 0x1000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Nop);
        assert_eq!(out[0].va, 0x1000);
    }

    #[test]
    fn ret_lifts_to_return() {
        // RET (x30) = 0xd65f03c0 (LE: c0 03 5f d6)
        let out = lift_bytes(&[0xc0, 0x03, 0x5f, 0xd6], 0x2000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Return);
    }

    #[test]
    fn add_x0_x0_x1_lifts_to_bin_add() {
        // ADD X0, X0, X1  =  0x8b010000  (LE: 00 00 01 8b)
        let out = lift_bytes(&[0x00, 0x00, 0x01, 0x8b], 0x1000);
        assert_eq!(out.len(), 1, "expected one op; got {:?}", out);
        match &out[0].op {
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                assert_eq!(*dst, VReg::phys("x0"));
                assert_eq!(*lhs, Value::Reg(VReg::phys("x0")));
                assert_eq!(*rhs, Value::Reg(VReg::phys("x1")));
            }
            other => panic!("expected Bin Add; got {:?}", other),
        }
    }

    #[test]
    fn cmp_x0_x1_emits_unsigned_and_signed_flag_writes() {
        // CMP X0, X1 = SUBS XZR, X0, X1  = 0xeb01001f (LE: 1f 00 01 eb)
        let out = lift_bytes(&[0x1f, 0x00, 0x01, 0xeb], 0x1000);
        assert_eq!(out.len(), 5, "cmp should lift to 5 LLIR ops: {:?}", out);
        let flags: Vec<VReg> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::Cmp { dst, .. } => Some(dst.clone()),
                _ => None,
            })
            .collect();
        for want in [
            VReg::Flag(Flag::Z),
            VReg::Flag(Flag::C),
            VReg::Flag(Flag::Ule),
            VReg::Flag(Flag::Slt),
            VReg::Flag(Flag::Sle),
        ] {
            assert!(flags.contains(&want), "missing {:?} in {:?}", want, flags);
        }
    }

    #[test]
    fn b_hi_reads_inverted_unsigned_less_or_equal_flag() {
        // B.HI +0xc from 0x1000 = 0x54000068 (LE: 68 00 00 54).
        let out = lift_bytes(&[0x68, 0x00, 0x00, 0x54], 0x1000);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].op,
            Op::CondJump {
                cond: VReg::Flag(Flag::Ule),
                target: 0x100c,
                inverted: true,
            }
        );
    }

    #[test]
    fn tbz_and_tbnz_lift_to_explicit_bit_tests_and_branches() {
        // TBZ W1,#3,+8 = 0x36180041; TBNZ W2,#31,+4 = 0x37f80022.
        let out = lift_bytes(&[0x41, 0x00, 0x18, 0x36, 0x22, 0x00, 0xf8, 0x37], 0x1000);
        assert_eq!(out.len(), 4, "each bit-test branch needs two ops: {out:#?}");
        assert!(matches!(
            &out[0].op,
            Op::Extract {
                dst: VReg::Flag(Flag::Bit),
                src: Value::Reg(reg),
                hi: 4,
                lo: 3,
            } if *reg == VReg::phys("w1")
        ));
        assert!(matches!(
            &out[1].op,
            Op::CondJump {
                target: 0x1008,
                inverted: true,
                ..
            }
        ));
        assert!(matches!(
            &out[2].op,
            Op::Extract {
                dst: VReg::Flag(Flag::Bit),
                src: Value::Reg(reg),
                hi: 32,
                lo: 31,
            } if *reg == VReg::phys("w2")
        ));
        assert!(matches!(
            &out[3].op,
            Op::CondJump {
                target: 0x1008,
                inverted: false,
                ..
            }
        ));
    }

    #[test]
    fn bl_to_direct_target_lifts_to_call_direct() {
        // BL +0x20 from 0x1000:  target = 0x1020. Encoding:
        //   0x94000008  (imm26 = 0x8 = 32/4). LE: 08 00 00 94
        let out = lift_bytes(&[0x08, 0x00, 0x00, 0x94], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Call {
                target: CallTarget::Direct(addr),
            } => assert_eq!(*addr, 0x1020),
            other => panic!("expected Call Direct; got {:?}", other),
        }
    }

    #[test]
    fn b_to_direct_target_lifts_to_jump() {
        // B +0x10 from 0x2000: 0x14000004  (LE: 04 00 00 14) — target 0x2010
        let out = lift_bytes(&[0x04, 0x00, 0x00, 0x14], 0x2000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Jump { target } => assert_eq!(*target, 0x2010),
            other => panic!("expected Jump; got {:?}", other),
        }
    }

    #[test]
    fn movz_x0_imm_lifts_to_assign() {
        // MOVZ X0, #0x1234 = 0xd2824680  (LE: 80 46 82 d2)
        // imm16 = 0x1234, hw = 0.
        let out = lift_bytes(&[0x80, 0x46, 0x82, 0xd2], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Assign {
                dst,
                src: Value::Const(v),
            } => {
                assert_eq!(*dst, VReg::phys("x0"));
                assert_eq!(*v, 0x1234);
            }
            other => panic!("expected Assign of const; got {:?}", other),
        }
    }

    #[test]
    fn movk_preserves_other_bits_with_a_masked_update() {
        // MOVK W8,#0x4004,LSL#16 = 0x72a80088.
        let out = lift_bytes(&[0x88, 0x00, 0xa8, 0x72], 0x1000);
        assert_eq!(out.len(), 2, "movk should be an and/or update: {out:#?}");
        assert!(matches!(
            &out[0].op,
            Op::Bin {
                dst,
                op: BinOp::And,
                lhs: Value::Reg(src),
                rhs: Value::Const(0xffff),
            } if *dst == VReg::phys("w8") && *src == VReg::phys("w8")
        ));
        assert!(matches!(
            &out[1].op,
            Op::Bin {
                dst,
                op: BinOp::Or,
                rhs: Value::Const(0x4004_0000),
                ..
            } if *dst == VReg::phys("w8")
        ));
    }

    #[test]
    fn unscaled_load_store_keep_displacement_and_register_width() {
        // LDUR W22,[X27,#-0x28]; STUR W9,[X27,#-0x30].
        let out = lift_bytes(&[0x76, 0x83, 0x5d, 0xb8, 0x69, 0x03, 0x1d, 0xb8], 0x1000);
        assert!(matches!(
            &out[0].op,
            Op::Load {
                dst,
                addr: MemOp { disp: -0x28, size: 4, .. },
            } if *dst == VReg::phys("w22")
        ));
        assert!(matches!(
            &out[1].op,
            Op::Store {
                src: Value::Reg(src),
                addr: MemOp { disp: -0x30, size: 4, .. },
            } if *src == VReg::phys("w9")
        ));
    }

    #[test]
    fn aarch64_environment_and_hint_ops_are_typed_intrinsics() {
        // PACIASP; MRS X8,SP_EL0; DMB OSHST.
        let out = lift_bytes(
            &[
                0x3f, 0x23, 0x03, 0xd5, 0x08, 0x41, 0x38, 0xd5, 0xbf, 0x32, 0x03, 0xd5,
            ],
            0x1000,
        );
        assert!(matches!(
            &out[0].op,
            Op::Intrinsic { name, outs, .. } if name == "paciasp" && outs.is_empty()
        ));
        assert!(matches!(
            &out[1].op,
            Op::Intrinsic { name, outs, .. }
                if name == "mrs_sp_el0"
                    && outs == &vec![(VReg::phys("x8"), Width::W64)]
        ));
        assert!(matches!(
            &out[2].op,
            Op::Intrinsic { name, outs, .. } if name == "dmb" && outs.is_empty()
        ));
    }

    #[test]
    fn neg_lifts_to_unary_negation() {
        // NEG X8,X23 = 0xcb1703e8.
        let out = lift_bytes(&[0xe8, 0x03, 0x17, 0xcb], 0x1000);
        assert_eq!(
            out[0].op,
            Op::Un {
                dst: VReg::phys("x8"),
                op: UnOp::Neg,
                src: Value::Reg(VReg::phys("x23")),
            }
        );
    }

    #[test]
    fn flag_consumers_and_flag_setting_aliases_have_explicit_semantics() {
        // CMN X0,#1; TST X1,X2; CSEL X0,X1,X2,HI; CSET W0,NE;
        // CINC X0,X1,EQ; NGC X8,XZR.
        let out = lift_bytes(
            &[
                0x1f, 0x04, 0x00, 0xb1, 0x3f, 0x00, 0x02, 0xea, 0x20, 0x80, 0x82, 0x9a, 0xe0, 0x07,
                0x9f, 0x1a, 0x20, 0x14, 0x81, 0x9a, 0xe8, 0x03, 0x1f, 0xda,
            ],
            0x1000,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "residual alias hole: {out:#?}"
        );
        assert!(matches!(
            &out[0].op,
            Op::Intrinsic { name, ins, .. } if name == "aarch64_cmn64" && ins.len() == 2
        ));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Intrinsic { name, ins, .. } if name == "aarch64_tst64" && ins.len() == 2
        )));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Ite { dst, width: Width::W64, .. } if *dst == VReg::phys("x0")
        )));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Ite { dst, width: Width::W32, .. } if *dst == VReg::phys("w0")
        )));
    }

    #[test]
    fn bitfield_aliases_lower_without_opaque_holes() {
        // BFI W9,W10,#8,#8; BFXIL W9,W8,#0,#8; UBFX W2,W8,#4,#4.
        let out = lift_bytes(
            &[
                0x49, 0x1d, 0x18, 0x33, 0x09, 0x1d, 0x00, 0x33, 0x02, 0x1d, 0x04, 0x53,
            ],
            0x1000,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "residual bitfield hole: {out:#?}"
        );
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Extract {
                src: Value::Reg(src),
                hi: 8,
                lo: 0,
                ..
            } if *src == VReg::phys("w10")
        )));
        assert!(matches!(
            &out.last().expect("ubfx output").op,
            Op::ZExt {
                dst,
                from: Width(4),
                to: Width::W32,
                ..
            } if *dst == VReg::phys("w2")
        ));
    }

    #[test]
    fn pre_indexed_stp_emits_sp_writeback() {
        // STP fp, lr, [sp, #-0x30]!   encoding 0xa9bd7bfd (LE fd 7b bd a9)
        // Real glibc-style ARM64 prologue. Pre-indexed form — capstone's
        // writeback flag is set and the memory operand's disp is -0x30.
        let out = lift_bytes(&[0xfd, 0x7b, 0xbd, 0xa9], 0x1000);
        // We want: two Stores at [sp - 0x30] and [sp - 0x28], followed by
        // an explicit sp += -0x30 writeback.
        let stores: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Store { .. }))
            .collect();
        assert_eq!(stores.len(), 2, "expected two stores; got {:#?}", out);
        let has_sp_writeback = out.iter().any(|i| {
            matches!(
                &i.op,
                Op::Bin {
                    dst,
                    op: BinOp::Add,
                    rhs: Value::Const(-0x30),
                    ..
                } if *dst == VReg::phys("sp")
            )
        });
        assert!(
            has_sp_writeback,
            "pre-indexed STP must emit an sp writeback: {:#?}",
            out
        );
    }

    #[test]
    fn stp_pair_decomposes_into_two_stores() {
        // STP X29, X30, [SP, #-16]!   = 0xa9bf7bfd  (LE: fd 7b bf a9)
        // Pre-index form with SP writeback. Capstone reports the memory
        // operand's base as SP and disp as -16 (writeback is modeled by
        // capstone separately; we don't model writeback yet and treat this
        // as a plain memory store pair).
        let out = lift_bytes(&[0xfd, 0x7b, 0xbf, 0xa9], 0x1000);
        // Should decompose into two stores.
        let stores: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Store { .. }))
            .collect();
        assert_eq!(stores.len(), 2, "expected two stores; got {:#?}", out);
        // The two store displacements must differ by 8 bytes.
        let disps: Vec<i64> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::Store {
                    addr: MemOp { disp, .. },
                    ..
                } => Some(*disp),
                _ => None,
            })
            .collect();
        assert_eq!(disps.len(), 2);
        assert_eq!((disps[1] - disps[0]).abs(), 8);
    }

    #[test]
    fn ldp_pair_decomposes_into_two_loads() {
        // LDP X29, X30, [SP, #16]   (immediate-offset form, no writeback)
        //   encoded: imm7=2 (scaled by 8 = 16), Rt2=30, Rn=31(SP), Rt=29.
        //   raw = 0xa9417bfd  (LE: fd 7b 41 a9)
        let out = lift_bytes(&[0xfd, 0x7b, 0x41, 0xa9], 0x1000);
        let loads: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Load { .. }))
            .collect();
        assert_eq!(loads.len(), 2, "expected two loads; got {:#?}", out);
    }

    #[test]
    fn unknown_mnemonic_preserves_source() {
        // MRS X0, NZCV = 0xd53b4200  (LE: 00 42 3b d5) — not in our lifter set.
        let out = lift_bytes(&[0x00, 0x42, 0x3b, 0xd5], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Unknown { mnemonic } => assert!(!mnemonic.is_empty(), "empty mnemonic in Unknown"),
            other => panic!(
                "expected Unknown preserving mnemonic ({}); got {:?}",
                last_op_mnem(&out),
                other
            ),
        }
    }

    #[test]
    fn real_arm64_binary_entry_lift_no_panic() {
        // End-to-end smoke against the committed ARM64 sample.
        let sample = std::path::Path::new(
            "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        );
        if !sample.exists() {
            eprintln!("sample missing: {}", sample.display());
            return;
        }
        let data = std::fs::read(sample).expect("read sample");
        let info = crate::analysis::entry::detect_entry(&data).expect("detect entry");
        let foff = info.file_offset.expect("file offset");
        let window = &data[foff..(foff + 128).min(data.len())];
        let ops = lift_bytes(window, info.entry_va);
        assert!(!ops.is_empty(), "no LLIR produced");
        // A compiled C entry invariably contains a call or branch within 128
        // bytes.
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Call { .. } | Op::Jump { .. } | Op::CondJump { .. } | Op::Return
            )),
            "expected some control-flow op in {:#?}",
            ops
        );
    }
}
