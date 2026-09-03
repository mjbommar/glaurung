//! x86 / x86-64 packed (SSE integer and float) lowering into the scalar LLIR.
//!
//! An XMM register is represented as four independent 32-bit dword lanes rather
//! than one 128-bit value, so the existing scalar LLIR, SSA, and C backend carry
//! exact lane dataflow without a second vector AST. `lift_x86`'s dispatch calls
//! into this module; the whole-register view is reconciled afterwards by
//! `super::synchronise_xmm_views`.

use iced_x86::{OpKind, Register};

use crate::ir::types::*;

use super::{mem_op_of, reg_name, zero_extending_gp_view};

pub(super) fn xorps_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    packed_dword_binary_ops(instr, BinOp::Xor)
}

/// One signed/unsigned 32-bit lane of an XMM register.
///
/// Packed integer operations are not scalar 128-bit arithmetic. Representing
/// the four dword lanes independently lets the existing scalar LLIR, SSA, and C
/// backend preserve exact lane dataflow without adding a second vector AST.
pub(super) fn packed_dword_lane(register: Register, lane: usize) -> VReg {
    crate::ir::types::packed_dword_lane(&reg_name(register), lane)
}

pub(super) fn is_xmm_register(register: Register) -> bool {
    reg_name(register)
        .strip_prefix("xmm")
        .is_some_and(|index| index.parse::<u8>().is_ok())
}

fn is_ymm_register(register: Register) -> bool {
    reg_name(register)
        .strip_prefix("ymm")
        .is_some_and(|index| index.parse::<u8>().is_ok())
}

fn packed_dword_lane_count(register: Register) -> Option<usize> {
    if is_xmm_register(register) {
        Some(4)
    } else if is_ymm_register(register) {
        Some(8)
    } else {
        None
    }
}

/// Define both scalar-LLIR views of a zeroed XMM register. Scalar floating
/// moves consume the whole-register name while packed operations consume four
/// dword lanes; a self-XOR proves all five values simultaneously.
fn xmm_zero_ops(register: Register) -> Vec<Op> {
    let mut ops = vec![Op::Assign {
        dst: VReg::phys(reg_name(register)),
        src: Value::Const(0),
    }];
    ops.extend((0..4).map(|lane| Op::Assign {
        dst: packed_dword_lane(register, lane),
        src: Value::Const(0),
    }));
    ops
}

pub(super) fn packed_dword_move_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => (0..4)
            .map(|lane| {
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                Op::Load {
                    dst: packed_dword_lane(instr.op_register(0), lane),
                    addr,
                }
            })
            .collect(),
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => (0..4)
            .map(|lane| {
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                Op::Store {
                    addr,
                    src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
                }
            })
            .collect(),
        (OpKind::Register, OpKind::Register)
            if is_xmm_register(instr.op_register(0)) && is_xmm_register(instr.op_register(1)) =>
        {
            (0..4)
                .map(|lane| Op::Assign {
                    dst: packed_dword_lane(instr.op_register(0), lane),
                    src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
                })
                .collect()
        }
        _ => vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }],
    }
}

/// Lower the fixed-width 256-bit VMOVDQU forms as eight lossless dword lanes.
///
/// This deliberately accepts only YMM forms. A move does not interpret its
/// bits, so lane decomposition is exact; accepting other AVX operations here
/// would falsely imply that the scalar LLIR models their vector semantics.
pub(super) fn vex_ymm_dword_move_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: "vmovdqu".into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_ymm_register(instr.op_register(0)) => (0..8)
            .map(|lane| {
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                Op::Load {
                    dst: packed_dword_lane(instr.op_register(0), lane),
                    addr,
                }
            })
            .collect(),
        (OpKind::Memory, OpKind::Register) if is_ymm_register(instr.op_register(1)) => (0..8)
            .map(|lane| {
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                Op::Store {
                    addr,
                    src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
                }
            })
            .collect(),
        (OpKind::Register, OpKind::Register)
            if is_ymm_register(instr.op_register(0)) && is_ymm_register(instr.op_register(1)) =>
        {
            (0..8)
                .map(|lane| Op::Assign {
                    dst: packed_dword_lane(instr.op_register(0), lane),
                    src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
                })
                .collect()
        }
        _ => vec![Op::Unknown {
            mnemonic: "vmovdqu".into(),
        }],
    }
}

/// Replicate one byte into every byte of a 256-bit YMM destination.
///
/// The replicated dword is `zext(byte) * 0x01010101`; assigning that same
/// value to eight dword lanes is the exact 32-byte broadcast.
pub(super) fn vex_ymm_byte_broadcast_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_ymm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "vpbroadcastb".into(),
        }];
    }
    let byte = VReg::Temp(104);
    let widened = VReg::Temp(105);
    let replicated = VReg::Temp(106);
    let mut ops = match instr.op_kind(1) {
        OpKind::Memory => {
            let mut addr = mem_op_of(instr);
            addr.size = 1;
            vec![Op::Load {
                dst: byte.clone(),
                addr,
            }]
        }
        OpKind::Register if is_xmm_register(instr.op_register(1)) => vec![Op::Trunc {
            dst: byte.clone(),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), 0)),
            from: Width::W32,
            to: Width::W8,
        }],
        _ => {
            return vec![Op::Unknown {
                mnemonic: "vpbroadcastb".into(),
            }];
        }
    };
    ops.extend([
        Op::ZExt {
            dst: widened.clone(),
            src: Value::Reg(byte),
            from: Width::W8,
            to: Width::W32,
        },
        Op::Bin {
            dst: replicated.clone(),
            op: BinOp::Mul,
            lhs: Value::Reg(widened),
            rhs: Value::Const(0x0101_0101),
        },
    ]);
    ops.extend((0..8).map(|lane| Op::Assign {
        dst: packed_dword_lane(instr.op_register(0), lane),
        src: Value::Reg(replicated.clone()),
    }));
    ops
}

/// Move the low 64 bits of an XMM register as two explicit dword lanes.
///
/// The XMM load/register forms clear the upper 64 bits; the memory store form
/// writes only the two low lanes. MMX and general-purpose-register MOVQ forms
/// deliberately remain unsupported rather than being given XMM semantics.
pub(super) fn packed_qword_move_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: "movq".into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => {
            let dst = instr.op_register(0);
            let mut ops: Vec<_> = (0..2)
                .map(|lane| {
                    let mut addr = mem_op_of(instr);
                    addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                    addr.size = 4;
                    Op::Load {
                        dst: packed_dword_lane(dst, lane),
                        addr,
                    }
                })
                .collect();
            ops.extend((2..4).map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            ops
        }
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => {
            let src = instr.op_register(1);
            (0..2)
                .map(|lane| {
                    let mut addr = mem_op_of(instr);
                    addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                    addr.size = 4;
                    Op::Store {
                        addr,
                        src: Value::Reg(packed_dword_lane(src, lane)),
                    }
                })
                .collect()
        }
        (OpKind::Register, OpKind::Register)
            if is_xmm_register(instr.op_register(0)) && is_xmm_register(instr.op_register(1)) =>
        {
            let dst = instr.op_register(0);
            let src = instr.op_register(1);
            let mut ops: Vec<_> = (0..2)
                .map(|lane| Op::Assign {
                    dst: packed_dword_lane(dst, lane),
                    src: Value::Reg(packed_dword_lane(src, lane)),
                })
                .collect();
            ops.extend((2..4).map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            ops
        }
        (OpKind::Register, OpKind::Register)
            if is_xmm_register(instr.op_register(0))
                && !is_xmm_register(instr.op_register(1))
                && phys_reg_width(&reg_name(instr.op_register(1))) == Some(Width::W64) =>
        {
            let dst = instr.op_register(0);
            let src = VReg::phys(reg_name(instr.op_register(1)));
            vec![
                Op::Trunc {
                    dst: packed_dword_lane(dst, 0),
                    src: Value::Reg(src.clone()),
                    from: Width::W64,
                    to: Width::W32,
                },
                Op::Extract {
                    dst: packed_dword_lane(dst, 1),
                    src: Value::Reg(src),
                    hi: 64,
                    lo: 32,
                },
                Op::Assign {
                    dst: packed_dword_lane(dst, 2),
                    src: Value::Const(0),
                },
                Op::Assign {
                    dst: packed_dword_lane(dst, 3),
                    src: Value::Const(0),
                },
                // The SCALAR view of the same bits. An XMM register has two
                // representations in this LLIR — the whole-register name that
                // scalar float ops use, and four dword lanes that packed ops
                // use — and nothing kept them in step. A `movsd` wrote the
                // scalar name, a following `movq %xmm0,%rax` read the lanes,
                // and the lanes still held whatever zeroed them: GCC's `-O0`
                // float return (`movsd -8(%rbp),%xmm0 ; movq %xmm0,%rax ;
                // movq %rax,%xmm0`) therefore returned a zero it had
                // reconstructed from empty lanes. Defining both here, and
                // reading the scalar below, closes the loop in both directions.
                Op::Assign {
                    dst: VReg::phys(reg_name(dst)),
                    src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
                },
            ]
        }
        (OpKind::Register, OpKind::Register)
            if !is_xmm_register(instr.op_register(0))
                && is_xmm_register(instr.op_register(1))
                && phys_reg_width(&reg_name(instr.op_register(0))) == Some(Width::W64) =>
        {
            vec![Op::Assign {
                dst: VReg::phys(reg_name(instr.op_register(0))),
                src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
            }]
        }
        _ => vec![Op::Unknown {
            mnemonic: "movq".into(),
        }],
    }
}

pub(super) fn packed_dword_binary_ops(instr: &iced_x86::Instruction, op: BinOp) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    }
    if op == BinOp::Xor
        && instr.op_kind(1) == OpKind::Register
        && instr.op_register(1) == instr.op_register(0)
    {
        return xmm_zero_ops(instr.op_register(0));
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    };
    for (lane, source) in sources.into_iter().enumerate() {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        ops.push(Op::Bin {
            dst: dst.clone(),
            op,
            lhs: Value::Reg(dst),
            rhs: source,
        });
    }
    ops
}

/// Lift a fixed-width three-operand VEX packed-dword operation.
///
/// VEX makes the old destination an explicit first source: `dst = lhs op rhs`.
/// Keeping that distinction matters whenever `dst != lhs`; routing this
/// through the two-operand SSE helper would silently read stale destination
/// lanes instead.
pub(super) fn vex_packed_dword_binary_ops(instr: &iced_x86::Instruction, op: BinOp) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
    {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    }
    let destination = instr.op_register(0);
    let lhs = instr.op_register(1);
    let Some(lanes) = packed_dword_lane_count(destination) else {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    };
    if packed_dword_lane_count(lhs) != Some(lanes) {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    }
    if op == BinOp::Xor && instr.op_kind(2) == OpKind::Register && instr.op_register(2) == lhs {
        return if lanes == 4 {
            xmm_zero_ops(destination)
        } else {
            (0..lanes)
                .map(|lane| Op::Assign {
                    dst: packed_dword_lane(destination, lane),
                    src: Value::Const(0),
                })
                .collect()
        };
    }
    let mut ops = Vec::new();
    let rhs: Vec<Value> = match instr.op_kind(2) {
        OpKind::Register if packed_dword_lane_count(instr.op_register(2)) == Some(lanes) => (0
            ..lanes)
            .map(|lane| Value::Reg(packed_dword_lane(instr.op_register(2), lane)))
            .collect(),
        OpKind::Memory => (0..lanes)
            .map(|lane| {
                let temporary = VReg::Temp(96 + lane as u32);
                let mut address = mem_op_of(instr);
                address.disp = address.disp.saturating_add((lane * 4) as i64);
                address.size = 4;
                ops.push(Op::Load {
                    dst: temporary.clone(),
                    addr: address,
                });
                Value::Reg(temporary)
            })
            .collect(),
        _ => {
            return vec![Op::Unknown {
                mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
            }];
        }
    };
    for (lane, rhs) in rhs.into_iter().enumerate() {
        ops.push(Op::Bin {
            dst: packed_dword_lane(destination, lane),
            op,
            lhs: Value::Reg(packed_dword_lane(lhs, lane)),
            rhs,
        });
    }
    ops
}

/// SHUFPS treats its operands as four 32-bit bit-pattern lanes. The low two
/// selectors address the old destination and the high two address the source.
pub(super) fn packed_float_shuffle_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "shufps".into(),
        }];
    }
    let dst = instr.op_register(0);
    let src = instr.op_register(1);
    let control = instr.immediate8();
    let mut ops = Vec::with_capacity(12);
    for lane in 0..4 {
        ops.push(Op::Assign {
            dst: VReg::Temp(84 + lane as u32),
            src: Value::Reg(packed_dword_lane(dst, lane)),
        });
        ops.push(Op::Assign {
            dst: VReg::Temp(88 + lane as u32),
            src: Value::Reg(packed_dword_lane(src, lane)),
        });
    }
    for lane in 0..4 {
        let selected = ((control >> (lane * 2)) & 0x3) as u32;
        let temporary = if lane < 2 {
            84 + selected
        } else {
            88 + selected
        };
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: Value::Reg(VReg::Temp(temporary)),
        });
    }
    ops
}

/// MOVMSKPS packs each dword lane's sign bit into a four-bit GPR mask.
pub(super) fn packed_float_sign_mask_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "movmskps".into(),
        }];
    }
    let dst = VReg::phys(reg_name(instr.op_register(0)));
    let src = instr.op_register(1);
    let mut ops = vec![Op::Assign {
        dst: dst.clone(),
        src: Value::Const(0),
    }];
    for lane in 0..4 {
        let sign = VReg::Temp(120 + lane as u32 * 2);
        let shifted = VReg::Temp(121 + lane as u32 * 2);
        ops.push(Op::Cmp {
            dst: sign.clone(),
            op: CmpOp::Slt,
            lhs: Value::Reg(packed_dword_lane(src, lane)),
            rhs: Value::Const(0),
        });
        ops.push(Op::Bin {
            dst: shifted.clone(),
            op: BinOp::Shl,
            lhs: Value::Reg(sign),
            rhs: Value::Const(lane as i64),
        });
        ops.push(Op::Bin {
            dst: dst.clone(),
            op: BinOp::Or,
            lhs: Value::Reg(dst.clone()),
            rhs: Value::Reg(shifted),
        });
    }
    ops
}

/// PEXTRW zero-extends one selected 16-bit XMM word into a 32-bit GPR.
pub(super) fn packed_word_extract_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pextrw".into(),
        }];
    }
    let word = usize::from(instr.immediate8() & 7);
    let lane = word / 2;
    let extracted = VReg::Temp(128);
    let mut ops = if word % 2 == 0 {
        vec![Op::Trunc {
            dst: extracted.clone(),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
            from: Width::W32,
            to: Width::W16,
        }]
    } else {
        vec![Op::Extract {
            dst: extracted.clone(),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
            hi: 32,
            lo: 16,
        }]
    };
    ops.push(Op::ZExt {
        dst: VReg::phys(reg_name(instr.op_register(0))),
        src: Value::Reg(extracted),
        from: Width::W16,
        to: Width::W32,
    });
    ops
}

/// Lift PSLLD's immediate form as four independent 32-bit lane shifts.
///
/// Intel specifies a zero result, rather than a masked shift count, when the
/// immediate is greater than 31. Register/memory count operands remain
/// unsupported until the low-64-bit count extraction is represented exactly.
pub(super) fn packed_dword_immediate_shift_left_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "pslld".into(),
        }];
    }
    let count = instr.immediate8();
    (0..4)
        .map(|lane| {
            let dst = packed_dword_lane(instr.op_register(0), lane);
            if count > 31 {
                Op::Assign {
                    dst,
                    src: Value::Const(0),
                }
            } else {
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(dst),
                    rhs: Value::Const(i64::from(count)),
                }
            }
        })
        .collect()
}

/// Lift PSRLD's immediate form as four independent unsigned 32-bit shifts.
/// Like PSLLD, Intel defines counts above 31 to clear each complete lane.
pub(super) fn packed_dword_immediate_logical_shift_right_ops(
    instr: &iced_x86::Instruction,
) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "psrld".into(),
        }];
    }
    let count = instr.immediate8();
    let mut ops = Vec::with_capacity(if count > 31 { 4 } else { 8 });
    for lane in 0..4 {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        if count > 31 {
            ops.push(Op::Assign {
                dst,
                src: Value::Const(0),
            });
        } else {
            let narrowed = VReg::Temp(140 + lane as u32);
            ops.push(Op::Trunc {
                dst: narrowed.clone(),
                src: Value::Reg(dst.clone()),
                from: Width::W64,
                to: Width::W32,
            });
            ops.push(Op::Bin {
                dst,
                op: BinOp::Shr,
                lhs: Value::Reg(narrowed),
                rhs: Value::Const(i64::from(count)),
            });
        }
    }
    ops
}

/// Lift PSRAD's immediate form as four signed 32-bit lane shifts.
///
/// Counts above the lane width produce the sign mask, which is equivalent to
/// shifting each signed dword by 31. Non-immediate count operands remain
/// unsupported until their low-64-bit count extraction is represented.
pub(super) fn packed_dword_immediate_arithmetic_shift_right_ops(
    instr: &iced_x86::Instruction,
) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "psrad".into(),
        }];
    }
    let count = instr.immediate8().min(31);
    (0..4)
        .map(|lane| {
            let dst = packed_dword_lane(instr.op_register(0), lane);
            Op::Bin {
                dst: dst.clone(),
                op: BinOp::Sar,
                lhs: Value::Reg(dst),
                rhs: Value::Const(i64::from(count)),
            }
        })
        .collect()
}

/// Snapshot two low dwords from each operand and write the requested lane order.
fn packed_low_unpack_ops(
    instr: &iced_x86::Instruction,
    mnemonic: &str,
    lane_order: [u32; 4],
) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    };
    let dst = instr.op_register(0);
    for (temporary, source) in [
        (104, Value::Reg(packed_dword_lane(dst, 0))),
        (105, Value::Reg(packed_dword_lane(dst, 1))),
        (106, sources[0].clone()),
        (107, sources[1].clone()),
    ] {
        ops.push(Op::Assign {
            dst: VReg::Temp(temporary),
            src: source,
        });
    }
    for (lane, temporary) in lane_order.into_iter().enumerate() {
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: Value::Reg(VReg::Temp(temporary)),
        });
    }
    ops
}

/// Interleave the low two dwords: `[dst0, src0, dst1, src1]`.
///
/// All inputs are snapshotted before the destination is overwritten, which
/// preserves the in-place form (`punpckldq xmm0,xmm0`) exactly.
pub(super) fn packed_dword_unpack_low_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    packed_low_unpack_ops(instr, "punpckldq", [104, 106, 105, 107])
}

/// Interleave the complete low qwords: `[dst0, dst1, src0, src1]`.
pub(super) fn packed_qword_unpack_low_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    packed_low_unpack_ops(instr, "punpcklqdq", [104, 105, 106, 107])
}

/// Add two packed 64-bit lanes while retaining carry between their dword views.
pub(super) fn packed_qword_binary_ops(
    instr: &iced_x86::Instruction,
    op: BinOp,
    mnemonic: &str,
) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    };
    let dst = instr.op_register(0);
    for qword in 0..2 {
        let low_lane = qword * 2;
        let high_lane = low_lane + 1;
        let lhs = VReg::Temp(108 + qword as u32 * 3);
        let rhs = VReg::Temp(109 + qword as u32 * 3);
        let sum = VReg::Temp(110 + qword as u32 * 3);
        ops.extend([
            Op::Concat {
                dst: lhs.clone(),
                hi: Value::Reg(packed_dword_lane(dst, high_lane)),
                lo: Value::Reg(packed_dword_lane(dst, low_lane)),
            },
            Op::Concat {
                dst: rhs.clone(),
                hi: sources[high_lane].clone(),
                lo: sources[low_lane].clone(),
            },
            Op::Bin {
                dst: sum.clone(),
                op,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(rhs),
            },
            Op::Trunc {
                dst: packed_dword_lane(dst, low_lane),
                src: Value::Reg(sum.clone()),
                from: Width::W64,
                to: Width::W32,
            },
            Op::Extract {
                dst: packed_dword_lane(dst, high_lane),
                src: Value::Reg(sum),
                hi: 64,
                lo: 32,
            },
        ]);
    }
    ops
}

/// Snapshot the four dword lanes of a packed instruction's second operand.
/// Register operands already have independent lane names; memory operands need
/// explicit scalar loads so the ordinary readonly-data pass can materialise
/// their bytes into portable constants later in the AST pipeline.
pub(super) fn packed_dword_sources(
    instr: &iced_x86::Instruction,
    first_temp: u32,
) -> Option<(Vec<Op>, Vec<Value>)> {
    match instr.op_kind(1) {
        OpKind::Register if is_xmm_register(instr.op_register(1)) => Some((
            Vec::new(),
            (0..4)
                .map(|lane| Value::Reg(packed_dword_lane(instr.op_register(1), lane)))
                .collect(),
        )),
        OpKind::Memory => {
            let mut ops = Vec::with_capacity(4);
            let mut values = Vec::with_capacity(4);
            for lane in 0..4 {
                let temporary = VReg::Temp(first_temp + lane as u32);
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                ops.push(Op::Load {
                    dst: temporary.clone(),
                    addr,
                });
                values.push(Value::Reg(temporary));
            }
            Some((ops, values))
        }
        _ => None,
    }
}

/// Lift PANDN's lane-wise `dst = (~dst) & src` semantics.
///
/// This cannot use [`packed_dword_binary_ops`]: unlike ordinary packed binary
/// operations, PANDN complements the old destination before combining it with
/// the source. Snapshot that complemented value in a temporary so the write to
/// each destination lane remains explicit for SSA and the C backend.
pub(super) fn packed_dword_and_not_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pandn".into(),
        }];
    }
    let mut ops = Vec::with_capacity(8);
    for lane in 0..4 {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let complemented = VReg::Temp(88 + lane as u32);
        ops.push(Op::Un {
            dst: complemented.clone(),
            op: UnOp::Not,
            src: Value::Reg(dst.clone()),
        });
        ops.push(Op::Bin {
            dst,
            op: BinOp::And,
            lhs: Value::Reg(complemented),
            rhs: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
        });
    }
    ops
}

pub(super) fn packed_dword_compare_equal_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "pcmpeqd".into(),
        }];
    }
    if instr.op_kind(1) == OpKind::Register && instr.op_register(0) == instr.op_register(1) {
        return (0..4)
            .map(|lane| Op::Assign {
                dst: packed_dword_lane(instr.op_register(0), lane),
                src: Value::Const(-1),
            })
            .collect();
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: "pcmpeqd".into(),
        }];
    };
    for (lane, source) in sources.into_iter().enumerate() {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let condition = VReg::Temp(96 + lane as u32);
        ops.push(Op::Cmp {
            dst: condition.clone(),
            op: CmpOp::Eq,
            lhs: Value::Reg(dst.clone()),
            rhs: source,
        });
        ops.push(Op::Ite {
            dst,
            cond: condition,
            t: Value::Const(-1),
            e: Value::Const(0),
            width: Width::W32,
        });
    }
    ops
}

pub(super) fn packed_dword_shuffle_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pshufd".into(),
        }];
    }
    let control = instr.immediate8();
    let mut ops = Vec::with_capacity(8);
    // Snapshot all input lanes first: PSHUFD permits an in-place destination,
    // and sequential assignments must not feed later selections from a lane
    // already overwritten by this same machine instruction.
    for lane in 0..4 {
        ops.push(Op::Assign {
            dst: VReg::Temp(84 + lane as u32),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
        });
    }
    for lane in 0..4 {
        let selected = ((control >> (lane * 2)) & 0x3) as u32;
        ops.push(Op::Assign {
            dst: packed_dword_lane(instr.op_register(0), lane),
            src: Value::Reg(VReg::Temp(84 + selected)),
        });
    }
    ops
}

pub(super) fn movd_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: "movd".into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Register) => {
            let dst = instr.op_register(0);
            let src = instr.op_register(1);
            let dst_name = reg_name(dst);
            let src_name = reg_name(src);
            if dst_name.starts_with("xmm") {
                let mut ops = vec![Op::Assign {
                    dst: packed_dword_lane(dst, 0),
                    src: Value::Reg(VReg::phys(src_name)),
                }];
                ops.extend((1..4).map(|lane| Op::Assign {
                    dst: packed_dword_lane(dst, lane),
                    src: Value::Const(0),
                }));
                ops
            } else if src_name.starts_with("xmm") {
                let src = Value::Reg(packed_dword_lane(src, 0));
                if bits == 64 && zero_extending_gp_view(&dst_name, bits).is_some() {
                    vec![Op::ZExt {
                        dst: VReg::phys(dst_name),
                        src,
                        from: Width::W32,
                        to: Width::W64,
                    }]
                } else {
                    vec![Op::Assign {
                        dst: VReg::phys(dst_name),
                        src,
                    }]
                }
            } else {
                vec![Op::Unknown {
                    mnemonic: "movd".into(),
                }]
            }
        }
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => {
            let dst = instr.op_register(0);
            let mut addr = mem_op_of(instr);
            addr.size = 4;
            let mut ops = vec![Op::Load {
                dst: packed_dword_lane(dst, 0),
                addr,
            }];
            ops.extend((1..4).map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            ops
        }
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => {
            let mut addr = mem_op_of(instr);
            addr.size = 4;
            vec![Op::Store {
                addr,
                src: Value::Reg(packed_dword_lane(instr.op_register(1), 0)),
            }]
        }
        _ => vec![Op::Unknown {
            mnemonic: "movd".into(),
        }],
    }
}
