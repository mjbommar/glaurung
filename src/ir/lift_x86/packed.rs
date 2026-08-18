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
fn packed_dword_lane(register: Register, lane: usize) -> VReg {
    crate::ir::types::packed_dword_lane(&reg_name(register), lane)
}

fn is_xmm_register(register: Register) -> bool {
    reg_name(register)
        .strip_prefix("xmm")
        .is_some_and(|index| index.parse::<u8>().is_ok())
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

/// Move ONE 64-bit half of an XMM register to or from memory, leaving the other
/// half of the register alone.
///
/// This is `MOVLPD`/`MOVLPS` (`half == XmmHalf::Low`, lanes `_d0`/`_d1`) and
/// `MOVHPD`/`MOVHPS` (`half == XmmHalf::High`, lanes `_d2`/`_d3`). All four
/// mnemonics encode ONLY memory forms — `iced_x86` has exactly eight `Code`
/// variants for them, `{Movlpd,Movhpd,Movlps,Movhps}_{xmm_m64,m64_xmm}`, and no
/// register/register variant at all. (`MOVLHPS`/`MOVHLPS` are the reg-reg
/// operations, and they are different instructions with their own mnemonics.)
/// The non-memory arm below is therefore unreachable by construction and exists
/// only so a future VEX/EVEX widening cannot silently acquire wrong semantics.
///
/// What separates these from [`packed_qword_move_ops`] is the half NOT named:
/// `movq xmm, m64` zeroes bits 64..127, whereas `movlpd xmm, m64` leaves them
/// exactly as they were, and `movhpd` leaves bits 0..63 alone. Reusing MOVQ's
/// lowering would therefore invent a zero the machine never wrote.
///
/// The MEMORY side is one 64-bit access, because that is what the machine
/// performs. Splitting it into two dword accesses is bit-identical but not
/// inference-identical: the stack-object recovery reads access widths as
/// evidence of the frame layout, and on `hfa197_quad4f_roundtrip` two 4-byte
/// stores made the spill slot two `int` objects, after which the function's
/// own 8-byte reload of it narrowed to the first four bytes and silently
/// dropped the second `float`. One 8-byte access, unpacked into lanes through
/// a temporary, keeps both the lane precision and the real access width.
///
/// The REGISTER side leaves both XMM spellings consistent. A LOW load defines
/// all three names the transferred bits have — lanes `_d0`/`_d1` and the
/// whole-register scalar view, which IS the low quadword. A HIGH load defines
/// `_d2`/`_d3` and deliberately nothing else, because `movhpd` does not touch
/// the low quadword and rebuilding the scalar name would overwrite a live
/// value. A LOW store READS the whole-register spelling rather than the lanes:
/// the two views are synchronised in one direction only — a lane write is
/// mirrored to the scalar name by [`super::synchronise_xmm_views`], a scalar
/// write is not mirrored to the lanes — so the scalar name is the one spelling
/// live under both kinds of producer. A HIGH store has no scalar spelling
/// available and concatenates its two lanes.
///
/// Clang's `-O0` System V code returns a four-`float` aggregate in `xmm0:xmm1`
/// and spills it with `movlpd %xmm0,-0x38(%rbp) ; movlpd %xmm1,-0x30(%rbp)`.
/// Unlifted, those two stores were `Op::Unknown`, which declares no register
/// reads: every consumer of the returned value vanished, the `SsePair` result
/// split had no users left and was dead-code eliminated, and — because
/// `movlpd` ends in `pd` — `ast::float_gate` classified it an unmodelled float
/// producer and shut the whole-function float gate, costing that one function
/// eight further `cvttss2si` conversions.
pub(super) fn packed_qword_half_move_ops(instr: &iced_x86::Instruction, half: XmmHalf) -> Vec<Op> {
    let mnemonic = || format!("{:?}", instr.mnemonic()).to_ascii_lowercase();
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: mnemonic(),
        }];
    }
    let (low_lane, high_lane) = (half.first_lane(), half.first_lane() + 1);
    let transfer = VReg::Temp(HALF_MOVE_TEMP);
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => {
            let dst = instr.op_register(0);
            let mut addr = mem_op_of(instr);
            addr.size = 8;
            let mut ops = vec![
                Op::Load {
                    dst: transfer.clone(),
                    addr,
                },
                Op::Trunc {
                    dst: packed_dword_lane(dst, low_lane),
                    src: Value::Reg(transfer.clone()),
                    from: Width::W64,
                    to: Width::W32,
                },
                Op::Extract {
                    dst: packed_dword_lane(dst, high_lane),
                    src: Value::Reg(transfer.clone()),
                    hi: 64,
                    lo: 32,
                },
            ];
            if half == XmmHalf::Low {
                // The whole-register spelling IS the low quadword, and this
                // instruction has just defined all of it. State that from the
                // 64-bit value rather than leaving `synchronise_xmm_views` to
                // rebuild it by concatenating the two lanes back together.
                ops.push(Op::Assign {
                    dst: VReg::phys(reg_name(dst)),
                    src: Value::Reg(transfer),
                });
            }
            ops
        }
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => {
            let src = instr.op_register(1);
            let mut addr = mem_op_of(instr);
            addr.size = 8;
            match half {
                // Read the WHOLE-REGISTER spelling, not the two lanes. The two
                // views are kept in step in one direction only: a lane write is
                // mirrored to the scalar name by `synchronise_xmm_views`, while
                // a scalar write (every `movsd`, every `cvtsi2sd`) leaves the
                // lanes untouched. The scalar name is therefore the spelling
                // that is live under both producers, and reading the lanes here
                // would find nothing after a scalar one.
                XmmHalf::Low => vec![Op::Store {
                    addr,
                    src: Value::Reg(VReg::phys(reg_name(src))),
                }],
                // Bits 64..127 have no scalar spelling to read, so the high
                // half is assembled from the only names that describe it.
                XmmHalf::High => vec![
                    Op::Concat {
                        dst: transfer.clone(),
                        hi: Value::Reg(packed_dword_lane(src, high_lane)),
                        lo: Value::Reg(packed_dword_lane(src, low_lane)),
                    },
                    Op::Store {
                        addr,
                        src: Value::Reg(transfer),
                    },
                ],
            }
        }
        _ => vec![Op::Unknown {
            mnemonic: mnemonic(),
        }],
    }
}

/// Scratch register for the 64-bit value a `MOVLP*`/`MOVHP*` transfers.
///
/// Temporaries are scoped to one lifted instruction, so this only has to avoid
/// the other temporaries this module spends inside a single lowering.
const HALF_MOVE_TEMP: u32 = 150;

/// Which 64-bit half of an XMM register a `MOVLP*`/`MOVHP*` names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum XmmHalf {
    /// Bits 0..63 — lanes `_d0`, `_d1`. Also the whole-register scalar view.
    Low,
    /// Bits 64..127 — lanes `_d2`, `_d3`.
    High,
}

impl XmmHalf {
    /// The lower-addressed of this half's two dword lanes.
    fn first_lane(self) -> usize {
        match self {
            XmmHalf::Low => 0,
            XmmHalf::High => 2,
        }
    }
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
fn packed_dword_sources(
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

pub(super) fn packed_dword_compare_greater_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pcmpgtd".into(),
        }];
    }
    let mut ops = Vec::with_capacity(8);
    for lane in 0..4 {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let src = packed_dword_lane(instr.op_register(1), lane);
        let condition = VReg::Temp(80 + lane as u32);
        // dst > src is the signed comparison src < dst. PCMPGTD writes an
        // all-ones mask for true, not the boolean value one.
        ops.push(Op::Cmp {
            dst: condition.clone(),
            op: CmpOp::Slt,
            lhs: Value::Reg(src),
            rhs: Value::Reg(dst.clone()),
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
