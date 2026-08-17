//! Scalar SSE (`movss`/`addsd`/`cvtsi2sd`/`comiss`, ...) lowering into the LLIR.
//!
//! These instructions address ONE lane of an XMM register under the whole-register
//! name, which is what separates them from `super::packed`: there the register is
//! four independent dword lanes, here it is a single float value. `lift_x86`'s
//! dispatch calls into this module; the two spellings are reconciled afterwards by
//! `super::synchronise_xmm_views`.
//!
//! The LLIR has no IEEE-754 arithmetic, so the value-producing forms lower to typed
//! [`Op::Intrinsic`]s that record the architectural destination and width -- enough
//! for SSA, liveness, and ABI recovery to stay sound while the AST layer turns the
//! mnemonic into the C operator or cast it denotes. The COMPARE forms are
//! different: their EFLAGS effect is exactly expressible, and
//! [`float_compare_flag_ops`] states it once for both SSE and x87.

use iced_x86::OpKind;

use crate::ir::types::*;

use super::{mem_op_of, reg_name, reg_size};

pub(super) fn scalar_move_ops(instr: &iced_x86::Instruction, width: u8, mnemonic: &str) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Register) => vec![Op::Assign {
            dst: VReg::phys(reg_name(instr.op_register(0))),
            src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
        }],
        (OpKind::Register, OpKind::Memory) => {
            let mut addr = mem_op_of(instr);
            addr.size = width;
            vec![Op::Load {
                dst: VReg::phys(reg_name(instr.op_register(0))),
                addr,
            }]
        }
        (OpKind::Memory, OpKind::Register) => {
            let mut addr = mem_op_of(instr);
            addr.size = width;
            vec![Op::Store {
                addr,
                src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
            }]
        }
        _ => vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }],
    }
}

/// Lift a scalar SSE arithmetic instruction with its real register footprint.
///
/// The integer LLIR cannot yet express IEEE-754 arithmetic, so representing
/// these as `Bin` would silently assign the wrong semantics.  A typed
/// intrinsic still records the architectural destination and inputs, which is
/// enough for SSA, liveness, and ABI output recovery to remain sound while the
/// float value/type lattice is introduced.
pub(super) fn scalar_float_binary_ops(
    instr: &iced_x86::Instruction,
    width: Width,
    mnemonic: &str,
) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }

    let dst = VReg::phys(reg_name(instr.op_register(0)));
    let mut ops = Vec::new();
    let rhs = match instr.op_kind(1) {
        OpKind::Register => Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
        OpKind::Memory => {
            let tmp = VReg::Temp(12);
            let mut addr = mem_op_of(instr);
            addr.size = u8::try_from(width.bytes()).expect("scalar SSE width fits MemOp");
            ops.push(Op::Load {
                dst: tmp.clone(),
                addr,
            });
            Value::Reg(tmp)
        }
        _ => {
            return vec![Op::Unknown {
                mnemonic: mnemonic.into(),
            }];
        }
    };
    ops.push(Op::Intrinsic {
        name: mnemonic.into(),
        ins: vec![Value::Reg(dst.clone()), rhs],
        outs: vec![(dst, width)],
        reads_mem: false,
        writes_mem: false,
    });
    ops
}

/// Encoded source width, in bytes, of a `cvtsi2ss`/`cvtsi2sd`.
///
/// The mnemonic alone is ambiguous: the `l` and `q` forms differ only in REX.W,
/// so the width has to come from the encoding. A memory source states its size
/// directly; a register source states it through the register chosen.
pub(super) fn scalar_convert_source_bytes(instr: &iced_x86::Instruction) -> u8 {
    match instr.op_kind(1) {
        OpKind::Register => reg_size(instr.op_register(1)),
        OpKind::Memory => instr.memory_size().size() as u8,
        _ => 4,
    }
}

/// Lift a scalar SSE conversion (`cvtss2sd`, `cvttsd2si`, `cvtsi2ss`, …).
///
/// One typed intrinsic per instruction, in the same shape
/// [`scalar_float_binary_ops`] uses: the architectural destination and its
/// width are recorded so SSA, liveness and ABI recovery stay sound, and the AST
/// layer turns the mnemonic into the C cast it denotes.
///
/// The SOURCE width is carried by the mnemonic rather than by the operand, and
/// deliberately so. `cvtsi2sdq %rax,%xmm0` and `cvtsi2sdl %eax,%xmm0` are
/// different instructions with different source widths but the same
/// destination, and reading the width off the destination would make a
/// `long`-to-`double` conversion indistinguishable from an `int`-to-`double`
/// one — which is exactly the disagreement `173_float_int_conversions`
/// separates `widen_int_to_float` from `widen_long_to_double` to detect.
pub(super) fn scalar_convert_ops(
    instr: &iced_x86::Instruction,
    mnemonic: &str,
    source_bytes: u8,
    destination: Width,
) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }

    let dst = VReg::phys(reg_name(instr.op_register(0)));
    let mut ops = Vec::new();
    let src = match instr.op_kind(1) {
        OpKind::Register => Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
        OpKind::Memory => {
            let tmp = VReg::Temp(13);
            let mut addr = mem_op_of(instr);
            addr.size = source_bytes;
            ops.push(Op::Load {
                dst: tmp.clone(),
                addr,
            });
            Value::Reg(tmp)
        }
        _ => {
            return vec![Op::Unknown {
                mnemonic: mnemonic.into(),
            }];
        }
    };
    ops.push(Op::Intrinsic {
        name: mnemonic.into(),
        ins: vec![src],
        outs: vec![(dst, destination)],
        reads_mem: false,
        writes_mem: false,
    });
    ops
}

/// The exact ZF/CF/PF/OF/SF/AF effect of `ucomiss`/`comiss`/`ucomisd`/`comisd`.
///
/// A float compare has FOUR outcomes where an integer compare has three, and
/// the fourth is the whole point: when either operand is a NaN the operands are
/// UNORDERED and x86 reports it by setting ZF, CF **and** PF at once. Lowering
/// these as if they were `cmp` produces code that is right on ordered inputs
/// and silently wrong on every NaN — which is what `174_float_compare_classify`
/// exists to catch, and what makes `ordered_compare_binary32`'s fourth return
/// value unreachable.
///
/// Intel SDM Vol. 2A (COMISS/UCOMISD), "Operation":
///
/// ```text
///   UNORDERED:  ZF=1 PF=1 CF=1
///   GREATER:    ZF=0 PF=0 CF=0
///   LESS:       ZF=0 PF=0 CF=1
///   EQUAL:      ZF=1 PF=0 CF=0
///   OF, SF, AF := 0                (always)
/// ```
///
/// so `PF = unordered`, `ZF = (a == b) | unordered`, `CF = (a < b) | unordered`.
/// Unorderedness is spelled `(a != a) | (b != b)`, which is exactly "either is
/// a NaN" for IEEE operands and needs no predicate the LLIR does not have.
/// Every `jb`/`jae`/`je`/`jbe`/`ja`/`jp`/`jnp` and every `setcc` then falls out
/// of the existing condition machinery unchanged — see [`super::materialize_condition`].
///
/// The comparison is `xmm1 <=> xmm2` in Intel operand order: `comiss %xmm0,%xmm1`
/// in AT&T syntax asks whether `xmm1` is above `xmm0`.
pub(super) fn scalar_float_compare_ops(
    instr: &iced_x86::Instruction,
    width: Width,
    mnemonic: &str,
) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }

    let lhs = Value::Reg(VReg::phys(reg_name(instr.op_register(0))));
    let mut ops = Vec::new();
    let rhs = match instr.op_kind(1) {
        OpKind::Register => Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
        OpKind::Memory => {
            let tmp = VReg::Temp(14);
            let mut addr = mem_op_of(instr);
            addr.size = u8::try_from(width.bytes()).expect("scalar SSE width fits MemOp");
            ops.push(Op::Load {
                dst: tmp.clone(),
                addr,
            });
            Value::Reg(tmp)
        }
        _ => {
            return vec![Op::Unknown {
                mnemonic: mnemonic.into(),
            }];
        }
    };

    ops.extend(float_compare_flag_ops(lhs, rhs));
    ops
}

/// The flag half of [`scalar_float_compare_ops`], for producers that already
/// hold both operands as values.
///
/// x87's `fcomi`/`fcomip`/`fucomi`/`fucomip` report the identical four-outcome
/// result into the identical EFLAGS bits — that is the entire reason those
/// instructions exist — so [`crate::ir::x87`] shares this model rather than
/// restating it. A second copy of the NaN rule is a second chance to get the
/// unordered case wrong on one architecture and not the other.
pub(crate) fn float_compare_flag_ops(lhs: Value, rhs: Value) -> Vec<Op> {
    let lhs_is_nan = VReg::Temp(15);
    let rhs_is_nan = VReg::Temp(16);
    let ordered_equal = VReg::Temp(17);
    let ordered_below = VReg::Temp(18);
    Vec::from([
        Op::Cmp {
            dst: lhs_is_nan.clone(),
            op: CmpOp::Ne,
            lhs: lhs.clone(),
            rhs: lhs.clone(),
        },
        Op::Cmp {
            dst: rhs_is_nan.clone(),
            op: CmpOp::Ne,
            lhs: rhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::P),
            op: BinOp::Or,
            lhs: Value::Reg(lhs_is_nan),
            rhs: Value::Reg(rhs_is_nan),
        },
        Op::Cmp {
            dst: ordered_equal.clone(),
            op: CmpOp::Eq,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::Z),
            op: BinOp::Or,
            lhs: Value::Reg(ordered_equal),
            rhs: Value::Reg(VReg::Flag(Flag::P)),
        },
        Op::Cmp {
            dst: ordered_below.clone(),
            op: CmpOp::Slt,
            lhs,
            rhs,
        },
        Op::Bin {
            dst: VReg::Flag(Flag::C),
            op: BinOp::Or,
            lhs: Value::Reg(ordered_below),
            rhs: Value::Reg(VReg::Flag(Flag::P)),
        },
        // Cleared, not poisoned: the architecture states a value for these.
        Op::Assign {
            dst: VReg::Flag(Flag::O),
            src: Value::Const(0),
        },
        Op::Assign {
            dst: VReg::Flag(Flag::S),
            src: Value::Const(0),
        },
        Op::Assign {
            dst: VReg::Flag(Flag::A),
            src: Value::Const(0),
        },
    ])
}
