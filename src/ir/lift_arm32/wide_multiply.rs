//! ARM32 operations whose result spans a pair of core registers.

use crate::core::instruction::Operand;
use crate::ir::types::{BinOp, Op, VReg, Value, Width};

use super::{operand_reg, operand_to_value};

/// Lower `smlal RdLo, RdHi, Rn, Rm` exactly.
///
/// The accumulator is the raw 64-bit bit pattern `{RdHi:RdLo}`. The
/// multiplicands are signed 32-bit values, and the 64-bit sum wraps modulo
/// 2^64. Materialize every input in a temporary before committing either
/// destination because ARM permits a multiplicand to overlap a destination.
pub(super) fn lift_signed_long_multiply_accumulate(ops: &[Operand]) -> Option<Vec<Op>> {
    if ops.len() != 4 {
        return None;
    }
    let rd_lo = operand_reg(&ops[0])?;
    let rd_hi = operand_reg(&ops[1])?;
    let rn = operand_to_value(&ops[2])?;
    let rm = operand_to_value(&ops[3])?;

    let lo64 = VReg::Temp(0);
    let hi64 = VReg::Temp(1);
    let shifted_hi = VReg::Temp(2);
    let accumulator = VReg::Temp(3);
    let rn64 = VReg::Temp(4);
    let rm64 = VReg::Temp(5);
    let product = VReg::Temp(6);
    let sum = VReg::Temp(7);

    Some(vec![
        Op::ZExt {
            dst: lo64.clone(),
            src: Value::Reg(rd_lo.clone()),
            from: Width::W32,
            to: Width::W64,
        },
        Op::ZExt {
            dst: hi64.clone(),
            src: Value::Reg(rd_hi.clone()),
            from: Width::W32,
            to: Width::W64,
        },
        Op::Bin {
            dst: shifted_hi.clone(),
            op: BinOp::Shl,
            lhs: Value::Reg(hi64),
            rhs: Value::Const(32),
        },
        Op::Bin {
            dst: accumulator.clone(),
            op: BinOp::Or,
            lhs: Value::Reg(shifted_hi),
            rhs: Value::Reg(lo64),
        },
        Op::SExt {
            dst: rn64.clone(),
            src: rn,
            from: Width::W32,
            to: Width::W64,
        },
        Op::SExt {
            dst: rm64.clone(),
            src: rm,
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
            lhs: Value::Reg(accumulator),
            rhs: Value::Reg(product),
        },
        Op::Trunc {
            dst: rd_lo,
            src: Value::Reg(sum.clone()),
            from: Width::W64,
            to: Width::W32,
        },
        Op::Extract {
            dst: rd_hi,
            src: Value::Reg(sum),
            hi: 64,
            lo: 32,
        },
    ])
}
