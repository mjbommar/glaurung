//! Exact ARM32 lifter regressions extracted from the packet-parser fixture.

use super::*;

fn lifted_ops(bytes: &[u8], thumb: bool) -> Vec<Op> {
    lift_bytes(bytes, 0x1000, thumb)
        .into_iter()
        .map(|instruction| instruction.op)
        .collect()
}

/// The packet parser's O0 bitfield temporary is assembled as two `bfi`
/// read-modify-writes. Dropping either write leaves the temporary byte
/// uninitialised and corrupts the decoded version/type fields.
#[test]
fn bitfield_insert_preserves_both_source_and_destination_lanes() {
    for (bytes, thumb) in [
        // Thumb-2: bfi r3, r2, #0, #4 = f362 0303
        (&[0x62u8, 0xf3, 0x03, 0x03][..], true),
        // A32: bfi r3, r2, #0, #4 = e7c33012
        (&[0x12, 0x30, 0xc3, 0xe7][..], false),
    ] {
        let out = lifted_ops(bytes, thumb);
        assert_eq!(
            out,
            vec![
                Op::Bin {
                    dst: VReg::Temp(0),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::phys("r2")),
                    rhs: Value::Const(0xf),
                },
                Op::Bin {
                    dst: VReg::Temp(1),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::phys("r3")),
                    rhs: Value::Const(0xffff_fff0),
                },
                Op::Bin {
                    dst: VReg::phys("r3"),
                    op: BinOp::Or,
                    lhs: Value::Reg(VReg::Temp(1)),
                    rhs: Value::Reg(VReg::Temp(0)),
                },
            ],
            "packet bfi must retain both lanes: {out:#?}"
        );
    }
}

/// Capstone uses the two-operand alias for A32's in-place immediate ROR.
/// It is the packet checksum's rotate-left-by-one (`ror #31`).
#[test]
fn a32_two_operand_rotate_right_is_not_opaque() {
    // A32: ror r3, r3, #31 = e1a03fe3.
    let out = lifted_ops(&[0xe3, 0x3f, 0xa0, 0xe1], false);
    assert_eq!(
        out,
        vec![
            Op::Bin {
                dst: VReg::Temp(SHIFT_TEMP + 1),
                op: BinOp::Shr,
                lhs: Value::Reg(VReg::phys("r3")),
                rhs: Value::Const(31),
            },
            Op::Bin {
                dst: VReg::Temp(SHIFT_TEMP + 2),
                op: BinOp::Shl,
                lhs: Value::Reg(VReg::phys("r3")),
                rhs: Value::Const(1),
            },
            Op::Bin {
                dst: VReg::Temp(SHIFT_TEMP),
                op: BinOp::Or,
                lhs: Value::Reg(VReg::Temp(SHIFT_TEMP + 1)),
                rhs: Value::Reg(VReg::Temp(SHIFT_TEMP + 2)),
            },
            Op::Assign {
                dst: VReg::phys("r3"),
                src: Value::Reg(VReg::Temp(SHIFT_TEMP)),
            },
        ],
        "packet rotate must preserve the checksum recurrence: {out:#?}"
    );
}

/// `smlabb` multiplies signed bottom halfwords, adds a signed 32-bit
/// accumulator, and truncates to the architectural 32-bit result. Widen before
/// the add so emitted C does not depend on signed-overflow UB.
#[test]
fn signed_halfword_multiply_accumulate_is_width_exact() {
    for (bytes, thumb) in [
        // Thumb-2: smlabb r2, r2, lr, r4 = fb12 420e
        (&[0x12u8, 0xfb, 0x0e, 0x42][..], true),
        // A32: smlabb r2, r2, r4, lr = e102e482
        (&[0x82, 0xe4, 0x02, 0xe1][..], false),
    ] {
        let out = lifted_ops(bytes, thumb);
        assert!(
            !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
            "smlabb remained opaque: {out:#?}"
        );
        assert!(
            out.iter()
                .filter(|op| matches!(
                    op,
                    Op::Trunc {
                        from: Width::W32,
                        to: Width::W16,
                        ..
                    }
                ))
                .count()
                == 2,
            "both multiplicands must select their bottom halfword: {out:#?}"
        );
        assert!(
            out.iter()
                .filter(|op| matches!(op, Op::SExt { to: Width::W64, .. }))
                .count()
                == 3,
            "multiplicands and accumulator must widen signed: {out:#?}"
        );
        assert!(
            out.iter()
                .any(|op| matches!(op, Op::Bin { op: BinOp::Mul, .. }))
                && out
                    .iter()
                    .any(|op| matches!(op, Op::Bin { op: BinOp::Add, .. }))
                && matches!(out.last(), Some(Op::Trunc { dst, from: Width::W64, to: Width::W32, .. }) if dst == &VReg::phys("r2")),
            "smlabb did not produce a wrapped multiply-accumulate: {out:#?}"
        );
    }
}
