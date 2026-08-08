//! Exact ARM32 long-multiply lifter regressions.

use super::*;

fn lifted_ops(bytes: &[u8], thumb: bool) -> Vec<Op> {
    lift_bytes(bytes, 0x1000, thumb)
        .into_iter()
        .map(|instruction| instruction.op)
        .collect()
}

/// The finite-difference stencil uses `smlal` to add `2 * source[i]` to
/// the signed 64-bit value already split across `r7:r3`. Both destination
/// halves are also inputs and must be consumed before either is overwritten.
#[test]
fn signed_long_multiply_accumulate_preserves_the_split_accumulator() {
    for (bytes, thumb) in [
        // Thumb-2: smlal r3, r7, ip, r2 = fbcc 3702.
        (&[0xccu8, 0xfb, 0x02, 0x37][..], true),
        // A32: smlal r3, r7, ip, r2 = e0e7329c.
        (&[0x9c, 0x32, 0xe7, 0xe0][..], false),
    ] {
        let out = lifted_ops(bytes, thumb);
        assert!(
            !out.iter().any(|op| matches!(op, Op::Unknown { .. })),
            "smlal remained opaque: {out:#?}"
        );
        assert_eq!(
            out.iter()
                .filter(|op| matches!(
                    op,
                    Op::ZExt {
                        from: Width::W32,
                        to: Width::W64,
                        ..
                    }
                ))
                .count(),
            2,
            "both accumulator halves must widen without changing their bits: {out:#?}"
        );
        assert_eq!(
            out.iter()
                .filter(|op| matches!(
                    op,
                    Op::SExt {
                        from: Width::W32,
                        to: Width::W64,
                        ..
                    }
                ))
                .count(),
            2,
            "both signed multiplicands must widen before multiplication: {out:#?}"
        );
        assert!(
            out.iter()
                .any(|op| matches!(op, Op::Bin { op: BinOp::Mul, .. }))
                && out
                    .iter()
                    .any(|op| matches!(op, Op::Bin { op: BinOp::Add, .. })),
            "smlal did not retain both multiply and accumulate operations: {out:#?}"
        );
        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::Trunc {
                    dst,
                    from: Width::W64,
                    to: Width::W32,
                    ..
                } if dst == &VReg::phys("r3")
            )),
            "smlal did not write the low result half: {out:#?}"
        );
        assert!(
            out.iter().any(|op| matches!(
                op,
                Op::Extract {
                    dst,
                    hi: 64,
                    lo: 32,
                    ..
                } if dst == &VReg::phys("r7")
            )),
            "smlal did not write the high result half: {out:#?}"
        );
    }
}
