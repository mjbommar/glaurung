//! Exact LLIR bit-width projection into ordinary C integer expressions.
//!
//! Keeping this boundary in one small module prevents AST lowering sites from
//! independently rounding bit widths into incompatible C storage types.

use super::{BinOp, Expr, Width};

/// Smallest ordinary C integer type that can carry an LLIR scalar width.
///
/// LLIR widths are bit-precise (`i13`, `i15`, ...), while C integer casts are
/// expressed in whole implementation types. Rounding down silently destroys
/// live bits. Widths above 64 retain the existing wide-value metadata; those
/// are rendered by the dedicated wide-integer paths.
pub(super) fn containing_c_integer_bytes(width: Width) -> u8 {
    match width.bits() {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 4,
        33..=64 => 8,
        bits => u8::try_from((bits / 8).max(1)).unwrap_or(u8::MAX),
    }
}

/// Constrain an expression to an exact, non-byte-aligned LLIR width.
///
/// A containing C cast alone preserves too many high bits. Signed values also
/// need their declared sign bit reconstructed because, for example, i13's sign
/// is bit 12 rather than `short`'s bit 15. `(x ^ sign) - sign` performs that
/// reconstruction after the exact-width mask without relying on a C bitfield.
pub(super) fn exact_non_byte_value(expr: Expr, width: Width, signed: bool) -> Expr {
    let bits = width.bits();
    if bits == 0 || bits >= 64 || bits % 8 == 0 {
        return expr;
    }

    let mask = ((1u64 << bits) - 1) as i64;
    let masked = Expr::Bin {
        op: BinOp::And,
        lhs: Box::new(expr),
        rhs: Box::new(Expr::Const(mask)),
    };
    if !signed {
        return masked;
    }

    let sign = (1u64 << (bits - 1)) as i64;
    // Force the formula into a signed C type before subtraction. Otherwise an
    // unsigned source register can make the usual arithmetic conversions wrap
    // the negative half of the range in unsigned arithmetic before the cast.
    let signed_value = Expr::Cast {
        signed: true,
        width: containing_c_integer_bytes(width),
        expr: Box::new(masked),
    };
    Expr::Bin {
        op: BinOp::Sub,
        lhs: Box::new(Expr::Bin {
            op: BinOp::Xor,
            lhs: Box::new(signed_value),
            rhs: Box::new(Expr::Const(sign)),
        }),
        rhs: Box::new(Expr::Const(sign)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{lower_op, Stmt};
    use super::*;
    use crate::ir::types::{Op, VReg, Value};

    /// LLIR bit slices are not restricted to byte boundaries. A 13- or 15-bit
    /// value needs a 16-bit C carrier before it is widened.
    #[test]
    fn non_byte_aligned_extensions_use_the_smallest_containing_c_integer() {
        for bits in [13, 15] {
            let statements = lower_op(
                &Op::ZExt {
                    dst: VReg::phys("ret"),
                    src: Value::Reg(VReg::phys("slice")),
                    from: Width(bits),
                    to: Width::W32,
                },
                false,
            );
            assert!(
                matches!(
                    statements.as_slice(),
                    [Stmt::Assign {
                        src: Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: outer,
                        },
                        ..
                    }] if matches!(
                        outer.as_ref(),
                        Expr::Cast {
                            signed: false,
                            width: 2,
                            expr,
                        } if matches!(
                            expr.as_ref(),
                            Expr::Bin {
                                op: BinOp::And,
                                rhs,
                                ..
                            } if matches!(rhs.as_ref(), Expr::Const(mask) if *mask == (1i64 << bits) - 1)
                        )
                    )
                ),
                "i{bits} must be carried by unsigned short: {statements:#?}"
            );
        }
    }

    /// The sign bit of i13 is bit 12, not the containing `short`'s bit 15.
    #[test]
    fn non_byte_aligned_sign_extension_uses_the_declared_sign_bit() {
        let statements = lower_op(
            &Op::SExt {
                dst: VReg::phys("ret"),
                src: Value::Reg(VReg::phys("slice")),
                from: Width(13),
                to: Width::W32,
            },
            false,
        );
        assert!(
            matches!(
                statements.as_slice(),
                [Stmt::Assign {
                    src: Expr::Cast {
                        signed: true,
                        width: 4,
                        expr: outer,
                    },
                    ..
                }] if matches!(
                    outer.as_ref(),
                    Expr::Cast {
                        signed: true,
                        width: 2,
                        expr,
                    } if matches!(
                        expr.as_ref(),
                        Expr::Bin {
                            op: BinOp::Sub,
                            lhs,
                            rhs,
                        } if matches!(rhs.as_ref(), Expr::Const(0x1000))
                            && matches!(
                                lhs.as_ref(),
                                Expr::Bin {
                                    op: BinOp::Xor,
                                    lhs: signed_value,
                                    rhs,
                                } if matches!(rhs.as_ref(), Expr::Const(0x1000))
                                    && matches!(
                                        signed_value.as_ref(),
                                        Expr::Cast {
                                            signed: true,
                                            width: 2,
                                            ..
                                        }
                                    )
                            )
                    )
                )
            ),
            "i13 sign extension must use bit 12: {statements:#?}"
        );
    }

    /// A non-byte-aligned truncation needs both a containing C type and an
    /// explicit bit mask; a cast alone would retain bits above the LLIR width.
    #[test]
    fn non_byte_aligned_truncation_masks_before_using_its_c_carrier() {
        let statements = lower_op(
            &Op::Trunc {
                dst: VReg::phys("ret"),
                src: Value::Reg(VReg::phys("arg0")),
                from: Width::W32,
                to: Width(13),
            },
            false,
        );
        assert!(
            matches!(
                statements.as_slice(),
                [Stmt::Assign {
                    src: Expr::Cast {
                        signed: false,
                        width: 2,
                        expr,
                    },
                    ..
                }] if matches!(
                    expr.as_ref(),
                    Expr::Bin {
                        op: BinOp::And,
                        rhs,
                        ..
                    } if matches!(rhs.as_ref(), Expr::Const(0x1fff))
                )
            ),
            "i13 truncation must retain exactly 13 bits: {statements:#?}"
        );
    }

    /// Select carries a C storage width in the AST just like integer casts.
    #[test]
    fn non_byte_aligned_select_uses_a_containing_c_integer() {
        let statements = lower_op(
            &Op::Ite {
                dst: VReg::phys("ret"),
                cond: VReg::phys("zf"),
                t: Value::Reg(VReg::phys("arg0")),
                e: Value::Const(0),
                width: Width(13),
            },
            false,
        );
        assert!(matches!(
            statements.as_slice(),
            [Stmt::Assign {
                src: Expr::Select { width: 2, .. },
                ..
            }]
        ));
    }
}
