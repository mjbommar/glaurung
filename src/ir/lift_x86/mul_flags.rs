//! CF and OF for the x86 multiplies, which is the one flag pair a multiply
//! actually defines and the one this lifter used to poison.
//!
//! Every other x86 arithmetic instruction leaves its flags in
//! [`super::flags`]. The multiplies are here because their overflow predicate
//! is not a property of the result — it is a property of a product WIDER than
//! the result, which the architectural write throws away. Reconstructing it
//! afterwards is impossible for the two-operand form, whose destination is one
//! of the multiplicands, so the wide product has to be snapshotted before the
//! result is written and turned into flags after. That two-step shape is the
//! reason this is a module and not three more functions in `flags`.
//!
//! Why it matters more than a flag usually does: the reader of OF after a
//! multiply is an overflow check. `seto` / `jo` after `imul` is how Rust
//! spells `overflowing_mul` / `checked_mul` / `saturating_mul`, and how Clang
//! range-checks an allocation byte count. While these flags were poisoned, the
//! decompiler rendered those checks as reads of an explicitly undefined value —
//! it showed the analyst a program in which the check was not there.

use crate::ir::types::*;

use super::flags::{append_undef_flags, signed_cmp_value, unsigned_cmp_value};

/// Snapshot the FULL signed product of a truncating x86 multiply.
///
/// `imul r, r/m` and `imul r, r/m, imm` write only the low `width` bits of a
/// `2 * width`-bit product, so the truncation itself is the only thing CF/OF
/// report — and reconstructing it after the fact is impossible, because the
/// two-operand form's destination IS one of the multiplicands. Take the wide
/// product before the architectural result is written; [`append_imul_overflow_flags`]
/// turns it into flags afterwards.
///
/// Returns `None` when the wide product does not fit the IR's canonical 64-bit
/// value width (i.e. at `width == 64`, where the architecture computes a 128-bit
/// intermediate). Callers keep explicit poison for that case.
pub(super) fn imul_wide_product(
    ops: &mut Vec<Op>,
    lhs: Value,
    rhs: Value,
    width: Width,
) -> Option<VReg> {
    if width.bits() >= Width::W64.bits() {
        return None;
    }
    let lhs = signed_cmp_value(lhs, width, VReg::Temp(80), ops);
    let rhs = signed_cmp_value(rhs, width, VReg::Temp(81), ops);
    let product = VReg::Temp(82);
    ops.push(Op::Bin {
        dst: product.clone(),
        op: BinOp::Mul,
        lhs,
        rhs,
    });
    Some(product)
}

/// Exact CF/OF for a truncating x86 multiply, from a [`imul_wide_product`] snapshot.
///
/// Intel SDM Vol. 2A, IMUL: "the CF and OF flags are set when the signed integer
/// value of the intermediate product differs from the sign extended
/// operand-size-truncated product, and cleared otherwise." That is literally the
/// predicate emitted here — `product != sext_width(trunc_width(product))` — and it
/// is what `seto` / `jo` after an `imul` reads. Marking those flags undefined is
/// not the conservative choice: a reader of OF would be reading a value the IR has
/// declared meaningless, which is exactly how `Rust`'s `overflowing_mul` /
/// `checked_mul` / `saturating_mul` lost their overflow verdict.
///
/// `product == None` means the width has no representable wide product, so the two
/// flags stay explicit poison rather than becoming a silently wrong predicate.
pub(super) fn append_imul_overflow_flags(ops: &mut Vec<Op>, product: Option<VReg>, width: Width) {
    let Some(product) = product else {
        append_undef_flags(
            ops,
            &[Flag::C, Flag::O],
            "x86 IMUL defines CF/OF from a 128-bit intermediate product, which is wider \
             than any IR value width",
        );
        return;
    };
    let truncated = VReg::Temp(83);
    let extended = VReg::Temp(84);
    ops.extend([
        Op::Trunc {
            dst: truncated.clone(),
            src: Value::Reg(product.clone()),
            from: Width::W64,
            to: width,
        },
        Op::SExt {
            dst: extended.clone(),
            src: Value::Reg(truncated),
            from: width,
            to: Width::W64,
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ne,
            lhs: Value::Reg(product.clone()),
            rhs: Value::Reg(extended.clone()),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::O),
            op: CmpOp::Ne,
            lhs: Value::Reg(product),
            rhs: Value::Reg(extended),
        },
    ]);
}

/// Exact CF/OF for the ONE-operand x86 multiplies, which keep the whole product
/// in `hi:lo` instead of truncating it.
///
/// SDM Vol. 2A, MUL: "the CF and OF flags are set to 0 if the upper half of the
/// result is 0; otherwise, they are set to 1". IMUL's one-operand form sets them
/// when the upper half is not the sign extension of the lower half. Both sentences
/// say "the product does not fit in `width` bits" — unsigned for MUL, signed for
/// IMUL — so both are expressed here as a fit test on a product taken at double
/// width, and the signed case is literally the truncating-IMUL predicate.
///
/// Below 64 bits the predicate is built from the MULTIPLICANDS, not from the
/// `hi`/`lo` registers the instruction just defined. At 16 bits those halves are
/// `dx`/`ax` — bit-preserving views `regview::ssa_parent` declines to merge — so a
/// bare read of one is a read of a name nothing in the function defines, the exact
/// failure [`super::wide_arith::wide_mul_ops`]'s accumulator snapshot exists to
/// avoid.
///
/// At 64 bits there is no wide product to take: the IR has no 128-bit value. But
/// this form does not need one, because the high half is already a materialised
/// output, and at that width the halves are `rdx`/`rax` — canonical names, safe to
/// read back. `mul r64; seto` is a real sequence, not a corner: it is how Clang
/// range-checks a `malloc`/VLA byte count (`33_knapsack:clang:O2` reaches it), and
/// poisoning OF there turned the check into `__unknown(0)`.
pub(super) fn append_wide_mul_overflow_flags(
    ops: &mut Vec<Op>,
    lhs: Value,
    rhs: Value,
    width: Width,
    signed: bool,
    halves: (&str, &str),
) {
    if width.bits() >= Width::W64.bits() {
        let (lo_name, hi_name) = halves;
        // Unsigned: the product overflows exactly when the high half is nonzero.
        // Signed: exactly when the high half is not the low half's sign extension.
        let expected = if signed {
            let sign = VReg::Temp(85);
            ops.push(Op::Bin {
                dst: sign.clone(),
                op: BinOp::Sar,
                lhs: Value::Reg(VReg::phys(lo_name)),
                rhs: Value::Const(i64::from(width.bits()) - 1),
            });
            Value::Reg(sign)
        } else {
            Value::Const(0)
        };
        ops.extend([Flag::C, Flag::O].map(|flag| Op::Cmp {
            dst: VReg::Flag(flag),
            op: CmpOp::Ne,
            lhs: Value::Reg(VReg::phys(hi_name)),
            rhs: expected.clone(),
        }));
        return;
    }
    if signed {
        let product = imul_wide_product(ops, lhs, rhs, width);
        append_imul_overflow_flags(ops, product, width);
        return;
    }
    let lhs = unsigned_cmp_value(lhs, width, VReg::Temp(85), ops);
    let rhs = unsigned_cmp_value(rhs, width, VReg::Temp(86), ops);
    let product = VReg::Temp(87);
    let truncated = VReg::Temp(88);
    let extended = VReg::Temp(89);
    ops.extend([
        Op::Bin {
            dst: product.clone(),
            op: BinOp::Mul,
            lhs,
            rhs,
        },
        Op::Trunc {
            dst: truncated.clone(),
            src: Value::Reg(product.clone()),
            from: Width::W64,
            to: width,
        },
        Op::ZExt {
            dst: extended.clone(),
            src: Value::Reg(truncated),
            from: width,
            to: Width::W64,
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ne,
            lhs: Value::Reg(product.clone()),
            rhs: Value::Reg(extended.clone()),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::O),
            op: CmpOp::Ne,
            lhs: Value::Reg(product),
            rhs: Value::Reg(extended),
        },
    ]);
}
