//! The concrete value domain — the emulator's backend.
//!
//! A value is a `u128` already reduced to its logical [`Width`]. All arithmetic
//! is modular at the operation width; signed operations interpret the operands
//! via two's complement at that width. This is the same model proven by the
//! Phase-1 design prototype, now implemented against the real trait.

use crate::exec::domain::{BranchDecision, Domain};
use crate::ir::types::{BinOp, CmpOp, UnOp, Width};

/// All-ones mask for `width` bits (saturating at 128).
fn mask(width: Width) -> u128 {
    let w = width.bits();
    if w >= 128 {
        u128::MAX
    } else if w == 0 {
        0
    } else {
        (1u128 << w) - 1
    }
}

/// Reduce raw bits to `width`.
fn reduce(bits: u128, width: Width) -> u128 {
    bits & mask(width)
}

/// Interpret the low `width` bits of `bits` as a two's-complement signed value,
/// returned as an `i128` (sign-extended to 128 bits).
fn as_signed(bits: u128, width: Width) -> i128 {
    let w = width.bits();
    if w == 0 || w >= 128 {
        return bits as i128;
    }
    let v = reduce(bits, width);
    let sign_bit = 1u128 << (w - 1);
    if v & sign_bit != 0 {
        // set the high bits above the width
        (v | !mask(width)) as i128
    } else {
        v as i128
    }
}

/// How a shift distance must be reduced to the operand width before a shift is
/// applied.
///
/// This enum and [`shift_reduction`] are the **single definition** of that
/// rule. `Concrete` implements it below; every SMT backend
/// (`crate::symbolic::expr`'s two text renderers plus the native z3, Bitwuzla
/// and Axeyum translators) asks this function what to do and then renders the
/// answer in its own API. Only the *decision* is shared, because sharing the
/// rendering is impossible across five unrelated term-building APIs and
/// duplicating the decision five ways would drift silently in four of them.
///
/// The rule exists because SMT-LIB and the hardware disagree:
/// `bvshl`/`bvlshr`/`bvashr` saturate to zero (or to the sign) once the
/// distance reaches the operand width, while x86 `shl`/`shr`/`sar` and A64
/// `LSLV`/`LSRV`/`ASRV` take the distance modulo the width. The LLIR is lifted
/// from those CPUs and this domain is what a solver model is replayed in, so
/// the solver is the side that moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShiftReduction {
    /// Bitwise-and the distance with this all-ones mask. Emitted when the
    /// width is a power of two, where masking and `mod width` are the same
    /// function and masking is far cheaper for a bit-blasting solver.
    Mask(u128),
    /// Take the unsigned remainder of the distance modulo this value. Required
    /// whenever the width is *not* a power of two — `Expr::Extract` and
    /// `Expr::Concat` mint such widths, so the mask shortcut is not always the
    /// right function and must never be hardcoded.
    Modulo(u128),
    /// Use the distance unchanged. Only a zero width, which no bit-vector sort
    /// can represent anyway.
    Passthrough,
}

/// The reduction a shift at `width` applies to its distance operand.
pub(crate) fn shift_reduction(width: Width) -> ShiftReduction {
    let bits = width.bits();
    if bits == 0 {
        ShiftReduction::Passthrough
    } else if bits.is_power_of_two() {
        ShiftReduction::Mask(u128::from(bits) - 1)
    } else {
        ShiftReduction::Modulo(u128::from(bits))
    }
}

/// The quotient this domain yields for a division by zero.
///
/// SMT-LIB defines `bvudiv` by zero as all-ones; a real x86 `div` raises `#DE`
/// and produces no value at all. Neither is what this domain does, so every SMT
/// backend guards its division with `ite(divisor = 0, this, bvudiv(a, b))`
/// rather than leaving the solver reasoning about a different function than the
/// executor runs. A genuine divide fault is modelled by a helper, above the
/// value domain.
pub(crate) const DIVIDE_BY_ZERO_QUOTIENT: u128 = 0;

/// The shift distance a shift at `width` actually applies: the operand reduced
/// to `width`, then put through [`shift_reduction`].
fn shift_distance(raw: u128, width: Width) -> u32 {
    let reduced = reduce(raw, width);
    let applied = match shift_reduction(width) {
        ShiftReduction::Mask(mask) => reduced & mask,
        ShiftReduction::Modulo(modulus) => reduced % modulus,
        ShiftReduction::Passthrough => reduced,
    };
    applied as u32
}

/// The concrete domain. Zero-sized; all state lives in the value `u128`s.
#[derive(Debug, Default, Clone, Copy)]
pub struct Concrete;

impl Domain for Concrete {
    type Val = u128;

    fn constant(&mut self, width: Width, bits: u128) -> u128 {
        reduce(bits, width)
    }

    fn binop(&mut self, op: BinOp, a: &u128, b: &u128, w: Width) -> u128 {
        let (a, b) = (*a, *b);
        let r = match op {
            BinOp::Add => a.wrapping_add(b),
            BinOp::Sub => a.wrapping_sub(b),
            BinOp::Mul => a.wrapping_mul(b),
            BinOp::Div => {
                // Unsigned division; division by zero yields 0 (a real divide
                // fault is modelled by a helper, not the value domain).
                //
                // The zero test is on the *width-reduced* divisor, not the raw
                // `u128`. Domain values are supposed to arrive reduced, but a
                // raw operand whose only set bits sit above `w` is nonzero and
                // reduces to zero, which used to reach `x / 0` and panic. It is
                // also the value an SMT `(_ BitVec w)` operand can represent, so
                // reducing first is what keeps this agreeing with
                // `crate::symbolic::expr`'s rendering of the same node.
                let (a, b) = (reduce(a, w), reduce(b, w));
                if b == 0 {
                    DIVIDE_BY_ZERO_QUOTIENT
                } else {
                    a / b
                }
            }
            BinOp::LogicalAnd => u128::from(a != 0 && b != 0),
            BinOp::LogicalOr => u128::from(a != 0 || b != 0),
            BinOp::And => a & b,
            BinOp::Or => a | b,
            BinOp::Xor => a ^ b,
            // Shifts take the distance MODULO the operand width, as x86
            // `shl`/`shr`/`sar` and A64 `LSLV`/`LSRV`/`ASRV` do. SMT-LIB's
            // `bvshl`/`bvlshr`/`bvashr` instead saturate at the width, so
            // `crate::symbolic::expr::ExprPool::render_bin` masks the distance
            // to reproduce *this* function. This side is the reference; see
            // that function's docs for why.
            //
            // The distance is reduced to the operand width before the modulo:
            // an SMT `(_ BitVec w)` operand cannot carry bits above `w`, and at
            // a width that is not a power of two `raw % w` and `(raw & mask) %
            // w` are different functions.
            BinOp::Shl => {
                let sh = shift_distance(b, w);
                a.checked_shl(sh).unwrap_or(0)
            }
            BinOp::Shr => {
                // Logical right shift on the width-reduced value.
                let sh = shift_distance(b, w);
                reduce(a, w).checked_shr(sh).unwrap_or(0)
            }
            BinOp::Sar => {
                // Arithmetic right shift: shift the signed interpretation.
                let sh = shift_distance(b, w);
                let s = as_signed(a, w);
                (s >> sh.min(127)) as u128
            }
        };
        reduce(r, w)
    }

    fn unop(&mut self, op: UnOp, a: &u128, w: Width) -> u128 {
        let r = match op {
            UnOp::Not => !*a,
            UnOp::Neg => 0u128.wrapping_sub(*a),
        };
        reduce(r, w)
    }

    fn cmp(&mut self, op: CmpOp, a: &u128, b: &u128, w: Width) -> u128 {
        let (ua, ub) = (reduce(*a, w), reduce(*b, w));
        let r = match op {
            CmpOp::Eq => ua == ub,
            CmpOp::Ne => ua != ub,
            CmpOp::Ult => ua < ub,
            CmpOp::Ule => ua <= ub,
            CmpOp::Slt => as_signed(*a, w) < as_signed(*b, w),
            CmpOp::Sle => as_signed(*a, w) <= as_signed(*b, w),
        };
        r as u128
    }

    fn zext(&mut self, a: &u128, from: Width, _to: Width) -> u128 {
        // The reduced source already has zeros above `from`; widening to `to`
        // changes nothing in the concrete (unbounded-u128) representation.
        reduce(*a, from)
    }

    fn sext(&mut self, a: &u128, from: Width, to: Width) -> u128 {
        let s = as_signed(*a, from);
        reduce(s as u128, to)
    }

    fn trunc(&mut self, a: &u128, to: Width) -> u128 {
        reduce(*a, to)
    }

    fn extract(&mut self, a: &u128, hi: u16, lo: u16) -> u128 {
        if hi <= lo {
            return 0;
        }
        let width = hi - lo;
        let shifted = a >> lo;
        reduce(shifted, Width(width))
    }

    fn concat(&mut self, hi: &u128, lo: &u128, hi_w: Width, lo_w: Width) -> u128 {
        let hi = reduce(*hi, hi_w);
        let lo = reduce(*lo, lo_w);
        (hi << lo_w.bits()) | lo
    }

    fn ite(&mut self, cond: &u128, t: &u128, e: &u128, w: Width) -> u128 {
        if *cond & 1 != 0 {
            reduce(*t, w)
        } else {
            reduce(*e, w)
        }
    }

    fn as_branch(&mut self, cond: &u128) -> BranchDecision {
        if *cond & 1 != 0 {
            BranchDecision::Taken
        } else {
            BranchDecision::NotTaken
        }
    }

    fn as_u64(&mut self, v: &u128) -> Option<u64> {
        Some(*v as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::Width;

    fn c() -> Concrete {
        Concrete
    }

    #[test]
    fn constant_is_reduced_to_width() {
        let mut d = c();
        assert_eq!(d.constant(Width::W8, 0x1ff), 0xff);
        assert_eq!(d.constant(Width::W32, 0xdead_beef), 0xdead_beef);
        assert_eq!(d.constant(Width::W64, u128::MAX), u64::MAX as u128);
    }

    #[test]
    fn add_wraps_at_width() {
        let mut d = c();
        // 0xff + 1 at 32 bits = 0x100 (no wrap)
        assert_eq!(d.binop(BinOp::Add, &0xff, &1, Width::W32), 0x100);
        // 0xffff_ffff + 1 at 32 bits wraps to 0
        assert_eq!(d.binop(BinOp::Add, &0xffff_ffff, &1, Width::W32), 0);
        // at 8 bits, 0xff + 1 = 0
        assert_eq!(d.binop(BinOp::Add, &0xff, &1, Width::W8), 0);
    }

    #[test]
    fn sub_mul_wrap() {
        let mut d = c();
        assert_eq!(d.binop(BinOp::Sub, &0, &1, Width::W32), 0xffff_ffff);
        assert_eq!(d.binop(BinOp::Mul, &0x1_0000, &0x1_0000, Width::W32), 0); // overflow at 32
    }

    #[test]
    fn div_by_zero_is_zero() {
        let mut d = c();
        assert_eq!(d.binop(BinOp::Div, &10, &0, Width::W32), 0);
        assert_eq!(d.binop(BinOp::Div, &10, &3, Width::W32), 3);
    }

    #[test]
    fn shifts() {
        let mut d = c();
        assert_eq!(d.binop(BinOp::Shl, &1, &4, Width::W32), 0x10);
        assert_eq!(d.binop(BinOp::Shr, &0x80, &3, Width::W32), 0x10);
        // arithmetic shift right of -8 (0xfffffff8 @32) by 1 = -4 (0xfffffffc)
        assert_eq!(
            d.binop(BinOp::Sar, &0xffff_fff8, &1, Width::W32),
            0xffff_fffc
        );
        // logical shift right of the same is large positive
        assert_eq!(
            d.binop(BinOp::Shr, &0xffff_fff8, &1, Width::W32),
            0x7fff_fffc
        );
    }

    #[test]
    fn unops() {
        let mut d = c();
        assert_eq!(d.unop(UnOp::Not, &0, Width::W8), 0xff);
        assert_eq!(d.unop(UnOp::Neg, &1, Width::W32), 0xffff_ffff);
    }

    #[test]
    fn unsigned_vs_signed_compare() {
        let mut d = c();
        // 0xffff_ffff @32: unsigned huge, signed = -1
        let big = 0xffff_ffffu128;
        assert_eq!(d.cmp(CmpOp::Ult, &1, &big, Width::W32), 1); // 1 < 4294967295 unsigned
        assert_eq!(d.cmp(CmpOp::Slt, &1, &big, Width::W32), 0); // 1 < -1 ? no
        assert_eq!(d.cmp(CmpOp::Slt, &big, &1, Width::W32), 1); // -1 < 1 ? yes
        assert_eq!(d.cmp(CmpOp::Eq, &5, &5, Width::W32), 1);
        assert_eq!(d.cmp(CmpOp::Ne, &5, &6, Width::W32), 1);
        assert_eq!(d.cmp(CmpOp::Ule, &5, &5, Width::W32), 1);
        assert_eq!(d.cmp(CmpOp::Sle, &big, &big, Width::W32), 1);
    }

    #[test]
    fn zero_and_sign_extend() {
        let mut d = c();
        // 0xff @8 zero-extended to 32 = 0xff
        assert_eq!(d.zext(&0xff, Width::W8, Width::W32), 0xff);
        // 0xff @8 sign-extended to 32 = 0xffff_ffff (it's -1 @8)
        assert_eq!(d.sext(&0xff, Width::W8, Width::W32), 0xffff_ffff);
        // 0x7f @8 sign-extended to 32 = 0x7f (positive)
        assert_eq!(d.sext(&0x7f, Width::W8, Width::W32), 0x7f);
        // 0x80 @8 sign-extended to 16 = 0xff80
        assert_eq!(d.sext(&0x80, Width::W8, Width::W16), 0xff80);
    }

    #[test]
    fn truncate() {
        let mut d = c();
        assert_eq!(d.trunc(&0xdead_beef, Width::W16), 0xbeef);
        assert_eq!(d.trunc(&0xdead_beef, Width::W8), 0xef);
    }

    #[test]
    fn extract_bits() {
        let mut d = c();
        // bits [8:16) of 0xAABBCCDD = 0xCC
        assert_eq!(d.extract(&0xAABB_CCDD, 16, 8), 0xCC);
        // bits [0:8) = 0xDD
        assert_eq!(d.extract(&0xAABB_CCDD, 8, 0), 0xDD);
        // degenerate
        assert_eq!(d.extract(&0xFF, 4, 4), 0);
    }

    #[test]
    fn concatenate() {
        let mut d = c();
        // hi=0xAB (8b), lo=0xCD (8b) → 0xABCD
        assert_eq!(d.concat(&0xAB, &0xCD, Width::W8, Width::W8), 0xABCD);
        // hi=0x1 (8b), lo=0x0000 (16b) → 0x1_0000
        assert_eq!(d.concat(&1, &0, Width::W8, Width::W16), 0x1_0000);
    }

    #[test]
    fn select_and_branch() {
        let mut d = c();
        assert_eq!(d.ite(&1, &0xAA, &0xBB, Width::W32), 0xAA);
        assert_eq!(d.ite(&0, &0xAA, &0xBB, Width::W32), 0xBB);
        assert_eq!(d.as_branch(&1), BranchDecision::Taken);
        assert_eq!(d.as_branch(&0), BranchDecision::NotTaken);
        // only the low bit matters for a 1-bit condition
        assert_eq!(d.as_branch(&2), BranchDecision::NotTaken);
    }

    #[test]
    fn as_u64_concretizes() {
        let mut d = c();
        assert_eq!(d.as_u64(&0x1_0000_0000_0000_0001), Some(1)); // low 64 bits
        assert_eq!(d.as_u64(&0xdeadbeef), Some(0xdeadbeef));
    }

    #[test]
    fn end_to_end_prototype_sequence() {
        // Reproduces the design prototype: rax=0xff; ebx = rax + 1 (32-bit);
        // zf = (ebx == 0x100). Done directly via the domain primitives — the
        // same calls the interpreter will make.
        let mut d = c();
        let rax = d.constant(Width::W64, 0xff);
        let one = d.constant(Width::W32, 1);
        let ebx = d.binop(BinOp::Add, &rax, &one, Width::W32);
        assert_eq!(ebx, 0x100);
        let k = d.constant(Width::W32, 0x100);
        let zf = d.cmp(CmpOp::Eq, &ebx, &k, Width::W32);
        assert_eq!(zf, 1);
        assert_eq!(d.as_branch(&zf), BranchDecision::Taken);
    }
}
