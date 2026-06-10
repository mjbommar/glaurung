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
                if b == 0 {
                    0
                } else {
                    reduce(a, w) / reduce(b, w)
                }
            }
            BinOp::And => a & b,
            BinOp::Or => a | b,
            BinOp::Xor => a ^ b,
            BinOp::Shl => {
                let sh = (b % w.bits().max(1) as u128) as u32;
                a.checked_shl(sh).unwrap_or(0)
            }
            BinOp::Shr => {
                // Logical right shift on the width-reduced value.
                let sh = (b % w.bits().max(1) as u128) as u32;
                reduce(a, w).checked_shr(sh).unwrap_or(0)
            }
            BinOp::Sar => {
                // Arithmetic right shift: shift the signed interpretation.
                let sh = (b % w.bits().max(1) as u128) as u32;
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
