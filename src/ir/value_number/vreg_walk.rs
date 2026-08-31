//! The untyped mutable walk over every register one operation mentions.
//!
//! Kept apart from `tagging`, which walks the same shape *positionally* to
//! thread SSA versions in `def_uses` order. This walker has no order to
//! respect, so its one reason to change is the `Op` set itself.

use crate::ir::types::{Op, VReg, Value};

/// Every register a single operation mentions, mutably, def and uses alike.
///
/// `tagging::tag_op` already walks this shape, but it walks it *positionally* — it has
/// to, because it is threading SSA versions in `def_uses` order. A renaming has
/// no order to respect, so this walker exists to keep the two concerns apart
/// rather than overload the tagging traversal with a second mode.
pub(crate) fn for_each_vreg_mut(op: &mut Op, f: &mut impl FnMut(&mut VReg)) {
    fn value(v: &mut Value, f: &mut impl FnMut(&mut VReg)) {
        if let Value::Reg(r) = v {
            f(r);
        }
    }
    fn memop(m: &mut crate::ir::types::MemOp, f: &mut impl FnMut(&mut VReg)) {
        if let Some(b) = m.base.as_mut() {
            f(b);
        }
        if let Some(i) = m.index.as_mut() {
            f(i);
        }
    }
    match op {
        Op::Assign { dst, src } => {
            value(src, f);
            f(dst);
        }
        Op::Undef { dst, .. } => f(dst),
        Op::Bin { dst, lhs, rhs, .. } => {
            value(lhs, f);
            value(rhs, f);
            f(dst);
        }
        Op::IndirectJump { target, index } => {
            value(target, f);
            if let Some(index) = index {
                value(index, f);
            }
        }
        Op::Un { dst, src, .. } => {
            value(src, f);
            f(dst);
        }
        Op::Cmp { dst, lhs, rhs, .. } => {
            value(lhs, f);
            value(rhs, f);
            f(dst);
        }
        Op::Load { dst, addr } => {
            memop(addr, f);
            f(dst);
        }
        Op::CondLoad {
            dst,
            cond,
            addr,
            fallback,
            ..
        } => {
            f(cond);
            memop(addr, f);
            value(fallback, f);
            f(dst);
        }
        Op::Store { addr, src } => {
            memop(addr, f);
            value(src, f);
        }
        Op::CondStore {
            cond, addr, src, ..
        } => {
            f(cond);
            memop(addr, f);
            value(src, f);
        }
        Op::CondJump { cond, .. } | Op::CondReturn { cond, .. } => f(cond),
        Op::CondReturnValue {
            cond,
            value: returned,
            ..
        } => {
            f(cond);
            value(returned, f);
        }
        Op::Call { target, effects } => {
            if let crate::ir::types::CallTarget::Indirect(v) = target {
                value(v, f);
            }
            if let Some(e) = effects {
                for a in e.args.iter_mut() {
                    f(a);
                }
                if let Some(r) = e.result.as_mut() {
                    f(r);
                }
            }
        }
        Op::ZExt { dst, src, .. }
        | Op::SExt { dst, src, .. }
        | Op::Trunc { dst, src, .. }
        | Op::Extract { dst, src, .. } => {
            value(src, f);
            f(dst);
        }
        Op::Concat { dst, hi, lo } => {
            value(hi, f);
            value(lo, f);
            f(dst);
        }
        Op::Ite {
            dst, cond, t, e, ..
        } => {
            f(cond);
            value(t, f);
            value(e, f);
            f(dst);
        }
        Op::Intrinsic { ins, outs, .. } => {
            for input in ins {
                value(input, f);
            }
            for out in outs.iter_mut() {
                f(&mut out.0);
            }
        }
        Op::ReturnValue { value: returned } => value(returned, f),
        Op::Jump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => {}
    }
}
