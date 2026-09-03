//! The peephole model shared by every normalisation pass.
//!
//! A **peephole** here is exactly VexINE's: one straight-line basic block, and
//! nothing else. Values *used but not defined* inside it are parameters and
//! must survive -- no pass may delete a read of something the block did not
//! itself produce, because the producer is in another block and the peephole
//! cannot see it. That single rule is what keeps a deliberately unsound local
//! rewriter from erasing a function's interface.
//!
//! The IR has no mutable use-visitor (`crate::ir::use_def` borrows immutably
//! and exposes only `def_mut`), so this module carries one. It mirrors
//! [`crate::ir::use_def::for_each_use`], and
//! `tests::mutable_and_immutable_use_walks_agree` pins the two together: if a
//! new `Op` variant grows a use and only one walker learns about it, that test
//! fails rather than the normaliser silently skipping the operand.

use crate::ir::types::{CallTarget, MemOp, Op, VReg, Value};

/// Visit every [`Value`]-typed operand slot an operation reads, mutably.
///
/// **Call arguments are deliberately excluded.** `abi::annotate_calls` fills
/// `CallEffects::args` with the calling convention's may-read register set;
/// those slots name ABI storage rather than a computed operand, and rewriting
/// them would replace the convention's statement with a local guess. The
/// dataflow graph resolves each of them to its reaching definition anyway, so
/// nothing is lost by leaving them alone.
pub fn for_each_value_use_mut(op: &mut Op, mut f: impl FnMut(&mut Value)) {
    match op {
        Op::Assign { src, .. } => f(src),
        Op::Bin { lhs, rhs, .. } | Op::Cmp { lhs, rhs, .. } => {
            f(lhs);
            f(rhs);
        }
        Op::Un { src, .. }
        | Op::ZExt { src, .. }
        | Op::SExt { src, .. }
        | Op::Trunc { src, .. }
        | Op::Extract { src, .. } => f(src),
        Op::IndirectJump { target, index } => {
            f(target);
            if let Some(index) = index {
                f(index);
            }
        }
        Op::CondLoad { fallback, .. } => f(fallback),
        Op::Store { src, .. } | Op::CondStore { src, .. } => f(src),
        Op::CondReturnValue { value, .. } | Op::ReturnValue { value } => f(value),
        Op::Call { target, .. } => {
            if let CallTarget::Indirect(value) = target {
                f(value);
            }
        }
        Op::Concat { hi, lo, .. } => {
            f(hi);
            f(lo);
        }
        Op::Ite { t, e, .. } => {
            f(t);
            f(e);
        }
        Op::Intrinsic { ins, .. } => {
            for input in ins {
                f(input);
            }
        }
        Op::Undef { .. }
        | Op::Load { .. }
        | Op::CondJump { .. }
        | Op::CondReturn { .. }
        | Op::Jump { .. }
        | Op::Return
        | Op::Nop
        | Op::Unknown { .. } => {}
    }
}

/// Visit every bare [`VReg`] operand slot an operation reads, mutably.
///
/// These are the slots that cannot hold a constant: a predicate register, and
/// a memory operand's base and index. A pass may retarget them to another
/// register but never to a value.
pub fn for_each_reg_use_mut(op: &mut Op, mut f: impl FnMut(&mut VReg)) {
    fn of_memop(memop: &mut MemOp, f: &mut impl FnMut(&mut VReg)) {
        if let Some(base) = &mut memop.base {
            f(base);
        }
        if let Some(index) = &mut memop.index {
            f(index);
        }
    }
    match op {
        Op::Load { addr, .. } | Op::Store { addr, .. } => of_memop(addr, &mut f),
        Op::CondLoad { cond, addr, .. } | Op::CondStore { cond, addr, .. } => {
            f(cond);
            of_memop(addr, &mut f);
        }
        Op::CondJump { cond, .. } | Op::CondReturn { cond, .. } => f(cond),
        Op::CondReturnValue { cond, .. } | Op::Ite { cond, .. } => f(cond),
        Op::Assign { .. }
        | Op::Undef { .. }
        | Op::Bin { .. }
        | Op::Cmp { .. }
        | Op::Un { .. }
        | Op::ZExt { .. }
        | Op::SExt { .. }
        | Op::Trunc { .. }
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::IndirectJump { .. }
        | Op::ReturnValue { .. }
        | Op::Call { .. }
        | Op::Intrinsic { .. }
        | Op::Jump { .. }
        | Op::Return
        | Op::Nop
        | Op::Unknown { .. } => {}
    }
}

/// The memory operand an operation reads or writes, if it has one.
pub fn memop_of(op: &Op) -> Option<&MemOp> {
    match op {
        Op::Load { addr, .. }
        | Op::Store { addr, .. }
        | Op::CondLoad { addr, .. }
        | Op::CondStore { addr, .. } => Some(addr),
        _ => None,
    }
}

/// The memory operand an operation reads or writes, mutably.
pub fn memop_of_mut(op: &mut Op) -> Option<&mut MemOp> {
    match op {
        Op::Load { addr, .. }
        | Op::Store { addr, .. }
        | Op::CondLoad { addr, .. }
        | Op::CondStore { addr, .. } => Some(addr),
        _ => None,
    }
}

/// Whether an operation computes a value out of registers alone: no memory, no
/// call, no control transfer, no declared side effect.
///
/// Only a pure operation may be re-associated with another one by CSE or
/// dropped by redundancy elimination. An [`Op::Load`] is *not* pure here even
/// though it writes only its destination: it reads memory, so moving it past a
/// store changes what it sees.
pub fn is_pure(op: &Op) -> bool {
    matches!(
        op,
        Op::Assign { .. }
            | Op::Bin { .. }
            | Op::Un { .. }
            | Op::Cmp { .. }
            | Op::ZExt { .. }
            | Op::SExt { .. }
            | Op::Trunc { .. }
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Ite { .. }
    )
}

/// Whether an operation may read memory written elsewhere in the block.
pub fn reads_memory(op: &Op) -> bool {
    match op {
        Op::Load { .. } | Op::CondLoad { .. } | Op::Call { .. } | Op::Unknown { .. } => true,
        Op::Intrinsic { reads_mem, .. } => *reads_mem,
        _ => false,
    }
}

/// Whether an operation may write memory another operation in the block reads.
pub fn writes_memory(op: &Op) -> bool {
    match op {
        Op::Store { .. } | Op::CondStore { .. } | Op::Call { .. } | Op::Unknown { .. } => true,
        Op::Intrinsic { writes_mem, .. } => *writes_mem,
        _ => false,
    }
}

/// Whether two memory operands may name overlapping bytes.
///
/// The one case this proves apart is the one that matters for stack traffic:
/// **the same base, index, scale and segment with byte ranges that do not
/// overlap**. `[rbp-8]` and `[rbp-16]` at eight bytes each are distinct objects
/// and every compiler's frame layout says so. Everything else -- different
/// bases, an index whose value is unknown, a segment override -- answers "may
/// alias", because a peephole has no alias analysis and guessing the other way
/// would let a store to one local delete a store to another.
pub fn may_alias(left: &MemOp, right: &MemOp) -> bool {
    if left.base != right.base
        || left.index != right.index
        || left.scale != right.scale
        || left.segment != right.segment
    {
        return true;
    }
    let left_end = left.disp.saturating_add(i64::from(left.size.max(1)));
    let right_end = right.disp.saturating_add(i64::from(right.size.max(1)));
    left.disp < right_end && right.disp < left_end
}

/// Whether two memory operands name exactly the same bytes, read the same way.
pub fn same_location(left: &MemOp, right: &MemOp) -> bool {
    left.base == right.base
        && left.index == right.index
        && left.scale == right.scale
        && left.segment == right.segment
        && left.endian == right.endian
        && left.disp == right.disp
        && left.size == right.size
}

/// Every register an operation reads, collected.
pub fn uses_of(op: &Op) -> Vec<VReg> {
    let mut out = Vec::new();
    crate::ir::use_def::for_each_use(op, |register| out.push(register.clone()));
    out
}

/// Every register an operation writes, collected.
pub fn defs_of(op: &Op) -> Vec<VReg> {
    let mut out = Vec::new();
    crate::ir::use_def::for_each_def(op, |register| out.push(register.clone()));
    out
}
