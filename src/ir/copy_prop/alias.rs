//! May these two memory accesses alias?
//!
//! Copy propagation records a source expression at its definition and replays
//! it at a later use. That is only sound while nothing in between can change
//! what the expression evaluates to, and the hard case is memory: a recorded
//! `Deref` is a *pending load*, and any intervening store or push may be a
//! write to the same bytes.
//!
//! This module holds the whole answer to that question, plus the structural
//! predicates the parent pass asks about a candidate source expression before
//! it will record one at all ([`is_scratch_reg`], [`contains_reg`],
//! [`contains_deref`], [`contains_unknown`], [`contains_select`]).
//!
//! The disjointness proof is deliberately fail-closed: [`addresses_disjoint`]
//! claims two accesses cannot overlap only from evidence already present in the
//! AST, in the two shapes documented on [`invalidate_loads_for_store`]. Anything
//! it does not enumerate answers "may alias", and the pending load is dropped.

use crate::ir::ast::Expr;
use crate::ir::types::{BinOp, VReg};

use super::reads::count_reg_uses;
use super::Copies;

/// A register we're willing to delete a dead copy to: physical scratch/role
/// registers, temporaries, and SSA-versioned predicate values, but NOT promoted
/// stack locals (owned by dead-store elimination) or unversioned architectural
/// flag names. A poisoned predicate is separately excluded from propagation.
pub(super) fn is_scratch_reg(v: &VReg) -> bool {
    match v {
        VReg::Temp(_) => true,
        VReg::Phys(n) => !n.starts_with("local_") && !n.starts_with("stack_"),
        VReg::FlagValue { .. } => true,
        VReg::Flag(_) => false,
    }
}

pub(super) fn contains_reg(e: &Expr, target: &VReg) -> bool {
    count_reg_uses(e, target) > 0
}

/// True if `e` reads memory (contains a `Deref`). A recorded copy whose source
/// reads memory must be dropped at any intervening store/push, since the store
/// may alias the loaded location — folding the load past it would read the
/// post-store value.
pub(super) fn contains_deref(e: &Expr) -> bool {
    match e {
        Expr::Deref { .. } | Expr::Call { .. } | Expr::FunctionTableEntry { .. } => true,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_deref(lhs) || contains_deref(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => contains_deref(cond) || contains_deref(if_true) || contains_deref(if_false),
        Expr::Un { src, .. } => contains_deref(src),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => contains_deref(expr),
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_deref),
    }
}

pub(super) fn contains_unknown(e: &Expr) -> bool {
    match e {
        Expr::Unknown(_) => true,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::Deref { addr, .. } => contains_unknown(addr),
        Expr::Call { target, args, .. } => {
            contains_unknown(target) || args.iter().any(contains_unknown)
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_unknown(lhs) || contains_unknown(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => contains_unknown(cond) || contains_unknown(if_true) || contains_unknown(if_false),
        Expr::Un { src, .. } => contains_unknown(src),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => contains_unknown(expr),
        Expr::FunctionTableEntry { index, .. } => contains_unknown(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_unknown),
    }
}

pub(super) fn contains_select(e: &Expr) -> bool {
    match e {
        Expr::Select { .. } => true,
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::NumericConvert { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => contains_select(addr),
        Expr::Call { target, args, .. } => {
            contains_select(target) || args.iter().any(contains_select)
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_select(lhs) || contains_select(rhs)
        }
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_select),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
    }
}

/// Drop every recorded copy whose source reads memory (a pending load that a
/// store/push could alias).
pub(super) fn invalidate_loads(copies: &mut Copies) {
    copies.retain(|_, src| !contains_deref(src));
}

/// Like [`invalidate_loads`], but keeps a pending load the store at `addr`
/// (width `size` bytes) provably cannot touch.
///
/// # Why this is not just `invalidate_loads`
///
/// Dropping every pending load at every store is correct but costs real
/// quality: measured over the fixture corpus at `-O0` and `-O2` (732 C/C++
/// lanes, 10,051 functions), 1,989 dropped loads had a use waiting in the same
/// straight-line run, and **1,308 of them were a store and a load to constant,
/// non-overlapping offsets of the *same* named stack object** — `local_18[0]`
/// written while `local_18[8]` sits pending. Only 8 genuinely overlapped.
///
/// # Fail-closed
///
/// Disjointness is claimed only from evidence already in the AST and only in
/// two shapes ([`addresses_disjoint`]): identical stack object with constant
/// displacements whose byte ranges do not intersect, and frame storage versus a
/// fixed image address. Everything else — an arbitrary pointer on either side,
/// two *different* named stack objects (stack promotion may nest one inside
/// another), a non-constant index, a call — keeps the original conservative
/// drop. A wrong claim here would reorder a load across an aliasing store and
/// silently produce wrong C, so every unproven case stays unproven.
pub(super) fn invalidate_loads_for_store(copies: &mut Copies, addr: &Expr, size: u8) {
    let store_size = i64::from(size);
    copies.retain(|_, src| {
        if !contains_deref(src) {
            return true;
        }
        let kept = loads_proven_disjoint(src, addr, store_size);
        if kept {
            crate::ir::pass_stats::fire("copyprop_load_kept_disjoint");
        }
        kept
    });
}

/// Constant byte displacement of `e` from its stack-object root.
///
/// `None` unless every term between the root and `e` is a literal constant, so
/// an indexed access never produces an offset a caller could reason with.
fn stack_offset(e: &Expr) -> Option<(&VReg, i64)> {
    match e {
        Expr::StackAddr { object, .. } => Some((object, 0)),
        Expr::Bin { op, lhs, rhs } => {
            let sign: i64 = match op {
                BinOp::Add => 1,
                BinOp::Sub => -1,
                _ => return None,
            };
            if let (Some((object, base)), Expr::Const(k)) = (stack_offset(lhs), rhs.as_ref()) {
                return base.checked_add(sign.checked_mul(*k)?).map(|d| (object, d));
            }
            // `const + &obj` only commutes for addition.
            match (lhs.as_ref(), stack_offset(rhs)) {
                (Expr::Const(k), Some((object, base))) if sign == 1 => {
                    base.checked_add(*k).map(|d| (object, d))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// True when `e` addresses a fixed image location rather than frame storage.
///
/// Every term must be a literal. `Addr(base) + reg` is deliberately refused:
/// the register is unbounded here, so "inside the image" is an assumption about
/// the index, not a proof about the address.
fn is_image_address(e: &Expr) -> bool {
    match e {
        Expr::Addr(_) | Expr::Named { .. } => true,
        Expr::Bin { op, lhs, rhs } if matches!(op, BinOp::Add | BinOp::Sub) => {
            match (lhs.as_ref(), rhs.as_ref()) {
                (base, Expr::Const(_)) => is_image_address(base),
                (Expr::Const(_), base) => matches!(op, BinOp::Add) && is_image_address(base),
                _ => false,
            }
        }
        _ => false,
    }
}

/// True only when the two accesses provably touch no common byte.
fn addresses_disjoint(a: &Expr, a_size: i64, b: &Expr, b_size: i64) -> bool {
    if let (Some((object_a, offset_a)), Some((object_b, offset_b))) =
        (stack_offset(a), stack_offset(b))
    {
        // Two *different* named objects are deliberately not claimed disjoint:
        // stack promotion can name an interior cell of a larger byte object.
        return object_a == object_b
            && (offset_a.saturating_add(a_size) <= offset_b
                || offset_b.saturating_add(b_size) <= offset_a);
    }
    // Frame storage and a fixed image address are different storage.
    (stack_offset(a).is_some() && is_image_address(b))
        || (is_image_address(a) && stack_offset(b).is_some())
}

/// True when every memory read inside `e` is proven disjoint from the store.
///
/// Mirrors [`contains_deref`]'s variant coverage exactly: any construct whose
/// memory footprint this function does not enumerate must answer `false`.
fn loads_proven_disjoint(e: &Expr, store_addr: &Expr, store_size: i64) -> bool {
    match e {
        // Opaque footprint — a call may write anything.
        Expr::Call { .. } | Expr::FunctionTableEntry { .. } => false,
        Expr::Deref { addr, size } => {
            addresses_disjoint(store_addr, store_size, addr, i64::from(*size))
                // The address computation may itself load.
                && loads_proven_disjoint(addr, store_addr, store_size)
        }
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            loads_proven_disjoint(lhs, store_addr, store_size)
                && loads_proven_disjoint(rhs, store_addr, store_size)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            loads_proven_disjoint(cond, store_addr, store_size)
                && loads_proven_disjoint(if_true, store_addr, store_size)
                && loads_proven_disjoint(if_false, store_addr, store_size)
        }
        Expr::Un { src, .. } => loads_proven_disjoint(src, store_addr, store_size),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            loads_proven_disjoint(expr, store_addr, store_size)
        }
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .all(|arg| loads_proven_disjoint(arg, store_addr, store_size)),
    }
}
