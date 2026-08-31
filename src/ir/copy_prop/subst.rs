//! Apply the copy environment to an expression.
//!
//! [`subst`] is the ONLY thing in this pass that rewrites an expression, which
//! makes it the sole source of the `changed` answer `propagate_copies` reports
//! to the [`crate::ir::ast::prepare`] fixpoint -- see the contract on
//! [`super::propagate_copies`]. Every `return` below is therefore an explicit
//! `true`/`false` and every recursion is folded in with `|`, never `||`.
//!
//! Two hazards live here rather than in the environment, because they are
//! properties of the *position* being substituted rather than of the recorded
//! value:
//!
//! * an `Lea` base/index slot holds a bare `VReg`, so a recorded arithmetic
//!   source cannot be dropped into it. [`expand_lea_with_copies`] rewrites the
//!   whole address into ordinary `Bin` arithmetic when that happens, which is
//!   what lets a reassembled address (`p = base + i*4`) inline into its `*p`.
//! * stack promotion spells `local_x = value` as a `Store` whose address is the
//!   bare promoted-local register, so replacing a top-level scratch address with
//!   `local_x` would silently turn an indirect write into an assignment.
//!   [`subst_store_addr`] is the one caller that refuses that substitution.
//!
//! Adding an [`Expr`] variant changes this file; changing an invalidation rule
//! does not.

use crate::ir::ast::Expr;
use crate::ir::types::{is_promoted_local_reg, VReg};

use super::env::Copies;

/// Substitute copies in an indirect-store address without changing its lvalue
/// category into a promoted-local assignment.
///
/// Stack promotion currently represents `local_x = value` as a `Store` whose
/// address is the bare promoted-local register. A machine pointer scratch can
/// also contain `local_x` as its scalar value: `p = local_x; *p = value`.
/// Replacing that top-level `p` with bare `local_x` would silently turn the
/// indirect write into an assignment. Keep the scratch in that one ambiguous
/// case; substitutions nested inside arithmetic addresses remain safe because
/// the address expression cannot be mistaken for local storage.
pub(super) fn subst_store_addr(address: &mut Expr, copies: &Copies) -> bool {
    if let Expr::Lea {
        base: Some(register),
        index: None,
        scale,
        disp,
        ..
    } = address
    {
        if *scale == 1 && *disp == 0 {
            if let Some(Expr::Reg(replacement)) = copies.get(register) {
                if is_promoted_local_reg(replacement) {
                    // Preserve the explicit address container while removing
                    // the scratch. General `subst` deliberately collapses a
                    // trivial Lea to its value, which is incorrect only at
                    // this overloaded Store-lvalue boundary.
                    *register = replacement.clone();
                    return true;
                }
            }
        }
    }
    if matches!(
        address,
        Expr::Reg(register)
            if matches!(copies.get(register), Some(Expr::Reg(replacement)) if is_promoted_local_reg(replacement))
    ) {
        return false;
    }
    subst(address, copies)
}

/// Substitute every active copy `dst -> src` into `e`.
///
/// Returns whether it rewrote anything. This is the ONLY thing in
/// `propagate_run`/`propagate_run_counted` that edits an expression, so the
/// answer it gives is what those two report to `propagate_copies`, and in turn
/// what the [`crate::ir::ast::prepare`] fixpoint stops on. Every `return` below
/// is therefore an explicit `true`/`false` rather than a bare `return`, and
/// every recursion is folded into the answer with `|` — never `||`, which
/// would skip the rest of the expression.
pub(super) fn subst(e: &mut Expr, copies: &Copies) -> bool {
    if copies.is_empty() {
        return false;
    }
    // Lea stores base/index as VRegs for the machine IR. Once a single-use
    // index is reconstructed as a real expression (for example the signed
    // extension of a loop counter), keeping that VReg-only container would
    // strand an otherwise dead scratch. Expand the address to ordinary Bin
    // arithmetic when either component has a non-register replacement.
    let expanded_lea = expand_lea_with_copies(e, copies);
    if let Some(expanded) = expanded_lea {
        *e = expanded;
        subst(e, copies);
        return true;
    }
    // A trivial `Lea` — base only, no index, zero displacement — denotes exactly
    // its base register. When that base has a recorded copy (which for a single-
    // use address is an arithmetic expression, not a bare register), fold the
    // whole `Lea` to the copied value. This is what lets a reassembled address
    // (`p = base + i*4`) inline into its `*p` use, since an `Lea` base/index slot
    // must otherwise stay a register.
    let trivial_lea_repl = match e {
        Expr::Lea {
            base: Some(r),
            index: None,
            disp,
            ..
        } if *disp == 0 => copies.get(r).cloned(),
        _ => None,
    };
    if let Some(repl) = trivial_lea_repl {
        *e = repl;
        subst(e, copies); // substitute within the inlined expression too
        return true;
    }
    match e {
        Expr::Reg(r) => {
            if let Some(src) = copies.get(r) {
                *e = src.clone();
                return true;
            }
            false
        }
        // A stack object's identity is stable storage, not a scalar value to
        // replace from the copy environment.
        Expr::StackAddr { .. } => false,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            // Only substitute when the replacement is itself a bare register
            // (an Lea base/index must stay a register).
            let mut substituted = false;
            if let Some(r) = base {
                if let Some(Expr::Reg(nr)) = copies.get(r) {
                    let nr = nr.clone();
                    *base = Some(nr);
                    substituted = true;
                }
            }
            if let Some(r) = index {
                if let Some(Expr::Reg(nr)) = copies.get(r) {
                    let nr = nr.clone();
                    *index = Some(nr);
                    substituted = true;
                }
            }
            substituted
        }
        Expr::Deref { addr, .. } => subst(addr, copies),
        Expr::Call { target, args, .. } => {
            let mut substituted = subst(target, copies);
            for argument in args {
                substituted |= subst(argument, copies);
            }
            substituted
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            subst(lhs, copies) | subst(rhs, copies)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => subst(cond, copies) | subst(if_true, copies) | subst(if_false, copies),
        Expr::Un { src, .. } => subst(src, copies),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => subst(expr, copies),
        Expr::FunctionTableEntry { index, .. } => subst(index, copies),
        Expr::WideArithmetic { args, .. } => {
            let mut substituted = false;
            for argument in args {
                substituted |= subst(argument, copies);
            }
            substituted
        }
    }
}

fn expand_lea_with_copies(e: &Expr, copies: &Copies) -> Option<Expr> {
    let Expr::Lea {
        base,
        index,
        scale,
        disp,
        segment: None,
    } = e
    else {
        return None;
    };
    let replacement = |reg: &VReg| {
        copies
            .get(reg)
            .cloned()
            .unwrap_or_else(|| Expr::Reg(reg.clone()))
    };
    let needs_expansion = base
        .iter()
        .chain(index.iter())
        .any(|reg| matches!(copies.get(reg), Some(expr) if !matches!(expr, Expr::Reg(_))));
    if !needs_expansion {
        return None;
    }

    let mut terms = Vec::new();
    if let Some(base) = base {
        terms.push(replacement(base));
    }
    if let Some(index) = index {
        let index = replacement(index);
        terms.push(if *scale > 1 {
            Expr::Bin {
                op: crate::ir::types::BinOp::Mul,
                lhs: Box::new(index),
                rhs: Box::new(Expr::Const(i64::from(*scale))),
            }
        } else {
            index
        });
    }
    if *disp != 0 || terms.is_empty() {
        terms.push(Expr::Const(*disp));
    }
    Some(
        terms
            .into_iter()
            .reduce(|lhs, rhs| Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
            .expect("a Lea expansion always has at least one address term"),
    )
}
