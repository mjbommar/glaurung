//! Resolving the reaching definition behind a captured call argument.
//!
//! `fold_one_call` scans backwards from a call and captures whatever each
//! argument slot holds. What it captures is often a register whose value was
//! computed a few statements earlier, so the capture is only useful once that
//! definition has been substituted into it -- and a stack argument *must* be
//! substituted, because once the push is folded away there is nothing left to
//! name the register.
//!
//! Substitution is legal only when the definition still says the same thing at
//! the call. A pure expression always does. An impure one qualifies only in
//! the narrow case this module admits: a constant `rbp`/`ebp` frame slot with
//! no intervening write that could reach it, checked here rather than through
//! generic alias analysis so the conditions stay readable and provable.
//!
//! [`is_pure_arg_normalisation`](super::is_pure_arg_normalisation) is the
//! purity half of that test and deliberately stays in the parent: the 32-bit
//! cdecl folding in [`super::cdecl32`] uses it too.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::{outgoing_sysv_stack_push, reads_reg_in_expr, ssa_base};

/// Resolve one reaching register definition in every argument captured so far.
///
/// The backward scan reaches the nearest definition first, so substitution is
/// specific to the call-site use even when an unversioned scratch register is
/// reused for several arguments. Memory reads remain statement-rooted: moving a
/// load across an intervening store could change its value, so an impure source
/// keeps the register definition and the call keeps referring to it.
pub(super) fn resolve_captured_definition(
    found: &mut [Option<(usize, Expr)>],
    stack_args: &mut [Expr],
    dst: &VReg,
    src: &Expr,
    substitutable: bool,
) -> bool {
    resolve_captured_definition_in(found, stack_args, dst, src, substitutable, true)
}

/// As [`resolve_captured_definition`], with control over whether REGISTER slots
/// participate in the substitution.
///
/// A versioned scratch name already has a distinct SSA identity, so a register
/// slot may keep naming it — following the definition edge one step further
/// changes which spelling the argument is rendered under for no gain, and
/// `resolved_got_tail_jump_becomes_a_call_and_return` pins that. A STACK
/// argument cannot: its capture is an expression that must stand on its own
/// once the push is folded away, so the definition has to be substituted in or
/// the argument is lost with it.
pub(super) fn resolve_captured_definition_in(
    found: &mut [Option<(usize, Expr)>],
    stack_args: &mut [Expr],
    dst: &VReg,
    src: &Expr,
    substitutable: bool,
    register_slots: bool,
) -> bool {
    let feeds_registers = found
        .iter()
        .flatten()
        .any(|(_, captured)| reads_reg_in_expr(captured, dst));
    let feeds_stack = stack_args
        .iter()
        .any(|captured| reads_reg_in_expr(captured, dst));
    let feeds = if register_slots {
        feeds_registers || feeds_stack
    } else {
        feeds_stack
    };
    if !feeds || !substitutable {
        return feeds;
    }
    if register_slots {
        for (_, captured) in found.iter_mut().flatten() {
            let _ = substitute_exact_reg(captured, dst, src);
        }
    }
    for captured in stack_args {
        let _ = substitute_exact_reg(captured, dst, src);
    }
    true
}

/// Whether an impure definition is a fixed frame read that remains unchanged
/// until the call.
///
/// This is deliberately narrower than generic alias analysis. Only constant
/// `rbp`/`ebp` slots qualify. Intervening stores must either target a disjoint
/// fixed frame slot or be an exact lowered outgoing push below the frame; an
/// unknown pointer store, overlapping slot, frame-base write, call, or control
/// boundary rejects substitution.
pub(super) fn is_stable_frame_arg_definition(
    expr: &Expr,
    body: &[Stmt],
    definition_index: usize,
    call_index: usize,
) -> bool {
    let mut reads = Vec::new();
    if !collect_fixed_frame_reads(expr, &mut reads) || reads.is_empty() {
        return false;
    }
    for (index, statement) in body
        .iter()
        .enumerate()
        .take(call_index)
        .skip(definition_index + 1)
    {
        match statement {
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            } if matches!(ssa_base(name), "ebp" | "rbp") => return false,
            Stmt::Store {
                addr,
                size: store_size,
                ..
            } => {
                if outgoing_sysv_stack_push(body, index).is_some() {
                    continue;
                }
                let Some((base, store_disp)) = fixed_frame_address(addr) else {
                    return false;
                };
                if reads.iter().any(|(read_base, read_disp, read_size)| {
                    base == *read_base
                        && byte_ranges_overlap(
                            store_disp,
                            i64::from(*store_size),
                            *read_disp,
                            i64::from(*read_size),
                        )
                }) {
                    return false;
                }
            }
            Stmt::Call { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Return { .. }
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. } => return false,
            _ => {}
        }
    }
    true
}

fn collect_fixed_frame_reads(expr: &Expr, reads: &mut Vec<(String, i64, u8)>) -> bool {
    match expr {
        Expr::Deref { addr, size } => {
            let Some((base, disp)) = fixed_frame_address(addr) else {
                return false;
            };
            reads.push((base, disp, *size));
            true
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_fixed_frame_reads(lhs, reads) && collect_fixed_frame_reads(rhs, reads)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_fixed_frame_reads(cond, reads)
                && collect_fixed_frame_reads(if_true, reads)
                && collect_fixed_frame_reads(if_false, reads)
        }
        Expr::Un { src, .. } => collect_fixed_frame_reads(src, reads),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            collect_fixed_frame_reads(expr, reads)
        }
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .all(|argument| collect_fixed_frame_reads(argument, reads)),
        Expr::Call { .. } => false,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. } => true,
        Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::Unknown(_) => false,
    }
}

fn fixed_frame_address(expr: &Expr) -> Option<(String, i64)> {
    let Expr::Lea {
        base: Some(VReg::Phys(base)),
        index: None,
        disp,
        ..
    } = expr
    else {
        return None;
    };
    matches!(ssa_base(base), "ebp" | "rbp").then(|| (ssa_base(base).to_string(), *disp))
}

fn byte_ranges_overlap(left: i64, left_size: i64, right: i64, right_size: i64) -> bool {
    left < right.saturating_add(right_size) && right < left.saturating_add(left_size)
}

/// Replace an exact SSA register use inside an ordinary value expression.
///
/// Address components remain VRegs by construction, so they are only rewritten
/// when the replacement is another bare register. `StackAddr` is storage
/// identity and intentionally does not participate in scalar substitution.
pub(super) fn substitute_exact_reg(expr: &mut Expr, target: &VReg, replacement: &Expr) -> bool {
    match expr {
        Expr::Reg(reg) if reg == target => {
            *expr = replacement.clone();
            true
        }
        Expr::Reg(_) | Expr::StackAddr { .. } => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            let Expr::Reg(replacement) = replacement else {
                return false;
            };
            let mut changed = false;
            if base.as_ref() == Some(target) {
                *base = Some(replacement.clone());
                changed = true;
            }
            if index.as_ref() == Some(target) {
                *index = Some(replacement.clone());
                changed = true;
            }
            changed
        }
        Expr::Deref { addr, .. } => substitute_exact_reg(addr, target, replacement),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            let mut changed = substitute_exact_reg(call_target, target, replacement);
            for argument in args {
                changed |= substitute_exact_reg(argument, target, replacement);
            }
            changed
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            let left = substitute_exact_reg(lhs, target, replacement);
            let right = substitute_exact_reg(rhs, target, replacement);
            left || right
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            let cond = substitute_exact_reg(cond, target, replacement);
            let if_true = substitute_exact_reg(if_true, target, replacement);
            let if_false = substitute_exact_reg(if_false, target, replacement);
            cond || if_true || if_false
        }
        Expr::Un { src, .. } => substitute_exact_reg(src, target, replacement),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            substitute_exact_reg(expr, target, replacement)
        }
        Expr::FunctionTableEntry { index, .. } => substitute_exact_reg(index, target, replacement),
        Expr::WideArithmetic { args, .. } => {
            let mut changed = false;
            for argument in args {
                changed |= substitute_exact_reg(argument, target, replacement);
            }
            changed
        }
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}
