//! Bounded local expansion of stack-address aliases.
//!
//! Optimised ARM commonly materialises one effective address through several
//! physical temporaries (`ip = sp + C; lr = ip + i*4; [lr - D]`). The ordinary
//! expression pass intentionally folds only lifter temporaries, while the
//! constant-address map in the parent pass intentionally cannot represent a
//! dynamic index. This module bridges those two owners without pretending to be
//! a general reaching-definitions oracle.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, VReg};

use super::{is_active_stack_base, is_stack_pointer_reg, StackContext};

/// Expand exact, locally value-numbered chains that carry stack addresses.
///
/// Only versioned, pure address expressions are propagated, and only within a
/// single linear control-flow run. Stack-pointer writes and every control
/// boundary clear the map, so an address can never move into a different frame
/// phase or predecessor.
pub(super) fn expand(body: &mut [Stmt], ctx: StackContext) {
    if !matches!(ctx.cc, Some(CallConv::Arm | CallConv::ArmHardFloat)) {
        return;
    }

    walk(body, ctx, &mut HashMap::new(), &mut HashMap::new());
}

fn pure_address_expression(expr: &Expr) -> bool {
    match expr {
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
        Expr::Bin { lhs, rhs, .. } => pure_address_expression(lhs) && pure_address_expression(rhs),
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => pure_address_expression(src),
        Expr::Deref { .. }
        | Expr::Cmp { .. }
        | Expr::Select { .. }
        | Expr::WideArithmetic { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn contains_active_stack_base(expr: &Expr, ctx: StackContext) -> bool {
    match expr {
        Expr::Reg(VReg::Phys(name)) => is_active_stack_base(name, ctx),
        Expr::Reg(_) => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.iter().chain(index).any(
                |register| matches!(register, VReg::Phys(name) if is_active_stack_base(name, ctx)),
            )
        }
        Expr::Deref { addr, .. } => contains_active_stack_base(addr, ctx),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_active_stack_base(lhs, ctx) || contains_active_stack_base(rhs, ctx)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            contains_active_stack_base(cond, ctx)
                || contains_active_stack_base(if_true, ctx)
                || contains_active_stack_base(if_false, ctx)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => contains_active_stack_base(src, ctx),
        Expr::FunctionTableEntry { index, .. } => contains_active_stack_base(index, ctx),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|argument| contains_active_stack_base(argument, ctx)),
        Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn contains_register(expr: &Expr, target: &VReg) -> bool {
    match expr {
        Expr::Reg(register) => register == target,
        Expr::StackAddr { object, .. } => object == target,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref() == Some(target) || index.as_ref() == Some(target)
        }
        Expr::Deref { addr, .. } => contains_register(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_register(lhs, target) || contains_register(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            contains_register(cond, target)
                || contains_register(if_true, target)
                || contains_register(if_false, target)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => contains_register(src, target),
        Expr::FunctionTableEntry { index, .. } => contains_register(index, target),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|argument| contains_register(argument, target)),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn replace_register(expr: &mut Expr, target: &VReg, replacement: &VReg) {
    match expr {
        Expr::Reg(register) => {
            if register == target {
                *register = replacement.clone();
            }
        }
        Expr::StackAddr { object, .. } => {
            if object == target {
                *object = replacement.clone();
            }
        }
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            for register in base.iter_mut().chain(index.iter_mut()) {
                if register == target {
                    *register = replacement.clone();
                }
            }
        }
        Expr::Deref { addr, .. } => replace_register(addr, target, replacement),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            replace_register(lhs, target, replacement);
            replace_register(rhs, target, replacement);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            replace_register(cond, target, replacement);
            replace_register(if_true, target, replacement);
            replace_register(if_false, target, replacement);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            replace_register(src, target, replacement)
        }
        Expr::FunctionTableEntry { index, .. } => replace_register(index, target, replacement),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                replace_register(argument, target, replacement);
            }
        }
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

fn add_offset(expression: Expr, offset: i64) -> Expr {
    if offset == 0 {
        expression
    } else {
        Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(expression),
            rhs: Box::new(Expr::Const(offset)),
        }
    }
}

fn expand_expr(expr: &mut Expr, aliases: &HashMap<VReg, Expr>) {
    if let Expr::Reg(register) = expr {
        if let Some(replacement) = aliases.get(register) {
            *expr = replacement.clone();
        }
        return;
    }
    if let Expr::Lea {
        base: Some(base),
        index,
        scale,
        disp,
        segment: None,
    } = expr
    {
        if let Some(base_expression) = aliases.get(base).cloned() {
            let mut expanded = base_expression;
            if let Some(index) = index.clone() {
                let scaled = if *scale == 1 {
                    Expr::Reg(index)
                } else if *scale > 1 {
                    Expr::Bin {
                        op: BinOp::Mul,
                        lhs: Box::new(Expr::Reg(index)),
                        rhs: Box::new(Expr::Const(i64::from(*scale))),
                    }
                } else {
                    return;
                };
                expanded = Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(expanded),
                    rhs: Box::new(scaled),
                };
            }
            *expr = add_offset(expanded, *disp);
            return;
        }
    }
    match expr {
        Expr::Deref { addr, .. } => expand_expr(addr, aliases),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expand_expr(lhs, aliases);
            expand_expr(rhs, aliases);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expand_expr(cond, aliases);
            expand_expr(if_true, aliases);
            expand_expr(if_false, aliases);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => expand_expr(src, aliases),
        Expr::FunctionTableEntry { index, .. } => expand_expr(index, aliases),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                expand_expr(argument, aliases);
            }
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => {}
    }
}

fn redefine_register(
    target: &VReg,
    aliases: &mut HashMap<VReg, Expr>,
    snapshots: &mut HashMap<VReg, VReg>,
) {
    // Coalescing can deliberately give an in-place update the same high
    // register name as its input. If the lifter first copied that old value
    // (`t = index; index = t + 1`), retarget pending address aliases to the
    // copy before the update. Without such a snapshot, discard dependent
    // aliases rather than substituting a definition that no longer reaches.
    if let Some(snapshot) = snapshots.get(target).cloned() {
        for expression in aliases.values_mut() {
            replace_register(expression, target, &snapshot);
        }
    } else {
        aliases
            .retain(|alias, expression| alias != target && !contains_register(expression, target));
    }
    aliases.remove(target);
    snapshots.retain(|source, snapshot| source != target && snapshot != target);
}

fn walk(
    body: &mut [Stmt],
    ctx: StackContext,
    aliases: &mut HashMap<VReg, Expr>,
    snapshots: &mut HashMap<VReg, VReg>,
) {
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                expand_expr(src, aliases);
                let copied_from = match src {
                    Expr::Reg(register) if register != dst => Some(register.clone()),
                    _ => None,
                };
                redefine_register(dst, aliases, snapshots);
                if is_stack_pointer_reg(dst, ctx) {
                    aliases.clear();
                    snapshots.clear();
                } else if matches!(dst, VReg::Phys(name) if name.contains('#'))
                    && !contains_register(src, dst)
                    && pure_address_expression(src)
                    && contains_active_stack_base(src, ctx)
                {
                    aliases.insert(dst.clone(), src.clone());
                }
                if let Some(source) = copied_from {
                    snapshots.insert(source, dst.clone());
                }
            }
            Stmt::Store { addr, src, .. } => {
                expand_expr(addr, aliases);
                expand_expr(src, aliases);
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                expand_expr(target, aliases);
                for argument in args {
                    expand_expr(argument, aliases);
                }
                if let Some(dst) = dst {
                    redefine_register(dst, aliases, snapshots);
                }
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    expand_expr(value, aliases);
                }
                aliases.clear();
                snapshots.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expand_expr(cond, aliases);
                let mut branch_aliases = aliases.clone();
                let mut branch_snapshots = snapshots.clone();
                walk(then_body, ctx, &mut branch_aliases, &mut branch_snapshots);
                if let Some(else_body) = else_body {
                    let mut branch_aliases = aliases.clone();
                    let mut branch_snapshots = snapshots.clone();
                    walk(else_body, ctx, &mut branch_aliases, &mut branch_snapshots);
                }
                aliases.clear();
                snapshots.clear();
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                expand_expr(cond, aliases);
                let mut loop_aliases = aliases.clone();
                let mut loop_snapshots = snapshots.clone();
                walk(body, ctx, &mut loop_aliases, &mut loop_snapshots);
                aliases.clear();
                snapshots.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                walk(std::slice::from_mut(init.as_mut()), ctx, aliases, snapshots);
                expand_expr(cond, aliases);
                let mut loop_aliases = aliases.clone();
                let mut loop_snapshots = snapshots.clone();
                walk(body, ctx, &mut loop_aliases, &mut loop_snapshots);
                walk(
                    std::slice::from_mut(step.as_mut()),
                    ctx,
                    &mut loop_aliases,
                    &mut loop_snapshots,
                );
                aliases.clear();
                snapshots.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                expand_expr(discriminant, aliases);
                for (_, case) in cases {
                    let mut case_aliases = aliases.clone();
                    let mut case_snapshots = snapshots.clone();
                    walk(case, ctx, &mut case_aliases, &mut case_snapshots);
                }
                if let Some(default) = default {
                    let mut default_aliases = aliases.clone();
                    let mut default_snapshots = snapshots.clone();
                    walk(default, ctx, &mut default_aliases, &mut default_snapshots);
                }
                aliases.clear();
                snapshots.clear();
            }
            Stmt::Push { value } => expand_expr(value, aliases),
            Stmt::Pop { target } => redefine_register(target, aliases, snapshots),
            Stmt::IndirectGoto { target } => {
                expand_expr(target, aliases);
                aliases.clear();
                snapshots.clear();
            }
            Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {
                aliases.clear();
                snapshots.clear();
            }
            Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}
