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

#[cfg(test)]
mod tests;

const MAX_AFFINE_COMPONENTS: usize = 256;
const MAX_AFFINE_COMPONENT_NODES: usize = 32;

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

    walk(
        body,
        ctx,
        &mut HashMap::new(),
        &mut HashMap::new(),
        &mut HashMap::new(),
    );
}

fn pure_address_expression(expr: &Expr) -> bool {
    match expr {
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
        Expr::Bin { lhs, rhs, .. } => pure_address_expression(lhs) && pure_address_expression(rhs),
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => pure_address_expression(src),
        Expr::Deref { .. }
        | Expr::Call { .. }
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

/// Whether a locally defined value is a bounded affine address component.
///
/// This deliberately excludes general arithmetic. GCC splits effective ARM
/// addresses into register-only `add`/`sub`/scaled-index instructions before a
/// final frame-base addition; retaining those SSA definitions is enough to
/// expose the complete address without turning this pass into global copy
/// propagation.
fn affine_component_size(expr: &Expr) -> Option<usize> {
    let size = match expr {
        Expr::Reg(_) | Expr::Const(_) => 1,
        Expr::Bin { op, lhs, rhs } => match op {
            BinOp::Add | BinOp::Sub => 1usize
                .checked_add(affine_component_size(lhs)?)?
                .checked_add(affine_component_size(rhs)?)?,
            BinOp::Mul => {
                if matches!(lhs.as_ref(), Expr::Const(_)) {
                    2usize.checked_add(affine_component_size(rhs)?)?
                } else if matches!(rhs.as_ref(), Expr::Const(_)) {
                    2usize.checked_add(affine_component_size(lhs)?)?
                } else {
                    return None;
                }
            }
            BinOp::Shl if matches!(rhs.as_ref(), Expr::Const(_)) => {
                2usize.checked_add(affine_component_size(lhs)?)?
            }
            _ => return None,
        },
        Expr::Cast { expr, .. } => 1usize.checked_add(affine_component_size(expr)?)?,
        _ => return None,
    };
    (size <= MAX_AFFINE_COMPONENT_NODES).then_some(size)
}

fn is_versioned_local_value(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if name.contains('#')) || matches!(register, VReg::Temp(_))
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
        Expr::Call { target, args, .. } => {
            contains_active_stack_base(target, ctx)
                || args
                    .iter()
                    .any(|argument| contains_active_stack_base(argument, ctx))
        }
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
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => contains_active_stack_base(src, ctx),
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
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            contains_register(call_target, target)
                || args
                    .iter()
                    .any(|argument| contains_register(argument, target))
        }
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
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => contains_register(src, target),
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
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            replace_register(call_target, target, replacement);
            for argument in args {
                replace_register(argument, target, replacement);
            }
        }
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
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => replace_register(src, target, replacement),
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

fn expanded_lea(expr: &Expr, definitions: &HashMap<VReg, Expr>) -> Option<Expr> {
    let Expr::Lea {
        base: Some(base),
        index,
        scale,
        disp,
        segment: None,
    } = expr
    else {
        return None;
    };
    let mut expanded = definitions.get(base)?.clone();
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
            return None;
        };
        expanded = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(expanded),
            rhs: Box::new(scaled),
        };
    }
    Some(add_offset(expanded, *disp))
}

fn expand_expr(expr: &mut Expr, aliases: &HashMap<VReg, Expr>) {
    if let Expr::Reg(register) = expr {
        if let Some(replacement) = aliases.get(register) {
            *expr = replacement.clone();
        }
        return;
    }
    if let Some(expanded) = expanded_lea(expr, aliases) {
        *expr = expanded;
        return;
    }
    match expr {
        Expr::Deref { addr, .. } => expand_expr(addr, aliases),
        Expr::Call { target, args, .. } => {
            expand_expr(target, aliases);
            for argument in args {
                expand_expr(argument, aliases);
            }
        }
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
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => expand_expr(src, aliases),
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

/// Expand a definition while preserving the register immediately scaled by a
/// shift/multiply as the affine index atom.
///
/// For `tmp = matched - 1; scaled = tmp << 2`, distributing `tmp` into
/// `(matched - 1) << 2` moves a constant out of the source-level array index
/// and into the byte displacement. That can make a proven `array[matched-1]`
/// access appear to start before the array. Keeping `tmp` intact retains both
/// the exact value and the object-relative coordinate.
fn expand_affine_definition(expr: &mut Expr, components: &HashMap<VReg, Expr>) {
    if let Expr::Reg(register) = expr {
        if let Some(replacement) = components.get(register) {
            *expr = replacement.clone();
        }
        return;
    }
    if let Some(expanded) = expanded_lea(expr, components) {
        *expr = expanded;
        return;
    }
    match expr {
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Reg(_)) && matches!(rhs.as_ref(), Expr::Const(_)) => {}
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } if (matches!(lhs.as_ref(), Expr::Reg(_)) && matches!(rhs.as_ref(), Expr::Const(_)))
            || (matches!(rhs.as_ref(), Expr::Reg(_)) && matches!(lhs.as_ref(), Expr::Const(_))) => {
        }
        Expr::Bin { lhs, rhs, .. } => {
            expand_affine_definition(lhs, components);
            expand_affine_definition(rhs, components);
        }
        Expr::Cast { expr, .. } => expand_affine_definition(expr, components),
        _ => {}
    }
}

/// Expand affine components only where an expression is used as a memory
/// address. Scalar uses remain in their original SSA form, keeping this pass
/// out of the general copy-propagation business.
fn expand_memory_address_components(expr: &mut Expr, components: &HashMap<VReg, Expr>) {
    match expr {
        Expr::Deref { addr, .. } => expand_affine_definition(addr, components),
        Expr::Call { target, args, .. } => {
            expand_memory_address_components(target, components);
            for argument in args {
                expand_memory_address_components(argument, components);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expand_memory_address_components(lhs, components);
            expand_memory_address_components(rhs, components);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expand_memory_address_components(cond, components);
            expand_memory_address_components(if_true, components);
            expand_memory_address_components(if_false, components);
        }
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => {
            expand_memory_address_components(src, components)
        }
        Expr::FunctionTableEntry { index, .. } => {
            expand_memory_address_components(index, components)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                expand_memory_address_components(argument, components);
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
    components: &mut HashMap<VReg, Expr>,
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
        for expression in components.values_mut() {
            replace_register(expression, target, &snapshot);
        }
    } else {
        aliases
            .retain(|alias, expression| alias != target && !contains_register(expression, target));
        components
            .retain(|alias, expression| alias != target && !contains_register(expression, target));
    }
    aliases.remove(target);
    components.remove(target);
    snapshots.retain(|source, snapshot| source != target && snapshot != target);
}

fn walk(
    body: &mut [Stmt],
    ctx: StackContext,
    aliases: &mut HashMap<VReg, Expr>,
    components: &mut HashMap<VReg, Expr>,
    snapshots: &mut HashMap<VReg, VReg>,
) {
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                expand_expr(src, aliases);
                expand_memory_address_components(src, components);
                // Keep scalar assignments readable, but retain a recursively
                // expanded affine definition for later memory-address uses.
                let mut expanded_definition = src.clone();
                expand_affine_definition(&mut expanded_definition, components);
                let copied_from = match src {
                    Expr::Reg(register) if register != dst => Some(register.clone()),
                    _ => None,
                };
                redefine_register(dst, aliases, components, snapshots);
                if is_stack_pointer_reg(dst, ctx) {
                    aliases.clear();
                    components.clear();
                    snapshots.clear();
                } else if is_versioned_local_value(dst)
                    && !contains_register(&expanded_definition, dst)
                {
                    if components.len() < MAX_AFFINE_COMPONENTS
                        && affine_component_size(&expanded_definition).is_some()
                    {
                        components.insert(dst.clone(), expanded_definition.clone());
                    }
                    if pure_address_expression(&expanded_definition)
                        && contains_active_stack_base(&expanded_definition, ctx)
                    {
                        aliases.insert(dst.clone(), expanded_definition);
                    }
                }
                if let Some(source) = copied_from {
                    snapshots.insert(source, dst.clone());
                }
            }
            Stmt::Store { addr, src, .. } => {
                expand_expr(addr, aliases);
                expand_affine_definition(addr, components);
                expand_expr(src, aliases);
                expand_memory_address_components(src, components);
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                expand_expr(target, aliases);
                expand_affine_definition(target, components);
                for argument in args {
                    expand_expr(argument, aliases);
                    expand_affine_definition(argument, components);
                }
                if let Some(dst) = dst {
                    redefine_register(dst, aliases, components, snapshots);
                }
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    expand_expr(value, aliases);
                }
                aliases.clear();
                components.clear();
                snapshots.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expand_expr(cond, aliases);
                let mut branch_aliases = aliases.clone();
                let mut branch_components = components.clone();
                let mut branch_snapshots = snapshots.clone();
                walk(
                    then_body,
                    ctx,
                    &mut branch_aliases,
                    &mut branch_components,
                    &mut branch_snapshots,
                );
                if let Some(else_body) = else_body {
                    let mut branch_aliases = aliases.clone();
                    let mut branch_components = components.clone();
                    let mut branch_snapshots = snapshots.clone();
                    walk(
                        else_body,
                        ctx,
                        &mut branch_aliases,
                        &mut branch_components,
                        &mut branch_snapshots,
                    );
                }
                aliases.clear();
                components.clear();
                snapshots.clear();
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                expand_expr(cond, aliases);
                let mut loop_aliases = aliases.clone();
                // A preheader scalar definition may be loop-carried even when
                // its current SSA-looking physical name is unchanged in the
                // structured AST (`cursor = cursor + 4`). Reusing it in the
                // body would freeze the first-iteration address. Only the
                // established stack-address aliases have the stronger proof
                // needed to cross a loop boundary; rebuild affine components
                // from definitions inside the body.
                let mut loop_components = HashMap::new();
                let mut loop_snapshots = snapshots.clone();
                walk(
                    body,
                    ctx,
                    &mut loop_aliases,
                    &mut loop_components,
                    &mut loop_snapshots,
                );
                aliases.clear();
                components.clear();
                snapshots.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                walk(
                    std::slice::from_mut(init.as_mut()),
                    ctx,
                    aliases,
                    components,
                    snapshots,
                );
                expand_expr(cond, aliases);
                let mut loop_aliases = aliases.clone();
                let mut loop_components = HashMap::new();
                let mut loop_snapshots = snapshots.clone();
                walk(
                    body,
                    ctx,
                    &mut loop_aliases,
                    &mut loop_components,
                    &mut loop_snapshots,
                );
                walk(
                    std::slice::from_mut(step.as_mut()),
                    ctx,
                    &mut loop_aliases,
                    &mut loop_components,
                    &mut loop_snapshots,
                );
                aliases.clear();
                components.clear();
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
                    let mut case_components = components.clone();
                    let mut case_snapshots = snapshots.clone();
                    walk(
                        case,
                        ctx,
                        &mut case_aliases,
                        &mut case_components,
                        &mut case_snapshots,
                    );
                }
                if let Some(default) = default {
                    let mut default_aliases = aliases.clone();
                    let mut default_components = components.clone();
                    let mut default_snapshots = snapshots.clone();
                    walk(
                        default,
                        ctx,
                        &mut default_aliases,
                        &mut default_components,
                        &mut default_snapshots,
                    );
                }
                aliases.clear();
                components.clear();
                snapshots.clear();
            }
            Stmt::Push { value } => expand_expr(value, aliases),
            Stmt::Pop { target } => redefine_register(target, aliases, components, snapshots),
            Stmt::IndirectGoto { target } => {
                expand_expr(target, aliases);
                expand_affine_definition(target, components);
                aliases.clear();
                components.clear();
                snapshots.clear();
            }
            Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {
                aliases.clear();
                components.clear();
                snapshots.clear();
            }
            Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}
