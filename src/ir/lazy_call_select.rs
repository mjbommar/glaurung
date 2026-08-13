//! Recover value-producing calls inside lazy conditional expressions.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::expression_width::explicit_expression_width;
use crate::ir::types::{is_promoted_local_name, BinOp, CmpOp, VReg};

#[derive(Clone, Debug, PartialEq, Eq)]
enum AssignmentTarget {
    Register(VReg),
    PromotedLocal { register: VReg, size: u8 },
}

/// Collapse lazy call diamonds using the active machine data model.
pub fn collapse_lazy_call_diamonds_with_pointer_width(function: &mut Function, pointer_width: u8) {
    collapse_body(&mut function.body, pointer_width);
}

fn collapse_body(body: &mut Vec<Stmt>, pointer_width: u8) {
    for statement in body.iter_mut() {
        visit_children(statement, pointer_width);
        if let Some(replacement) = collapse_statement(statement, pointer_width) {
            *statement = replacement;
        }
    }

    let mut index = 0;
    let mut goto_counts = count_gotos(body);
    while index < body.len() {
        if let Some(replacement) =
            collapse_conditional_jump(body, index, &goto_counts, pointer_width)
        {
            body[index] = replacement;
            body.drain(index + 1..=index + 6);
            goto_counts = count_gotos(body);
            index += 1;
            continue;
        }
        let Some(replacement) = collapse_linearized(body, index, &goto_counts, pointer_width)
        else {
            index += 1;
            continue;
        };
        body[index] = replacement;
        body.drain(index + 1..=index + 2);
        goto_counts = count_gotos(body);
        index += 1;
    }
}

fn collapse_conditional_jump(
    body: &[Stmt],
    index: usize,
    goto_counts: &std::collections::BTreeMap<u64, usize>,
    pointer_width: u8,
) -> Option<Stmt> {
    let [Stmt::If {
        cond,
        then_body,
        else_body: None,
    }, first_call_statement, second_call_statement, Stmt::Goto { target: join }, Stmt::Label(constant_label), constant_statement, Stmt::Label(join_label)] =
        body.get(index..index + 7)?
    else {
        return None;
    };
    let [Stmt::Goto {
        target: constant_target,
    }] = then_body.as_slice()
    else {
        return None;
    };
    if constant_target != constant_label
        || join != join_label
        || goto_counts.get(constant_label).copied() != Some(1)
        || goto_counts.get(join).copied() != Some(1)
    {
        return None;
    }
    let call_statements = [first_call_statement.clone(), second_call_statement.clone()];
    let (destination, call_value) = call_arm(&call_statements, pointer_width)?;
    let (constant_destination, constant_value) =
        constant_arm(std::slice::from_ref(constant_statement))?;
    if destination != constant_destination {
        return None;
    }
    selected_assignment(
        destination,
        &negated_comparison(cond)?,
        call_value,
        constant_value,
    )
}

fn negated_comparison(condition: &Expr) -> Option<Expr> {
    let Expr::Cmp { op, lhs, rhs } = condition else {
        return None;
    };
    let (op, lhs, rhs) = match op {
        CmpOp::Eq => (CmpOp::Ne, lhs.clone(), rhs.clone()),
        CmpOp::Ne => (CmpOp::Eq, lhs.clone(), rhs.clone()),
        CmpOp::Slt => (CmpOp::Sle, rhs.clone(), lhs.clone()),
        CmpOp::Sle => (CmpOp::Slt, rhs.clone(), lhs.clone()),
        CmpOp::Ult => (CmpOp::Ule, rhs.clone(), lhs.clone()),
        CmpOp::Ule => (CmpOp::Ult, rhs.clone(), lhs.clone()),
    };
    Some(Expr::Cmp { op, lhs, rhs })
}

fn visit_children(statement: &mut Stmt, pointer_width: u8) {
    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            collapse_body(then_body, pointer_width);
            if let Some(else_body) = else_body {
                collapse_body(else_body, pointer_width);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            collapse_body(body, pointer_width)
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, case_body) in cases {
                collapse_body(case_body, pointer_width);
            }
            if let Some(default_body) = default {
                collapse_body(default_body, pointer_width);
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            collapse_body(try_body, pointer_width);
            for catch in catches {
                collapse_body(&mut catch.body, pointer_width);
            }
        }
        _ => {}
    }
}

fn collapse_linearized(
    body: &[Stmt],
    index: usize,
    goto_counts: &std::collections::BTreeMap<u64, usize>,
    pointer_width: u8,
) -> Option<Stmt> {
    let Stmt::If {
        cond,
        then_body,
        else_body: None,
    } = body.get(index)?
    else {
        return None;
    };
    let (Stmt::Goto { target: join }, call_statements) = then_body.split_last()? else {
        return None;
    };
    if goto_counts.get(join).copied() != Some(1)
        || !matches!(body.get(index + 2), Some(Stmt::Label(label)) if label == join)
    {
        return None;
    }
    let (destination, call_value) = call_arm(call_statements, pointer_width)?;
    let (constant_destination, constant_value) =
        constant_arm(std::slice::from_ref(body.get(index + 1)?))?;
    (destination == constant_destination)
        .then_some(())
        .and_then(|()| selected_assignment(destination, cond, call_value, constant_value))
}

fn count_gotos(body: &[Stmt]) -> std::collections::BTreeMap<u64, usize> {
    fn body_counts(body: &[Stmt], counts: &mut std::collections::BTreeMap<u64, usize>) {
        for statement in body {
            match statement {
                Stmt::Goto { target } => *counts.entry(*target).or_default() += 1,
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    body_counts(then_body, counts);
                    if let Some(else_body) = else_body {
                        body_counts(else_body, counts);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body_counts(body, counts),
                Stmt::For {
                    init, step, body, ..
                } => {
                    body_counts(std::slice::from_ref(init.as_ref()), counts);
                    body_counts(body, counts);
                    body_counts(std::slice::from_ref(step.as_ref()), counts);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        body_counts(case_body, counts);
                    }
                    if let Some(default_body) = default {
                        body_counts(default_body, counts);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    body_counts(try_body, counts);
                    for catch in catches {
                        body_counts(&catch.body, counts);
                    }
                }
                _ => {}
            }
        }
    }

    let mut counts = std::collections::BTreeMap::new();
    body_counts(body, &mut counts);
    counts
}

fn collapse_statement(statement: &Stmt, pointer_width: u8) -> Option<Stmt> {
    let Stmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = statement
    else {
        return None;
    };

    if let (Some((destination, call_value)), Some((constant_destination, constant_value))) =
        (call_arm(then_body, pointer_width), constant_arm(else_body))
    {
        if destination == constant_destination {
            return selected_assignment(destination, cond, call_value, constant_value);
        }
    }
    if let (Some((constant_destination, constant_value)), Some((destination, call_value))) =
        (constant_arm(then_body), call_arm(else_body, pointer_width))
    {
        if destination == constant_destination {
            return selected_assignment(destination, cond, constant_value, call_value);
        }
    }
    None
}

fn selected_assignment(
    destination: AssignmentTarget,
    cond: &Expr,
    mut if_true: Expr,
    mut if_false: Expr,
) -> Option<Stmt> {
    let width = explicit_expression_width(&if_true)
        .into_iter()
        .chain(explicit_expression_width(&if_false))
        .max()
        .unwrap_or(8);
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    match (
        condition_proves_nonnegative(cond),
        saturation_call(&if_true),
        &if_false,
    ) {
        (Some(true), true, Expr::Const(-1)) => {
            if_false = unsigned_all_ones(width);
        }
        _ if condition_proves_negative(cond)
            && saturation_call(&if_false)
            && matches!(if_true, Expr::Const(-1)) =>
        {
            if_true = unsigned_all_ones(width);
        }
        _ => return None,
    }
    let selected = Expr::Select {
        cond: Box::new(cond.clone()),
        if_true: Box::new(if_true),
        if_false: Box::new(if_false),
        width,
    };
    Some(match destination {
        AssignmentTarget::Register(dst) => Stmt::Assign { dst, src: selected },
        AssignmentTarget::PromotedLocal { register, size } => Stmt::Store {
            addr: Expr::Reg(register),
            src: selected,
            size,
        },
    })
}

fn saturation_call(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } if (matches!(lhs.as_ref(), Expr::Call { .. })
            && matches!(rhs.as_ref(), Expr::Const(2)))
            || (matches!(rhs.as_ref(), Expr::Call { .. })
                && matches!(lhs.as_ref(), Expr::Const(2)))
    )
}

fn condition_proves_nonnegative(condition: &Expr) -> Option<bool> {
    match condition {
        Expr::Cmp {
            op: CmpOp::Sle,
            lhs,
            ..
        } if matches!(lhs.as_ref(), Expr::Const(0)) => Some(true),
        _ => None,
    }
}

fn condition_proves_negative(condition: &Expr) -> bool {
    matches!(
        condition,
        Expr::Cmp {
            op: CmpOp::Slt,
            rhs,
            ..
        } if matches!(rhs.as_ref(), Expr::Const(0))
    )
}

fn unsigned_all_ones(width: u8) -> Expr {
    Expr::Cast {
        signed: false,
        width,
        expr: Box::new(Expr::Const(-1)),
    }
}

fn constant_arm(body: &[Stmt]) -> Option<(AssignmentTarget, Expr)> {
    let [statement] = body else {
        return None;
    };
    let (destination, source) = assignment(statement)?;
    constant_expression(source).then(|| (destination, source.clone()))
}

fn constant_expression(expression: &Expr) -> bool {
    match expression {
        Expr::Const(_) | Expr::FloatConst { .. } | Expr::Addr(_) | Expr::Named { .. } => true,
        Expr::Cast { expr, .. } => constant_expression(expr),
        _ => false,
    }
}

fn call_arm(body: &[Stmt], pointer_width: u8) -> Option<(AssignmentTarget, Expr)> {
    let [Stmt::Call {
        target,
        args,
        dst: Some(call_result),
        call_spec,
    }, assignment_statement] = body
    else {
        return None;
    };
    if call_spec
        .as_ref()
        .is_some_and(|spec| spec.call_prototype.return_type.trim() == "void")
        || target.contains_reg(call_result)
        || args
            .iter()
            .any(|argument| argument.contains_reg(call_result))
    {
        return None;
    }
    let (destination, src) = assignment(assignment_statement)?;
    let call_spec = call_spec.clone().unwrap_or_else(|| {
        crate::ir::call_contracts::recover_call_site_spec(target, args, Some(call_result))
    });
    let result_width = call_result_width(&call_spec, pointer_width);
    let call = Expr::Call {
        target: Box::new(target.clone()),
        args: args.clone(),
        call_spec: Some(call_spec),
        result_width,
    };
    derive_from_call(src, call_result, &call).map(|value| (destination, value))
}

fn call_result_width(
    call_spec: &crate::ir::call_contracts::CallSiteSpec,
    pointer_width: u8,
) -> Option<u8> {
    let c_type = &call_spec.call_prototype.return_type;
    crate::ir::call_contracts::integer_c_type_width(c_type, pointer_width).or_else(|| {
        crate::ir::call_contracts::call_return_hint(c_type).map(|hint| match hint {
            crate::ir::types_recover::TypeHint::Int { width, .. }
            | crate::ir::types_recover::TypeHint::Float { width } => width,
            crate::ir::types_recover::TypeHint::Pointer { .. }
            | crate::ir::types_recover::TypeHint::CodePointer => pointer_width,
            crate::ir::types_recover::TypeHint::BoolLike => 4,
        })
    })
}

fn assignment(statement: &Stmt) -> Option<(AssignmentTarget, &Expr)> {
    match statement {
        Stmt::Assign { dst, src } => Some((AssignmentTarget::Register(dst.clone()), src)),
        Stmt::Store {
            addr: Expr::Reg(register @ VReg::Phys(name)),
            src,
            size,
        } if is_promoted_local_name(name) => Some((
            AssignmentTarget::PromotedLocal {
                register: register.clone(),
                size: *size,
            },
            src,
        )),
        _ => None,
    }
}

fn derive_from_call(expression: &Expr, call_result: &VReg, call: &Expr) -> Option<Expr> {
    let uses = count_register_uses(expression, call_result)?;
    match uses {
        1 => substitute_call_result(expression, call_result, call),
        2 => doubled_call(expression, call_result, call),
        _ => None,
    }
}

fn doubled_call(expression: &Expr, call_result: &VReg, call: &Expr) -> Option<Expr> {
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = expression
    else {
        return None;
    };
    if lhs != rhs || !is_integer_view_of(lhs, call_result) {
        return None;
    }
    let one_call = substitute_call_result(lhs, call_result, call)?;
    Some(Expr::Bin {
        op: BinOp::Mul,
        lhs: Box::new(one_call),
        rhs: Box::new(Expr::Const(2)),
    })
}

fn is_integer_view_of(expression: &Expr, target: &VReg) -> bool {
    match expression {
        Expr::Reg(register) => register == target,
        Expr::Cast { expr, .. } => is_integer_view_of(expr, target),
        _ => false,
    }
}

/// Count exact scalar uses, rejecting expression forms that could move the call
/// across another lazy boundary or an opaque/memory effect.
fn count_register_uses(expression: &Expr, target: &VReg) -> Option<usize> {
    match expression {
        Expr::Reg(register) => Some(usize::from(register == target)),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. } => Some(0),
        Expr::Bin { op, lhs, rhs } if !matches!(op, BinOp::LogicalAnd | BinOp::LogicalOr) => {
            Some(count_register_uses(lhs, target)? + count_register_uses(rhs, target)?)
        }
        Expr::Cmp { lhs, rhs, .. } => {
            Some(count_register_uses(lhs, target)? + count_register_uses(rhs, target)?)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } | Expr::NumericConvert { expr: src, .. } => count_register_uses(src, target),
        Expr::WideArithmetic { args, .. } => args.iter().try_fold(0usize, |count, argument| {
            Some(count + count_register_uses(argument, target)?)
        }),
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => (!base
            .iter()
            .chain(index.iter())
            .any(|register| register == target))
        .then_some(0),
        Expr::Deref { .. }
        | Expr::Call { .. }
        | Expr::Select { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::Unknown(_)
        | Expr::Bin { .. } => None,
    }
}

fn substitute_call_result(expression: &Expr, target: &VReg, call: &Expr) -> Option<Expr> {
    match expression {
        Expr::Reg(register) if register == target => Some(call.clone()),
        Expr::NumericConvert { from, to, expr } => Some(Expr::NumericConvert {
            from: *from,
            to: *to,
            expr: Box::new(substitute_call_result(expr, target, call)?),
        }),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => Some(expression.clone()),
        Expr::Bin { op, lhs, rhs } if !matches!(op, BinOp::LogicalAnd | BinOp::LogicalOr) => {
            Some(Expr::Bin {
                op: *op,
                lhs: Box::new(substitute_call_result(lhs, target, call)?),
                rhs: Box::new(substitute_call_result(rhs, target, call)?),
            })
        }
        Expr::Cmp { op, lhs, rhs } => Some(Expr::Cmp {
            op: *op,
            lhs: Box::new(substitute_call_result(lhs, target, call)?),
            rhs: Box::new(substitute_call_result(rhs, target, call)?),
        }),
        Expr::Un { op, src } => Some(Expr::Un {
            op: *op,
            src: Box::new(substitute_call_result(src, target, call)?),
        }),
        Expr::Cast {
            signed,
            width,
            expr,
        } => Some(Expr::Cast {
            signed: *signed,
            width: *width,
            expr: Box::new(substitute_call_result(expr, target, call)?),
        }),
        Expr::WideArithmetic { op, args, width } => Some(Expr::WideArithmetic {
            op: *op,
            args: args
                .iter()
                .map(|argument| substitute_call_result(argument, target, call))
                .collect::<Option<Vec<_>>>()?,
            width: *width,
        }),
        Expr::Deref { .. }
        | Expr::Call { .. }
        | Expr::Select { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::Unknown(_)
        | Expr::Bin { .. } => None,
    }
}

#[cfg(test)]
#[path = "lazy_call_select/tests.rs"]
mod tests;
