//! Collapse structurally proven assignment diamonds into pure selects.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::expression_width::explicit_expression_width;
use crate::ir::types::{is_promoted_local_name as is_promoted_local, UnOp, VReg};

/// Render exact comparison masks as arithmetic values instead of fake branches.
///
/// C comparisons evaluate to exactly `0` or `1`, so `-(comparison)` is exactly
/// equivalent to `(comparison) ? -1 : 0`.  The restriction to [`Expr::Cmp`] is
/// essential: negating an arbitrary truthy integer would not preserve select
/// semantics.
pub fn fold_boolean_masks(function: &mut Function) {
    fold_masks_in_body(&mut function.body);
}

fn fold_masks_in_body(body: &mut [Stmt]) {
    for statement in body {
        fold_masks_in_stmt(statement);
    }
}

fn fold_masks_in_stmt(statement: &mut Stmt) {
    match statement {
        Stmt::Assign { src, .. } => fold_masks_in_expr(src),
        Stmt::Store { addr, src, .. } => {
            fold_masks_in_expr(addr);
            fold_masks_in_expr(src);
        }
        Stmt::Call { target, args, .. } => {
            fold_masks_in_expr(target);
            for argument in args {
                fold_masks_in_expr(argument);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value {
                fold_masks_in_expr(value);
            }
        }
        Stmt::IndirectGoto { target } => fold_masks_in_expr(target),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            fold_masks_in_expr(cond);
            fold_masks_in_body(then_body);
            if let Some(else_body) = else_body {
                fold_masks_in_body(else_body);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            fold_masks_in_expr(cond);
            fold_masks_in_body(body);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            fold_masks_in_stmt(init);
            fold_masks_in_expr(cond);
            fold_masks_in_stmt(step);
            fold_masks_in_body(body);
        }
        Stmt::Push { value } => fold_masks_in_expr(value),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            fold_masks_in_expr(discriminant);
            for (_, case_body) in cases {
                fold_masks_in_body(case_body);
            }
            if let Some(default) = default {
                fold_masks_in_body(default);
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => {}
    }
}

fn fold_masks_in_expr(expr: &mut Expr) {
    match expr {
        Expr::FunctionTableEntry { index, .. } => fold_masks_in_expr(index),
        Expr::Deref { addr, .. } => fold_masks_in_expr(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_masks_in_expr(lhs);
            fold_masks_in_expr(rhs);
        }
        Expr::Un { src, .. } => fold_masks_in_expr(src),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            fold_masks_in_expr(cond);
            fold_masks_in_expr(if_true);
            fold_masks_in_expr(if_false);
        }
        Expr::Cast { expr, .. } => fold_masks_in_expr(expr),
        Expr::WideArithmetic { args, .. } => args.iter_mut().for_each(fold_masks_in_expr),
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

    let replacement = match expr {
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } if matches!(cond.as_ref(), Expr::Cmp { .. })
            && matches!(if_true.as_ref(), Expr::Const(-1))
            && matches!(if_false.as_ref(), Expr::Const(0)) =>
        {
            Some(Expr::Un {
                op: UnOp::Neg,
                src: cond.clone(),
            })
        }
        _ => None,
    };
    if let Some(replacement) = replacement {
        *expr = replacement;
    }
}

/// Collapse exact two-arm, same-destination assignment diamonds.
///
/// `Expr::Select` preserves lazy arm evaluation, so this identity is valid for
/// arbitrary value expressions. Stores are accepted only for promoted stack
/// locals: moving a genuine pointer-address calculation out of an arm could
/// change faults or other address dependencies.
///
/// # When a diamond may NOT collapse
///
/// Validity is not the only question — the collapse also has to be the *likely
/// source spelling*, because DecBench scores structure as graph edit distance
/// against the source CFG and Joern gives `?:` and `if` different CFGs.
/// Measured against pyjoern (see the unit tests below for the shapes):
///
/// * `int r; if (c) r = a; else r = b; return r;` — a **joined result whose only
///   use is the return**. Every C author writes that as `if (c) return a; return
///   b;`, not as a ternary, and the two spellings are 5 vs 6 CFG nodes: turning
///   `branches.c:classify` into one nested ternary cost GED 7 where keeping the
///   branch costs 0-2. So an *immediately returned* destination keeps its
///   branch, and [`crate::ir::ast::fold_exhaustive_if_returns`] later moves the
///   `return` into both arms — the exact source shape.
///
/// What still collapses is the case the transform was added for: a value that is
/// consumed by a larger computation (`arith.c:signs`, whose source really is two
/// sequential ternaries summed, scores GED 0 as a select pair and GED 3 as
/// branches). Those are genuine value selects, not source-level control flow.
///
/// A **nested** select is deliberately still allowed. Refusing it was tried and
/// measured: `statemachine.c:fsm` writes `st = (c=='b') ? 2 : (c=='a' ? 1 : 0);`
/// in the source, and blocking the nesting turned `statemachine:clang:O0` from
/// GED 0.0 into GED 3.0 while improving nothing — the joined-result rule above
/// already keeps the `classify` if-chain intact without it.
pub fn collapse_assignment_diamonds(function: &mut Function) {
    collapse_body(&mut function.body, None);
}

/// Recover direct returns from an initialized result guarded by a lazy select.
///
/// Optimized code commonly initializes the return register with the guard
/// operand, conditionally overwrites it with a two-way selected value, and then
/// returns the register:
///
/// ```text
/// result = view(x);
/// if (x != 0) result = y ? a : b;
/// return result;
/// ```
///
/// Leaving this as a C ternary adds a synthetic join to the recovered CFG.  When
/// the initializer is a side-effect-free register view and the guarded select
/// does not read the result being replaced, the source-level spelling is the
/// exact terminating shape `if (x) { if (y) return a; else return b; } return
/// view(x);`.  If the false edge of `x != 0` proves that view to be zero, emit
/// the stronger `return 0`.
pub fn recover_guarded_select_returns(function: &mut Function) {
    recover_guarded_select_returns_body(&mut function.body);
}

fn recover_guarded_select_returns_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_guarded_select_returns_body(then_body);
                if let Some(else_body) = else_body {
                    recover_guarded_select_returns_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_guarded_select_returns_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_guarded_select_returns_body(case);
                }
                if let Some(default) = default {
                    recover_guarded_select_returns_body(default);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index + 2 < body.len() {
        let candidate = match (&body[index], &body[index + 1], &body[index + 2]) {
            (
                Stmt::Assign {
                    dst: result,
                    src: default_value,
                },
                Stmt::If {
                    cond: outer_condition,
                    then_body,
                    else_body: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(returned)),
                },
            ) if result == returned && movable_register_view(default_value) => {
                let [Stmt::Assign {
                    dst: selected_result,
                    src:
                        Expr::Select {
                            cond: select_condition,
                            if_true,
                            if_false,
                            ..
                        },
                }] = then_body.as_slice()
                else {
                    index += 1;
                    continue;
                };
                if selected_result != result
                    || expression_reads_register(default_value, result)
                    || expression_reads_register(outer_condition, result)
                    || expression_reads_register(select_condition, result)
                    || expression_reads_register(if_true, result)
                    || expression_reads_register(if_false, result)
                {
                    index += 1;
                    continue;
                }
                Some((
                    result.clone(),
                    default_value.clone(),
                    outer_condition.clone(),
                    select_condition.as_ref().clone(),
                    if_true.as_ref().clone(),
                    if_false.as_ref().clone(),
                ))
            }
            _ => None,
        };
        let Some((_result, default_value, outer_condition, select_condition, yes, no)) = candidate
        else {
            index += 1;
            continue;
        };

        let trailing_value = false_edge_value(&outer_condition, &default_value);
        body[index] = Stmt::If {
            cond: outer_condition,
            then_body: vec![Stmt::If {
                cond: select_condition,
                then_body: vec![Stmt::Return { value: Some(yes) }],
                else_body: Some(vec![Stmt::Return { value: Some(no) }]),
            }],
            else_body: None,
        };
        body[index + 1] = Stmt::Return {
            value: Some(trailing_value),
        };
        body.remove(index + 2);
        index += 2;
    }
}

fn movable_register_view(expression: &Expr) -> bool {
    match expression {
        Expr::Reg(_) | Expr::Const(_) => true,
        Expr::Cast { expr, .. } => movable_register_view(expr),
        _ => false,
    }
}

fn strip_integer_views(expression: &Expr) -> &Expr {
    match expression {
        Expr::Cast { expr, .. } => strip_integer_views(expr),
        _ => expression,
    }
}

fn false_edge_value(condition: &Expr, default_value: &Expr) -> Expr {
    let Expr::Cmp {
        op: crate::ir::types::CmpOp::Ne,
        lhs,
        rhs,
    } = condition
    else {
        return default_value.clone();
    };
    let tested = match (lhs.as_ref(), rhs.as_ref()) {
        (tested, Expr::Const(0)) | (Expr::Const(0), tested) => tested,
        _ => return default_value.clone(),
    };
    if strip_integer_views(default_value) == strip_integer_views(tested) {
        Expr::Const(0)
    } else {
        default_value.clone()
    }
}

fn expression_reads_register(expression: &Expr, target: &VReg) -> bool {
    match expression {
        Expr::Reg(reg) => reg == target,
        Expr::StackAddr { object, .. } => object == target,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => base
            .iter()
            .chain(index.iter())
            .any(|register| register == target),
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => expression_reads_register(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expression_reads_register(lhs, target) || expression_reads_register(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expression_reads_register(cond, target)
                || expression_reads_register(if_true, target)
                || expression_reads_register(if_false, target)
        }
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|argument| expression_reads_register(argument, target)),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

/// `joined_result` is the register the enclosing control flow returns once this
/// body falls through — the reason `branches.c:nested` recovers four direct
/// returns rather than an outer `if` around an inner ternary. It is inherited
/// through `if` arms only: a loop body or a `switch` case does not fall through
/// to the join, so recovery there sees no joined result and behaves as before.
fn collapse_body(body: &mut Vec<Stmt>, joined_result: Option<VReg>) {
    for index in 0..body.len() {
        let returned = immediately_returned_register(body, index).or_else(|| joined_result.clone());
        match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_body(then_body, returned.clone());
                if let Some(else_body) = else_body {
                    collapse_body(else_body, returned.clone());
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_body(body, None)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collapse_body(case_body, None);
                }
                if let Some(default) = default {
                    collapse_body(default, None);
                }
            }
            _ => {}
        }
        if let Some(replacement) = select_from_diamond(&body[index], returned.as_ref()) {
            body[index] = replacement;
        }
    }

    for index in (0..body.len()).rev() {
        let _ = fold_created_select_return(body, index);
    }
}

/// The register this body returns immediately after `index`, if any.
///
/// Layout noise (`Nop`, a rendered prologue/epilogue comment) sits between a
/// join and its return often enough that skipping it is what makes the check
/// meaningful; anything else terminates the search, because a following
/// *statement* means the value has another use and the diamond is a real value
/// select rather than the tail of an `if`/`return` chain.
fn immediately_returned_register(body: &[Stmt], index: usize) -> Option<VReg> {
    let mut cursor = index + 1;
    while matches!(body.get(cursor), Some(Stmt::Comment(_) | Stmt::Nop)) {
        cursor += 1;
    }
    match body.get(cursor) {
        Some(Stmt::Return { value: Some(value) }) => match strip_integer_views(value) {
            Expr::Reg(register) => Some(register.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn fold_created_select_return(body: &mut Vec<Stmt>, index: usize) -> bool {
    let (destination, selected) = match body.get(index) {
        Some(Stmt::Assign {
            dst,
            src: selected @ Expr::Select { .. },
        }) => (dst.clone(), selected.clone()),
        Some(Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            src: selected @ Expr::Select { .. },
            ..
        }) if is_promoted_local(name) => (dst.clone(), selected.clone()),
        _ => return false,
    };
    let mut return_index = index + 1;
    while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
        return_index += 1;
    }
    let Some(Stmt::Return {
        value: Some(Expr::Reg(returned)),
    }) = body.get(return_index)
    else {
        return false;
    };
    if returned != &destination {
        return false;
    }
    body[return_index] = Stmt::Return {
        value: Some(selected),
    };
    body.remove(index);
    true
}

fn select_from_diamond(statement: &Stmt, immediately_returned: Option<&VReg>) -> Option<Stmt> {
    match statement {
        Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } => {
            let [then_statement] = then_body.as_slice() else {
                return None;
            };
            let [else_statement] = else_body.as_slice() else {
                return None;
            };
            match (
                assignment_value(then_statement),
                assignment_value(else_statement),
            ) {
                (
                    Some(AssignmentValue::Register(then_dst, then_src)),
                    Some(AssignmentValue::Register(else_dst, else_src)),
                ) if then_dst == else_dst && immediately_returned != Some(then_dst) => {
                    Some(Stmt::Assign {
                        dst: then_dst.clone(),
                        src: make_select(cond, then_src, else_src),
                    })
                }
                (
                    Some(AssignmentValue::PromotedLocal(then_dst, then_src, then_size)),
                    Some(AssignmentValue::PromotedLocal(else_dst, else_src, else_size)),
                ) if then_dst == else_dst
                    && then_size == else_size
                    && immediately_returned != Some(then_dst) =>
                {
                    Some(Stmt::Store {
                        addr: Expr::Reg(then_dst.clone()),
                        src: make_select(cond, then_src, else_src),
                        size: then_size,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

enum AssignmentValue<'a> {
    Register(&'a VReg, &'a Expr),
    PromotedLocal(&'a VReg, &'a Expr, u8),
}

fn assignment_value(statement: &Stmt) -> Option<AssignmentValue<'_>> {
    match statement {
        Stmt::Assign { dst, src } => Some(AssignmentValue::Register(dst, src)),
        Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            src,
            size,
        } if is_promoted_local(name) => Some(AssignmentValue::PromotedLocal(dst, src, *size)),
        _ => None,
    }
}

fn make_select(cond: &Expr, if_true: &Expr, if_false: &Expr) -> Expr {
    Expr::Select {
        cond: Box::new(cond.clone()),
        if_true: Box::new(if_true.clone()),
        if_false: Box::new(if_false.clone()),
        width: select_width(if_true, if_false),
    }
}

fn select_width(if_true: &Expr, if_false: &Expr) -> u8 {
    explicit_expression_width(if_true)
        .into_iter()
        .chain(explicit_expression_width(if_false))
        .max()
        .unwrap_or(8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::{CmpOp, VReg};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn assign(dst: &str, src: Expr) -> Stmt {
        Stmt::Assign { dst: reg(dst), src }
    }

    fn return_reg(name: &str) -> Stmt {
        Stmt::Return {
            value: Some(Expr::Reg(reg(name))),
        }
    }

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "diamond".into(),
            entry_va: 0x1000,
            body,
        }
    }

    #[test]
    fn comparison_select_mask_becomes_arithmetic_negation() {
        let comparison = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("left"))),
            rhs: Box::new(Expr::Reg(reg("right"))),
        };
        let mut f = function(vec![assign(
            "mask",
            Expr::Select {
                cond: Box::new(comparison),
                if_true: Box::new(Expr::Const(-1)),
                if_false: Box::new(Expr::Const(0)),
                width: 4,
            },
        )]);

        fold_boolean_masks(&mut f);

        assert!(matches!(
            f.body.as_slice(),
            [Stmt::Assign {
                src: Expr::Un {
                    op: UnOp::Neg,
                    src,
                },
                ..
            }] if matches!(src.as_ref(), Expr::Cmp { op: CmpOp::Slt, .. })
        ));
    }

    #[test]
    fn arbitrary_truthy_select_mask_is_not_folded() {
        let original = Expr::Select {
            cond: Box::new(Expr::Reg(reg("truthy"))),
            if_true: Box::new(Expr::Const(-1)),
            if_false: Box::new(Expr::Const(0)),
            width: 4,
        };
        let mut f = function(vec![assign("mask", original.clone())]);

        fold_boolean_masks(&mut f);

        assert_eq!(f.body, vec![assign("mask", original)]);
    }

    #[test]
    /// `branches.c:classify` in miniature. Collapsing the OUTER diamond too
    /// produced `return c ? (d ? a : b) : e;` — one nested ternary where the
    /// source is an `if`/`else if`/`return` chain. Measured against pyjoern that
    /// spelling is 6 nodes / 7 edges against the source's 5 / 4 (GED 7); keeping
    /// the outer branch is 5 / 5 (GED 2). The inner diamond still collapses:
    /// its value is consumed by the outer arm, not returned.
    fn nested_same_destination_diamond_keeps_its_returned_outer_branch() {
        let mut f = function(vec![
            Stmt::If {
                cond: Expr::Reg(reg("outer")),
                then_body: vec![Stmt::If {
                    cond: Expr::Reg(reg("inner")),
                    then_body: vec![assign("result", Expr::Reg(reg("inner_yes")))],
                    else_body: Some(vec![assign("result", Expr::Reg(reg("inner_no")))]),
                }],
                else_body: Some(vec![assign("result", Expr::Reg(reg("outer_no")))]),
            },
            return_reg("result"),
        ]);

        let original = f.body.clone();
        collapse_assignment_diamonds(&mut f);

        assert_eq!(
            f.body, original,
            "both diamonds feed the same joined return, so both keep their branch"
        );
    }

    /// The inner diamond of a returned nest is refused *because* it is inherited
    /// through the arm; a diamond whose value is consumed inside the arm is not.
    #[test]
    fn a_diamond_consumed_inside_a_returned_arm_still_collapses() {
        let mut f = function(vec![
            Stmt::If {
                cond: Expr::Reg(reg("outer")),
                then_body: vec![
                    Stmt::If {
                        cond: Expr::Reg(reg("inner")),
                        then_body: vec![assign("scratch", Expr::Const(1))],
                        else_body: Some(vec![assign("scratch", Expr::Const(2))]),
                    },
                    assign("result", Expr::Reg(reg("scratch"))),
                ],
                else_body: Some(vec![assign("result", Expr::Reg(reg("outer_no")))]),
            },
            return_reg("result"),
        ]);

        collapse_assignment_diamonds(&mut f);

        let Stmt::If { then_body, .. } = &f.body[0] else {
            panic!("{:?}", f.body)
        };
        assert!(
            matches!(
                then_body.as_slice(),
                [
                    Stmt::Assign {
                        src: Expr::Select { .. },
                        ..
                    },
                    Stmt::Assign { .. }
                ]
            ),
            "{:?}",
            f.body
        );
    }

    #[test]
    fn a_terminal_result_diamond_keeps_its_branch() {
        let diamond = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: Some(vec![assign("result", Expr::Const(2))]),
        };
        let terminal_return = return_reg("result");
        let mut f = function(vec![diamond.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(
            f.body,
            vec![diamond, terminal_return],
            "a joined result whose only use is the return is a source-level `if`"
        );
    }

    #[test]
    fn a_terminal_promoted_local_diamond_keeps_its_branch() {
        let local = reg("local_2c");
        let store = |value| Stmt::Store {
            addr: Expr::Reg(local.clone()),
            src: Expr::Const(value),
            size: 4,
        };
        let diamond = Stmt::If {
            cond: Expr::Reg(reg("is_b")),
            then_body: vec![store(2)],
            else_body: Some(vec![store(0)]),
        };
        let terminal_return = return_reg("local_2c");
        let mut f = function(vec![diamond.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![diamond, terminal_return]);
    }

    #[test]
    fn a_diamond_returned_through_a_cast_keeps_its_branch() {
        let diamond = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: Some(vec![assign("result", Expr::Const(2))]),
        };
        let terminal_return = Stmt::Return {
            value: Some(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("result"))),
            }),
        };
        let mut f = function(vec![diamond.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![diamond, terminal_return]);
    }

    /// `statemachine.c:fsm` really does write
    /// `st = (c=='b') ? 2 : (c=='a' ? 1 : 0);`. Refusing to nest a select inside
    /// a select's arm was tried and measured: it moved `statemachine:clang:O0`
    /// from GED 0.0 to 3.0 and improved no other cell, because the joined-result
    /// refusal already protects the `classify` if-chain.
    #[test]
    fn a_diamond_whose_arm_already_selects_still_collapses() {
        let inner = Expr::Select {
            cond: Box::new(Expr::Reg(reg("inner"))),
            if_true: Box::new(Expr::Const(1)),
            if_false: Box::new(Expr::Const(2)),
            width: 4,
        };
        let diamond = Stmt::If {
            cond: Expr::Reg(reg("outer")),
            then_body: vec![assign("scratch", inner)],
            else_body: Some(vec![assign("scratch", Expr::Const(3))]),
        };
        let mut f = function(vec![
            diamond,
            assign("other", Expr::Reg(reg("scratch"))),
            return_reg("other"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Assign {
                    src: Expr::Select { if_true, .. },
                    ..
                }) if matches!(if_true.as_ref(), Expr::Select { .. })
            ),
            "{:?}",
            f.body
        );
    }

    #[test]
    fn guarded_return_select_recovers_nested_direct_returns() {
        let arg0 = Expr::Reg(reg("arg0"));
        let arg1 = Expr::Reg(reg("arg1"));
        let result = reg("ret");
        let mut f = function(vec![
            Stmt::Assign {
                dst: result.clone(),
                src: Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(arg0.clone()),
                    }),
                },
            },
            Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(arg0),
                    rhs: Box::new(Expr::Const(0)),
                },
                then_body: vec![Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Select {
                        cond: Box::new(Expr::Cmp {
                            op: CmpOp::Ne,
                            lhs: Box::new(arg1),
                            rhs: Box::new(Expr::Const(0)),
                        }),
                        if_true: Box::new(Expr::Reg(reg("yes"))),
                        if_false: Box::new(Expr::Reg(reg("no"))),
                        width: 4,
                    },
                }],
                else_body: None,
            },
            Stmt::Return {
                value: Some(Expr::Reg(result)),
            },
        ]);

        recover_guarded_select_returns(&mut f);

        assert!(matches!(
            f.body.as_slice(),
            [
                Stmt::If {
                    then_body,
                    else_body: None,
                    ..
                },
                Stmt::Return {
                    value: Some(Expr::Const(0))
                }
            ] if matches!(
                then_body.as_slice(),
                [Stmt::If {
                    then_body: yes,
                    else_body: Some(no),
                    ..
                }] if matches!(yes.as_slice(), [Stmt::Return { .. }])
                    && matches!(no.as_slice(), [Stmt::Return { .. }])
            )
        ));
    }

    #[test]
    fn guarded_return_select_does_not_move_a_memory_initializer() {
        let result = reg("ret");
        let original = vec![
            Stmt::Assign {
                dst: result.clone(),
                src: Expr::Deref {
                    addr: Box::new(Expr::Reg(reg("pointer"))),
                    size: 4,
                },
            },
            Stmt::If {
                cond: Expr::Reg(reg("outer")),
                then_body: vec![Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("inner"))),
                        if_true: Box::new(Expr::Const(1)),
                        if_false: Box::new(Expr::Const(2)),
                        width: 4,
                    },
                }],
                else_body: None,
            },
            Stmt::Return {
                value: Some(Expr::Reg(result)),
            },
        ];
        let mut f = function(original.clone());

        recover_guarded_select_returns(&mut f);

        assert_eq!(
            f.body, original,
            "a memory read must keep its evaluation point"
        );
    }

    #[test]
    fn unrelated_guard_does_not_turn_the_default_value_into_zero() {
        let result = reg("ret");
        let default_value = Expr::Reg(reg("default_value"));
        let mut f = function(vec![
            assign("ret", default_value.clone()),
            Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(Expr::Reg(reg("guard"))),
                    rhs: Box::new(Expr::Const(0)),
                },
                then_body: vec![Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("inner"))),
                        if_true: Box::new(Expr::Const(1)),
                        if_false: Box::new(Expr::Const(2)),
                        width: 4,
                    },
                }],
                else_body: None,
            },
            Stmt::Return {
                value: Some(Expr::Reg(result)),
            },
        ]);

        recover_guarded_select_returns(&mut f);

        assert!(matches!(
            f.body.last(),
            Some(Stmt::Return { value: Some(value) }) if value == &default_value
        ));
    }

    #[test]
    fn different_destinations_do_not_collapse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("left", Expr::Const(1))],
            else_body: Some(vec![assign("right", Expr::Const(2))]),
        };
        let terminal_return = return_reg("left");
        let mut f = function(vec![original.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, terminal_return]);
    }

    /// A rendered epilogue comment must not hide the terminal return from the
    /// refusal above — `local_X = ...; // epilogue; return local_X;` is the same
    /// source-level `if` as the comment-free spelling.
    #[test]
    fn a_terminal_result_diamond_keeps_its_branch_through_comments() {
        let diamond = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: Some(vec![assign("result", Expr::Const(2))]),
        };
        let mut f = function(vec![
            diamond.clone(),
            Stmt::Comment("epilogue".into()),
            return_reg("result"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body[0], diamond, "{:?}", f.body);
    }

    /// A lifted `Expr::Select` (a real CMOV, not a recovered diamond) still
    /// folds into its adjacent return: both spellings are the same CFG, and the
    /// copy is pure noise.
    #[test]
    fn a_lifted_select_still_folds_into_its_return() {
        let mut f = function(vec![
            assign(
                "result",
                Expr::Select {
                    cond: Box::new(Expr::Reg(reg("cond"))),
                    if_true: Box::new(Expr::Const(1)),
                    if_false: Box::new(Expr::Const(2)),
                    width: 4,
                },
            ),
            Stmt::Comment("epilogue".into()),
            return_reg("result"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.as_slice(),
                [
                    Stmt::Comment(_),
                    Stmt::Return {
                        value: Some(Expr::Select { .. })
                    }
                ]
            ),
            "{:?}",
            f.body
        );
    }

    #[test]
    fn a_non_return_assignment_diamond_becomes_a_select() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("scratch", Expr::Const(1))],
            else_body: Some(vec![assign("scratch", Expr::Const(2))]),
        };
        let mut f = function(vec![
            original.clone(),
            Stmt::Return {
                value: Some(Expr::Reg(reg("result"))),
            },
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Assign {
                    dst,
                    src: Expr::Select { .. },
                }) if dst == &reg("scratch")
            ),
            "nonterminal value diamonds are still exact selects: {:?}",
            f.body
        );
    }

    #[test]
    fn promoted_local_assignment_diamond_becomes_a_nonterminal_select() {
        let local = reg("local_2c");
        let store = |value| Stmt::Store {
            addr: Expr::Reg(local.clone()),
            src: Expr::Const(value),
            size: 4,
        };
        let mut f = function(vec![
            Stmt::If {
                cond: Expr::Reg(reg("is_b")),
                then_body: vec![store(2)],
                else_body: Some(vec![store(0)]),
            },
            Stmt::Store {
                addr: Expr::Reg(reg("local_state")),
                src: Expr::Reg(local.clone()),
                size: 4,
            },
            return_reg("local_state"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Store {
                    addr: Expr::Reg(destination),
                    src: Expr::Select { .. },
                    size: 4,
                }) if destination == &local
            ),
            "same-local stores should become one lazy value select: {:?}",
            f.body
        );
    }

    #[test]
    fn an_overwritten_diamond_can_collapse_before_later_dse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: Some(vec![assign("result", Expr::Const(2))]),
        };
        let overwrite = assign("result", Expr::Const(3));
        let terminal_return = return_reg("result");
        let mut f = function(vec![
            original.clone(),
            overwrite.clone(),
            terminal_return.clone(),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(matches!(
            f.body.first(),
            Some(Stmt::Assign {
                dst,
                src: Expr::Select { .. }
            }) if dst == &reg("result")
        ));
        assert_eq!(f.body[1..], [overwrite, terminal_return]);
    }

    #[test]
    fn multi_statement_arms_do_not_collapse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![
                assign("side", Expr::Const(1)),
                assign("result", Expr::Const(2)),
            ],
            else_body: Some(vec![assign("result", Expr::Const(3))]),
        };
        let terminal_return = return_reg("result");
        let mut f = function(vec![original.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, terminal_return]);
    }

    #[test]
    fn one_armed_conditionals_do_not_collapse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: None,
        };
        let terminal_return = return_reg("result");
        let mut f = function(vec![original.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, terminal_return]);
    }
}
