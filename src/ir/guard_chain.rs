//! Recovery of source-level short-circuit validation guards.

use std::collections::HashMap;

use crate::ir::ast::{negate_cmp_expr, Expr, Function, Stmt};
use crate::ir::const_fold::{is_exact_boolean, is_short_circuit_safe_boolean};
use crate::ir::types::{BinOp, CmpOp};

struct GuardLadder {
    target: u64,
    exit_conditions: Vec<Expr>,
    exit_body: Vec<Stmt>,
    continuation: Vec<Stmt>,
    consumed_gotos: usize,
}

/// Collapse a nested validation ladder that jumps to one pure shared exit.
///
/// The accepted shape is deliberately exact: the first exit arm owns the only
/// label, every later exit arm is a terminal goto to that label, the opposite
/// arm is either the next guard or the final continuation, and no other goto in
/// the function targets the label. Those facts make the source-level form
/// `if (bad0 || bad1 || !valid) { exit } else { continuation }` equivalent while
/// preserving left-to-right short-circuit evaluation.
pub fn collapse_shared_exit_guard_ladders(function: &mut Function) {
    loop {
        let mut labels = HashMap::new();
        let mut gotos = HashMap::new();
        count_targets(&function.body, &mut labels, &mut gotos);
        if !collapse_one(&mut function.body, &labels, &gotos) {
            break;
        }
    }
}

/// Collapse a cross-branch shared assignment into one short-circuit guard.
///
/// GCC -O0 commonly lowers `if (a && (b || !c)) { update; }` by putting the
/// update behind a label in `b`'s true arm, jumping back to it from `!c`, and
/// jumping forward over it from `c`. Recovery is permitted only when both
/// labels and both gotos are uniquely owned by that exact adjacent shape.
pub fn collapse_shared_assignment_guards(function: &mut Function) {
    loop {
        let mut labels = HashMap::new();
        let mut gotos = HashMap::new();
        count_targets(&function.body, &mut labels, &mut gotos);
        if !collapse_assignment_one(&mut function.body, &labels, &gotos) {
            break;
        }
    }
}

/// Fuse adjacent `if (condition) { break; }` statements.
///
/// The source-level disjunction preserves the original left-to-right behavior:
/// the second condition is evaluated exactly when the first is false. Requiring
/// exact adjacency prevents any intervening effect from being skipped.
pub fn collapse_adjacent_break_guards(function: &mut Function) {
    while collapse_break_one(&mut function.body) {}
}

/// Fuse an exact nested terminal-return guard into one conjunction.
///
/// `if (a) { if (b) { return x; } }` and
/// `if (a && b) { return x; }` have identical left-to-right evaluation: `b`
/// runs only when `a` succeeds. Requiring each body to contain exactly the next
/// guard/return rejects intervening effects and requiring absent `else` arms
/// rejects shapes whose false paths perform work.
pub fn collapse_nested_terminal_return_guards(function: &mut Function) {
    while collapse_nested_return_one(&mut function.body) {}
}

/// Keep one shared terminal return when an early guard returns the exact same
/// value as the function's final statement.
///
/// `if (bad) return x; work; return x;` is exactly
/// `if (!bad) { work; } return x;`. This is useful after a compiler has routed
/// both the validation failure and ordinary function fallthrough to one return
/// instruction. The pass requires an exactly negatable predicate, identical
/// return ASTs, a non-empty structured continuation, and no labels/gotos whose
/// scope would change when wrapped.
pub fn collapse_matching_terminal_return_guard(function: &mut Function) {
    let body = &mut function.body;
    if body.len() < 3 {
        return;
    }
    if collapse_matching_terminal_guard_pair(body) {
        return;
    }
    let Some(final_return @ Stmt::Return { .. }) = body.last().cloned() else {
        return;
    };
    for index in 0..body.len() - 2 {
        let Stmt::If {
            cond,
            then_body,
            else_body: None,
        } = &body[index]
        else {
            continue;
        };
        if then_body.as_slice() != std::slice::from_ref(&final_return) {
            continue;
        }
        let Some(continuation_condition) = negate_exact_condition(cond.clone()) else {
            continue;
        };
        let continuation = body[index + 1..body.len() - 1].to_vec();
        if continuation.is_empty() || contains_unstructured_transfer(&continuation) {
            continue;
        }
        body.splice(
            index..,
            [
                Stmt::If {
                    cond: continuation_condition,
                    then_body: continuation,
                    else_body: None,
                },
                final_return,
            ],
        );
        return;
    }
}

/// Recover two adjacent terminal guards that share the first guard's return.
///
/// `if (bad) return x; if (good) return y; return x;` is exactly
/// `if (bad || !good) return x; return y;`.  This retains one CFG node for the
/// shared terminal instead of cloning it into both machine paths.  Eager
/// bitwise boolean trees are accepted only when their exact-boolean leaves are
/// free of memory reads and trapping operations.
fn collapse_matching_terminal_guard_pair(body: &mut Vec<Stmt>) -> bool {
    let Some(final_start) = terminal_return_tail_start(body) else {
        return false;
    };
    let final_tail = body[final_start..].to_vec();
    for index in 0..final_start.saturating_sub(1) {
        let (
            Stmt::If {
                cond: exit_condition,
                then_body: exit_tail,
                else_body: None,
            },
            Stmt::If {
                cond: success_condition,
                then_body: success_tail,
                else_body: None,
            },
        ) = (&body[index], &body[index + 1])
        else {
            continue;
        };
        if index + 2 != final_start
            || terminal_return_tail_start(exit_tail) != Some(0)
            || exit_tail != &final_tail
            || terminal_return_tail_start(success_tail) != Some(0)
        {
            continue;
        }
        if !is_safe_exact_eager_boolean(exit_condition) {
            continue;
        }
        let exit_condition = exit_condition.clone();
        let Some(failed_success) = negate_exact_condition(success_condition.clone()) else {
            continue;
        };
        let mut replacement = vec![Stmt::If {
            cond: Expr::Bin {
                op: BinOp::LogicalOr,
                lhs: Box::new(exit_condition),
                rhs: Box::new(failed_success),
            },
            then_body: final_tail,
            else_body: None,
        }];
        replacement.extend(success_tail.clone());
        body.splice(index.., replacement);
        return true;
    }
    false
}

/// Return the first statement of a terminal tail containing only renderer
/// trivia followed by one return.
fn terminal_return_tail_start(body: &[Stmt]) -> Option<usize> {
    let return_index = body.len().checked_sub(1)?;
    if !matches!(body[return_index], Stmt::Return { .. }) {
        return None;
    }
    let mut start = return_index;
    while start > 0 && matches!(body[start - 1], Stmt::Comment(_) | Stmt::Nop) {
        start -= 1;
    }
    Some(start)
}

fn is_safe_exact_eager_boolean(condition: &Expr) -> bool {
    match condition {
        Expr::Bin { op, lhs, rhs } if matches!(op, BinOp::And | BinOp::Or) => {
            is_safe_exact_eager_boolean(lhs) && is_safe_exact_eager_boolean(rhs)
        }
        exact => is_exact_boolean(exact) && is_short_circuit_safe_boolean(exact),
    }
}

/// Remove a repeated reaching copy that is the only statement separating two
/// nested guards, then recover their short-circuit conjunction.
///
/// The copy immediately before the outer guard and the copy at the start of its
/// true arm must be structurally identical, and its source must be a register or
/// constant. Since condition expressions cannot assign registers, the second
/// copy writes the value already present and is redundant. Restricting the
/// source rejects memory-backed values that could change between reads.
pub fn collapse_redundant_copy_nested_guards(function: &mut Function) {
    while collapse_redundant_copy_nested_one(&mut function.body) {}
}

fn collapse_redundant_copy_nested_one(body: &mut Vec<Stmt>) -> bool {
    for index in 0..body.len() {
        if index + 1 < body.len() {
            let replacement = match (&body[index], &body[index + 1]) {
                (
                    previous @ Stmt::Assign { src, .. },
                    Stmt::If {
                        cond: outer_condition,
                        then_body,
                        else_body: None,
                    },
                ) if matches!(src, Expr::Reg(_) | Expr::Const(_)) => match then_body.as_slice() {
                    [duplicate, Stmt::If {
                        cond: inner_condition,
                        then_body: inner_body,
                        else_body: None,
                    }] if duplicate == previous => Some(Stmt::If {
                        cond: Expr::Bin {
                            op: BinOp::LogicalAnd,
                            lhs: Box::new(outer_condition.clone()),
                            rhs: Box::new(inner_condition.clone()),
                        },
                        then_body: inner_body.clone(),
                        else_body: None,
                    }),
                    _ => None,
                },
                _ => None,
            };
            if let Some(replacement) = replacement {
                body[index + 1] = replacement;
                return true;
            }
        }

        let changed = match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_redundant_copy_nested_one(then_body)
                    || else_body
                        .as_mut()
                        .is_some_and(collapse_redundant_copy_nested_one)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_redundant_copy_nested_one(body)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| collapse_redundant_copy_nested_one(body))
                    || default
                        .as_mut()
                        .is_some_and(collapse_redundant_copy_nested_one)
            }
            Stmt::TryCatch { try_body, catches } => {
                collapse_redundant_copy_nested_one(try_body)
                    || catches
                        .iter_mut()
                        .any(|catch| collapse_redundant_copy_nested_one(&mut catch.body))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn contains_unstructured_transfer(body: &[Stmt]) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Label(_) | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            contains_unstructured_transfer(then_body)
                || else_body
                    .as_deref()
                    .is_some_and(contains_unstructured_transfer)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            contains_unstructured_transfer(body)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| contains_unstructured_transfer(body))
                || default
                    .as_deref()
                    .is_some_and(contains_unstructured_transfer)
        }
        Stmt::TryCatch { try_body, catches } => {
            contains_unstructured_transfer(try_body)
                || catches
                    .iter()
                    .any(|catch| contains_unstructured_transfer(&catch.body))
        }
        _ => false,
    })
}

fn collapse_nested_return_one(body: &mut Vec<Stmt>) -> bool {
    for index in 0..body.len() {
        let replacement = match &body[index] {
            Stmt::If {
                cond: outer_condition,
                then_body,
                else_body: None,
            } => match then_body.as_slice() {
                [Stmt::If {
                    cond: inner_condition,
                    then_body: return_body,
                    else_body: None,
                }] if matches!(return_body.as_slice(), [Stmt::Return { .. }]) => Some(Stmt::If {
                    cond: Expr::Bin {
                        op: BinOp::LogicalAnd,
                        lhs: Box::new(outer_condition.clone()),
                        rhs: Box::new(inner_condition.clone()),
                    },
                    then_body: return_body.clone(),
                    else_body: None,
                }),
                _ => None,
            },
            _ => None,
        };
        if let Some(replacement) = replacement {
            body[index] = replacement;
            return true;
        }

        let changed = match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_nested_return_one(then_body)
                    || else_body.as_mut().is_some_and(collapse_nested_return_one)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_nested_return_one(body)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| collapse_nested_return_one(body))
                    || default.as_mut().is_some_and(collapse_nested_return_one)
            }
            Stmt::TryCatch { try_body, catches } => {
                collapse_nested_return_one(try_body)
                    || catches
                        .iter_mut()
                        .any(|catch| collapse_nested_return_one(&mut catch.body))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn collapse_break_one(body: &mut Vec<Stmt>) -> bool {
    for index in 0..body.len() {
        if index + 1 < body.len() {
            let left = break_guard_condition(&body[index]);
            let right = break_guard_condition(&body[index + 1]);
            if let (Some(left), Some(right)) = (left, right) {
                body[index] = Stmt::If {
                    cond: Expr::Bin {
                        op: BinOp::LogicalOr,
                        lhs: Box::new(left),
                        rhs: Box::new(right),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                };
                body.remove(index + 1);
                return true;
            }
        }

        let changed = match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_break_one(then_body) || else_body.as_mut().is_some_and(collapse_break_one)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_break_one(body)
            }
            Stmt::Switch { cases, default, .. } => {
                cases.iter_mut().any(|(_, body)| collapse_break_one(body))
                    || default.as_mut().is_some_and(collapse_break_one)
            }
            Stmt::TryCatch { try_body, catches } => {
                collapse_break_one(try_body)
                    || catches
                        .iter_mut()
                        .any(|catch| collapse_break_one(&mut catch.body))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn break_guard_condition(statement: &Stmt) -> Option<Expr> {
    let Stmt::If {
        cond,
        then_body,
        else_body: None,
    } = statement
    else {
        return None;
    };
    matches!(then_body.as_slice(), [Stmt::Break]).then(|| cond.clone())
}

fn collapse_assignment_one(
    body: &mut Vec<Stmt>,
    labels: &HashMap<u64, usize>,
    gotos: &HashMap<u64, usize>,
) -> bool {
    for index in 0..body.len() {
        if index + 1 < body.len() {
            if let Some((condition, update_body, update_label, join_label)) =
                recover_shared_assignment(&body[index], &body[index + 1])
            {
                let labels_are_owned = labels.get(&update_label).copied() == Some(1)
                    && labels.get(&join_label).copied() == Some(1);
                let gotos_are_owned = gotos.get(&update_label).copied() == Some(1)
                    && gotos.get(&join_label).copied() == Some(1);
                if labels_are_owned && gotos_are_owned {
                    body.splice(
                        index..=index + 1,
                        [Stmt::If {
                            cond: condition,
                            then_body: update_body,
                            else_body: None,
                        }],
                    );
                    return true;
                }
            }
        }

        let changed = match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_assignment_one(then_body, labels, gotos)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| collapse_assignment_one(body, labels, gotos))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_assignment_one(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| collapse_assignment_one(body, labels, gotos))
                    || default
                        .as_mut()
                        .is_some_and(|body| collapse_assignment_one(body, labels, gotos))
            }
            Stmt::TryCatch { try_body, catches } => {
                collapse_assignment_one(try_body, labels, gotos)
                    || catches
                        .iter_mut()
                        .any(|catch| collapse_assignment_one(&mut catch.body, labels, gotos))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn recover_shared_assignment(
    statement: &Stmt,
    following: &Stmt,
) -> Option<(Expr, Vec<Stmt>, u64, u64)> {
    let Stmt::If {
        cond: outer_condition,
        then_body,
        else_body: None,
    } = statement
    else {
        return None;
    };
    let [Stmt::If {
        cond: direct_update_condition,
        then_body: direct_update_body,
        else_body: Some(indirect_update_body),
    }] = then_body.as_slice()
    else {
        return None;
    };
    let (Stmt::Label(update_label), update_body) = direct_update_body.split_first()? else {
        return None;
    };
    if !matches!(update_body, [Stmt::Assign { .. } | Stmt::Store { .. }]) {
        return None;
    }
    let [Stmt::If {
        cond: skip_condition,
        then_body: skip_body,
        else_body: None,
    }, Stmt::Goto {
        target: indirect_update_label,
    }] = indirect_update_body.as_slice()
    else {
        return None;
    };
    let [Stmt::Goto {
        target: skipped_update_label,
    }] = skip_body.as_slice()
    else {
        return None;
    };
    let Stmt::Label(join_label) = following else {
        return None;
    };
    if update_label != indirect_update_label
        || join_label != skipped_update_label
        || update_label == join_label
    {
        return None;
    }

    let indirect_condition = negate_exact_condition(skip_condition.clone())?;
    let update_condition = Expr::Bin {
        op: BinOp::LogicalOr,
        lhs: Box::new(direct_update_condition.clone()),
        rhs: Box::new(indirect_condition),
    };
    Some((
        Expr::Bin {
            op: BinOp::LogicalAnd,
            lhs: Box::new(outer_condition.clone()),
            rhs: Box::new(update_condition),
        },
        update_body.to_vec(),
        *update_label,
        *join_label,
    ))
}

fn count_targets(body: &[Stmt], labels: &mut HashMap<u64, usize>, gotos: &mut HashMap<u64, usize>) {
    for statement in body {
        match statement {
            Stmt::Label(target) => *labels.entry(*target).or_default() += 1,
            Stmt::Goto { target } => *gotos.entry(*target).or_default() += 1,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                count_targets(then_body, labels, gotos);
                if let Some(else_body) = else_body {
                    count_targets(else_body, labels, gotos);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                count_targets(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    count_targets(case_body, labels, gotos);
                }
                if let Some(default_body) = default {
                    count_targets(default_body, labels, gotos);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                count_targets(try_body, labels, gotos);
                for catch in catches {
                    count_targets(&catch.body, labels, gotos);
                }
            }
            _ => {}
        }
    }
}

fn collapse_one(
    body: &mut Vec<Stmt>,
    labels: &HashMap<u64, usize>,
    gotos: &HashMap<u64, usize>,
) -> bool {
    for index in 0..body.len() {
        let candidate = recover_ladder(&body[index]);
        if let Some(candidate) = candidate {
            if labels.get(&candidate.target).copied() == Some(1)
                && gotos.get(&candidate.target).copied() == Some(candidate.consumed_gotos)
            {
                let condition = candidate
                    .exit_conditions
                    .into_iter()
                    .reduce(|lhs, rhs| Expr::Bin {
                        op: BinOp::LogicalOr,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    })
                    .expect("a guard ladder has at least its root condition");
                body[index] = Stmt::If {
                    cond: condition,
                    then_body: candidate.exit_body,
                    else_body: Some(candidate.continuation),
                };
                return true;
            }
        }

        let changed = match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_one(then_body, labels, gotos)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| collapse_one(body, labels, gotos))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_one(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| collapse_one(body, labels, gotos))
                    || default
                        .as_mut()
                        .is_some_and(|body| collapse_one(body, labels, gotos))
            }
            Stmt::TryCatch { try_body, catches } => {
                collapse_one(try_body, labels, gotos)
                    || catches
                        .iter_mut()
                        .any(|catch| collapse_one(&mut catch.body, labels, gotos))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn recover_ladder(statement: &Stmt) -> Option<GuardLadder> {
    let Stmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = statement
    else {
        return None;
    };
    let (Stmt::Label(target), exit_body) = then_body.split_first()? else {
        return None;
    };
    if exit_body.is_empty() || else_body.len() != 1 {
        return None;
    }
    let Stmt::If { .. } = &else_body[0] else {
        return None;
    };
    let (mut exit_conditions, continuation, consumed_gotos) = recover_tail(&else_body[0], *target)?;
    exit_conditions.insert(0, cond.clone());
    Some(GuardLadder {
        target: *target,
        exit_conditions,
        exit_body: exit_body.to_vec(),
        continuation,
        consumed_gotos,
    })
}

fn recover_tail(statement: &Stmt, target: u64) -> Option<(Vec<Expr>, Vec<Stmt>, usize)> {
    let Stmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = statement
    else {
        return None;
    };

    if is_only_goto(then_body, target) {
        if let [next @ Stmt::If { .. }] = else_body.as_slice() {
            let (mut conditions, continuation, gotos) = recover_tail(next, target)?;
            conditions.insert(0, cond.clone());
            return Some((conditions, continuation, gotos + 1));
        }
        return Some((vec![cond.clone()], else_body.clone(), 1));
    }

    if is_only_goto(else_body, target) {
        let negated = negate_exact_condition(cond.clone())?;
        return Some((vec![negated], then_body.clone(), 1));
    }

    None
}

fn is_only_goto(body: &[Stmt], target: u64) -> bool {
    matches!(body, [Stmt::Goto { target: candidate }] if *candidate == target)
}

/// Negate only comparison predicates whose inverse the AST represents exactly.
/// `UnOp::Not` is machine bitwise NOT, not C logical `!`, so a bare scalar must
/// make recovery fail closed rather than turning both zero and one into true.
fn negate_exact_condition(condition: Expr) -> Option<Expr> {
    match condition {
        comparison @ Expr::Cmp {
            op: CmpOp::Eq | CmpOp::Ne | CmpOp::Ult | CmpOp::Ule | CmpOp::Slt | CmpOp::Sle,
            ..
        } => Some(negate_cmp_expr(comparison)),
        Expr::Bin {
            op: BinOp::LogicalAnd,
            lhs,
            rhs,
        } => Some(Expr::Bin {
            op: BinOp::LogicalOr,
            lhs: Box::new(negate_exact_condition(*lhs)?),
            rhs: Box::new(negate_exact_condition(*rhs)?),
        }),
        Expr::Bin {
            op: BinOp::LogicalOr,
            lhs,
            rhs,
        } => Some(Expr::Bin {
            op: BinOp::LogicalAnd,
            lhs: Box::new(negate_exact_condition(*lhs)?),
            rhs: Box::new(negate_exact_condition(*rhs)?),
        }),
        Expr::Bin { op, lhs, rhs }
            if matches!(op, BinOp::And | BinOp::Or)
                && is_exact_boolean(&lhs)
                && is_exact_boolean(&rhs)
                && is_short_circuit_safe_boolean(&lhs)
                && is_short_circuit_safe_boolean(&rhs) =>
        {
            Some(Expr::Bin {
                op: if op == BinOp::Or {
                    BinOp::LogicalAnd
                } else {
                    BinOp::LogicalOr
                },
                lhs: Box::new(negate_exact_condition(*lhs)?),
                rhs: Box::new(negate_exact_condition(*rhs)?),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::ir::ast::{render_decbench, Expr, Function, Stmt};
    use crate::ir::types::{BinOp, CmpOp, VReg};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn dijkstra_style_ladder(extra_target: bool) -> Function {
        let mut body = vec![Stmt::If {
            cond: Expr::Reg(reg("bad_weights")),
            then_body: vec![
                Stmt::Label(0x117a),
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
            ],
            else_body: Some(vec![Stmt::If {
                cond: Expr::Reg(reg("bad_distance")),
                then_body: vec![Stmt::Goto { target: 0x117a }],
                else_body: Some(vec![Stmt::If {
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("valid_source"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    then_body: vec![Stmt::Assign {
                        dst: reg("local_4"),
                        src: Expr::Const(1),
                    }],
                    else_body: Some(vec![Stmt::Goto { target: 0x117a }]),
                }]),
            }]),
        }];
        if extra_target {
            body.push(Stmt::Goto { target: 0x117a });
        }
        body.push(Stmt::Return {
            value: Some(Expr::Reg(reg("ret"))),
        });
        Function {
            name: "guarded".into(),
            entry_va: 0x1000,
            body,
        }
    }

    #[test]
    fn a_shared_exit_validation_ladder_becomes_one_short_circuit_guard() {
        let mut function = dijkstra_style_ladder(false);

        super::collapse_shared_exit_guard_ladders(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" || ").count(), 2, "{rendered}");
        assert!(!rendered.contains("goto "), "{rendered}");
        assert!(!rendered.contains("L_117a"), "{rendered}");
        assert!(rendered.contains("local_4 = 1;"), "{rendered}");
        assert!(rendered.contains("ret = 0;"), "{rendered}");
    }

    #[test]
    fn an_external_jump_to_the_shared_exit_blocks_ladder_recovery() {
        let mut function = dijkstra_style_ladder(true);

        super::collapse_shared_exit_guard_ladders(&mut function);

        let rendered = render_decbench(&function);
        assert!(rendered.contains("goto L_117a;"), "{rendered}");
        assert!(rendered.contains("L_117a: ;"), "{rendered}");
        assert!(!rendered.contains(" || "), "{rendered}");
    }

    fn best_node_ladder(extra_update_target: bool) -> Function {
        let mut body = vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: crate::ir::types::CmpOp::Eq,
                    lhs: Box::new(Expr::Reg(reg("used"))),
                    rhs: Box::new(Expr::Const(0)),
                },
                then_body: vec![Stmt::If {
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(reg("best"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![
                        Stmt::Label(0x122d),
                        Stmt::Assign {
                            dst: reg("best"),
                            src: Expr::Reg(reg("candidate")),
                        },
                    ],
                    else_body: Some(vec![
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: crate::ir::types::CmpOp::Sle,
                                lhs: Box::new(Expr::Reg(reg("best_distance"))),
                                rhs: Box::new(Expr::Reg(reg("candidate_distance"))),
                            },
                            then_body: vec![Stmt::Goto { target: 0x1233 }],
                            else_body: None,
                        },
                        Stmt::Goto { target: 0x122d },
                    ]),
                }],
                else_body: None,
            },
            Stmt::Label(0x1233),
        ];
        if extra_update_target {
            body.push(Stmt::Goto { target: 0x122d });
        }
        body.push(Stmt::Return {
            value: Some(Expr::Reg(reg("best"))),
        });
        Function {
            name: "choose_best".into(),
            entry_va: 0x1200,
            body,
        }
    }

    #[test]
    fn cross_branch_shared_assignment_becomes_one_short_circuit_guard() {
        let mut function = best_node_ladder(false);

        super::collapse_shared_assignment_guards(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" && ").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" || ").count(), 1, "{rendered}");
        assert!(!rendered.contains("goto "), "{rendered}");
        assert!(!rendered.contains("L_122d"), "{rendered}");
        assert!(!rendered.contains("L_1233"), "{rendered}");
        assert!(rendered.contains("best = candidate;"), "{rendered}");
    }

    #[test]
    fn an_external_jump_to_the_shared_assignment_blocks_recovery() {
        let mut function = best_node_ladder(true);

        super::collapse_shared_assignment_guards(&mut function);

        let rendered = render_decbench(&function);
        assert!(rendered.contains("goto L_122d;"), "{rendered}");
        assert!(rendered.contains("L_122d: ;"), "{rendered}");
        assert!(!rendered.contains(" && "), "{rendered}");
    }

    #[test]
    fn adjacent_break_guards_become_one_short_circuit_guard() {
        let mut function = Function {
            name: "stop_search".into(),
            entry_va: 0x1300,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::If {
                        cond: Expr::Cmp {
                            op: crate::ir::types::CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(reg("best"))),
                            rhs: Box::new(Expr::Const(0)),
                        },
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::If {
                        cond: Expr::Cmp {
                            op: crate::ir::types::CmpOp::Eq,
                            lhs: Box::new(Expr::Reg(reg("distance"))),
                            rhs: Box::new(Expr::Const(0x7fff_ffff)),
                        },
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: reg("iteration"),
                        src: Expr::Const(1),
                    },
                ],
            }],
        };

        super::collapse_adjacent_break_guards(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" || ").count(), 1, "{rendered}");
        assert_eq!(rendered.matches("break;").count(), 1, "{rendered}");
        assert!(rendered.contains("iteration = 1;"), "{rendered}");
    }

    #[test]
    fn nested_terminal_return_guards_become_one_conjunction() {
        let mut function = Function {
            name: "bounded_return".into(),
            entry_va: 0x1350,
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("outer")),
                then_body: vec![Stmt::If {
                    cond: Expr::Reg(reg("inner")),
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(reg("result"))),
                    }],
                    else_body: None,
                }],
                else_body: None,
            }],
        };

        super::collapse_nested_terminal_return_guards(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" && ").count(), 1, "{rendered}");
        assert_eq!(rendered.matches("return result;").count(), 1, "{rendered}");
    }

    #[test]
    fn nested_guard_with_else_or_intervening_effect_stays_nested() {
        let nested = |inner_else| Stmt::If {
            cond: Expr::Reg(reg("outer")),
            then_body: vec![Stmt::If {
                cond: Expr::Reg(reg("inner")),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
                else_body: inner_else,
            }],
            else_body: None,
        };
        let mut function = Function {
            name: "ordered_guards".into(),
            entry_va: 0x1360,
            body: vec![
                nested(Some(vec![Stmt::Return {
                    value: Some(Expr::Const(0)),
                }])),
                Stmt::If {
                    cond: Expr::Reg(reg("outer2")),
                    then_body: vec![
                        Stmt::Assign {
                            dst: reg("effect"),
                            src: Expr::Const(1),
                        },
                        Stmt::If {
                            cond: Expr::Reg(reg("inner2")),
                            then_body: vec![Stmt::Return {
                                value: Some(Expr::Const(2)),
                            }],
                            else_body: None,
                        },
                    ],
                    else_body: None,
                },
            ],
        };

        super::collapse_nested_terminal_return_guards(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("if (").count(), 4, "{rendered}");
        assert!(!rendered.contains(" && "), "{rendered}");
        assert!(rendered.contains("effect = 1;"), "{rendered}");
    }

    #[test]
    fn matching_early_and_final_return_wraps_the_continuation() {
        let result = Expr::Reg(reg("result"));
        let mut function = Function {
            name: "shared_terminal".into(),
            entry_va: 0x1370,
            body: vec![
                Stmt::If {
                    cond: Expr::Bin {
                        op: BinOp::LogicalOr,
                        lhs: Box::new(Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(Expr::Reg(reg("pointer"))),
                            rhs: Box::new(Expr::Const(0)),
                        }),
                        rhs: Box::new(Expr::Cmp {
                            op: CmpOp::Ule,
                            lhs: Box::new(Expr::Const(16)),
                            rhs: Box::new(Expr::Reg(reg("count"))),
                        }),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(result.clone()),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("work"),
                    src: Expr::Const(1),
                },
                Stmt::Return {
                    value: Some(result),
                },
            ],
        };

        super::collapse_matching_terminal_return_guard(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("return result;").count(), 1, "{rendered}");
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" && ").count(), 1, "{rendered}");
        assert!(rendered.contains("work = 1;"), "{rendered}");
    }

    /// Machine-epilogue comments are renderer metadata rather than control
    /// flow.  They must not prevent two paths reaching the same return from
    /// being represented by one shared source-level terminal.
    #[test]
    fn matching_commented_returns_keep_one_shared_terminal() {
        let epilogue = Stmt::Comment("x86-64 epilogue: restore rbp".into());
        let terminal = Stmt::Return {
            value: Some(Expr::Const(0x5868)),
        };
        let mut function = Function {
            name: "user_name".into(),
            entry_va: 0x408a,
            body: vec![
                Stmt::If {
                    cond: Expr::Bin {
                        op: BinOp::Or,
                        lhs: Box::new(Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(Expr::Reg(reg("length"))),
                            rhs: Box::new(Expr::Const(0)),
                        }),
                        rhs: Box::new(Expr::Cmp {
                            op: CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(reg("length"))),
                            rhs: Box::new(Expr::Const(0)),
                        }),
                    },
                    then_body: vec![epilogue.clone(), terminal.clone()],
                    else_body: None,
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(Expr::Reg(reg("length"))),
                        rhs: Box::new(Expr::Const(21)),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Const(0x82d0)),
                    }],
                    else_body: None,
                },
                epilogue,
                terminal,
            ],
        };

        super::collapse_matching_terminal_return_guard(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("return 0x5868;").count(), 1, "{rendered}");
        assert_eq!(
            rendered.matches("x86-64 epilogue: restore rbp").count(),
            1,
            "{rendered}"
        );
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert!(rendered.contains(" || "), "{rendered}");
        assert!(rendered.contains("return 0x82d0;"), "{rendered}");
    }

    #[test]
    fn eager_boolean_with_memory_read_is_not_short_circuited() {
        let condition = Expr::Bin {
            op: BinOp::Or,
            lhs: Box::new(Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(reg("length"))),
                rhs: Box::new(Expr::Const(0)),
            }),
            rhs: Box::new(Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Deref {
                    addr: Box::new(Expr::Reg(reg("pointer"))),
                    size: 4,
                }),
                rhs: Box::new(Expr::Const(0)),
            }),
        };

        assert!(super::negate_exact_condition(condition).is_none());
    }

    #[test]
    fn shared_terminal_pair_with_memory_predicate_stays_separate() {
        let terminal = Stmt::Return {
            value: Some(Expr::Const(-7)),
        };
        let mut function = Function {
            name: "volatile_guard".into(),
            entry_va: 0x4090,
            body: vec![
                Stmt::If {
                    cond: Expr::Bin {
                        op: BinOp::Or,
                        lhs: Box::new(Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(Expr::Reg(reg("length"))),
                            rhs: Box::new(Expr::Const(0)),
                        }),
                        rhs: Box::new(Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(Expr::Deref {
                                addr: Box::new(Expr::Reg(reg("pointer"))),
                                size: 4,
                            }),
                            rhs: Box::new(Expr::Const(0)),
                        }),
                    },
                    then_body: vec![terminal.clone()],
                    else_body: None,
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(Expr::Reg(reg("length"))),
                        rhs: Box::new(Expr::Const(21)),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Const(42)),
                    }],
                    else_body: None,
                },
                terminal,
            ],
        };
        let original = function.clone();

        super::collapse_matching_terminal_return_guard(&mut function);

        assert_eq!(function, original);
    }

    #[test]
    fn mismatched_or_unnegatable_terminal_guard_stays_early() {
        let mut mismatched = Function {
            name: "mismatched".into(),
            entry_va: 0x1380,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(reg("condition")),
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Const(1)),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("work"),
                    src: Expr::Const(1),
                },
                Stmt::Return {
                    value: Some(Expr::Const(2)),
                },
            ],
        };
        let original = mismatched.clone();

        super::collapse_matching_terminal_return_guard(&mut mismatched);

        assert_eq!(mismatched, original);
    }

    #[test]
    fn duplicate_reaching_copy_exposes_nested_conjunction() {
        let copy = Stmt::Assign {
            dst: reg("top"),
            src: Expr::Reg(reg("previous_top")),
        };
        let mut function = Function {
            name: "bounded_descent".into(),
            entry_va: 0x1390,
            body: vec![
                copy.clone(),
                Stmt::If {
                    cond: Expr::Reg(reg("valid_node")),
                    then_body: vec![
                        copy,
                        Stmt::If {
                            cond: Expr::Reg(reg("stack_has_room")),
                            then_body: vec![Stmt::Assign {
                                dst: reg("descended"),
                                src: Expr::Const(1),
                            }],
                            else_body: None,
                        },
                    ],
                    else_body: None,
                },
            ],
        };

        super::collapse_redundant_copy_nested_guards(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(
            rendered.matches("top = previous_top;").count(),
            1,
            "{rendered}"
        );
        assert_eq!(rendered.matches("if (").count(), 1, "{rendered}");
        assert_eq!(rendered.matches(" && ").count(), 1, "{rendered}");
        assert!(rendered.contains("descended = 1;"), "{rendered}");
    }

    #[test]
    fn changed_or_memory_backed_copy_blocks_nested_conjunction() {
        let mut function = Function {
            name: "mutable_copy".into(),
            entry_va: 0x13a0,
            body: vec![
                Stmt::Assign {
                    dst: reg("top"),
                    src: Expr::Reg(reg("before")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("valid")),
                    then_body: vec![
                        Stmt::Assign {
                            dst: reg("top"),
                            src: Expr::Reg(reg("after")),
                        },
                        Stmt::If {
                            cond: Expr::Reg(reg("room")),
                            then_body: vec![Stmt::Return { value: None }],
                            else_body: None,
                        },
                    ],
                    else_body: None,
                },
            ],
        };
        let original = function.clone();

        super::collapse_redundant_copy_nested_guards(&mut function);

        assert_eq!(function, original);
    }

    #[test]
    fn an_intervening_effect_blocks_break_guard_fusion() {
        let mut function = Function {
            name: "ordered_effect".into(),
            entry_va: 0x1400,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::If {
                        cond: Expr::Reg(reg("first")),
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: reg("effect"),
                        src: Expr::Const(1),
                    },
                    Stmt::If {
                        cond: Expr::Reg(reg("second")),
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                ],
            }],
        };

        super::collapse_adjacent_break_guards(&mut function);

        let rendered = render_decbench(&function);
        assert_eq!(rendered.matches("if (").count(), 2, "{rendered}");
        assert!(!rendered.contains(" || "), "{rendered}");
        assert_eq!(rendered.matches("break;").count(), 2, "{rendered}");
    }
}
