//! Drop labels whose VA is never referenced by a `goto`.
//!
//! Each unstructured block lowers to a `Stmt::Label(va)` + its statements.
//! When structural analysis recognises a Seq/If/While region, the blocks
//! inside stop needing a Label because control arrives through structured
//! flow. But a few labels still survive — typically in the Unstructured
//! fallback — and clutter the output.
//!
//! This pass walks the body, collects every `Stmt::Goto { target }`'s VA
//! (plus every If/While cond-jump target we can observe), and removes any
//! `Stmt::Label(va)` whose VA doesn't appear in that set.

use std::collections::{HashMap, HashSet};

use crate::ir::ast::{negate_cmp_expr, Expr, Function, Stmt};

/// Remove labels whose VA is never referenced by a `goto` within `f`.
pub fn prune_unreferenced_labels(f: &mut Function) {
    let mut referenced: HashSet<u64> = HashSet::new();
    collect_goto_targets(&f.body, &mut referenced);
    drop_unreferenced(&mut f.body, &referenced);
}

/// Remove statements that cannot be reached by sequential execution after an
/// unconditional terminator, then discard labels whose only incoming goto was
/// itself in the removed tail.
///
/// Every surviving label is conservatively treated as a possible entry while
/// scanning a statement list. This means the pass can remove a tail after
/// `return`, `goto`, `break`, or an indirect goto without pretending to solve
/// cross-region reachability. Repeating tail removal and target-based label
/// pruning reaches the useful fixed point for compiler-generated shared-return
/// epilogues while preserving every externally referenced label.
pub fn prune_unreachable_tails(f: &mut Function) {
    loop {
        let before = f.clone();
        prune_unreachable_body(&mut f.body);
        prune_unreferenced_labels(f);
        if *f == before {
            break;
        }
    }
}

/// Inline uniquely labelled, straight-line return tails at their goto sites.
///
/// Compilers routinely share one return epilogue across several branches. A
/// conservative AST renders that as `goto label`, even when the labelled tail
/// is only assignments followed by a return. Duplicating that exact tail at
/// each goto preserves both the effects and their order while recovering the
/// source-level early returns. The pass rejects tails with another label,
/// nested control flow, stores, calls, or a non-returning fallthrough; it is not
/// a general-purpose code duplicator.
pub fn inline_terminal_goto_tails(function: &mut Function) {
    loop {
        let mut labels = HashMap::new();
        let mut gotos = HashMap::new();
        count_labels_and_gotos(&function.body, &mut labels, &mut gotos);
        let Some((target, tail)) = find_terminal_tail(&function.body, &labels, &gotos) else {
            break;
        };
        let expected = gotos.get(&target).copied().unwrap_or_default();
        let replaced = replace_target_gotos(&mut function.body, target, &tail);
        debug_assert_eq!(replaced, expected);
        if replaced != expected || !remove_target_label(&mut function.body, target) {
            break;
        }
        // Removing one entry label can leave the old fall-through copy of a
        // later terminal tail unreachable. Prune it now so the next iteration
        // can see an immediately preceding shared-return label.
        prune_unreachable_tails(function);
    }
}

/// Recover a forward-goto region whose exits all join at the adjacent label.
///
/// A sequence such as `if (stop) goto join; work; join:` is exactly
/// `if (!stop) { work; }`. Multiple such guards become nested continuations.
/// If the final statement in that continuation is a loop, a goto from that
/// loop to the immediately following join is exactly `break`. The pass requires
/// one globally unique label, accounts for every goto to it, rejects any other
/// label in the moved region, and refuses to turn a non-tail loop exit into a
/// break (because that would execute statements the goto skipped).
pub fn recover_forward_exit_regions(function: &mut Function) {
    loop {
        let mut labels = HashMap::new();
        let mut gotos = HashMap::new();
        count_labels_and_gotos(&function.body, &mut labels, &mut gotos);
        if !recover_one_forward_exit(&mut function.body, &labels, &gotos) {
            break;
        }
    }
}

fn recover_one_forward_exit(
    body: &mut Vec<Stmt>,
    labels: &HashMap<u64, usize>,
    gotos: &HashMap<u64, usize>,
) -> bool {
    for label_index in 0..body.len() {
        let Stmt::Label(target) = body[label_index] else {
            continue;
        };
        let expected_gotos = gotos.get(&target).copied().unwrap_or_default();
        if labels.get(&target).copied() != Some(1) || expected_gotos == 0 {
            continue;
        }
        let Some(start) = body[..label_index]
            .iter()
            .position(|statement| direct_exit_guard(statement, target).is_some())
        else {
            continue;
        };
        let segment = &body[start..label_index];
        if body_contains_label(segment) || count_target_gotos(segment, target) != expected_gotos {
            continue;
        }
        let Some(replacement) = structure_forward_segment(segment.to_vec(), target) else {
            continue;
        };
        body.splice(start..=label_index, replacement);
        return true;
    }

    for statement in body {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_one_forward_exit(then_body, labels, gotos)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| recover_one_forward_exit(body, labels, gotos))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_one_forward_exit(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| recover_one_forward_exit(body, labels, gotos))
                    || default
                        .as_mut()
                        .is_some_and(|body| recover_one_forward_exit(body, labels, gotos))
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_one_forward_exit(try_body, labels, gotos)
                    || catches
                        .iter_mut()
                        .any(|catch| recover_one_forward_exit(&mut catch.body, labels, gotos))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn structure_forward_segment(mut segment: Vec<Stmt>, target: u64) -> Option<Vec<Stmt>> {
    let tail_index = segment
        .iter()
        .rposition(|statement| !matches!(statement, Stmt::Nop | Stmt::Comment(_)))?;
    if statement_contains_target_goto(&segment[tail_index], target) {
        match &mut segment[tail_index] {
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                replace_one_loop_exit_gotos(body, target)?;
            }
            _ => return None,
        }
    }

    let mut guard_indices = Vec::new();
    for (index, statement) in segment.iter().enumerate() {
        if direct_exit_guard(statement, target).is_some() {
            guard_indices.push(index);
        } else if statement_contains_target_goto(statement, target) {
            return None;
        }
    }
    if guard_indices.is_empty() {
        return None;
    }

    for index in guard_indices.into_iter().rev() {
        let condition = direct_exit_guard(&segment[index], target)?;
        let continuation = segment.split_off(index + 1);
        segment[index] = Stmt::If {
            cond: negate_cmp_expr(condition),
            then_body: continuation,
            else_body: None,
        };
    }
    Some(segment)
}

fn replace_one_loop_exit_gotos(body: &mut Vec<Stmt>, target: u64) -> Option<usize> {
    let mut replaced = 0;
    for statement in body {
        match statement {
            Stmt::Goto { target: seen } if *seen == target => {
                *statement = Stmt::Break;
                replaced += 1;
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                replaced += replace_one_loop_exit_gotos(then_body, target)?;
                if let Some(else_body) = else_body {
                    replaced += replace_one_loop_exit_gotos(else_body, target)?;
                }
            }
            _ if statement_contains_target_goto(statement, target) => return None,
            _ => {}
        }
    }
    Some(replaced)
}

fn direct_exit_guard(statement: &Stmt, target: u64) -> Option<Expr> {
    let Stmt::If {
        cond,
        then_body,
        else_body: None,
    } = statement
    else {
        return None;
    };
    matches!(then_body.as_slice(), [Stmt::Goto { target: seen }] if *seen == target)
        .then(|| cond.clone())
}

fn body_contains_label(body: &[Stmt]) -> bool {
    body.iter().any(statement_contains_any_label)
}

fn statement_contains_any_label(statement: &Stmt) -> bool {
    match statement {
        Stmt::Label(_) => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_contains_label(then_body) || else_body.as_deref().is_some_and(body_contains_label)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            body_contains_label(body)
        }
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| body_contains_label(body))
                || default.as_deref().is_some_and(body_contains_label)
        }
        Stmt::TryCatch { try_body, catches } => {
            body_contains_label(try_body)
                || catches.iter().any(|catch| body_contains_label(&catch.body))
        }
        _ => false,
    }
}

fn count_target_gotos(body: &[Stmt], target: u64) -> usize {
    body.iter()
        .map(|statement| count_target_gotos_in_statement(statement, target))
        .sum()
}

fn count_target_gotos_in_statement(statement: &Stmt, target: u64) -> usize {
    match statement {
        Stmt::Goto { target: seen } => usize::from(*seen == target),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            count_target_gotos(then_body, target)
                + else_body
                    .as_deref()
                    .map(|body| count_target_gotos(body, target))
                    .unwrap_or_default()
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            count_target_gotos(body, target)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .map(|(_, body)| count_target_gotos(body, target))
                .sum::<usize>()
                + default
                    .as_deref()
                    .map(|body| count_target_gotos(body, target))
                    .unwrap_or_default()
        }
        Stmt::TryCatch { try_body, catches } => {
            count_target_gotos(try_body, target)
                + catches
                    .iter()
                    .map(|catch| count_target_gotos(&catch.body, target))
                    .sum::<usize>()
        }
        _ => 0,
    }
}

fn statement_contains_target_goto(statement: &Stmt, target: u64) -> bool {
    count_target_gotos_in_statement(statement, target) > 0
}

fn find_terminal_tail(
    body: &[Stmt],
    labels: &HashMap<u64, usize>,
    gotos: &HashMap<u64, usize>,
) -> Option<(u64, Vec<Stmt>)> {
    for (index, statement) in body.iter().enumerate() {
        let Stmt::Label(target) = statement else {
            continue;
        };
        let tail = &body[index + 1..];
        if labels.get(target).copied() == Some(1)
            && gotos.get(target).copied().unwrap_or_default() > 0
            && straight_line_return_tail(tail)
        {
            return Some((*target, tail.to_vec()));
        }
    }

    for statement in body {
        let candidate = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => find_terminal_tail(then_body, labels, gotos).or_else(|| {
                else_body
                    .as_deref()
                    .and_then(|body| find_terminal_tail(body, labels, gotos))
            }),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                find_terminal_tail(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .find_map(|(_, body)| find_terminal_tail(body, labels, gotos))
                .or_else(|| {
                    default
                        .as_deref()
                        .and_then(|body| find_terminal_tail(body, labels, gotos))
                }),
            Stmt::TryCatch { try_body, catches } => find_terminal_tail(try_body, labels, gotos)
                .or_else(|| {
                    catches
                        .iter()
                        .find_map(|catch| find_terminal_tail(&catch.body, labels, gotos))
                }),
            _ => None,
        };
        if candidate.is_some() {
            return candidate;
        }
    }
    None
}

fn straight_line_return_tail(tail: &[Stmt]) -> bool {
    !tail.is_empty()
        && matches!(tail.last(), Some(Stmt::Return { .. }))
        && tail[..tail.len() - 1].iter().all(|statement| {
            matches!(
                statement,
                Stmt::Assign { .. } | Stmt::Nop | Stmt::Comment(_)
            )
        })
}

fn replace_target_gotos(body: &mut Vec<Stmt>, target: u64, tail: &[Stmt]) -> usize {
    let mut replaced = 0;
    let mut index = 0;
    while index < body.len() {
        if matches!(&body[index], Stmt::Goto { target: seen } if *seen == target) {
            body.splice(index..=index, tail.to_vec());
            replaced += 1;
            index += tail.len();
            continue;
        }
        replaced += match &mut body[index] {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                replace_target_gotos(then_body, target, tail)
                    + else_body
                        .as_mut()
                        .map(|body| replace_target_gotos(body, target, tail))
                        .unwrap_or_default()
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                replace_target_gotos(body, target, tail)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .map(|(_, body)| replace_target_gotos(body, target, tail))
                    .sum::<usize>()
                    + default
                        .as_mut()
                        .map(|body| replace_target_gotos(body, target, tail))
                        .unwrap_or_default()
            }
            Stmt::TryCatch { try_body, catches } => {
                replace_target_gotos(try_body, target, tail)
                    + catches
                        .iter_mut()
                        .map(|catch| replace_target_gotos(&mut catch.body, target, tail))
                        .sum::<usize>()
            }
            _ => 0,
        };
        index += 1;
    }
    replaced
}

fn remove_target_label(body: &mut Vec<Stmt>, target: u64) -> bool {
    if let Some(index) = body
        .iter()
        .position(|statement| matches!(statement, Stmt::Label(seen) if *seen == target))
    {
        body.remove(index);
        return true;
    }
    for statement in body {
        let removed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                remove_target_label(then_body, target)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| remove_target_label(body, target))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                remove_target_label(body, target)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| remove_target_label(body, target))
                    || default
                        .as_mut()
                        .is_some_and(|body| remove_target_label(body, target))
            }
            Stmt::TryCatch { try_body, catches } => {
                remove_target_label(try_body, target)
                    || catches
                        .iter_mut()
                        .any(|catch| remove_target_label(&mut catch.body, target))
            }
            _ => false,
        };
        if removed {
            return true;
        }
    }
    false
}

fn count_labels_and_gotos(
    body: &[Stmt],
    labels: &mut HashMap<u64, usize>,
    gotos: &mut HashMap<u64, usize>,
) {
    for statement in body {
        match statement {
            Stmt::Label(target) => *labels.entry(*target).or_default() += 1,
            Stmt::Goto { target } => *gotos.entry(*target).or_default() += 1,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                count_labels_and_gotos(then_body, labels, gotos);
                if let Some(else_body) = else_body {
                    count_labels_and_gotos(else_body, labels, gotos);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                count_labels_and_gotos(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    count_labels_and_gotos(case_body, labels, gotos);
                }
                if let Some(default_body) = default {
                    count_labels_and_gotos(default_body, labels, gotos);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                count_labels_and_gotos(try_body, labels, gotos);
                for catch in catches {
                    count_labels_and_gotos(&catch.body, labels, gotos);
                }
            }
            _ => {}
        }
    }
}

fn prune_unreachable_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                prune_unreachable_body(then_body);
                if let Some(else_body) = else_body {
                    prune_unreachable_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                prune_unreachable_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    prune_unreachable_body(case_body);
                }
                if let Some(default) = default {
                    prune_unreachable_body(default);
                }
            }
            _ => {}
        }
    }

    let mut reachable = true;
    body.retain(|statement| {
        if matches!(statement, Stmt::Label(_)) {
            // A label may be entered by a goto from any nested region. Target
            // pruning below will remove it on the next iteration if no such
            // edge survives.
            reachable = true;
        }
        if !reachable {
            return false;
        }
        if matches!(
            statement,
            Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } | Stmt::Break
        ) {
            reachable = false;
        }
        true
    });
}

/// Collect every concrete goto target in an already-lowered AST.
///
/// Lowering uses this too: raw block terminators can survive inside a recovered
/// switch even though they are not represented as `Region::Goto` nodes.  A
/// second, target-aware lowering pass then puts labels on the blocks those
/// statements actually reach.
pub(crate) fn collect_goto_targets(body: &[Stmt], out: &mut HashSet<u64>) {
    for s in body {
        match s {
            Stmt::Goto { target } => {
                out.insert(*target);
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_expr_goto(cond, out);
                collect_goto_targets(then_body, out);
                if let Some(eb) = else_body {
                    collect_goto_targets(eb, out);
                }
            }
            Stmt::While { cond, body } => {
                collect_expr_goto(cond, out);
                collect_goto_targets(body, out);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_goto_targets(std::slice::from_ref(init.as_ref()), out);
                collect_expr_goto(cond, out);
                collect_goto_targets(body, out);
                collect_goto_targets(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::DoWhile { body, cond } => {
                collect_goto_targets(body, out);
                collect_expr_goto(cond, out);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_expr_goto(discriminant, out);
                for (_, case_body) in cases {
                    collect_goto_targets(case_body, out);
                }
                if let Some(default_body) = default {
                    collect_goto_targets(default_body, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_expr_goto(_e: &Expr, _out: &mut HashSet<u64>) {
    // Expressions don't carry goto targets in our AST. Left as a no-op
    // for future-proofing (e.g. if we ever model computed goto).
}

fn drop_unreferenced(body: &mut Vec<Stmt>, referenced: &HashSet<u64>) {
    // Recurse into nested bodies first so inner arms are pruned
    // independently.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                drop_unreferenced(then_body, referenced);
                if let Some(eb) = else_body {
                    drop_unreferenced(eb, referenced);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                drop_unreferenced(body, referenced)
            }
            Stmt::For { body, .. } => drop_unreferenced(body, referenced),
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    drop_unreferenced(case_body, referenced);
                }
                if let Some(default_body) = default {
                    drop_unreferenced(default_body, referenced);
                }
            }
            _ => {}
        }
    }

    // An imported/thunk region can end in an indirect jump or in the Call +
    // Return produced by tail-call recovery. Region recovery may place that
    // stub before the current function's lexical fallthrough. The following
    // label is then the only remaining boundary for that fallthrough because
    // structuring consumed its explicit conditional edge. Keep every label
    // immediately after an unconditional terminator: without CFG provenance at
    // this layer, deleting such a boundary is not a sound reachability proof.
    let after_terminator: HashSet<u64> =
        body.windows(2)
            .filter_map(|pair| match pair {
                [Stmt::Return { .. }
                | Stmt::Goto { .. }
                | Stmt::IndirectGoto { .. }
                | Stmt::Break, Stmt::Label(va)] => Some(*va),
                _ => None,
            })
            .collect();
    body.retain(|s| {
        !matches!(s, Stmt::Label(va) if !referenced.contains(va) && !after_terminator.contains(va))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::types::{CmpOp, VReg};

    #[test]
    fn forward_skip_to_an_adjacent_label_becomes_a_guarded_region() {
        let work = Stmt::Assign {
            dst: VReg::phys("value"),
            src: Expr::Const(1),
        };
        let mut function = Function {
            name: "forward_skip".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(VReg::phys("skip"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    then_body: vec![Stmt::Goto { target: 0x1200 }],
                    else_body: None,
                },
                work.clone(),
                Stmt::Label(0x1200),
                Stmt::Return { value: None },
            ],
        };

        recover_forward_exit_regions(&mut function);

        assert!(matches!(
            function.body.as_slice(),
            [
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs,
                        rhs,
                    },
                    then_body,
                    else_body: None,
                },
                Stmt::Return { value: None },
            ] if lhs.as_ref() == &Expr::Reg(VReg::phys("skip"))
                && rhs.as_ref() == &Expr::Const(1)
                && then_body == &[work]
        ));
    }

    #[test]
    fn shared_forward_exits_guard_a_tail_loop_and_become_breaks() {
        let first_work = Stmt::Assign {
            dst: VReg::phys("a"),
            src: Expr::Const(1),
        };
        let second_work = Stmt::Assign {
            dst: VReg::phys("b"),
            src: Expr::Const(2),
        };
        let mut function = Function {
            name: "shared_forward_exit".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("skip_first")),
                    then_body: vec![Stmt::Goto { target: 0x1200 }],
                    else_body: None,
                },
                first_work.clone(),
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("skip_second")),
                    then_body: vec![Stmt::Goto { target: 0x1200 }],
                    else_body: None,
                },
                second_work.clone(),
                Stmt::DoWhile {
                    body: vec![
                        Stmt::If {
                            cond: Expr::Reg(VReg::phys("leave_loop")),
                            then_body: vec![Stmt::Goto { target: 0x1200 }],
                            else_body: None,
                        },
                        Stmt::Nop,
                    ],
                    cond: Expr::Reg(VReg::phys("latch")),
                },
                Stmt::Label(0x1200),
                Stmt::Return { value: None },
            ],
        };

        recover_forward_exit_regions(&mut function);

        let Stmt::If {
            then_body: first_body,
            else_body: None,
            ..
        } = &function.body[0]
        else {
            panic!("first exit was not recovered: {:#?}", function.body);
        };
        assert_eq!(first_body[0], first_work);
        let Stmt::If {
            then_body: second_body,
            else_body: None,
            ..
        } = &first_body[1]
        else {
            panic!("second exit was not recovered: {first_body:#?}");
        };
        assert_eq!(second_body[0], second_work);
        let Stmt::DoWhile { body, .. } = &second_body[1] else {
            panic!("tail loop was lost: {second_body:#?}");
        };
        assert!(matches!(
            body.first(),
            Some(Stmt::If { then_body, .. }) if then_body == &[Stmt::Break]
        ));
        assert!(matches!(function.body.last(), Some(Stmt::Return { .. })));
        assert!(!format!("{:#?}", function.body).contains("Goto"));
        assert!(!format!("{:#?}", function.body).contains("Label"));
    }

    #[test]
    fn a_forward_exit_from_a_non_tail_loop_is_not_rewritten_as_break() {
        let original = vec![
            Stmt::If {
                cond: Expr::Reg(VReg::phys("skip")),
                then_body: vec![Stmt::Goto { target: 0x1200 }],
                else_body: None,
            },
            Stmt::While {
                cond: Expr::Reg(VReg::phys("running")),
                body: vec![Stmt::Goto { target: 0x1200 }],
            },
            Stmt::Assign {
                dst: VReg::phys("after_loop"),
                src: Expr::Const(1),
            },
            Stmt::Label(0x1200),
            Stmt::Return { value: None },
        ];
        let mut function = Function {
            name: "non_tail_loop_exit".into(),
            entry_va: 0,
            body: original.clone(),
        };

        recover_forward_exit_regions(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn shared_straight_line_return_tail_is_inlined_at_each_goto() {
        let tail = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(-1),
            },
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("ret"))),
            },
        ];
        let mut function = Function {
            name: "shared_return".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("failed")),
                    then_body: vec![Stmt::Goto { target: 0x1200 }],
                    else_body: None,
                },
                Stmt::Nop,
                Stmt::Label(0x1200),
                tail[0].clone(),
                tail[1].clone(),
            ],
        };

        inline_terminal_goto_tails(&mut function);

        assert_eq!(
            function.body,
            vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("failed")),
                    then_body: tail.clone(),
                    else_body: None,
                },
                Stmt::Nop,
                tail[0].clone(),
                tail[1].clone(),
            ]
        );
    }

    #[test]
    fn a_nonterminal_shared_tail_is_not_inlined() {
        let original = vec![
            Stmt::Goto { target: 0x1200 },
            Stmt::Label(0x1200),
            Stmt::Assign {
                dst: VReg::phys("value"),
                src: Expr::Const(1),
            },
        ];
        let mut function = Function {
            name: "nonterminal_tail".into(),
            entry_va: 0,
            body: original.clone(),
        };

        inline_terminal_goto_tails(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn another_label_inside_a_shared_tail_blocks_inlining() {
        let original = vec![
            Stmt::Goto { target: 0x1200 },
            Stmt::Label(0x1200),
            Stmt::Assign {
                dst: VReg::phys("value"),
                src: Expr::Const(1),
            },
            Stmt::Label(0x1210),
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("value"))),
            },
        ];
        let mut function = Function {
            name: "multi_entry_tail".into(),
            entry_va: 0,
            body: original.clone(),
        };

        inline_terminal_goto_tails(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn unreferenced_label_is_dropped() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Label(0x100), Stmt::Nop, Stmt::Return { value: None }],
        };
        prune_unreferenced_labels(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Nop));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn referenced_label_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Goto { target: 0x100 },
                Stmt::Label(0x100),
                Stmt::Return { value: None },
            ],
        };
        let orig = f.clone();
        prune_unreferenced_labels(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn label_inside_if_is_pruned_when_unreferenced() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Label(0x200), Stmt::Nop],
                else_body: None,
            }],
        };
        prune_unreferenced_labels(&mut f);
        if let Stmt::If { then_body, .. } = &f.body[0] {
            assert_eq!(then_body.len(), 1);
            assert!(matches!(&then_body[0], Stmt::Nop));
        }
    }

    #[test]
    fn label_is_kept_when_only_referenced_from_nested_arm() {
        // `if (...) { goto L_100; }  L_100: return;`
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Goto { target: 0x100 }],
                    else_body: None,
                },
                Stmt::Label(0x100),
                Stmt::Return { value: None },
            ],
        };
        prune_unreferenced_labels(&mut f);
        // Label 0x100 must survive.
        assert!(f.body.iter().any(|s| matches!(s, Stmt::Label(0x100))));
    }

    #[test]
    fn label_is_kept_when_only_referenced_from_switch_arm() {
        // A jump-table arm may converge on a loop latch emitted after the
        // switch.  That edge is just as real as one nested in an `if`; pruning
        // its target changes the jump into the renderer's trailing empty label.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Switch {
                    discriminant: Expr::Reg(crate::ir::types::VReg::phys("state")),
                    cases: vec![(Some(0), vec![Stmt::Goto { target: 0x100 }])],
                    default: None,
                },
                Stmt::Label(0x100),
                Stmt::Return { value: None },
            ],
        };

        prune_unreferenced_labels(&mut f);

        assert!(f.body.iter().any(|s| matches!(s, Stmt::Label(0x100))));
    }

    #[test]
    fn return_prunes_trailing_statements_then_their_now_unreferenced_label() {
        let result = crate::ir::types::VReg::phys("local_4");
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(result.clone()),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Label(0x100),
                Stmt::Return {
                    value: Some(Expr::Reg(result.clone())),
                },
                Stmt::Store {
                    addr: Expr::Reg(result),
                    src: Expr::Const(1),
                    size: 4,
                },
                Stmt::Goto { target: 0x100 },
            ],
        };

        prune_unreachable_tails(&mut f);

        assert_eq!(
            f.body.len(),
            2,
            "unreachable tail and dead label: {:?}",
            f.body
        );
        assert!(matches!(f.body[0], Stmt::Store { .. }));
        assert!(matches!(f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn referenced_label_after_return_remains_a_reachable_entry() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(crate::ir::types::VReg::phys("cond")),
                    then_body: vec![Stmt::Goto { target: 0x100 }],
                    else_body: None,
                },
                Stmt::Return { value: None },
                Stmt::Label(0x100),
                Stmt::Return {
                    value: Some(Expr::Const(1)),
                },
            ],
        };

        let expected = f.clone();
        prune_unreachable_tails(&mut f);

        assert_eq!(f, expected, "a live goto keeps its target entry reachable");
    }

    #[test]
    fn block_after_indirect_tail_jump_remains_a_region_entry() {
        // Real `describe_change` contains imported tail-call blocks in the
        // recovered region before the function's conditional fallthrough.
        // The fallthrough label has no explicit Goto after structuring, but it
        // is still the boundary that prevents unreachable-tail cleanup from
        // deleting the rest of the function after the imported IndirectGoto.
        let mut f = Function {
            name: "describe_change".into(),
            entry_va: 0x3630,
            body: vec![
                Stmt::IndirectGoto {
                    target: Expr::Reg(crate::ir::types::VReg::phys("plt_target")),
                },
                Stmt::Label(0x364a),
                Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(7),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(crate::ir::types::VReg::phys("result"))),
                },
            ],
        };

        prune_unreachable_tails(&mut f);

        assert_eq!(
            f.body.len(),
            4,
            "fallthrough region was deleted: {:#?}",
            f.body
        );
        assert!(matches!(f.body[1], Stmt::Label(0x364a)));
        assert!(matches!(f.body[2], Stmt::Assign { .. }));
    }

    #[test]
    fn block_after_recovered_tail_call_return_remains_a_region_entry() {
        // Tail-call recovery turns the indirect PLT jump into Call + Return
        // before label cleanup. `describe_change` therefore reaches this exact
        // spelling when its real fallthrough region follows imported stubs.
        let mut f = Function {
            name: "describe_change".into(),
            entry_va: 0x3630,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2480,
                        name: "free".into(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Return { value: None },
                Stmt::Label(0x364a),
                Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(7),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(crate::ir::types::VReg::phys("result"))),
                },
            ],
        };

        prune_unreachable_tails(&mut f);

        assert_eq!(
            f.body.len(),
            5,
            "fallthrough region was deleted: {:#?}",
            f.body
        );
        assert!(matches!(f.body[2], Stmt::Label(0x364a)));
        assert!(matches!(f.body[3], Stmt::Assign { .. }));
    }
}
