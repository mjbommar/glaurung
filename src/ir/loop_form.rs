//! Recover source-level loop forms from conservative structured AST lowering.
//!
//! The region lowerer must preserve loop-header work until later semantic passes
//! decide whether it can move.  Its safe fallback is therefore
//! `while (1) { pre; if (exit) break; body }`.  Copy propagation can eliminate a
//! pure reload-only `pre`, leaving the exit guard as the literal first statement.
//! At that point no motion or data-flow prediction is required: the guarded
//! infinite loop is exactly equivalent to `while (!exit) { body }`. This needs
//! no induction-variable guess: the guard is already the literal first statement
//! and its arm is exactly one `break`, so no work is moved or discarded.

use std::collections::HashMap;

use crate::ir::ast::{negate_cmp_expr, Expr, Function, Stmt};
use crate::ir::effectful_loop::rotate_effectful_call_headers;
use crate::ir::types::{BinOp, CmpOp, VReg};

/// Recover a linearised tail-tested loop from its exact label/backedge form.
///
/// Conservative structuring can leave a natural loop as
/// `label: body; if (condition) goto label;`.  This is precisely a `do-while`
/// when the label and backedge are uniquely owned, the latch is the only goto
/// to the label, and no label occurs in the body being moved.  Those ownership
/// checks exclude secondary entries and make the rewrite a representation
/// change only: every body statement and the original latch condition remain
/// in their original execution order.
pub fn recover_linear_latched_do_whiles(function: &mut Function) {
    loop {
        let mut labels = HashMap::new();
        let mut gotos = HashMap::new();
        count_control_targets(&function.body, &mut labels, &mut gotos);
        if !recover_one_linear_latch(&mut function.body, &labels, &gotos) {
            break;
        }
    }
}

fn recover_one_linear_latch(
    body: &mut Vec<Stmt>,
    labels: &HashMap<u64, usize>,
    gotos: &HashMap<u64, usize>,
) -> bool {
    for start in 0..body.len() {
        let Stmt::Label(target) = body[start] else {
            continue;
        };
        if labels.get(&target).copied() != Some(1) || gotos.get(&target).copied() != Some(1) {
            continue;
        }

        for latch in start + 1..body.len() {
            if let Some(condition) = tail_latch_condition(&body[latch], target) {
                let loop_body = body[start + 1..latch].to_vec();
                body.splice(
                    start..=latch,
                    [Stmt::DoWhile {
                        body: loop_body,
                        cond: condition,
                    }],
                );
                return true;
            }
            if statement_contains_label(&body[latch])
                || matches!(
                    body[latch],
                    Stmt::Return { .. }
                        | Stmt::Goto { .. }
                        | Stmt::IndirectGoto { .. }
                        | Stmt::Break
                        | Stmt::Throw { .. }
                )
            {
                break;
            }
        }
    }

    for statement in body {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_one_linear_latch(then_body, labels, gotos)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| recover_one_linear_latch(body, labels, gotos))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_one_linear_latch(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| recover_one_linear_latch(body, labels, gotos))
                    || default
                        .as_mut()
                        .is_some_and(|body| recover_one_linear_latch(body, labels, gotos))
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_one_linear_latch(try_body, labels, gotos)
                    || catches
                        .iter_mut()
                        .any(|catch| recover_one_linear_latch(&mut catch.body, labels, gotos))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn tail_latch_condition(statement: &Stmt, target: u64) -> Option<Expr> {
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

fn statement_contains_label(statement: &Stmt) -> bool {
    match statement {
        Stmt::Label(_) => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(statement_contains_label)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(statement_contains_label))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            body.iter().any(statement_contains_label)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(statement_contains_label))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(statement_contains_label))
        }
        Stmt::TryCatch { try_body, catches } => {
            try_body.iter().any(statement_contains_label)
                || catches
                    .iter()
                    .any(|catch| catch.body.iter().any(statement_contains_label))
        }
        _ => false,
    }
}

fn count_control_targets(
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
                count_control_targets(then_body, labels, gotos);
                if let Some(else_body) = else_body {
                    count_control_targets(else_body, labels, gotos);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                count_control_targets(body, labels, gotos)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    count_control_targets(case_body, labels, gotos);
                }
                if let Some(default_body) = default {
                    count_control_targets(default_body, labels, gotos);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                count_control_targets(try_body, labels, gotos);
                for catch in catches {
                    count_control_targets(&catch.body, labels, gotos);
                }
            }
            _ => {}
        }
    }
}

/// Recover exact head-tested loops from their conservative guarded form.
///
/// This pass intentionally does not move, fold, or discard any statement before
/// the guard. If even one statement remains there, the conservative form stays
/// intact.
pub fn recover_head_tested_whiles(f: &mut Function) {
    seed_exit_value_copies(&mut f.body);
    rotate_effectful_call_headers(&mut f.body);
    recover_body(&mut f.body);
}

/// Rotate an exact sentinel-terminated search into its source-level loop.
///
/// Optimised code often shares a null return between an entry guard and the
/// post-advance loop exit, leaving this faithful but inside-out AST:
///
/// ```text
/// if (initial == sentinel) return sentinel;
/// result = initial; current = initial;
/// while (!match(current)) {
///     result = advance(current); current = result;
///     if (result == sentinel) return sentinel;
/// }
/// return result;
/// ```
///
/// The two exact alias assignments prove `result == current` at every loop
/// test.  Moving the sentinel check to the loop head therefore recovers the
/// ordinary `while (current != sentinel) { if (match) return current; ... }`
/// without moving a dereference above its null guard or guessing an induction
/// variable.  Every statement in the matched window is required; any extra
/// effect, different value, casted sentinel, or additional continuation makes
/// the pass fail closed.
pub fn recover_sentinel_search_loops(f: &mut Function) {
    recover_sentinel_search_body(&mut f.body);
}

/// Recover a pre-tested loop after compiler loop rotation.
///
/// `if (initial == sentinel) return result; seeds; do { body; current = latch; }
/// while (latch != sentinel); return result;` is exactly `seeds; while (current
/// != sentinel) { body; } return result` when `current` is seeded from
/// `initial`.  The matched returns must be identical and the latch-to-current
/// copy must be the final loop statement, so the rewrite neither changes the
/// zero-iteration result nor evaluates the body for a sentinel input.
pub fn recover_guarded_do_whiles(f: &mut Function) {
    recover_guarded_do_while_body(&mut f.body);
}

fn recover_guarded_do_while_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                recover_owned_pretested_do_while(cond, then_body, else_body.as_deref());
                recover_guarded_do_while_body(then_body);
                if let Some(else_body) = else_body {
                    recover_guarded_do_while_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_guarded_do_while_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    recover_guarded_do_while_body(case_body);
                }
                if let Some(default_body) = default {
                    recover_guarded_do_while_body(default_body);
                }
            }
            _ => {}
        }
    }

    let mut start = 0;
    while start < body.len() {
        let Some((do_index, current, sentinel)) = guarded_do_while_candidate(body, start) else {
            start += 1;
            continue;
        };
        let Stmt::DoWhile {
            body: loop_body, ..
        } = body.remove(do_index)
        else {
            unreachable!("guarded do-while candidate points at a do-while")
        };
        body.remove(start);
        body.insert(
            do_index - 1,
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(Expr::Reg(current)),
                    rhs: Box::new(sentinel),
                },
                body: loop_body,
            },
        );
        start = do_index;
    }
}

/// Turn an entry-owned rotated loop back into a head-tested loop after phi
/// coalescing has made the seed and latch cursor one value.
///
/// The outer `if` is retained, so no seed moves across the entry guard. The new
/// head test is only an extra check on the taken path, and alias substitution
/// proves it equal to the guard there. Every effect and the latch condition keep
/// their original order inside the loop.
fn recover_owned_pretested_do_while(
    entry_guard: &Expr,
    then_body: &mut [Stmt],
    else_body: Option<&[Stmt]>,
) {
    if else_body.is_some() {
        return;
    }
    let Some((last, prelude)) = then_body.split_last_mut() else {
        return;
    };
    let Stmt::DoWhile {
        body: loop_body,
        cond: latch_guard,
    } = last
    else {
        return;
    };
    let mut aliases = HashMap::<VReg, Expr>::new();
    for statement in prelude {
        match statement {
            Stmt::Nop => {}
            Stmt::Assign { dst, src } if stable_value_expr(src) => {
                aliases.insert(dst.clone(), src.clone());
            }
            _ => return,
        }
    }
    // The aliases execute only after the entry guard. They may prove that the
    // latch guard names the entry value, but they must never rewrite the entry
    // guard itself.
    if resolve_entry_aliases(latch_guard, &aliases, 0) != *entry_guard {
        return;
    }
    *last = Stmt::While {
        cond: latch_guard.clone(),
        body: std::mem::take(loop_body),
    };
}

fn resolve_entry_aliases(expr: &Expr, aliases: &HashMap<VReg, Expr>, depth: usize) -> Expr {
    if depth > aliases.len() {
        return expr.clone();
    }
    match expr {
        Expr::Reg(reg) => aliases.get(reg).map_or_else(
            || expr.clone(),
            |value| resolve_entry_aliases(value, aliases, depth + 1),
        ),
        Expr::Bin { op, lhs, rhs } => Expr::Bin {
            op: *op,
            lhs: Box::new(resolve_entry_aliases(lhs, aliases, depth + 1)),
            rhs: Box::new(resolve_entry_aliases(rhs, aliases, depth + 1)),
        },
        Expr::Cmp { op, lhs, rhs } => Expr::Cmp {
            op: *op,
            lhs: Box::new(resolve_entry_aliases(lhs, aliases, depth + 1)),
            rhs: Box::new(resolve_entry_aliases(rhs, aliases, depth + 1)),
        },
        Expr::Un { op, src } => Expr::Un {
            op: *op,
            src: Box::new(resolve_entry_aliases(src, aliases, depth + 1)),
        },
        Expr::Cast {
            signed,
            width,
            expr,
        } => Expr::Cast {
            signed: *signed,
            width: *width,
            expr: Box::new(resolve_entry_aliases(expr, aliases, depth + 1)),
        },
        _ => expr.clone(),
    }
}

fn guarded_do_while_candidate(body: &[Stmt], start: usize) -> Option<(usize, VReg, Expr)> {
    let Stmt::If {
        cond: entry_guard,
        then_body,
        else_body: None,
    } = body.get(start)?
    else {
        return None;
    };
    let [Stmt::Return {
        value: guard_result,
    }] = then_body.as_slice()
    else {
        return None;
    };
    let (initial, sentinel) = match entry_guard {
        Expr::Cmp {
            op: CmpOp::Eq,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => (lhs.as_ref(), rhs.as_ref()),
        Expr::Cmp {
            op: CmpOp::Eq,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Const(_)) => (rhs.as_ref(), lhs.as_ref()),
        _ => return None,
    };

    let mut cursor = start + 1;
    while let Some(statement) = body.get(cursor) {
        match statement {
            Stmt::Nop => cursor += 1,
            Stmt::Assign { src, .. } if stable_value_expr(src) => cursor += 1,
            Stmt::Assign { .. } => return None,
            _ => break,
        }
    }
    let Stmt::DoWhile {
        body: loop_body,
        cond: latch_guard,
    } = body.get(cursor)?
    else {
        return None;
    };
    let latch = not_equal_other_side(latch_guard, sentinel).and_then(reg_through_casts)?;
    let Stmt::Assign {
        dst: current,
        src: carried_latch,
    } = loop_body.last()?
    else {
        return None;
    };
    let pre_loop = &body[start + 1..cursor];
    let current_seed = pre_loop.iter().rev().find_map(|statement| match statement {
        Stmt::Assign { dst, src } if dst == current => Some(src),
        _ => None,
    });
    let mut result_inputs = Vec::new();
    if let Some(result) = guard_result {
        collect_expr_regs(result, &mut result_inputs);
    }
    if reg_through_casts(carried_latch) != Some(latch)
        || current_seed != Some(initial)
        || pre_loop.iter().any(|statement| {
            result_inputs
                .iter()
                .any(|result_input| writes_reg(statement, result_input))
        })
    {
        return None;
    }

    let return_index = cursor + 1;
    let Stmt::Return {
        value: final_result,
    } = body.get(return_index)?
    else {
        return None;
    };
    if guard_result != final_result
        || body[return_index + 1..]
            .iter()
            .any(|statement| !matches!(statement, Stmt::Nop | Stmt::Comment(_)))
    {
        return None;
    }
    Some((cursor, current.clone(), sentinel.clone()))
}

fn not_equal_other_side<'a>(expr: &'a Expr, expected: &Expr) -> Option<&'a Expr> {
    let Expr::Cmp {
        op: CmpOp::Ne,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    if lhs.as_ref() == expected {
        Some(rhs)
    } else if rhs.as_ref() == expected {
        Some(lhs)
    } else {
        None
    }
}

#[derive(Debug)]
struct SentinelSearch {
    end: usize,
    current: VReg,
    initial: Expr,
    sentinel: Expr,
    match_continue: Expr,
    advance: Expr,
}

fn recover_sentinel_search_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_sentinel_search_body(then_body);
                if let Some(else_body) = else_body {
                    recover_sentinel_search_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_sentinel_search_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    recover_sentinel_search_body(case_body);
                }
                if let Some(default_body) = default {
                    recover_sentinel_search_body(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let Some(candidate) = sentinel_search_candidate(body, index) else {
            index += 1;
            continue;
        };
        let match_cond = negate_cmp_expr(candidate.match_continue);
        let replacement = vec![
            Stmt::Assign {
                dst: candidate.current.clone(),
                src: candidate.initial,
            },
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(Expr::Reg(candidate.current.clone())),
                    rhs: Box::new(candidate.sentinel.clone()),
                },
                body: vec![
                    Stmt::If {
                        cond: match_cond,
                        then_body: vec![Stmt::Return {
                            value: Some(Expr::Reg(candidate.current.clone())),
                        }],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: candidate.current,
                        src: candidate.advance,
                    },
                ],
            },
            Stmt::Return {
                value: Some(candidate.sentinel),
            },
        ];
        body.splice(index..=candidate.end, replacement);
        index += 3;
    }
}

fn sentinel_search_candidate(body: &[Stmt], start: usize) -> Option<SentinelSearch> {
    let Stmt::If {
        cond: initial_guard,
        then_body,
        else_body: None,
    } = body.get(start)?
    else {
        return None;
    };
    let [Stmt::Return {
        value: Some(sentinel),
    }] = then_body.as_slice()
    else {
        return None;
    };
    if !matches!(sentinel, Expr::Const(_)) {
        return None;
    }
    let initial = equality_other_side(initial_guard, sentinel)?.clone();
    if !stable_value_expr(&initial) {
        return None;
    }

    let mut cursor = start + 1;
    let mut seeds: Vec<(&VReg, &Expr)> = Vec::new();
    while let Some(statement) = body.get(cursor) {
        match statement {
            Stmt::Assign { dst, src } if src == &initial => seeds.push((dst, src)),
            Stmt::Nop => {}
            Stmt::While { .. } => break,
            _ => return None,
        }
        cursor += 1;
    }
    if !(1..=2).contains(&seeds.len()) || (seeds.len() == 2 && seeds[0].0 == seeds[1].0) {
        return None;
    }

    let Stmt::While {
        cond: match_continue,
        body: loop_body,
    } = body.get(cursor)?
    else {
        return None;
    };
    let (result, current, advance, exit_body) = match loop_body.as_slice() {
        [Stmt::Assign {
            dst: current,
            src: advance,
        }, Stmt::If {
            cond: exit_guard,
            then_body: exit_body,
            else_body: None,
        }] if seeds.len() == 1 => {
            if seeds[0].0 != current
                || equality_other_side(exit_guard, sentinel).and_then(reg_through_casts)
                    != Some(current)
                || !match_continue.contains_reg(current)
                || !advance.contains_reg(current)
            {
                return None;
            }
            (current, current, advance, exit_body)
        }
        [Stmt::Assign {
            dst: result,
            src: advance,
        }, Stmt::Assign {
            dst: current,
            src: carried_result,
        }, Stmt::If {
            cond: exit_guard,
            then_body: exit_body,
            else_body: None,
        }] if seeds.len() == 2 => {
            if result == current
                || reg_through_casts(carried_result) != Some(result)
                || equality_other_side(exit_guard, sentinel).and_then(reg_through_casts)
                    != Some(result)
                || !seeds.iter().any(|(seed, _)| *seed == result)
                || !seeds.iter().any(|(seed, _)| *seed == current)
                || !match_continue.contains_reg(current)
                || match_continue.contains_reg(result)
                || !advance.contains_reg(current)
                || advance.contains_reg(result)
            {
                return None;
            }
            (result, current, advance, exit_body)
        }
        _ => return None,
    };
    if exit_body.as_slice()
        != [Stmt::Return {
            value: Some(sentinel.clone()),
        }]
    {
        return None;
    }

    let return_index = cursor + 1;
    let Stmt::Return {
        value: Some(returned),
    } = body.get(return_index)?
    else {
        return None;
    };
    if reg_through_casts(returned) != Some(result)
        || body[return_index + 1..]
            .iter()
            .any(|statement| !matches!(statement, Stmt::Nop | Stmt::Comment(_)))
    {
        return None;
    }

    Some(SentinelSearch {
        end: return_index,
        current: current.clone(),
        initial,
        sentinel: sentinel.clone(),
        match_continue: match_continue.clone(),
        advance: advance.clone(),
    })
}

fn equality_other_side<'a>(expr: &'a Expr, expected: &Expr) -> Option<&'a Expr> {
    let Expr::Cmp {
        op: CmpOp::Eq,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    if lhs.as_ref() == expected {
        Some(rhs)
    } else if rhs.as_ref() == expected {
        Some(lhs)
    } else {
        None
    }
}

fn reg_through_casts(mut expr: &Expr) -> Option<&VReg> {
    while let Expr::Cast { expr: inner, .. } = expr {
        expr = inner;
    }
    match expr {
        Expr::Reg(reg) => Some(reg),
        _ => None,
    }
}

/// Move an exact loop-exit value seed before a guarded infinite loop.
///
/// Dead-store elimination must retain `exit = carried` before a conditional
/// break: that copy supplies the value when the loop exits at its first guard.
/// Keeping it inside the body, however, prevents the exact head-test recovery
/// below.  Moving it once before the loop is equivalent when every fall-through
/// backedge unconditionally assigns `carried` and `exit` the same expression.
/// The equality is structural and the proof deliberately rejects a bypass of
/// those tail assignments; this is a narrow value-identity rule, not a general
/// loop-hoisting heuristic.
fn seed_exit_value_copies(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                seed_exit_value_copies(then_body);
                if let Some(body) = else_body {
                    seed_exit_value_copies(body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => seed_exit_value_copies(body),
            Stmt::For { body, .. } => seed_exit_value_copies(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    seed_exit_value_copies(body);
                }
                if let Some(body) = default {
                    seed_exit_value_copies(body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < stmts.len() {
        let Some(seeds) = exit_value_seed_candidate(&stmts[index]) else {
            index += 1;
            continue;
        };
        let seed_count = seeds.len();
        let Stmt::While { body, .. } = &mut stmts[index] else {
            unreachable!("exit-value candidates are always while loops");
        };
        body.drain(..seed_count);
        stmts.splice(index..index, seeds);
        index += seed_count + 1;
    }
}

fn exit_value_seed_candidate(stmt: &Stmt) -> Option<Vec<Stmt>> {
    let Stmt::While {
        cond: Expr::Const(1),
        body,
    } = stmt
    else {
        return None;
    };
    let mut pairs = Vec::new();
    for stmt in body {
        let Stmt::Assign {
            dst: exit_value,
            src: Expr::Reg(carried),
        } = stmt
        else {
            break;
        };
        if exit_value == carried
            || pairs.iter().any(|(other_exit, other_carried)| {
                exit_value == other_exit
                    || exit_value == other_carried
                    || carried == other_exit
                    || carried == other_carried
            })
        {
            return None;
        }
        pairs.push((exit_value.clone(), carried.clone()));
    }
    let seed_count = pairs.len();
    if seed_count == 0 {
        return None;
    }
    let Stmt::If {
        then_body,
        else_body: None,
        ..
    } = body.get(seed_count)?
    else {
        return None;
    };
    if then_body.as_slice() != [Stmt::Break] {
        return None;
    }

    let tail = &body[seed_count + 1..];
    let all_targets: Vec<&VReg> = pairs
        .iter()
        .flat_map(|(exit_value, carried)| [exit_value, carried])
        .collect();
    let mut final_assignment = 0;
    for (exit_value, carried) in &pairs {
        let (carried_index, carried_value) = last_assignment(tail, carried)?;
        let (exit_index, exit_tail_value) = last_assignment(tail, exit_value)?;
        if carried_value != exit_tail_value
            || !stable_value_expr(carried_value)
            || all_targets
                .iter()
                .any(|target| carried_value.contains_reg(target))
        {
            return None;
        }

        // The same RHS must still denote the same value at both assignments.
        // Intervening writes to one of its inputs invalidate the proof even
        // though the expression trees remain textually equal.
        let lo = carried_index.min(exit_index);
        let hi = carried_index.max(exit_index);
        let mut dependencies = Vec::new();
        collect_expr_regs(carried_value, &mut dependencies);
        if tail[lo + 1..hi].iter().any(|stmt| {
            dependencies
                .iter()
                .any(|dependency| writes_reg(stmt, dependency))
        }) || tail[carried_index + 1..]
            .iter()
            .any(|stmt| writes_reg(stmt, carried))
            || tail[exit_index + 1..]
                .iter()
                .any(|stmt| writes_reg(stmt, exit_value))
        {
            return None;
        }
        final_assignment = final_assignment.max(hi);
    }
    if tail[..=final_assignment].iter().any(bypasses_loop_tail) {
        return None;
    }

    Some(body[..seed_count].to_vec())
}

/// Restrict the equality proof to side-effect-free values. In particular, two
/// identical dereferences separated by a store or call are not necessarily the
/// same value, and an opaque expression has no inspectable dependency set.
fn stable_value_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. } | Expr::FunctionTableEntry { .. } | Expr::Unknown(_) => false,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            stable_value_expr(lhs) && stable_value_expr(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => stable_value_expr(cond) && stable_value_expr(if_true) && stable_value_expr(if_false),
        Expr::Un { src, .. } => stable_value_expr(src),
        Expr::Cast { expr, .. } => stable_value_expr(expr),
        Expr::WideArithmetic { op, args, .. } => {
            matches!(
                op,
                crate::ir::ast::WideArithmetic::UnsignedMulHigh
                    | crate::ir::ast::WideArithmetic::SignedMulHigh
            ) && args.iter().all(stable_value_expr)
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
    }
}

fn collect_expr_regs(expr: &Expr, out: &mut Vec<VReg>) {
    match expr {
        Expr::Reg(reg) | Expr::StackAddr { object: reg, .. } => out.push(reg.clone()),
        Expr::Deref { addr, .. } => collect_expr_regs(addr, out),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_expr_regs(lhs, out);
            collect_expr_regs(rhs, out);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_expr_regs(cond, out);
            collect_expr_regs(if_true, out);
            collect_expr_regs(if_false, out);
        }
        Expr::Un { src, .. } => collect_expr_regs(src, out),
        Expr::Cast { expr, .. } => collect_expr_regs(expr, out),
        Expr::FunctionTableEntry { index, .. } => collect_expr_regs(index, out),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                collect_expr_regs(argument, out);
            }
        }
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            out.extend(base.iter().cloned());
            out.extend(index.iter().cloned());
        }
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

fn last_assignment<'a>(body: &'a [Stmt], target: &VReg) -> Option<(usize, &'a Expr)> {
    body.iter()
        .enumerate()
        .rev()
        .find_map(|(index, stmt)| match stmt {
            Stmt::Assign { dst, src } if dst == target => Some((index, src)),
            _ => None,
        })
}

/// Whether a statement can re-enter the current loop without reaching later
/// unconditional tail assignments. Returns leave the function and nested-loop
/// breaks leave only that nested loop, so neither is a bypass of this backedge.
fn bypasses_loop_tail(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Goto { .. } | Stmt::IndirectGoto { .. } | Stmt::Break => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(bypasses_loop_tail)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(bypasses_loop_tail))
        }
        Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => false,
        // A structured switch owns its ordinary `break`, but it can still
        // contain a non-local goto. Keep this proof local instead of trying to
        // distinguish the two kinds of exit here.
        Stmt::Switch { .. } => true,
        Stmt::Assign { .. }
        | Stmt::Store { .. }
        | Stmt::Call { .. }
        | Stmt::Return { .. }
        | Stmt::Push { .. }
        | Stmt::Pop { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => false,
    }
}

fn writes_reg(stmt: &Stmt, target: &VReg) -> bool {
    match stmt {
        Stmt::Assign { dst, .. } => dst == target,
        Stmt::Call { dst, .. } => dst.as_ref() == Some(target),
        Stmt::Pop { target: dst } => dst == target,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(|stmt| writes_reg(stmt, target))
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(|stmt| writes_reg(stmt, target)))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            body.iter().any(|stmt| writes_reg(stmt, target))
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(|stmt| writes_reg(stmt, target)))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(|stmt| writes_reg(stmt, target)))
        }
        _ => false,
    }
}

/// Promote a narrow, structurally exact counted-loop shape to `Stmt::For`.
///
/// The first A3 slice accepts only an adjacent initializer, a head guard (either
/// direct or the conservative `if (exit) break` form), and one unconditional
/// unit-increment tail iterator for the same variable. Returns and structured
/// switches are safe in the body: a return exits the function, and a switch's
/// implicit breaks do not bypass the loop iterator. Bodies containing an explicit
/// loop-level `break`, `goto`, or nested loop remain conservative: until
/// `continue` is represented explicitly, such control can bypass the tail
/// iterator and cannot safely become C `continue` semantics.
pub fn promote_for_loops(f: &mut Function) {
    promote_for_body(&mut f.body);
}

fn promote_for_body(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                promote_for_body(then_body);
                if let Some(body) = else_body {
                    promote_for_body(body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => promote_for_body(body),
            Stmt::For { body, .. } => promote_for_body(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    promote_for_body(body);
                }
                if let Some(body) = default {
                    promote_for_body(body);
                }
            }
            _ => {}
        }
    }

    let mut index = 1;
    while index < stmts.len() {
        let Some(promoted) = for_candidate(&stmts[index - 1], &stmts[index]) else {
            index += 1;
            continue;
        };
        stmts.splice(index - 1..=index, [promoted]);
    }
}

fn for_candidate(init: &Stmt, loop_stmt: &Stmt) -> Option<Stmt> {
    let init_target = assigned_target(init)?;
    let Stmt::While { cond, body } = loop_stmt else {
        return None;
    };

    let (loop_cond, loop_body) = if matches!(cond, Expr::Const(1)) {
        let Stmt::If {
            cond: exit_cond,
            then_body,
            else_body: None,
        } = body.first()?
        else {
            return None;
        };
        if then_body.as_slice() != [Stmt::Break] {
            return None;
        }
        (negate_cmp_expr(exit_cond.clone()), &body[1..])
    } else {
        (cond.clone(), body.as_slice())
    };

    let (step, core_body) = loop_body.split_last()?;
    let step_target = assigned_target(step)?;
    if step_target != init_target
        || !is_unit_increment(step, step_target)
        || !loop_cond.contains_reg(init_target)
        || core_body.iter().any(has_iterator_bypass)
    {
        return None;
    }

    Some(Stmt::For {
        init: Box::new(init.clone()),
        cond: loop_cond,
        step: Box::new(step.clone()),
        body: core_body.to_vec(),
    })
}

fn is_unit_increment(stmt: &Stmt, target: &VReg) -> bool {
    let src = match stmt {
        Stmt::Assign { src, .. } | Stmt::Store { src, .. } => src,
        _ => return false,
    };
    // Width-changing ops are part of the update's machine semantics and remain
    // intact in the `for` step. They should not hide the exact underlying
    // `i + 1` identity from shape recognition.
    fn without_casts(mut expr: &Expr) -> &Expr {
        while let Expr::Cast { expr: inner, .. } = expr {
            expr = inner;
        }
        expr
    }
    let src = without_casts(src);
    matches!(
        src,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } if matches!(without_casts(lhs), Expr::Reg(read) if read == target)
            && matches!(rhs.as_ref(), Expr::Const(1))
    )
}

fn assigned_target(stmt: &Stmt) -> Option<&VReg> {
    match stmt {
        Stmt::Assign { dst, .. } => Some(dst),
        Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            ..
        } if name.starts_with("local_") || name.starts_with("stack_") => Some(dst),
        _ => None,
    }
}

fn has_iterator_bypass(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Goto { .. } | Stmt::Break => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(has_iterator_bypass)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(has_iterator_bypass))
        }
        Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => true,
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(has_iterator_bypass))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(has_iterator_bypass))
        }
        _ => false,
    }
}

fn recover_body(stmts: &mut [Stmt]) {
    for stmt in stmts {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_body(then_body);
                if let Some(body) = else_body {
                    recover_body(body);
                }
            }
            Stmt::While { cond, body } => {
                recover_body(body);

                if !matches!(cond, crate::ir::ast::Expr::Const(1)) {
                    continue;
                }
                let Some(Stmt::If {
                    cond: exit_cond,
                    then_body,
                    else_body: None,
                }) = body.first()
                else {
                    continue;
                };
                if then_body.as_slice() != [Stmt::Break] {
                    continue;
                }
                *cond = negate_cmp_expr(exit_cond.clone());
                body.remove(0);
            }
            Stmt::For { body, .. } => recover_body(body),
            Stmt::DoWhile { body, .. } => recover_body(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    recover_body(body);
                }
                if let Some(body) = default {
                    recover_body(body);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Label(_)
            | Stmt::IndirectGoto { .. }
            | Stmt::Goto { .. }
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CmpOp, VReg};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    #[test]
    fn unique_linear_tail_latch_becomes_a_do_while() {
        let condition = Expr::Cmp {
            op: CmpOp::Ult,
            lhs: Box::new(Expr::Reg(reg("current"))),
            rhs: Box::new(Expr::Reg(reg("limit"))),
        };
        let loop_statement = Stmt::Assign {
            dst: reg("current"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("current"))),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let mut function = Function {
            name: "linear_tail_latch".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("current"),
                    src: Expr::Const(0),
                },
                Stmt::Label(0x1010),
                loop_statement.clone(),
                Stmt::If {
                    cond: condition.clone(),
                    then_body: vec![Stmt::Goto { target: 0x1010 }],
                    else_body: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("current"))),
                },
            ],
        };

        recover_linear_latched_do_whiles(&mut function);

        assert_eq!(
            function.body,
            vec![
                Stmt::Assign {
                    dst: reg("current"),
                    src: Expr::Const(0),
                },
                Stmt::DoWhile {
                    body: vec![loop_statement],
                    cond: condition,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("current"))),
                },
            ]
        );
    }

    #[test]
    fn a_second_entry_to_a_linear_tail_latch_blocks_recovery() {
        let original = vec![
            Stmt::If {
                cond: Expr::Reg(reg("enter_again")),
                then_body: vec![Stmt::Goto { target: 0x1010 }],
                else_body: None,
            },
            Stmt::Label(0x1010),
            Stmt::Nop,
            Stmt::If {
                cond: Expr::Reg(reg("continue_loop")),
                then_body: vec![Stmt::Goto { target: 0x1010 }],
                else_body: None,
            },
        ];
        let mut function = Function {
            name: "multiple_entries".into(),
            entry_va: 0,
            body: original.clone(),
        };

        recover_linear_latched_do_whiles(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn an_internal_label_blocks_linear_tail_latch_recovery() {
        let original = vec![
            Stmt::Label(0x1010),
            Stmt::Assign {
                dst: reg("current"),
                src: Expr::Const(1),
            },
            Stmt::Label(0x1020),
            Stmt::If {
                cond: Expr::Reg(reg("continue_loop")),
                then_body: vec![Stmt::Goto { target: 0x1010 }],
                else_body: None,
            },
        ];
        let mut function = Function {
            name: "internal_entry".into(),
            entry_va: 0,
            body: original.clone(),
        };

        recover_linear_latched_do_whiles(&mut function);

        assert_eq!(function.body, original);
    }

    fn sentinel_search_fixture() -> Function {
        let current = reg("current");
        let result = reg("result");
        let initial = Expr::Reg(reg("arg0"));
        let sentinel = Expr::Const(0);
        let match_continue = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Deref {
                addr: Box::new(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(current.clone())),
                    rhs: Box::new(Expr::Const(8)),
                }),
                size: 4,
            }),
            rhs: Box::new(Expr::Reg(reg("needle"))),
        };
        let advance = Expr::Deref {
            addr: Box::new(Expr::Reg(current.clone())),
            size: 8,
        };
        Function {
            name: "find".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(initial.clone()),
                        rhs: Box::new(sentinel.clone()),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(sentinel.clone()),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: result.clone(),
                    src: initial.clone(),
                },
                Stmt::Nop,
                Stmt::Assign {
                    dst: current.clone(),
                    src: initial,
                },
                Stmt::While {
                    cond: match_continue,
                    body: vec![
                        Stmt::Assign {
                            dst: result.clone(),
                            src: advance,
                        },
                        Stmt::Assign {
                            dst: current,
                            src: Expr::Reg(result.clone()),
                        },
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: CmpOp::Eq,
                                lhs: Box::new(Expr::Reg(result.clone())),
                                rhs: Box::new(sentinel.clone()),
                            },
                            then_body: vec![Stmt::Return {
                                value: Some(sentinel),
                            }],
                            else_body: None,
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result)),
                },
            ],
        }
    }

    #[test]
    fn exact_sentinel_search_rotates_to_a_null_guarded_loop() {
        let mut function = sentinel_search_fixture();

        recover_sentinel_search_loops(&mut function);

        assert_eq!(function.body.len(), 3, "{:#?}", function.body);
        assert!(matches!(
            &function.body[0],
            Stmt::Assign { dst, src: Expr::Reg(initial) }
                if dst == &reg("current") && initial == &reg("arg0")
        ));
        let Stmt::While { cond, body } = &function.body[1] else {
            panic!(
                "sentinel scan did not recover a while: {:#?}",
                function.body
            );
        };
        assert!(matches!(
            cond,
            Expr::Cmp { op: CmpOp::Ne, lhs, rhs }
                if lhs.as_ref() == &Expr::Reg(reg("current"))
                    && rhs.as_ref() == &Expr::Const(0)
        ));
        assert!(matches!(
            body.as_slice(),
            [
                Stmt::If {
                    then_body,
                    else_body: None,
                    ..
                },
                Stmt::Assign { dst, .. }
            ] if then_body == &[Stmt::Return {
                value: Some(Expr::Reg(reg("current")))
            }] && dst == &reg("current")
        ));
        assert_eq!(
            function.body[2],
            Stmt::Return {
                value: Some(Expr::Const(0))
            }
        );
    }

    #[test]
    fn coalesced_sentinel_result_rotates_to_a_null_guarded_loop() {
        let current = reg("current");
        let initial = Expr::Reg(reg("arg0"));
        let sentinel = Expr::Const(0);
        let match_continue = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Deref {
                addr: Box::new(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(current.clone())),
                    rhs: Box::new(Expr::Const(8)),
                }),
                size: 4,
            }),
            rhs: Box::new(Expr::Reg(reg("needle"))),
        };
        let advance = Expr::Deref {
            addr: Box::new(Expr::Reg(current.clone())),
            size: 8,
        };
        let mut function = Function {
            name: "coalesced_find".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(initial.clone()),
                        rhs: Box::new(sentinel.clone()),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(sentinel.clone()),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: current.clone(),
                    src: initial,
                },
                Stmt::While {
                    cond: match_continue,
                    body: vec![
                        Stmt::Assign {
                            dst: current.clone(),
                            src: advance,
                        },
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: CmpOp::Eq,
                                lhs: Box::new(Expr::Reg(current.clone())),
                                rhs: Box::new(sentinel.clone()),
                            },
                            then_body: vec![Stmt::Return {
                                value: Some(sentinel.clone()),
                            }],
                            else_body: None,
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(current.clone())),
                },
            ],
        };

        recover_sentinel_search_loops(&mut function);

        assert_eq!(function.body.len(), 3, "{:#?}", function.body);
        assert!(matches!(
            &function.body[1],
            Stmt::While {
                cond: Expr::Cmp { op: CmpOp::Ne, lhs, rhs },
                body,
            } if lhs.as_ref() == &Expr::Reg(current.clone())
                && rhs.as_ref() == &Expr::Const(0)
                && matches!(body.as_slice(), [Stmt::If { then_body, .. }, Stmt::Assign { dst, .. }]
                    if then_body == &[Stmt::Return { value: Some(Expr::Reg(current.clone())) }]
                        && dst == &current)
        ));
        assert_eq!(
            function.body[2],
            Stmt::Return {
                value: Some(Expr::Const(0)),
            }
        );
    }

    #[test]
    fn extra_effect_in_sentinel_loop_blocks_rotation() {
        let mut function = sentinel_search_fixture();
        let original = function.clone();
        let Stmt::While { body, .. } = &mut function.body[4] else {
            unreachable!()
        };
        body.insert(
            1,
            Stmt::Assign {
                dst: reg("observable"),
                src: Expr::Const(7),
            },
        );

        recover_sentinel_search_loops(&mut function);

        let mut expected = original;
        let Stmt::While { body, .. } = &mut expected.body[4] else {
            unreachable!()
        };
        body.insert(
            1,
            Stmt::Assign {
                dst: reg("observable"),
                src: Expr::Const(7),
            },
        );
        assert_eq!(function, expected);
    }

    fn guarded_do_while_fixture() -> Function {
        Function {
            name: "sum".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("result"),
                    src: Expr::Const(0),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("arg0"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(reg("result"))),
                    }],
                    else_body: None,
                },
                Stmt::Nop,
                Stmt::Assign {
                    dst: reg("current"),
                    src: Expr::Reg(reg("arg0")),
                },
                Stmt::DoWhile {
                    body: vec![
                        Stmt::Assign {
                            dst: reg("result"),
                            src: Expr::Bin {
                                op: BinOp::Add,
                                lhs: Box::new(Expr::Reg(reg("result"))),
                                rhs: Box::new(Expr::Const(1)),
                            },
                        },
                        Stmt::Assign {
                            dst: reg("latch"),
                            src: Expr::Deref {
                                addr: Box::new(Expr::Reg(reg("current"))),
                                size: 8,
                            },
                        },
                        Stmt::Assign {
                            dst: reg("current"),
                            src: Expr::Reg(reg("latch")),
                        },
                    ],
                    cond: Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(reg("latch"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("result"))),
                },
            ],
        }
    }

    #[test]
    fn guarded_do_while_rotates_back_to_pre_tested_while() {
        let mut function = guarded_do_while_fixture();

        recover_guarded_do_whiles(&mut function);

        assert_eq!(function.body.len(), 5, "{:#?}", function.body);
        assert!(!function
            .body
            .iter()
            .any(|statement| matches!(statement, Stmt::If { .. } | Stmt::DoWhile { .. })));
        assert!(matches!(
            &function.body[3],
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs,
                    rhs,
                },
                ..
            } if lhs.as_ref() == &Expr::Reg(reg("current"))
                && rhs.as_ref() == &Expr::Const(0)
        ));
    }

    #[test]
    fn an_entry_owned_coalesced_cursor_recovers_a_head_tested_loop() {
        let guard = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(reg("arg0"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let latch = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(reg("cursor"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let mut function = Function {
            name: "list_sum".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: guard,
                then_body: vec![
                    Stmt::Assign {
                        dst: reg("cursor"),
                        src: Expr::Reg(reg("arg0")),
                    },
                    Stmt::DoWhile {
                        body: vec![Stmt::Assign {
                            dst: reg("cursor"),
                            src: Expr::Deref {
                                addr: Box::new(Expr::Reg(reg("cursor"))),
                                size: 8,
                            },
                        }],
                        cond: latch.clone(),
                    },
                ],
                else_body: None,
            }],
        };

        recover_guarded_do_whiles(&mut function);

        let Stmt::If { then_body, .. } = &function.body[0] else {
            panic!("entry guard was not retained: {function:#?}");
        };
        assert!(matches!(
            &then_body[1],
            Stmt::While { cond, .. } if cond == &latch
        ));
    }

    #[test]
    fn an_entry_guard_overwritten_by_the_prelude_stays_rotated() {
        let entry_guard = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(reg("cursor"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let latch_guard = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(reg("arg0"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let original = Function {
            name: "overwritten_entry_guard".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: entry_guard,
                then_body: vec![
                    Stmt::Assign {
                        dst: reg("cursor"),
                        src: Expr::Reg(reg("arg0")),
                    },
                    Stmt::DoWhile {
                        body: vec![Stmt::Nop],
                        cond: latch_guard,
                    },
                ],
                else_body: None,
            }],
        };
        let mut function = original.clone();

        recover_guarded_do_whiles(&mut function);

        assert_eq!(function, original);
    }

    #[test]
    fn guarded_do_while_with_different_zero_iteration_result_stays_rotated() {
        let mut function = guarded_do_while_fixture();
        let original = function.clone();
        let Stmt::Return { value } = &mut function.body[5] else {
            unreachable!()
        };
        *value = Some(Expr::Const(9));

        recover_guarded_do_whiles(&mut function);

        let mut expected = original;
        let Stmt::Return { value } = &mut expected.body[5] else {
            unreachable!()
        };
        *value = Some(Expr::Const(9));
        assert_eq!(function, expected);
    }

    #[test]
    fn potentially_trapping_seed_keeps_the_entry_guard() {
        let mut function = guarded_do_while_fixture();
        function.body.insert(
            4,
            Stmt::Assign {
                dst: reg("loaded"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Reg(reg("arg0"))),
                    size: 8,
                },
            },
        );
        let expected = function.clone();

        recover_guarded_do_whiles(&mut function);

        assert_eq!(function, expected);
    }

    #[test]
    fn later_current_overwrite_keeps_the_entry_guard() {
        let mut function = guarded_do_while_fixture();
        function.body.insert(
            4,
            Stmt::Assign {
                dst: reg("current"),
                src: Expr::Reg(reg("different")),
            },
        );
        let expected = function.clone();

        recover_guarded_do_whiles(&mut function);

        assert_eq!(function, expected);
    }

    #[test]
    fn zero_iteration_result_overwrite_keeps_the_entry_guard() {
        let mut function = guarded_do_while_fixture();
        function.body.insert(
            4,
            Stmt::Assign {
                dst: reg("result"),
                src: Expr::Const(9),
            },
        );
        let expected = function.clone();

        recover_guarded_do_whiles(&mut function);

        assert_eq!(function, expected);
    }

    #[test]
    fn a_statement_before_the_guard_blocks_promotion() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Assign {
                    dst: reg("t"),
                    src: Expr::Reg(reg("i")),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Sle,
                        lhs: Box::new(Expr::Reg(reg("t"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("i"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("i"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
            ],
        };
        let mut f = Function {
            name: "protected".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn exit_value_copy_is_seeded_before_a_head_tested_loop() {
        // Both GCC's optimized `fib` and the real `sum_until_zero` fixture
        // carry a value to the loop exit with this shape:
        //
        //   while (1) {
        //       exit_value = carried;
        //       if (done) break;
        //       ...
        //       carried = next;
        //       exit_value = next;
        //   }
        //
        // The header copy is live when the first guard exits, so DSE must not
        // delete it.  It also need not block head-test recovery: seeding the
        // copy once before the loop is exact because the tail re-establishes
        // the same value on every fall-through backedge.
        let exit_value = reg("exit_value");
        let carried = reg("carried");
        let next = reg("next");
        let tail_value = Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(Expr::Reg(next.clone())),
        };
        let mut f = Function {
            name: "seeded_head_test".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::Assign {
                        dst: exit_value.clone(),
                        src: Expr::Reg(carried.clone()),
                    },
                    Stmt::If {
                        cond: Expr::Reg(reg("done")),
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: carried.clone(),
                        src: tail_value.clone(),
                    },
                    Stmt::Assign {
                        dst: exit_value.clone(),
                        src: tail_value.clone(),
                    },
                ],
            }],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(
            f.body,
            vec![
                Stmt::Assign {
                    dst: exit_value.clone(),
                    src: Expr::Reg(carried.clone()),
                },
                Stmt::While {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("done"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    body: vec![
                        Stmt::Assign {
                            dst: carried,
                            src: tail_value.clone(),
                        },
                        Stmt::Assign {
                            dst: exit_value,
                            src: tail_value,
                        },
                    ],
                },
            ]
        );
    }

    #[test]
    fn exit_value_copy_group_is_seeded_before_a_head_tested_loop() {
        // Optimized GCC recursion carries several values through each loop
        // header. Their matching backedge writes are interleaved with the
        // rest of the loop-state tuple, so this is the real multi-value shape
        // rather than repeated adjacent pairs.
        let original_loop = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Assign {
                    dst: reg("exit_a"),
                    src: Expr::Reg(reg("carried_a")),
                },
                Stmt::Assign {
                    dst: reg("exit_b"),
                    src: Expr::Reg(reg("carried_b")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("done")),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("carried_a"),
                    src: Expr::Reg(reg("next_a")),
                },
                Stmt::Assign {
                    dst: reg("unrelated"),
                    src: Expr::Const(7),
                },
                Stmt::Assign {
                    dst: reg("carried_b"),
                    src: Expr::Reg(reg("next_b")),
                },
                Stmt::Assign {
                    dst: reg("exit_a"),
                    src: Expr::Reg(reg("next_a")),
                },
                Stmt::Assign {
                    dst: reg("exit_b"),
                    src: Expr::Reg(reg("next_b")),
                },
            ],
        };
        let mut f = Function {
            name: "seeded_head_test_group".into(),
            entry_va: 0,
            body: vec![original_loop],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body.len(), 3);
        assert!(matches!(
            &f.body[0],
            Stmt::Assign { dst, src: Expr::Reg(carried) }
                if dst == &reg("exit_a") && carried == &reg("carried_a")
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign { dst, src: Expr::Reg(carried) }
                if dst == &reg("exit_b") && carried == &reg("carried_b")
        ));
        let Stmt::While { cond, body } = &f.body[2] else {
            panic!("copy group should be followed by the recovered loop");
        };
        assert!(!matches!(cond, Expr::Const(1)));
        assert_eq!(body.len(), 5);
        assert!(matches!(body.first(), Some(Stmt::Assign { dst, .. }) if dst == &reg("carried_a")));
    }

    #[test]
    fn exit_value_copy_stays_in_loop_when_tail_values_differ() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Assign {
                    dst: reg("exit_value"),
                    src: Expr::Reg(reg("carried")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("done")),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("carried"),
                    src: Expr::Reg(reg("next")),
                },
                Stmt::Assign {
                    dst: reg("exit_value"),
                    src: Expr::Reg(reg("different")),
                },
            ],
        };
        let mut f = Function {
            name: "not_seedable".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn exit_value_copy_stays_in_loop_when_tail_reads_a_destination() {
        // The two expressions are structurally equal, but assignment order
        // makes their values differ. After the original backedge, the header
        // copy repairs that difference before testing the guard; hoisting it
        // would expose the second value at loop exit.
        let increment = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("carried"))),
            rhs: Box::new(Expr::Const(1)),
        };
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Assign {
                    dst: reg("exit_value"),
                    src: Expr::Reg(reg("carried")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("done")),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("carried"),
                    src: increment.clone(),
                },
                Stmt::Assign {
                    dst: reg("exit_value"),
                    src: increment,
                },
            ],
        };
        let mut f = Function {
            name: "order_sensitive_tail".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn exit_value_copy_stays_in_loop_when_control_bypasses_the_tail() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Assign {
                    dst: reg("exit_value"),
                    src: Expr::Reg(reg("carried")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("done")),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::If {
                    cond: Expr::Reg(reg("skip_tail")),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("carried"),
                    src: Expr::Reg(reg("next")),
                },
                Stmt::Assign {
                    dst: reg("exit_value"),
                    src: Expr::Reg(reg("next")),
                },
            ],
        };
        let mut f = Function {
            name: "bypassed_tail".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn a_nontrivial_break_arm_blocks_promotion() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("done")),
                then_body: vec![Stmt::Comment("effect".into()), Stmt::Break],
                else_body: None,
            }],
        };
        let mut f = Function {
            name: "protected".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn exact_first_exit_guard_recovers_incrementing_variable_bound_while() {
        let step = Stmt::Assign {
            dst: reg("i"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Sle,
                        lhs: Box::new(Expr::Reg(reg("n"))),
                        rhs: Box::new(Expr::Reg(reg("i"))),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                step.clone(),
            ],
        };
        let mut f = Function {
            name: "later_slice".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("i"))),
                    rhs: Box::new(Expr::Reg(reg("n"))),
                },
                body: vec![step],
            }]
        );
    }

    #[test]
    fn promotes_a_guarded_counted_loop_with_adjacent_initializer() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let work = Stmt::Assign {
            dst: reg("sum"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("sum"))),
                rhs: Box::new(Expr::Reg(induction.clone())),
            },
        };
        let mut f = Function {
            name: "counted".into(),
            entry_va: 0,
            body: vec![
                init.clone(),
                Stmt::While {
                    cond: Expr::Const(1),
                    body: vec![
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: CmpOp::Sle,
                                lhs: Box::new(Expr::Reg(reg("n"))),
                                rhs: Box::new(Expr::Reg(induction.clone())),
                            },
                            then_body: vec![Stmt::Break],
                            else_body: None,
                        },
                        work.clone(),
                        step.clone(),
                    ],
                },
            ],
        };

        promote_for_loops(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::For {
                init: Box::new(init),
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(induction)),
                    rhs: Box::new(Expr::Reg(reg("n"))),
                },
                step: Box::new(step),
                body: vec![work],
            }]
        );
    }

    #[test]
    fn promotes_counted_loop_with_switch_and_early_return() {
        let induction = reg("local_i");
        let init = Stmt::Store {
            addr: Expr::Reg(induction.clone()),
            src: Expr::Const(0),
            size: 4,
        };
        let step = Stmt::Store {
            addr: Expr::Reg(induction.clone()),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
            size: 4,
        };
        let switch = Stmt::Switch {
            discriminant: Expr::Reg(reg("state")),
            cases: vec![
                (Some(0), vec![Stmt::Nop]),
                (
                    Some(1),
                    vec![Stmt::Return {
                        value: Some(Expr::Const(1)),
                    }],
                ),
            ],
            default: None,
        };
        let condition = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(induction.clone())),
            rhs: Box::new(Expr::Reg(reg("n"))),
        };
        let mut function = Function {
            name: "fsm".to_string(),
            entry_va: 0,
            body: vec![
                init.clone(),
                Stmt::While {
                    cond: condition.clone(),
                    body: vec![switch.clone(), step.clone()],
                },
            ],
        };

        promote_for_loops(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::For {
                init: Box::new(init),
                cond: condition,
                step: Box::new(step),
                body: vec![switch],
            }]
        );
    }

    #[test]
    fn explicit_width_casts_do_not_hide_a_unit_increment() {
        let induction = reg("local_i");
        let step = Stmt::Store {
            addr: Expr::Reg(induction.clone()),
            src: Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(induction.clone())),
                        rhs: Box::new(Expr::Const(1)),
                    }),
                }),
            },
            size: 4,
        };

        assert!(is_unit_increment(&step, &induction));
    }

    #[test]
    fn operand_width_casts_do_not_hide_a_unit_increment() {
        let induction = reg("local_i");
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(induction.clone())),
                    }),
                }),
                rhs: Box::new(Expr::Const(1)),
            },
        };

        assert!(is_unit_increment(&step, &induction));
    }

    #[test]
    fn a_memory_store_is_not_an_induction_variable_assignment() {
        let pointer = reg("ptr");
        let init = Stmt::Store {
            addr: Expr::Reg(pointer.clone()),
            src: Expr::Const(0),
            size: 4,
        };
        let step = Stmt::Store {
            addr: Expr::Reg(pointer.clone()),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(pointer.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
            size: 4,
        };
        let original_loop = Stmt::While {
            cond: Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Reg(pointer)),
                rhs: Box::new(Expr::Reg(reg("end"))),
            },
            body: vec![step],
        };
        let mut f = Function {
            name: "memory_store".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop.clone()],
        };

        promote_for_loops(&mut f);

        assert_eq!(f.body, vec![init, original_loop]);
    }

    #[test]
    fn a_body_goto_that_can_bypass_the_iterator_blocks_promotion() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let original_loop = Stmt::While {
            cond: Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Reg(induction)),
                rhs: Box::new(Expr::Reg(reg("n"))),
            },
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(reg("skip")),
                    then_body: vec![Stmt::Goto { target: 0x1000 }],
                    else_body: None,
                },
                step,
            ],
        };
        let mut f = Function {
            name: "continue_like_goto".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop.clone()],
        };

        promote_for_loops(&mut f);

        assert_eq!(f.body, vec![init, original_loop]);
    }

    #[test]
    fn a_decrementing_source_while_stays_a_while_in_the_first_a3_slice() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(10),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let original_loop = Stmt::While {
            cond: Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Const(0)),
                rhs: Box::new(Expr::Reg(induction)),
            },
            body: vec![step],
        };
        let mut f = Function {
            name: "source_while".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop.clone()],
        };

        promote_for_loops(&mut f);

        assert_eq!(f.body, vec![init, original_loop]);
    }

    #[test]
    fn right_handed_accumulator_does_not_block_exact_for_recovery() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let cond = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(induction.clone())),
            rhs: Box::new(Expr::Reg(reg("n"))),
        };
        let update = Stmt::Assign {
            dst: reg("sum"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction)),
                rhs: Box::new(Expr::Reg(reg("sum"))),
            },
        };
        let original_loop = Stmt::While {
            cond: cond.clone(),
            body: vec![update.clone(), step.clone()],
        };
        let mut f = Function {
            name: "right_handed".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop],
        };
        promote_for_loops(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::For {
                init: Box::new(init),
                cond,
                step: Box::new(step),
                body: vec![update],
            }]
        );
    }
}
