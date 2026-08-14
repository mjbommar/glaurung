//! Recover loop-latch predicates obscured by a carried-value update.
//!
//! A compiler commonly preserves the old carried value, computes the next
//! value and its continuation predicate, then installs the next value:
//!
//! ```text
//! old = current;
//! next = ...;
//! keep_going = next < current;
//! current = next;
//! } while (keep_going);
//! ```
//!
//! The source condition is `next < old`.  This module owns the deliberately
//! narrow proof and rewrite so loop recovery does not leak into the renderer.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Fold proven latch predicate temporaries into their owning do-while.
pub(crate) fn fold_latched_predicates(function: &mut Function) {
    fold_body(&mut function.body);
}

/// Coalesce a dead source identity with the loop carrier it initializes.
pub(crate) fn coalesce_loop_entry_copies(
    function: &mut Function,
    protected: &std::collections::HashSet<String>,
    types: &mut crate::ir::types_recover::TypeMap,
) {
    // Lexical nesting is not a region boundary when a goto can enter a sibling
    // body or an indirect transfer can target any surviving label. A recursive
    // local scan would otherwise rewrite the destination before seeing the
    // incoming edge. Stay fail closed until this query is backed by a real CFG
    // reaching-definitions oracle.
    if function.body.iter().any(statement_contains_goto) {
        return;
    }
    coalesce_body(&mut function.body, protected, types);
}

/// Fold a typed machine scratch used only to install the next value of a
/// debug-proven source loop variable.
///
/// Optimized code often spells `i++` as `next = i + 1; ...; i = next`, with
/// both values occupying different SSA roles in the same physical register.
/// Once DWARF has established `i` as the source object, keeping `next` as a
/// second C object can widen the update and materially change recompilation.
/// This deliberately handles only a closed, top-level structured loop with one
/// dominating scratch definition, identical semantic types, no later use of
/// the scratch, and no read of the old carrier after that definition.
pub(crate) fn coalesce_source_loop_updates(
    function: &mut Function,
    protected: &std::collections::HashSet<String>,
    types: &crate::ir::types_recover::TypeMap,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
) {
    let mut index = 0;
    while index < function.body.len() {
        let candidate = source_loop_update_candidate(
            &function.body[index],
            &function.body[index + 1..],
            protected,
            types,
            exact_value_widths,
        );
        if let Some((definition, carrier, scratch)) = candidate {
            let (loop_body, condition) = match &mut function.body[index] {
                Stmt::While { body, cond } | Stmt::DoWhile { body, cond } => (body, cond),
                _ => unreachable!("candidate only accepts while-like loops"),
            };
            let tail = loop_body.len() - 1;
            for statement in &mut loop_body[definition..tail] {
                replace_statement_register(statement, &scratch, &carrier);
            }
            replace_register(condition, &scratch, &carrier);
            loop_body.pop();
        }
        index += 1;
    }
}

fn source_loop_update_candidate(
    statement: &Stmt,
    suffix: &[Stmt],
    protected: &std::collections::HashSet<String>,
    types: &crate::ir::types_recover::TypeMap,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
) -> Option<(usize, VReg, VReg)> {
    let (body, condition) = match statement {
        Stmt::While { body, cond } | Stmt::DoWhile { body, cond } => (body, cond),
        _ => return None,
    };
    let (carrier, scratch) = match body.last()? {
        Stmt::Assign {
            dst,
            src: Expr::Reg(source),
        } if dst != source => (dst.clone(), source.clone()),
        _ => return None,
    };
    let compatible_type = types.get(&carrier) == types.get(&scratch)
        || matches!(
            (types.get(&carrier), types.get(&scratch), &scratch),
            (
                Some(crate::ir::types_recover::TypeHint::Int {
                    signed: carrier_signed,
                    width: carrier_width,
                }),
                Some(crate::ir::types_recover::TypeHint::Int {
                    signed: scratch_signed,
                    ..
                }),
                VReg::Phys(scratch_name),
            ) if carrier_signed == scratch_signed
                && exact_value_widths
                    .and_then(|widths| widths.get(scratch_name))
                    .copied()
                    == Some(carrier_width)
        );
    if !protected_register(&carrier, protected)
        || protected_register(&scratch, protected)
        || crate::ir::ast::parse_arg_index(match &scratch {
            VReg::Phys(name) => name,
            _ => return None,
        })
        .is_some()
        || types.get(&carrier).is_none()
        || !compatible_type
        || suffix
            .iter()
            .any(|statement| statement_mentions(statement, &scratch))
    {
        return None;
    }

    let tail = body.len() - 1;
    let definitions = body[..tail]
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| top_level_defines(statement, &scratch).then_some(index))
        .collect::<Vec<_>>();
    let [definition] = definitions.as_slice() else {
        return None;
    };
    let Stmt::Assign { src, .. } = &body[*definition] else {
        return None;
    };
    if !expression_reads(src, &carrier)
        || expression_reads(src, &scratch)
        || body[..*definition]
            .iter()
            .any(|statement| statement_mentions(statement, &scratch))
        || body[*definition + 1..tail]
            .iter()
            .any(|statement| statement_mentions(statement, &carrier))
        || body[*definition..tail]
            .iter()
            .any(|statement| !straight_line_update_statement(statement))
        || (!expression_reads(condition, &scratch)
            && !body[*definition..tail]
                .iter()
                .any(|statement| statement_mentions(statement, &scratch)))
    {
        return None;
    }
    Some((*definition, carrier, scratch))
}

fn straight_line_update_statement(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Nop
            | Stmt::Comment(_)
    )
}

fn coalesce_body(
    body: &mut Vec<Stmt>,
    protected: &std::collections::HashSet<String>,
    types: &mut crate::ir::types_recover::TypeMap,
) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                coalesce_body(then_body, protected, types);
                if let Some(else_body) = else_body {
                    coalesce_body(else_body, protected, types);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                coalesce_body(body, protected, types)
            }
            Stmt::For { body, .. } => coalesce_body(body, protected, types),
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    coalesce_body(case_body, protected, types);
                }
                if let Some(default_body) = default {
                    coalesce_body(default_body, protected, types);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                coalesce_body(try_body, protected, types);
                for catch in catches {
                    coalesce_body(&mut catch.body, protected, types);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index + 1 < body.len() {
        let candidate = match (&body[index], &body[index + 1]) {
            (
                Stmt::Assign {
                    dst,
                    src: Expr::Reg(source),
                },
                loop_statement @ (Stmt::While { .. } | Stmt::DoWhile { .. }),
            ) if coalescible_value_role(dst)
                && coalescible_value_role(source)
                && dst != source
                // Rename the dead seed prefix into a fresh carrier, rather
                // than renaming the carrier's suffix into the seed. The latter
                // is unsound across an outer backedge because the carrier can
                // be live on the next iteration even when a lexical suffix
                // scan says otherwise.
                && types.get(source).is_some()
                && types
                    .get(dst)
                    .map_or(true, |destination| Some(destination) == types.get(source))
                && !protected_register(dst, protected)
                && !protected_register(source, protected)
                && statement_mentions(loop_statement, dst)
                && body[..index]
                    .iter()
                    .any(|statement| top_level_defines(statement, source))
                && !body[..index]
                    .iter()
                    .any(|statement| statement_mentions(statement, dst))
                && !body.iter().any(statement_contains_goto)
                && !body[index + 1..]
                    .iter()
                    .any(|statement| statement_mentions(statement, source)) =>
            {
                Some((
                    dst.clone(),
                    source.clone(),
                    types
                        .get(source)
                        .expect("candidate requires a source type")
                        .clone(),
                ))
            }
            _ => None,
        };
        let Some((carrier, seed, seed_type)) = candidate else {
            index += 1;
            continue;
        };

        for statement in &mut body[..index] {
            replace_statement_register(statement, &seed, &carrier);
        }
        if types.get(&carrier).is_none() {
            types.upsert_public(carrier, seed_type);
        }
        body.remove(index);
    }
}

fn top_level_defines(statement: &Stmt, target: &VReg) -> bool {
    matches!(statement, Stmt::Assign { dst, .. } if dst == target)
        || matches!(statement, Stmt::Call { dst: Some(dst), .. } if dst == target)
        || matches!(statement, Stmt::Pop { target: dst } if dst == target)
}

fn statement_contains_goto(statement: &Stmt) -> bool {
    match statement {
        Stmt::Goto { .. } => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(statement_contains_goto)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(statement_contains_goto))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            body.iter().any(statement_contains_goto)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(statement_contains_goto))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(statement_contains_goto))
        }
        Stmt::TryCatch { try_body, catches } => {
            try_body.iter().any(statement_contains_goto)
                || catches
                    .iter()
                    .any(|catch| catch.body.iter().any(statement_contains_goto))
        }
        Stmt::IndirectGoto { .. } => true,
        Stmt::Assign { .. }
        | Stmt::Store { .. }
        | Stmt::Call { .. }
        | Stmt::Return { .. }
        | Stmt::Throw { .. }
        | Stmt::Push { .. }
        | Stmt::Pop { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => false,
    }
}

fn coalescible_value_role(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if name.strip_prefix("var").is_some_and(|tail| !tail.is_empty() && tail.chars().all(|ch| ch.is_ascii_digit())))
}

fn protected_register(register: &VReg, protected: &std::collections::HashSet<String>) -> bool {
    matches!(register, VReg::Phys(name) if protected.contains(name))
}

fn statement_mentions(statement: &Stmt, target: &VReg) -> bool {
    match statement {
        Stmt::Assign { dst, src } => dst == target || expression_reads(src, target),
        Stmt::Store { addr, src, .. } => {
            expression_reads(addr, target) || expression_reads(src, target)
        }
        Stmt::Call {
            target: callee,
            args,
            dst,
            ..
        } => {
            dst.as_ref() == Some(target)
                || expression_reads(callee, target)
                || args
                    .iter()
                    .any(|argument| expression_reads(argument, target))
        }
        Stmt::Return { value } => value
            .as_ref()
            .is_some_and(|value| expression_reads(value, target)),
        Stmt::Throw { value } | Stmt::Push { value } => expression_reads(value, target),
        Stmt::TryCatch { try_body, catches } => {
            try_body
                .iter()
                .any(|statement| statement_mentions(statement, target))
                || catches.iter().any(|catch| {
                    catch.binding == *target
                        || catch
                            .body
                            .iter()
                            .any(|statement| statement_mentions(statement, target))
                })
        }
        Stmt::IndirectGoto { target: value } => expression_reads(value, target),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expression_reads(cond, target)
                || then_body
                    .iter()
                    .any(|statement| statement_mentions(statement, target))
                || else_body.as_ref().is_some_and(|body| {
                    body.iter()
                        .any(|statement| statement_mentions(statement, target))
                })
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            expression_reads(cond, target)
                || body
                    .iter()
                    .any(|statement| statement_mentions(statement, target))
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            statement_mentions(init, target)
                || expression_reads(cond, target)
                || statement_mentions(step, target)
                || body
                    .iter()
                    .any(|statement| statement_mentions(statement, target))
        }
        Stmt::Pop {
            target: destination,
        } => destination == target,
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            expression_reads(discriminant, target)
                || cases.iter().any(|(_, body)| {
                    body.iter()
                        .any(|statement| statement_mentions(statement, target))
                })
                || default.as_ref().is_some_and(|body| {
                    body.iter()
                        .any(|statement| statement_mentions(statement, target))
                })
        }
        Stmt::Label(_)
        | Stmt::Goto { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => false,
    }
}

fn replace_statement_register(statement: &mut Stmt, target: &VReg, replacement: &VReg) {
    let replace_vreg = |register: &mut VReg| {
        if register == target {
            *register = replacement.clone();
        }
    };
    match statement {
        Stmt::Assign { dst, src } => {
            replace_vreg(dst);
            replace_register(src, target, replacement);
        }
        Stmt::Store { addr, src, .. } => {
            replace_register(addr, target, replacement);
            replace_register(src, target, replacement);
        }
        Stmt::Call {
            target: callee,
            args,
            dst,
            ..
        } => {
            replace_register(callee, target, replacement);
            for argument in args {
                replace_register(argument, target, replacement);
            }
            if let Some(dst) = dst {
                replace_vreg(dst);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value {
                replace_register(value, target, replacement);
            }
        }
        Stmt::Throw { value } | Stmt::Push { value } => {
            replace_register(value, target, replacement)
        }
        Stmt::TryCatch { try_body, catches } => {
            for statement in try_body {
                replace_statement_register(statement, target, replacement);
            }
            for catch in catches {
                replace_vreg(&mut catch.binding);
                for statement in &mut catch.body {
                    replace_statement_register(statement, target, replacement);
                }
            }
        }
        Stmt::IndirectGoto { target: value } => replace_register(value, target, replacement),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            replace_register(cond, target, replacement);
            for statement in then_body {
                replace_statement_register(statement, target, replacement);
            }
            if let Some(else_body) = else_body {
                for statement in else_body {
                    replace_statement_register(statement, target, replacement);
                }
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            replace_register(cond, target, replacement);
            for statement in body {
                replace_statement_register(statement, target, replacement);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            replace_statement_register(init, target, replacement);
            replace_register(cond, target, replacement);
            replace_statement_register(step, target, replacement);
            for statement in body {
                replace_statement_register(statement, target, replacement);
            }
        }
        Stmt::Pop {
            target: destination,
        } => replace_vreg(destination),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            replace_register(discriminant, target, replacement);
            for (_, body) in cases {
                for statement in body {
                    replace_statement_register(statement, target, replacement);
                }
            }
            if let Some(body) = default {
                for statement in body {
                    replace_statement_register(statement, target, replacement);
                }
            }
        }
        Stmt::Label(_)
        | Stmt::Goto { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

fn fold_body(body: &mut [Stmt]) {
    for statement in body {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_body(then_body);
                if let Some(else_body) = else_body {
                    fold_body(else_body);
                }
            }
            Stmt::While { body, .. } => fold_body(body),
            Stmt::For {
                init, step, body, ..
            } => {
                fold_body(std::slice::from_mut(init.as_mut()));
                fold_body(body);
                fold_body(std::slice::from_mut(step.as_mut()));
            }
            Stmt::DoWhile { body, cond } => {
                fold_body(body);
                fold_one_latch(body, cond);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_body(case_body);
                }
                if let Some(default_body) = default {
                    fold_body(default_body);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                fold_body(try_body);
                for catch in catches {
                    fold_body(&mut catch.body);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Throw { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Push { .. }
            | Stmt::Pop { .. } => {}
        }
    }
}

fn fold_one_latch(body: &mut Vec<Stmt>, cond: &mut Expr) {
    let Expr::Reg(predicate) = cond else {
        return;
    };
    let Some((tail, prefix)) = body.split_last() else {
        return;
    };
    let Stmt::Assign {
        dst: carried,
        src: next_value,
    } = tail
    else {
        return;
    };
    let Some((predicate_statement, before_predicate)) = prefix.split_last() else {
        return;
    };
    let Stmt::Assign {
        dst: predicate_destination,
        src: predicate_expression,
    } = predicate_statement
    else {
        return;
    };
    if predicate_destination != predicate
        || predicate == carried
        || !expression_reads(predicate_expression, carried)
        || expression_reads(next_value, predicate)
    {
        return;
    }

    // Keep this proof intentionally straight-line. A branch, nested loop, call,
    // store or unstructured transfer can invalidate either dominance of the
    // snapshot or the absence of an observer between predicate evaluation and
    // installing the next value.
    if !before_predicate
        .iter()
        .all(|statement| matches!(statement, Stmt::Assign { .. } | Stmt::Comment(_)))
    {
        return;
    }

    let snapshots: Vec<(usize, &VReg)> = before_predicate
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| match statement {
            Stmt::Assign {
                dst,
                src: Expr::Reg(source),
            } if source == carried && dst != carried => Some((index, dst)),
            _ => None,
        })
        .collect();
    let [(snapshot_index, saved)] = snapshots.as_slice() else {
        return;
    };
    if *saved == predicate || *saved == next_value_root(next_value).unwrap_or(carried) {
        return;
    }

    let after_snapshot = &before_predicate[snapshot_index + 1..];
    if after_snapshot
        .iter()
        .any(|statement| statement_writes(statement, carried) || statement_writes(statement, saved))
        || before_predicate
            .iter()
            .any(|statement| statement_writes(statement, predicate))
        || before_predicate
            .iter()
            .any(|statement| statement_reads(statement, predicate))
    {
        return;
    }

    let mut rewritten = predicate_expression.clone();
    replace_register(&mut rewritten, carried, saved);
    if expression_reads(&rewritten, carried) {
        return;
    }
    *cond = rewritten;
    body.remove(body.len() - 2);
}

fn next_value_root(expression: &Expr) -> Option<&VReg> {
    match expression {
        Expr::Reg(register) => Some(register),
        Expr::Cast { expr, .. } => next_value_root(expr),
        _ => None,
    }
}

fn statement_writes(statement: &Stmt, target: &VReg) -> bool {
    matches!(statement, Stmt::Assign { dst, .. } if dst == target)
        || matches!(statement, Stmt::Pop { target: dst } if dst == target)
        || matches!(statement, Stmt::Call { dst: Some(dst), .. } if dst == target)
}

fn statement_reads(statement: &Stmt, target: &VReg) -> bool {
    match statement {
        Stmt::Assign { src, .. } => expression_reads(src, target),
        Stmt::Comment(_) => false,
        _ => true,
    }
}

fn expression_reads(expression: &Expr, target: &VReg) -> bool {
    match expression {
        Expr::Reg(register)
        | Expr::StackAddr {
            object: register, ..
        } => register == target,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref() == Some(target) || index.as_ref() == Some(target)
        }
        Expr::Deref { addr, .. } => expression_reads(addr, target),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            expression_reads(call_target, target)
                || args
                    .iter()
                    .any(|argument| expression_reads(argument, target))
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expression_reads(lhs, target) || expression_reads(rhs, target)
        }
        Expr::Un { src, .. } => expression_reads(src, target),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expression_reads(cond, target)
                || expression_reads(if_true, target)
                || expression_reads(if_false, target)
        }
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|argument| expression_reads(argument, target)),
        Expr::Cast { expr, .. }
        | Expr::NumericConvert { expr, .. }
        | Expr::FunctionTableEntry { index: expr, .. } => expression_reads(expr, target),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn replace_register(expression: &mut Expr, target: &VReg, replacement: &VReg) {
    match expression {
        Expr::Reg(register)
        | Expr::StackAddr {
            object: register, ..
        } => {
            if register == target {
                *register = replacement.clone();
            }
        }
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            for register in [base, index].into_iter().flatten() {
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
        Expr::Un { src, .. } => replace_register(src, target, replacement),
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
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                replace_register(argument, target, replacement);
            }
        }
        Expr::Cast { expr, .. }
        | Expr::NumericConvert { expr, .. }
        | Expr::FunctionTableEntry { index: expr, .. } => {
            replace_register(expr, target, replacement);
        }
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

#[cfg(test)]
#[path = "latch_predicate_tests.rs"]
mod tests;
