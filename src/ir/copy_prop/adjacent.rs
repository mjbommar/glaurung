//! Move one expression into its immediately adjacent sole consumer.
//!
//! Five of this module's public entry points live here, and they are one owner
//! rather than five: each proves the *same* local def-use fact and performs the
//! *same* edit. The fact is "this definition's value is consumed exactly once,
//! by the next non-comment statement, and by nothing else that can still run";
//! the edit is "substitute the expression there and delete the definition".
//!
//! # Why this is not the general copy environment
//!
//! [`super::env`] records a value and *replays* it at later uses, leaving the
//! definition alone. That is unsound for anything whose evaluation must happen
//! exactly once (a call would be invoked twice) and unavailable for anything
//! whose destination is not globally SSA (a promoted stack local is a mutable C
//! variable; a physical role name is reused across a function). Deleting the
//! definition in the same step is what buys those cases: the expression's
//! evaluation point crosses no observable statement, so it happens exactly once,
//! at the same place, and no global SSA claim is needed.
//!
//! Each entry point is one such shape:
//!
//! * [`propagate_adjacent_promoted_values`] / the typed variant -- a promoted
//!   stack temporary. `Store { addr: Reg(local_*), .. }` is ambiguous between a
//!   frame-slot assignment and a real write through a pointer held in the slot,
//!   so the untyped pass rejects every store and the typed one accepts only a
//!   destination type recovery has proven scalar.
//! * [`propagate_adjacent_guard_values`] -- a physical scratch consumed by the
//!   `if` that immediately follows it, when that guard is its only reader in the
//!   whole function (the whole-function count is what stops a loop-carried
//!   definition that also reaches a read after the loop).
//! * [`propagate_adjacent_overwritten_values`] -- `result = predicate; result =
//!   table[result];`, where the second assignment both consumes and overwrites
//!   the first.
//! * [`move_adjacent_effectful_scratch_values`] -- the one case where the value
//!   contains a call, and therefore the ONLY safe form: move it, never copy it.
//!
//! A new adjacent shape, or a new restriction on moving an expression past a
//! statement, changes this file. Changing an invalidation rule does not.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::is_promoted_local_reg;
use crate::ir::types_recover::{TypeHint, TypeMap};

use super::alias::{
    contains_deref, contains_reg, contains_select, contains_unknown, is_scratch_reg,
};
use super::env::Copies;
use super::hash::RegMap;
use super::reads::{count_reads_body, count_reads_stmt, count_reg_uses};
use super::subst::subst;

/// Inline an adjacent, one-use promoted-stack value temporary represented as
/// an explicit assignment.
///
/// Promoted locals are mutable variables rather than SSA values, so the general
/// copy environment must not carry them into a loop condition or across a
/// control-flow edge. This deliberately narrower transform accepts only:
///
/// `local_tmp = narrow_value; <next linear statement reads local_tmp once>`
///
/// `Store { addr: Reg(local_*), .. }` is deliberately excluded. Stack promotion
/// historically overloaded that shape for both a frame-slot assignment and a
/// real write through a pointer held in the slot; local adjacency cannot prove
/// which meaning applies. Ambiguous stores remain explicit until stack storage
/// carries a distinct assignment representation.
pub fn propagate_adjacent_promoted_values(f: &mut Function) {
    loop {
        if !fold_one_adjacent_promoted_value(&mut f.body, None) {
            break;
        }
    }
}

/// Inline adjacent promoted-stack stores only when recovered source types prove
/// that the destination is scalar storage rather than a pointer value.
///
/// Stack promotion retains `Store { addr: Reg(local_*), .. }` for both a frame
/// slot assignment and a genuine write through a pointer loaded from that slot.
/// The untyped pass above therefore rejects every store. Once type recovery has
/// classified the rendered local as an integer or boolean, pointer and code-
/// pointer interpretations are excluded and the same local def/use proof is
/// safe. Unknown, float, pointer, and code-pointer destinations remain explicit.
pub fn propagate_adjacent_typed_promoted_values(f: &mut Function, types: &TypeMap) {
    loop {
        if !fold_one_adjacent_promoted_value(&mut f.body, Some(types)) {
            break;
        }
    }
}

/// Inline a physical/scratch value definition into its immediately following,
/// sole eager guard use.
///
/// Explicit machine-width lifting can produce
/// `ret = zext(load); if ((ret & mask) == 0) break;`. The physical role name is
/// not globally SSA, so ordinary counted propagation correctly refuses it. This
/// local def-use proof needs no global SSA claim: only comments may intervene,
/// the guard is the value's sole read in the whole function, neither arm nor the
/// remaining linear body reads it, and no conditional [`Expr::Select`] can defer
/// the moved load. The whole-function count matters for loop-carried values: a
/// guard definition may also reach a read after the loop. Under these constraints
/// the expression stays at the same observable evaluation point while the
/// loop-form pass gets the source-level guard back.
pub fn propagate_adjacent_guard_values(f: &mut Function) {
    loop {
        let mut reads = RegMap::default();
        count_reads_body(&f.body, &mut reads);
        if !fold_one_adjacent_guard_value(&mut f.body, &reads) {
            break;
        }
    }
}

/// Inline a pure value into the immediately following assignment that both
/// consumes and overwrites it.
///
/// Optimised conditional indexing commonly becomes `result = predicate;
/// result = table[result];`. The first value has exactly one observable use:
/// the second assignment's right-hand side, after which the same destination
/// is overwritten. Moving a nontrapping, nonselect expression into that RHS is
/// exact and does not rely on the physical register being globally SSA.
pub fn propagate_adjacent_overwritten_values(function: &mut Function) {
    while fold_one_adjacent_overwritten_value(&mut function.body) {}
}

/// Move one effectful scratch value into its sole adjacent direct consumer.
///
/// An [`Expr::Call`] must never be copied: evaluating two structurally equal
/// call expressions still invokes the callee twice. Late source-shape recovery
/// can leave `scratch = lazy_call; local = scratch` after the ordinary copy
/// fixpoint. When the scratch has exactly one whole-function read and only
/// comments separate that direct read from its definition, moving the
/// expression is exact: its evaluation point crosses no observable statement,
/// and removing the definition keeps the call count at one.
pub fn move_adjacent_effectful_scratch_values(function: &mut Function) {
    loop {
        let mut reads = RegMap::default();
        count_reads_body(&function.body, &mut reads);
        if !move_one_adjacent_effectful_scratch_value(&mut function.body, &reads) {
            break;
        }
    }
}

fn move_one_adjacent_effectful_scratch_value(body: &mut Vec<Stmt>, reads: &RegMap<usize>) -> bool {
    for index in 0..body.len().saturating_sub(1) {
        let Some((destination, source)) = (match &body[index] {
            Stmt::Assign { dst, src }
                if is_scratch_reg(dst)
                    && !is_promoted_local_reg(dst)
                    && src.contains_call()
                    && !contains_reg(src, dst)
                    && reads.get(dst).copied() == Some(1) =>
            {
                Some((dst.clone(), src.clone()))
            }
            _ => None,
        }) else {
            continue;
        };
        let Some(consumer_index) = (index + 1..body.len())
            .find(|next| !matches!(body[*next], Stmt::Comment(_) | Stmt::Nop))
        else {
            continue;
        };
        let consumed = match &mut body[consumer_index] {
            Stmt::Assign { src, .. } => {
                if !matches!(&*src, Expr::Reg(register) if register == &destination) {
                    false
                } else {
                    *src = source;
                    true
                }
            }
            // A bare promoted-local address denotes the recovered stack object
            // itself, not an indirect pointer evaluation. Moving into a
            // general Store would be unsound: C does not sequence evaluation
            // of the store address and source expression.
            Stmt::Store {
                addr: Expr::Reg(address),
                src,
                ..
            } if is_promoted_local_reg(address) => {
                if !matches!(&*src, Expr::Reg(register) if register == &destination) {
                    false
                } else {
                    *src = source;
                    true
                }
            }
            _ => false,
        };
        if consumed {
            body.remove(index);
            return true;
        }
    }

    for statement in body {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                move_one_adjacent_effectful_scratch_value(then_body, reads)
                    || else_body.as_mut().is_some_and(|else_body| {
                        move_one_adjacent_effectful_scratch_value(else_body, reads)
                    })
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                move_one_adjacent_effectful_scratch_value(body, reads)
            }
            Stmt::Switch { cases, default, .. } => {
                cases.iter_mut().any(|(_, case_body)| {
                    move_one_adjacent_effectful_scratch_value(case_body, reads)
                }) || default.as_mut().is_some_and(|default_body| {
                    move_one_adjacent_effectful_scratch_value(default_body, reads)
                })
            }
            Stmt::TryCatch { try_body, catches } => {
                move_one_adjacent_effectful_scratch_value(try_body, reads)
                    || catches.iter_mut().any(|catch| {
                        move_one_adjacent_effectful_scratch_value(&mut catch.body, reads)
                    })
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn fold_one_adjacent_overwritten_value(body: &mut Vec<Stmt>) -> bool {
    for statement in body.iter_mut() {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_one_adjacent_overwritten_value(then_body)
                    || else_body
                        .as_mut()
                        .is_some_and(fold_one_adjacent_overwritten_value)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_one_adjacent_overwritten_value(body)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| fold_one_adjacent_overwritten_value(body))
                    || default
                        .as_mut()
                        .is_some_and(fold_one_adjacent_overwritten_value)
            }
            Stmt::TryCatch { try_body, catches } => {
                fold_one_adjacent_overwritten_value(try_body)
                    || catches
                        .iter_mut()
                        .any(|catch| fold_one_adjacent_overwritten_value(&mut catch.body))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }

    for index in 0..body.len().saturating_sub(1) {
        let Some((destination, source)) = (match &body[index] {
            Stmt::Assign { dst, src }
                if is_scratch_reg(dst)
                    && !is_promoted_local_reg(dst)
                    && !contains_reg(src, dst)
                    && !contains_deref(src)
                    && !contains_unknown(src)
                    && !contains_select(src) =>
            {
                Some((dst.clone(), src.clone()))
            }
            _ => None,
        }) else {
            continue;
        };
        let Some(next_index) = (index + 1..body.len())
            .find(|next| !matches!(body[*next], Stmt::Comment(_) | Stmt::Nop))
        else {
            continue;
        };
        let Stmt::Assign {
            dst: overwritten,
            src: consumer,
        } = &mut body[next_index]
        else {
            continue;
        };
        if *overwritten != destination || count_reg_uses(consumer, &destination) != 1 {
            continue;
        }
        subst(consumer, &Copies::single(destination.clone(), source));
        body.remove(index);
        return true;
    }
    false
}

fn fold_one_adjacent_guard_value(body: &mut Vec<Stmt>, reads: &RegMap<usize>) -> bool {
    for statement in body.iter_mut() {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_one_adjacent_guard_value(then_body, reads)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| fold_one_adjacent_guard_value(body, reads))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_one_adjacent_guard_value(body, reads)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| fold_one_adjacent_guard_value(body, reads))
                    || default
                        .as_mut()
                        .is_some_and(|body| fold_one_adjacent_guard_value(body, reads))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }

    for index in 0..body.len().saturating_sub(1) {
        let Some((dst, source)) = (match &body[index] {
            Stmt::Assign { dst, src }
                if is_scratch_reg(dst)
                    && !is_promoted_local_reg(dst)
                    && reads.get(dst).copied() == Some(1)
                    && !contains_reg(src, dst)
                    && !contains_unknown(src)
                    && !contains_select(src) =>
            {
                Some((dst.clone(), src.clone()))
            }
            _ => None,
        }) else {
            continue;
        };
        let Some(guard_index) = (index + 1..body.len())
            .find(|next| !matches!(body[*next], Stmt::Comment(_) | Stmt::Nop))
        else {
            continue;
        };
        let Stmt::If {
            cond,
            then_body,
            else_body,
        } = &body[guard_index]
        else {
            continue;
        };
        if contains_select(cond) || count_reg_uses(cond, &dst) != 1 {
            continue;
        }
        let mut other_reads = RegMap::default();
        count_reads_body(then_body, &mut other_reads);
        if let Some(else_body) = else_body {
            count_reads_body(else_body, &mut other_reads);
        }
        count_reads_body(&body[guard_index + 1..], &mut other_reads);
        if other_reads.get(&dst).copied().unwrap_or(0) != 0 {
            continue;
        }

        let Stmt::If { cond, .. } = &mut body[guard_index] else {
            unreachable!()
        };
        subst(cond, &Copies::single(dst, source));
        body.remove(index);
        return true;
    }
    false
}

fn fold_one_adjacent_promoted_value(body: &mut Vec<Stmt>, types: Option<&TypeMap>) -> bool {
    for index in 0..body.len().saturating_sub(1) {
        let candidate = match &body[index] {
            Stmt::Assign { dst, src }
                if is_promoted_local_reg(dst)
                    && is_deferable_promoted_value(src)
                    && !contains_reg(src, dst)
                    && promoted_value_width(src).is_some() =>
            {
                Some((dst.clone(), src.clone()))
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                size,
            } if is_promoted_local_reg(dst)
                && types.is_some_and(|types| {
                    matches!(
                        types.get(dst),
                        Some(TypeHint::Int { width, .. })
                            if width > 0 && width <= *size
                    ) || matches!(types.get(dst), Some(TypeHint::BoolLike))
                })
                && is_deferable_promoted_value(src)
                && !contains_reg(src, dst)
                && promoted_value_width(src).is_some_and(|width| width <= *size) =>
            {
                Some((dst.clone(), src.clone()))
            }
            _ => None,
        };
        let Some((dst, selected)) = candidate else {
            continue;
        };

        let Some(next_index) = (index + 1..body.len())
            .find(|next| !matches!(body[*next], Stmt::Comment(_) | Stmt::Nop))
        else {
            continue;
        };

        let mut next_reads = RegMap::default();
        count_reads_stmt(&body[next_index], &mut next_reads);
        if next_reads.get(&dst).copied().unwrap_or(0) != 1 {
            continue;
        }
        let mut later_reads = RegMap::default();
        count_reads_body(&body[next_index + 1..], &mut later_reads);
        if later_reads.get(&dst).copied().unwrap_or(0) != 0 {
            // Another use in this same structured run still observes the
            // definition. Other cases/arms live in a different Vec and do not
            // block an exact local def-use fold.
            continue;
        }

        let substituted = match &mut body[next_index] {
            Stmt::Assign { src, .. } | Stmt::Store { src, .. } => {
                let copies = Copies::single(dst, selected);
                subst(src, &copies);
                true
            }
            Stmt::Return { value: Some(value) } | Stmt::Push { value } => {
                let copies = Copies::single(dst, selected);
                subst(value, &copies);
                true
            }
            _ => false,
        };
        if substituted {
            body.remove(index);
            return true;
        }
    }

    for statement in body {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_one_adjacent_promoted_value(then_body, types)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| fold_one_adjacent_promoted_value(body, types))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_one_adjacent_promoted_value(body, types)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| fold_one_adjacent_promoted_value(body, types))
                    || default
                        .as_mut()
                        .is_some_and(|body| fold_one_adjacent_promoted_value(body, types))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn promoted_value_width(e: &Expr) -> Option<u8> {
    match e {
        Expr::Const(value) if (0..=127).contains(value) => Some(1),
        Expr::Cmp { .. } => Some(1),
        Expr::Select { width, .. } if *width > 0 => Some(*width),
        Expr::Cast { width, .. } if *width > 0 => Some(*width),
        _ => None,
    }
}

/// Expressions whose evaluation may be moved from a promoted temporary store
/// to its sole later use. Effectful calls and memory loads are excluded because
/// moving either can change observable behavior; unknown expressions remain
/// rooted where the lifter placed them.
///
/// A promoted stack slot is represented as a store whose bare-register address
/// is the source variable itself (`Store local_x = value`). It is assignment
/// semantics, not an indirect write through a pointer named `local_x`.
fn is_deferable_promoted_value(e: &Expr) -> bool {
    !contains_deref(e) && !contains_unknown(e)
}

#[cfg(test)]
mod tests {
    use super::super::propagate_copies;
    use super::*;
    use crate::ir::types::{BinOp, CmpOp, VReg};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn an_adjacent_single_use_moves_one_effectful_value_without_duplication() {
        let selected = Expr::Select {
            cond: Box::new(Expr::Reg(reg("enabled"))),
            if_true: Box::new(Expr::Call {
                target: Box::new(Expr::Named {
                    va: 0x2000,
                    name: "grow_capacity".into(),
                }),
                args: vec![Expr::Reg(reg("capacity"))],
                call_spec: None,
                result_width: Some(8),
            }),
            if_false: Box::new(Expr::Const(-1)),
            width: 8,
        };
        let mut function = Function {
            name: "effectful_single_use".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var14"),
                    src: selected.clone(),
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_10")),
                    src: Expr::Reg(reg("var14")),
                    size: 8,
                },
            ],
        };

        move_adjacent_effectful_scratch_values(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::Store {
                addr: Expr::Reg(reg("local_10")),
                src: selected,
                size: 8,
            }],
            "the call must move to its sole adjacent consumer, not be copied"
        );
    }

    #[test]
    fn an_effectful_value_with_multiple_reads_is_not_moved() {
        let mut function = Function {
            name: "shared_effectful_value".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var14"),
                    src: Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "read_once".into(),
                        }),
                        args: Vec::new(),
                        call_spec: None,
                        result_width: Some(8),
                    },
                },
                Stmt::Assign {
                    dst: reg("local_10"),
                    src: Expr::Reg(reg("var14")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var14"))),
                },
            ],
        };
        let before = function.clone();

        move_adjacent_effectful_scratch_values(&mut function);

        assert_eq!(function, before);
    }

    #[test]
    fn an_effectful_value_is_not_moved_into_an_indirect_store() {
        let mut function = Function {
            name: "effectful_indirect_store".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var14"),
                    src: Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "read_once".into(),
                        }),
                        args: Vec::new(),
                        call_spec: None,
                        result_width: Some(8),
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("var20")),
                    src: Expr::Reg(reg("var14")),
                    size: 8,
                },
            ],
        };
        let before = function.clone();

        move_adjacent_effectful_scratch_values(&mut function);

        assert_eq!(
            function, before,
            "moving the call into an indirect store could reorder address evaluation"
        );
    }

    #[test]
    fn single_use_promoted_local_select_folds_into_return() {
        // A stack-slot assignment diamond has already become one lazy Select.
        // The explicit local assignment is compiler storage, not source state.
        let selected = Expr::Select {
            cond: Box::new(Expr::Reg(reg("cond"))),
            if_true: Box::new(Expr::Const(1)),
            if_false: Box::new(Expr::Const(2)),
            width: 4,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_tmp"),
                    src: selected.clone(),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_tmp"))),
                },
            ],
        };

        propagate_copies(&mut f);

        propagate_adjacent_promoted_values(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::Return {
                value: Some(selected),
            }],
            "the one-use promoted temporary chain should disappear"
        );
    }

    #[test]
    fn ambiguous_store_through_promoted_pointer_is_not_value_propagated() {
        // Stack promotion currently uses the same `Store { addr: local }`
        // spelling for assigning the frame slot and for writing through a
        // pointer loaded from it. Local adjacency cannot distinguish these:
        // folding the second store into the return would change a pointer
        // return into the stored integer value.
        let pointer = reg("local_8");
        let mut function = Function {
            name: "write_and_return".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(pointer.clone()),
                    src: Expr::Reg(reg("source_pointer")),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Reg(pointer.clone()),
                    src: Expr::Const(42),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(pointer)),
                },
            ],
        };
        let expected = function.clone();

        propagate_adjacent_promoted_values(&mut function);
        let mut types = crate::ir::types_recover::TypeMap::default();
        types.upsert_public(
            reg("local_8"),
            crate::ir::types_recover::TypeHint::Pointer { pointee_width: 4 },
        );
        propagate_adjacent_typed_promoted_values(&mut function, &types);

        assert_eq!(function, expected);
    }

    #[test]
    fn typed_scalar_promoted_store_folds_into_return() {
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("state"))),
            rhs: Box::new(Expr::Const(3)),
        };
        let mut function = Function {
            name: "finished".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_4")),
                    src: predicate.clone(),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_4"))),
                },
            ],
        };
        let mut types = crate::ir::types_recover::TypeMap::default();
        types.upsert_public(
            reg("local_4"),
            crate::ir::types_recover::TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        propagate_adjacent_typed_promoted_values(&mut function, &types);

        assert_eq!(
            function.body,
            vec![Stmt::Return {
                value: Some(predicate),
            }]
        );
    }

    #[test]
    fn typed_scalar_store_does_not_erase_a_wider_source_truncation() {
        let mut function = Function {
            name: "truncate".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_4")),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("wide"))),
                    },
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_4"))),
                },
            ],
        };
        let expected = function.clone();
        let mut types = crate::ir::types_recover::TypeMap::default();
        types.upsert_public(
            reg("local_4"),
            crate::ir::types_recover::TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        propagate_adjacent_typed_promoted_values(&mut function, &types);

        assert_eq!(function, expected);
    }

    #[test]
    fn adjacent_boolean_promoted_local_folds_into_return() {
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("state"))),
            rhs: Box::new(Expr::Const(3)),
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_result"),
                    src: predicate.clone(),
                },
                Stmt::Comment("epilogue".into()),
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_result"))),
                },
            ],
        };

        propagate_adjacent_promoted_values(&mut f);

        assert_eq!(
            f.body,
            vec![
                Stmt::Comment("epilogue".into()),
                Stmt::Return {
                    value: Some(predicate),
                },
            ]
        );
    }

    #[test]
    fn adjacent_physical_load_folds_into_its_only_eager_guard_use() {
        // x86-64 `movzx eax, byte ptr [base+index]; test eax,eax` now carries
        // the architectural zero-extension explicitly. After role naming the
        // destination is the physical `ret` role rather than an SSA Temp, but
        // the immediately following guard is still its one reaching use. Keep
        // the load at the same evaluation point while exposing the loop guard.
        let loaded = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 1,
                expr: Box::new(Expr::Deref {
                    addr: Box::new(Expr::Reg(reg("cursor"))),
                    size: 1,
                }),
            }),
        };
        let mut f = Function {
            name: "str_len".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::Assign {
                        dst: reg("ret"),
                        src: loaded.clone(),
                    },
                    Stmt::If {
                        cond: Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(Expr::Bin {
                                op: BinOp::And,
                                lhs: Box::new(Expr::Reg(reg("ret"))),
                                rhs: Box::new(Expr::Const(255)),
                            }),
                            rhs: Box::new(Expr::Const(0)),
                        },
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: reg("cursor"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("cursor"))),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    },
                ],
            }],
        };

        propagate_adjacent_guard_values(&mut f);

        let Stmt::While { body, .. } = &f.body[0] else {
            panic!("expected loop")
        };
        assert_eq!(
            body.len(),
            2,
            "the physical scratch definition should disappear"
        );
        let Stmt::If { cond, .. } = &body[0] else {
            panic!("the reconstructed guard must remain first")
        };
        let dump = format!("{cond:?}");
        assert!(
            dump.contains("Deref"),
            "the load must move into the guard: {dump}"
        );
        assert!(
            !dump.contains("ret"),
            "the scratch read must be replaced: {dump}"
        );
    }

    #[test]
    fn adjacent_predicate_folds_into_the_assignment_that_overwrites_it() {
        let result = reg("result");
        let mut function = Function {
            name: "predicate_index".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Cmp {
                        op: CmpOp::Sle,
                        lhs: Box::new(Expr::Reg(reg("lhs"))),
                        rhs: Box::new(Expr::Reg(reg("rhs"))),
                    },
                },
                Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("base"))),
                            rhs: Box::new(Expr::Bin {
                                op: BinOp::Mul,
                                lhs: Box::new(Expr::Reg(result.clone())),
                                rhs: Box::new(Expr::Const(4)),
                            }),
                        }),
                        size: 4,
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result.clone())),
                },
            ],
        };

        propagate_adjacent_overwritten_values(&mut function);

        assert_eq!(function.body.len(), 2, "{:#?}", function.body);
        let Stmt::Assign { dst, src } = &function.body[0] else {
            panic!("overwriting assignment disappeared: {:#?}", function.body);
        };
        assert_eq!(dst, &result);
        assert_eq!(count_reg_uses(src, &result), 0);
        assert!(format!("{src:#?}").contains("op: Sle"), "{src:#?}");
    }

    #[test]
    fn adjacent_overwrite_keeps_impure_or_multiply_read_values() {
        let result = reg("result");
        let overwrite = |source: Expr, consumer: Expr| Function {
            name: "unsafe_predicate_index".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: result.clone(),
                    src: source,
                },
                Stmt::Assign {
                    dst: result.clone(),
                    src: consumer,
                },
            ],
        };
        let mut memory_source = overwrite(
            Expr::Deref {
                addr: Box::new(Expr::Reg(reg("cursor"))),
                size: 4,
            },
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(result.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        );
        let mut multiply_read = overwrite(
            Expr::Cmp {
                op: CmpOp::Sle,
                lhs: Box::new(Expr::Reg(reg("lhs"))),
                rhs: Box::new(Expr::Reg(reg("rhs"))),
            },
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(result.clone())),
                rhs: Box::new(Expr::Reg(result.clone())),
            },
        );
        let expected_memory = memory_source.clone();
        let expected_multiple = multiply_read.clone();

        propagate_adjacent_overwritten_values(&mut memory_source);
        propagate_adjacent_overwritten_values(&mut multiply_read);

        assert_eq!(memory_source, expected_memory, "loads must not be moved");
        assert_eq!(
            multiply_read, expected_multiple,
            "a value used twice must not be duplicated"
        );
    }

    #[test]
    fn adjacent_physical_guard_value_with_an_arm_read_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("cursor"))),
                        size: 1,
                    },
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("ret"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(reg("ret"))),
                    }],
                    else_body: None,
                },
            ],
        };
        let expected = f.clone();

        propagate_adjacent_guard_values(&mut f);

        assert_eq!(
            f, expected,
            "a second reaching read must keep the definition"
        );
    }

    #[test]
    fn loop_header_value_read_after_the_loop_is_kept() {
        // `while_reload_header` uses the last loaded element both to decide
        // whether to leave the loop and in the joined return. Moving the load
        // into the loop condition would make that joined read undefined.
        let mut f = Function {
            name: "while_reload_header".into(),
            entry_va: 0,
            body: vec![
                Stmt::While {
                    cond: Expr::Const(1),
                    body: vec![
                        Stmt::Assign {
                            dst: reg("var3"),
                            src: Expr::Deref {
                                addr: Box::new(Expr::Reg(reg("cursor"))),
                                size: 4,
                            },
                        },
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: CmpOp::Ne,
                                lhs: Box::new(Expr::Bin {
                                    op: BinOp::And,
                                    lhs: Box::new(Expr::Reg(reg("var3"))),
                                    rhs: Box::new(Expr::Const(1)),
                                }),
                                rhs: Box::new(Expr::Const(0)),
                            },
                            then_body: vec![Stmt::Break],
                            else_body: None,
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var3"))),
                },
            ],
        };
        let expected = f.clone();

        propagate_adjacent_guard_values(&mut f);

        assert_eq!(
            f, expected,
            "a joined post-loop read must keep the reaching loop definition"
        );
    }

    #[test]
    fn adjacent_physical_value_is_not_moved_across_select_evaluation() {
        let mut source_select = Function {
            name: "source_select".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("choose_load"))),
                        if_true: Box::new(Expr::Deref {
                            addr: Box::new(Expr::Reg(reg("cursor"))),
                            size: 1,
                        }),
                        if_false: Box::new(Expr::Const(0)),
                        width: 1,
                    },
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("ret"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
            ],
        };
        let expected_source = source_select.clone();

        propagate_adjacent_guard_values(&mut source_select);

        assert_eq!(
            source_select, expected_source,
            "a select source must retain its original conditional evaluation"
        );

        let mut guard_select = Function {
            name: "guard_select".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("cursor"))),
                        size: 1,
                    },
                },
                Stmt::If {
                    cond: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("skip_read"))),
                        if_true: Box::new(Expr::Const(1)),
                        if_false: Box::new(Expr::Reg(reg("ret"))),
                        width: 1,
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
            ],
        };
        let expected_guard = guard_select.clone();

        propagate_adjacent_guard_values(&mut guard_select);

        assert_eq!(
            guard_select, expected_guard,
            "a select guard must not make an eager load conditional"
        );
    }

    #[test]
    fn adjacent_promoted_value_with_a_second_read_is_kept() {
        let selected = Expr::Select {
            cond: Box::new(Expr::Reg(reg("cond"))),
            if_true: Box::new(Expr::Const(1)),
            if_false: Box::new(Expr::Const(2)),
            width: 4,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_tmp"),
                    src: selected,
                },
                Stmt::Assign {
                    dst: reg("first"),
                    src: Expr::Reg(reg("local_tmp")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_tmp"))),
                },
            ],
        };
        let expected = f.clone();

        propagate_adjacent_promoted_values(&mut f);

        assert_eq!(
            f, expected,
            "a later read still needs the rooted definition"
        );
    }
}
