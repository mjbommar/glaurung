//! Normalize range-guarded switches without changing their case semantics.
//!
//! Clang commonly lowers a dense switch as an unsigned range check followed by
//! an indirect dispatch. Region recovery faithfully reconstructs both pieces,
//! but the source-level result is needlessly nested:
//!
//! ```text
//! tmp = (u64)(u32)value;
//! if ((u32)value <= 3) { switch (tmp) { case 0: ... case 3: ... } }
//! ```
//!
//! The guard is redundant precisely when every case label is inside its range
//! and the switch has no default. If the guard is false, the zero-extended
//! discriminator cannot equal a case label; if it is true, the switch already
//! performs the same label selection. This pass encodes that proof rather than
//! treating every `if { switch }` shape as safe.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{CmpOp, VReg};
use crate::ir::types_recover::{TypeHint, TypeMap};

/// Remove redundant outer unsigned-range guards around proven switch statements.
pub fn collapse_range_guards(function: &mut Function) {
    collapse_body(&mut function.body, None);
}

/// Typed second chance for range guards whose discriminator explicitly narrows
/// or widens a register. The recovered width proves whether that cast preserves
/// the guarded value; without it the untyped pass deliberately leaves the guard.
pub fn collapse_range_guards_with_types(function: &mut Function, types: &TypeMap) {
    collapse_body(&mut function.body, Some(types));
}

fn collapse_body(body: &mut Vec<Stmt>, types: Option<&TypeMap>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_body(then_body, types);
                if let Some(else_body) = else_body {
                    collapse_body(else_body, types);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_body(body, types);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collapse_body(case_body, types);
                }
                if let Some(default) = default {
                    collapse_body(default, types);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let Some(GuardedSwitchCandidate {
            mut switch,
            guarded_value,
            consumed,
            hoisted,
        }) = guarded_switch_at(body, index)
        else {
            index += 1;
            continue;
        };

        let Stmt::Switch { discriminant, .. } = &mut switch else {
            unreachable!("guarded_switch only returns switch statements")
        };
        if is_unsigned_extension_of(discriminant, &guarded_value, types) {
            let replacement_len = hoisted.len() + 1;
            install_candidate(body, index, consumed, hoisted, switch);
            index += replacement_len;
            continue;
        }

        // Stack promotion deliberately leaves source variables named `local_*`,
        // so ordinary copy propagation will not inline this compiler-generated
        // discriminator temporary. Inline it here only when the immediately
        // preceding definition is its sole remaining read.
        if index == 0 {
            index += 1;
            continue;
        }
        let Some((temporary, value)) = body
            .get(index - 1)
            .and_then(|statement| discriminant_copy(statement, types))
        else {
            index += 1;
            continue;
        };
        if *discriminant != Expr::Reg(temporary.clone())
            || !is_unsigned_extension_of(&value, &guarded_value, types)
            || count_reads_in_body(&body[index..], &temporary) != 1
        {
            index += 1;
            continue;
        }

        *discriminant = value;
        install_candidate(body, index, consumed, hoisted, switch);
        body.remove(index - 1);
        // The replacement moved left by one. Continue after it.
    }
}

fn install_candidate(
    body: &mut Vec<Stmt>,
    index: usize,
    consumed: usize,
    hoisted: Vec<Stmt>,
    switch: Stmt,
) {
    body.splice(
        index..index + consumed,
        hoisted.into_iter().chain(std::iter::once(switch)),
    );
}

/// Return the sole switch and its guarded unsigned view when eliminating the
/// wrapper is semantically justified by the case domain.
struct GuardedSwitchCandidate {
    switch: Stmt,
    guarded_value: Expr,
    consumed: usize,
    hoisted: Vec<Stmt>,
}

fn guarded_switch_at(body: &[Stmt], index: usize) -> Option<GuardedSwitchCandidate> {
    guarded_switch(&body[index])
        .map(|(switch, guarded_value)| GuardedSwitchCandidate {
            switch,
            guarded_value,
            consumed: 1,
            hoisted: Vec::new(),
        })
        .or_else(|| {
            guarded_switch_after_early_return(body.get(index)?, body.get(index + 1)?).map(
                |(switch, guarded_value)| GuardedSwitchCandidate {
                    switch,
                    guarded_value,
                    consumed: 2,
                    hoisted: Vec::new(),
                },
            )
        })
        .or_else(|| {
            let middle = body.get(index + 1)?;
            if !safe_to_speculate_before_guard(&body[index], middle) {
                return None;
            }
            guarded_switch_after_early_return(&body[index], body.get(index + 2)?).map(
                |(switch, guarded_value)| GuardedSwitchCandidate {
                    switch,
                    guarded_value,
                    consumed: 3,
                    hoisted: vec![middle.clone()],
                },
            )
        })
}

/// Whether the sole interstitial statement can execute before the range guard.
/// Restrict this to a register copy/cast with no guard dependency: loads, calls,
/// arithmetic, and memory stores may trap, overflow, or carry observable effects.
fn safe_to_speculate_before_guard(guard: &Stmt, statement: &Stmt) -> bool {
    let Stmt::Assign { dst, src } = statement else {
        return false;
    };
    count_reads_in_statement(guard, dst) == 0 && is_total_copy_expression(src)
}

fn is_total_copy_expression(expr: &Expr) -> bool {
    match expr {
        Expr::Reg(_) | Expr::Const(_) => true,
        Expr::Cast { expr, .. } => is_total_copy_expression(expr),
        _ => false,
    }
}

fn guarded_switch(statement: &Stmt) -> Option<(Stmt, Expr)> {
    let Stmt::If {
        cond,
        then_body,
        else_body,
    } = statement
    else {
        return None;
    };

    // `if (unsigned_value <= bound) switch (value)`: outside the guard no case
    // can match, so removing the wrapper preserves both matched cases and
    // fallthrough through gaps in the case domain.
    if let Expr::Cmp {
        op: CmpOp::Ule,
        lhs,
        rhs,
    } = cond
    {
        let Expr::Const(bound) = rhs.as_ref() else {
            return None;
        };
        let [switch @ Stmt::Switch { cases, default, .. }] = then_body.as_slice() else {
            return None;
        };
        if else_body.is_none() && default.is_none() && labels_within_unsigned_bound(cases, *bound) {
            return Some((switch.clone(), lhs.as_ref().clone()));
        }
        return None;
    }

    // Clang's other common form is
    // `if (bound < unsigned_value) default_body; else switch (value)`.
    // The outside arm may become the switch default only when the else-side
    // labels exhaustively cover 0..=bound.  Merely being in range is not enough:
    // a missing label originally falls through, whereas a synthesized default
    // would execute `default_body`.
    let Expr::Cmp {
        op: CmpOp::Ult,
        lhs,
        rhs,
    } = cond
    else {
        return None;
    };
    let Expr::Const(bound) = lhs.as_ref() else {
        return None;
    };
    let [switch @ Stmt::Switch { cases, default, .. }] = else_body.as_deref()? else {
        return None;
    };
    if default.is_some() || !labels_exhaust_unsigned_bound(cases, *bound) {
        return None;
    }

    let mut switch = switch.clone();
    let Stmt::Switch { default, .. } = &mut switch else {
        unreachable!()
    };
    *default = Some(then_body.clone());
    Some((switch, rhs.as_ref().clone()))
}

/// Recognize optimized `if (bound < value) return default; switch (value)`.
/// The early arm becomes a default only when the following switch exhaustively
/// covers the guard's inside range; otherwise an in-range case gap would change
/// from falling out of the switch to taking the synthesized default.
fn guarded_switch_after_early_return(guard: &Stmt, following: &Stmt) -> Option<(Stmt, Expr)> {
    let Stmt::If {
        cond: Expr::Cmp {
            op: CmpOp::Ult,
            lhs,
            rhs,
        },
        then_body,
        else_body: None,
    } = guard
    else {
        return None;
    };
    let Expr::Const(bound) = lhs.as_ref() else {
        return None;
    };
    if !is_straight_line_return_body(then_body) {
        return None;
    }
    let Stmt::Switch { cases, default, .. } = following else {
        return None;
    };
    if default.is_some() || !labels_exhaust_unsigned_bound(cases, *bound) {
        return None;
    }

    let mut switch = following.clone();
    let Stmt::Switch { default, .. } = &mut switch else {
        unreachable!()
    };
    *default = Some(then_body.clone());
    Some((switch, rhs.as_ref().clone()))
}

/// Whether an early guard arm executes only ordinary statements and then
/// unconditionally returns.
///
/// GCC commonly spells a cold default as `call; return result`, rather than a
/// single return expression. Moving that sequence into a switch default keeps
/// its execution condition and order. Control-bearing statements are rejected:
/// in particular, moving a `break` from an enclosing loop into a switch would
/// silently retarget it to the switch.
fn is_straight_line_return_body(body: &[Stmt]) -> bool {
    let Some((last, prefix)) = body.split_last() else {
        return false;
    };
    matches!(last, Stmt::Return { .. })
        && prefix.iter().all(|statement| {
            matches!(
                statement,
                Stmt::Assign { .. }
                    | Stmt::Store { .. }
                    | Stmt::Call { .. }
                    | Stmt::Nop
                    | Stmt::Unknown(_)
                    | Stmt::Comment(_)
                    | Stmt::Push { .. }
                    | Stmt::Pop { .. }
            )
        })
}

fn labels_within_unsigned_bound(cases: &[(Option<i64>, Vec<Stmt>)], bound: i64) -> bool {
    bound >= 0
        && !cases.is_empty()
        && cases
            .iter()
            .all(|(label, _)| matches!(label, Some(value) if *value >= 0 && *value <= bound))
}

fn labels_exhaust_unsigned_bound(cases: &[(Option<i64>, Vec<Stmt>)], bound: i64) -> bool {
    let Some(domain_len) = bound
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    if domain_len == 0 || cases.len() != domain_len {
        return false;
    }
    let labels: std::collections::HashSet<i64> =
        cases.iter().filter_map(|(label, _)| *label).collect();
    labels.len() == domain_len && labels.iter().all(|value| (0..=bound).contains(value))
}

/// True when `candidate` is exactly the guarded unsigned value, optionally
/// wrapped in wider unsigned casts. A narrowing or signed cast would not
/// preserve the range proof and is rejected.
fn is_unsigned_extension_of(candidate: &Expr, guarded: &Expr, types: Option<&TypeMap>) -> bool {
    if candidate == guarded {
        return true;
    }

    // Lossless unsigned views of the same recovered-width source are
    // equivalent for case selection even when the guard, rather than the
    // discriminator, carries the wider spelling. This is the shape produced
    // by Clang -O0 after x86 32-bit writes are represented explicitly:
    //
    //   tmp = u32(state); if (u64(u32(state)) <= K) switch (tmp)
    //
    // Requiring the source width to fit through the narrowest cast on both
    // sides rules out every truncating view.
    fn unsigned_view(expr: &Expr) -> (&Expr, u8) {
        let mut current = expr;
        let mut narrowest = u8::MAX;
        while let Expr::Cast {
            signed: false,
            width,
            expr,
        } = current
        {
            narrowest = narrowest.min(*width);
            current = expr;
        }
        (current, narrowest)
    }

    let (candidate_root, candidate_narrowest) = unsigned_view(candidate);
    let (guarded_root, guarded_narrowest) = unsigned_view(guarded);
    if candidate_root == guarded_root
        && known_width(candidate_root, types)
            .is_some_and(|width| width <= candidate_narrowest && width <= guarded_narrowest)
    {
        return true;
    }

    let mut current = candidate;
    let mut narrowest_cast = u8::MAX;
    while let Expr::Cast {
        signed: false,
        width,
        expr,
    } = current
    {
        narrowest_cast = narrowest_cast.min(*width);
        current = expr;
        if current == guarded {
            return known_width(guarded, types).is_some_and(|width| width <= narrowest_cast);
        }
    }
    false
}

fn known_width(expr: &Expr, types: Option<&TypeMap>) -> Option<u8> {
    match expr {
        Expr::Cast { width, .. } => Some(*width),
        Expr::Reg(register) => match types?.get(register)? {
            TypeHint::Int { width, .. } => Some(width),
            TypeHint::BoolLike => Some(1),
            TypeHint::Float { width } => Some(width),
            TypeHint::Pointer { .. } | TypeHint::CodePointer => None,
        },
        _ => None,
    }
}

fn discriminant_copy(statement: &Stmt, types: Option<&TypeMap>) -> Option<(VReg, Expr)> {
    match statement {
        Stmt::Assign { dst, src } => Some((dst.clone(), src.clone())),
        // Stack-local promotion represents a write to the recovered object as
        // `Store { addr: Reg(local_*), ... }`; the C renderer already treats it
        // as an assignment. It is a lossless discriminator copy only when the
        // source's recovered width fits in the destination object. Requiring
        // the promoted-local prefix prevents a genuine pointer store from ever
        // being mistaken for a register copy.
        Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            src,
            size,
        } if (name.starts_with("local_") || name.starts_with("stack_"))
            && known_width(src, types).is_some_and(|width| width <= *size) =>
        {
            Some((dst.clone(), src.clone()))
        }
        _ => None,
    }
}

fn count_reads_in_body(body: &[Stmt], target: &VReg) -> usize {
    body.iter()
        .map(|statement| count_reads_in_statement(statement, target))
        .sum()
}

fn count_reads_in_statement(statement: &Stmt, target: &VReg) -> usize {
    match statement {
        Stmt::Assign { src, .. } => count_reads_in_expr(src, target),
        Stmt::Store { addr, src, .. } => {
            count_reads_in_expr(addr, target) + count_reads_in_expr(src, target)
        }
        Stmt::Call {
            target: callee,
            args,
            ..
        } => {
            count_reads_in_expr(callee, target)
                + args
                    .iter()
                    .map(|argument| count_reads_in_expr(argument, target))
                    .sum::<usize>()
        }
        Stmt::Return { value } => value
            .as_ref()
            .map(|value| count_reads_in_expr(value, target))
            .unwrap_or(0),
        Stmt::IndirectGoto { target: value } | Stmt::Push { value } => {
            count_reads_in_expr(value, target)
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            count_reads_in_expr(cond, target)
                + count_reads_in_body(then_body, target)
                + else_body
                    .as_deref()
                    .map(|body| count_reads_in_body(body, target))
                    .unwrap_or(0)
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            count_reads_in_expr(cond, target) + count_reads_in_body(body, target)
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            count_reads_in_statement(init, target)
                + count_reads_in_expr(cond, target)
                + count_reads_in_statement(step, target)
                + count_reads_in_body(body, target)
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            count_reads_in_expr(discriminant, target)
                + cases
                    .iter()
                    .map(|(_, body)| count_reads_in_body(body, target))
                    .sum::<usize>()
                + default
                    .as_deref()
                    .map(|body| count_reads_in_body(body, target))
                    .unwrap_or(0)
        }
        Stmt::Pop { .. }
        | Stmt::Label(_)
        | Stmt::Goto { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => 0,
    }
}

fn count_reads_in_expr(expr: &Expr, target: &VReg) -> usize {
    match expr {
        Expr::Reg(register) => usize::from(register == target),
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => count_reads_in_expr(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reads_in_expr(lhs, target) + count_reads_in_expr(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_reads_in_expr(cond, target)
                + count_reads_in_expr(if_true, target)
                + count_reads_in_expr(if_false, target)
        }
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .map(|argument| count_reads_in_expr(argument, target))
            .sum(),
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            usize::from(base.as_ref() == Some(target)) + usize::from(index.as_ref() == Some(target))
        }
        Expr::StackAddr { object, .. } => usize::from(object == target),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::{CmpOp, VReg};

    fn unsigned(width: u8, expr: Expr) -> Expr {
        Expr::Cast {
            signed: false,
            width,
            expr: Box::new(expr),
        }
    }

    #[test]
    fn removes_proven_unsigned_guard_and_its_one_use_discriminant_copy() {
        let source = VReg::phys("local_18");
        let temporary = VReg::phys("local_28");
        let guarded_value = unsigned(4, Expr::Reg(source.clone()));
        let discriminant_value = unsigned(8, guarded_value.clone());
        let mut function = Function {
            name: "fsm".to_string(),
            entry_va: 0x1100,
            body: vec![
                Stmt::Assign {
                    dst: temporary.clone(),
                    src: discriminant_value.clone(),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(guarded_value),
                        rhs: Box::new(Expr::Const(3)),
                    },
                    then_body: vec![Stmt::Switch {
                        discriminant: Expr::Reg(temporary),
                        cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                        default: None,
                    }],
                    else_body: None,
                },
            ],
        };

        collapse_range_guards(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: discriminant_value,
                cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                default: None,
            }]
        );
    }

    #[test]
    fn keeps_guard_when_a_default_arm_would_observe_rejected_values() {
        let source = VReg::phys("state");
        let guarded_value = unsigned(4, Expr::Reg(source));
        let original = Stmt::If {
            cond: Expr::Cmp {
                op: CmpOp::Ule,
                lhs: Box::new(guarded_value.clone()),
                rhs: Box::new(Expr::Const(3)),
            },
            then_body: vec![Stmt::Switch {
                discriminant: guarded_value,
                cases: vec![(Some(0), vec![Stmt::Nop])],
                default: Some(vec![Stmt::Return {
                    value: Some(Expr::Const(-1)),
                }]),
            }],
            else_body: None,
        };
        let mut function = Function {
            name: "guarded_default".to_string(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, vec![original]);
    }

    #[test]
    fn keeps_guard_when_a_case_lies_outside_the_proven_range() {
        let source = VReg::phys("state");
        let guarded_value = unsigned(4, Expr::Reg(source));
        let original = Stmt::If {
            cond: Expr::Cmp {
                op: CmpOp::Ule,
                lhs: Box::new(guarded_value.clone()),
                rhs: Box::new(Expr::Const(3)),
            },
            then_body: vec![Stmt::Switch {
                discriminant: guarded_value,
                cases: vec![(Some(4), vec![Stmt::Nop])],
                default: None,
            }],
            else_body: None,
        };
        let mut function = Function {
            name: "outside_case".to_string(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, vec![original]);
    }

    #[test]
    fn merges_an_outside_range_arm_into_an_exhaustive_switch_default() {
        let source = VReg::phys("op");
        let guarded_value = unsigned(4, Expr::Reg(source));
        let cases: Vec<(Option<i64>, Vec<Stmt>)> = (0..=3)
            .map(|case| {
                (
                    Some(case),
                    vec![Stmt::Assign {
                        dst: VReg::phys("result"),
                        src: Expr::Const(case),
                    }],
                )
            })
            .collect();
        let default_body = vec![Stmt::Assign {
            dst: VReg::phys("result"),
            src: Expr::Const(-1),
        }];
        let mut function = Function {
            name: "outside_default".to_string(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Const(3)),
                    rhs: Box::new(guarded_value.clone()),
                },
                then_body: default_body.clone(),
                else_body: Some(vec![Stmt::Switch {
                    discriminant: guarded_value.clone(),
                    cases: cases.clone(),
                    default: None,
                }]),
            }],
        };

        collapse_range_guards(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: guarded_value,
                cases,
                default: Some(default_body),
            }]
        );
    }

    #[test]
    fn keeps_outside_range_arm_when_the_switch_has_a_case_gap() {
        let source = VReg::phys("op");
        let guarded_value = unsigned(4, Expr::Reg(source));
        let original = Stmt::If {
            cond: Expr::Cmp {
                op: CmpOp::Ult,
                lhs: Box::new(Expr::Const(3)),
                rhs: Box::new(guarded_value.clone()),
            },
            then_body: vec![Stmt::Assign {
                dst: VReg::phys("result"),
                src: Expr::Const(-1),
            }],
            else_body: Some(vec![Stmt::Switch {
                discriminant: guarded_value,
                cases: vec![
                    (Some(0), vec![Stmt::Nop]),
                    (Some(1), vec![Stmt::Nop]),
                    // Case 2 is deliberately absent. Folding would make it
                    // execute the outside-range default instead of falling through.
                    (Some(3), vec![Stmt::Nop]),
                ],
                default: None,
            }]),
        };
        let mut function = Function {
            name: "gapped_switch".to_string(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, vec![original]);
    }

    #[test]
    fn merges_terminating_range_guard_with_its_following_exhaustive_switch() {
        let guarded_value = unsigned(4, Expr::Reg(VReg::phys("op")));
        let cases: Vec<(Option<i64>, Vec<Stmt>)> = (0..=3)
            .map(|case| {
                (
                    Some(case),
                    vec![Stmt::Return {
                        value: Some(Expr::Const(case)),
                    }],
                )
            })
            .collect();
        let default_body = vec![Stmt::Return {
            value: Some(Expr::Const(-1)),
        }];
        let mut function = Function {
            name: "optimized_dispatch".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ult,
                        lhs: Box::new(Expr::Const(3)),
                        rhs: Box::new(guarded_value.clone()),
                    },
                    then_body: default_body.clone(),
                    else_body: None,
                },
                Stmt::Switch {
                    discriminant: guarded_value.clone(),
                    cases: cases.clone(),
                    default: None,
                },
            ],
        };

        collapse_range_guards(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: guarded_value,
                cases,
                default: Some(default_body),
            }]
        );
    }

    #[test]
    fn merges_straight_line_call_and_return_into_the_exhaustive_switch_default() {
        let guarded_value = unsigned(4, Expr::Reg(VReg::phys("op")));
        let result = VReg::phys("ret");
        let cases: Vec<(Option<i64>, Vec<Stmt>)> = (0..=1)
            .map(|case| {
                (
                    Some(case),
                    vec![Stmt::Return {
                        value: Some(Expr::Const(case)),
                    }],
                )
            })
            .collect();
        let default_body = vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "dispatch_cold".to_string(),
                },
                args: vec![guarded_value.clone()],
                dst: Some(result.clone()),
                call_spec: None,
            },
            Stmt::Return {
                value: Some(Expr::Reg(result)),
            },
        ];
        let mut function = Function {
            name: "optimized_dispatch_with_cold_default".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ult,
                        lhs: Box::new(Expr::Const(1)),
                        rhs: Box::new(guarded_value.clone()),
                    },
                    then_body: default_body.clone(),
                    else_body: None,
                },
                Stmt::Switch {
                    discriminant: guarded_value.clone(),
                    cases: cases.clone(),
                    default: None,
                },
            ],
        };

        collapse_range_guards(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: guarded_value,
                cases,
                default: Some(default_body),
            }]
        );
    }

    #[test]
    fn keeps_a_loop_breaking_guard_outside_the_following_switch() {
        let guarded_value = unsigned(4, Expr::Reg(VReg::phys("op")));
        let loop_body = vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Const(1)),
                    rhs: Box::new(guarded_value.clone()),
                },
                then_body: vec![
                    Stmt::Break,
                    Stmt::Return {
                        value: Some(Expr::Const(-1)),
                    },
                ],
                else_body: None,
            },
            Stmt::Switch {
                discriminant: guarded_value,
                cases: vec![(Some(0), vec![Stmt::Nop]), (Some(1), vec![Stmt::Nop])],
                default: None,
            },
        ];
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: loop_body,
        };
        let mut function = Function {
            name: "loop_break_before_dispatch".to_string(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, vec![original]);
    }

    #[test]
    fn keeps_nonterminating_guard_before_a_following_switch() {
        let guarded_value = unsigned(4, Expr::Reg(VReg::phys("op")));
        let original = vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Const(1)),
                    rhs: Box::new(guarded_value.clone()),
                },
                then_body: vec![Stmt::Assign {
                    dst: VReg::phys("observed"),
                    src: Expr::Const(-1),
                }],
                else_body: None,
            },
            Stmt::Switch {
                discriminant: guarded_value,
                cases: vec![(Some(0), vec![Stmt::Nop]), (Some(1), vec![Stmt::Nop])],
                default: None,
            },
        ];
        let mut function = Function {
            name: "fallthrough_guard".to_string(),
            entry_va: 0,
            body: original.clone(),
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn hoists_a_total_copy_between_terminating_guard_and_switch() {
        let guarded_value = unsigned(4, Expr::Reg(VReg::phys("op")));
        let copy = Stmt::Assign {
            dst: VReg::phys("case_operand"),
            src: Expr::Cast {
                signed: true,
                width: 8,
                expr: Box::new(Expr::Reg(VReg::phys("rhs"))),
            },
        };
        let cases = vec![
            (
                Some(0),
                vec![Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("case_operand"))),
                }],
            ),
            (
                Some(1),
                vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
            ),
        ];
        let default_body = vec![Stmt::Return {
            value: Some(Expr::Const(-1)),
        }];
        let mut function = Function {
            name: "copy_before_dispatch".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ult,
                        lhs: Box::new(Expr::Const(1)),
                        rhs: Box::new(guarded_value.clone()),
                    },
                    then_body: default_body.clone(),
                    else_body: None,
                },
                copy.clone(),
                Stmt::Switch {
                    discriminant: guarded_value.clone(),
                    cases: cases.clone(),
                    default: None,
                },
            ],
        };

        collapse_range_guards(&mut function);

        assert_eq!(
            function.body,
            vec![
                copy,
                Stmt::Switch {
                    discriminant: guarded_value,
                    cases,
                    default: Some(default_body),
                },
            ]
        );
    }

    #[test]
    fn keeps_a_potentially_trapping_load_after_the_early_return_guard() {
        let guarded_value = unsigned(4, Expr::Reg(VReg::phys("op")));
        let original = vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Const(0)),
                    rhs: Box::new(guarded_value.clone()),
                },
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(-1)),
                }],
                else_body: None,
            },
            Stmt::Assign {
                dst: VReg::phys("loaded"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Reg(VReg::phys("ptr"))),
                    size: 4,
                },
            },
            Stmt::Switch {
                discriminant: guarded_value,
                cases: vec![(
                    Some(0),
                    vec![Stmt::Return {
                        value: Some(Expr::Const(0)),
                    }],
                )],
                default: None,
            },
        ];
        let mut function = Function {
            name: "trapping_load".to_string(),
            entry_va: 0,
            body: original.clone(),
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn keeps_discriminant_copy_when_it_has_a_later_read() {
        let source = VReg::phys("state");
        let temporary = VReg::phys("switch_value");
        let guarded_value = unsigned(4, Expr::Reg(source));
        let discriminant_value = unsigned(8, guarded_value.clone());
        let assignment = Stmt::Assign {
            dst: temporary.clone(),
            src: discriminant_value,
        };
        let guarded = Stmt::If {
            cond: Expr::Cmp {
                op: CmpOp::Ule,
                lhs: Box::new(guarded_value),
                rhs: Box::new(Expr::Const(1)),
            },
            then_body: vec![Stmt::Switch {
                discriminant: Expr::Reg(temporary.clone()),
                cases: vec![(Some(0), vec![Stmt::Nop]), (Some(1), vec![Stmt::Nop])],
                default: None,
            }],
            else_body: None,
        };
        let later_read = Stmt::Return {
            value: Some(Expr::Reg(temporary)),
        };
        let mut function = Function {
            name: "used_later".to_string(),
            entry_va: 0,
            body: vec![assignment.clone(), guarded.clone(), later_read.clone()],
        };

        collapse_range_guards(&mut function);

        assert_eq!(function.body, vec![assignment, guarded, later_read]);
    }

    #[test]
    fn recovered_width_proves_compiler_discriminant_cast_is_lossless() {
        let source = VReg::phys("state");
        let temporary = VReg::phys("switch_value");
        let discriminant_value = unsigned(8, unsigned(4, Expr::Reg(source.clone())));
        let switch = Stmt::Switch {
            discriminant: Expr::Reg(temporary.clone()),
            cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
            default: None,
        };
        let mut function = Function {
            name: "typed_state".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: temporary,
                    src: discriminant_value.clone(),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(Expr::Reg(source.clone())),
                        rhs: Box::new(Expr::Const(3)),
                    },
                    then_body: vec![switch],
                    else_body: None,
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            source,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        collapse_range_guards_with_types(&mut function, &types);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: discriminant_value,
                cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                default: None,
            }]
        );
    }

    #[test]
    fn recovered_width_equates_guard_widening_with_narrow_discriminant_copy() {
        // Clang -O0 materializes the 32-bit switch word into an eight-byte
        // stack slot, while its range guard keeps the canonical 64-bit parent
        // view. Both spell the same value when the recovered source is exactly
        // four bytes; the wider guard must not prevent switch recovery.
        let source = VReg::phys("local_18");
        let temporary = VReg::phys("local_28");
        let narrow = unsigned(4, Expr::Reg(source.clone()));
        let guarded_value = unsigned(8, unsigned(8, narrow.clone()));
        let mut function = Function {
            name: "clang_o0_guarded_switch".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(temporary.clone()),
                    src: narrow,
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(guarded_value),
                        rhs: Box::new(Expr::Const(3)),
                    },
                    then_body: vec![Stmt::Switch {
                        discriminant: Expr::Reg(temporary),
                        cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                        default: None,
                    }],
                    else_body: None,
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            source.clone(),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        collapse_range_guards_with_types(&mut function, &types);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(Expr::Reg(source)),
                },
                cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                default: None,
            }]
        );
    }

    #[test]
    fn recovered_wide_source_rejects_narrowing_discriminant_cast() {
        let source = VReg::phys("wide_state");
        let temporary = VReg::phys("switch_value");
        let assignment = Stmt::Assign {
            dst: temporary.clone(),
            src: unsigned(4, Expr::Reg(source.clone())),
        };
        let guarded = Stmt::If {
            cond: Expr::Cmp {
                op: CmpOp::Ule,
                lhs: Box::new(Expr::Reg(source.clone())),
                rhs: Box::new(Expr::Const(3)),
            },
            then_body: vec![Stmt::Switch {
                discriminant: Expr::Reg(temporary),
                cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                default: None,
            }],
            else_body: None,
        };
        let mut function = Function {
            name: "wide_state".to_string(),
            entry_va: 0,
            body: vec![assignment.clone(), guarded.clone()],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            source,
            TypeHint::Int {
                signed: false,
                width: 8,
            },
        );

        collapse_range_guards_with_types(&mut function, &types);

        assert_eq!(function.body, vec![assignment, guarded]);
    }

    #[test]
    fn typed_promoted_stack_store_is_a_lossless_discriminant_copy() {
        let source = VReg::phys("local_18");
        let temporary = VReg::phys("local_28");
        let mut function = Function {
            name: "promoted_stack_state".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(temporary.clone()),
                    src: Expr::Reg(source.clone()),
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(Expr::Reg(source.clone())),
                        rhs: Box::new(Expr::Const(3)),
                    },
                    then_body: vec![Stmt::Switch {
                        discriminant: Expr::Reg(temporary),
                        cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                        default: None,
                    }],
                    else_body: None,
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            source.clone(),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        collapse_range_guards_with_types(&mut function, &types);

        assert_eq!(
            function.body,
            vec![Stmt::Switch {
                discriminant: Expr::Reg(source),
                cases: (0..=3).map(|case| (Some(case), vec![Stmt::Nop])).collect(),
                default: None,
            }]
        );
    }
}
