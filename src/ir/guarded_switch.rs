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
        let Some((mut switch, guarded_value)) = guarded_switch(&body[index]) else {
            index += 1;
            continue;
        };

        let Stmt::Switch { discriminant, .. } = &mut switch else {
            unreachable!("guarded_switch only returns switch statements")
        };
        if is_unsigned_extension_of(discriminant, &guarded_value, types) {
            body[index] = switch;
            index += 1;
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
        body[index] = switch;
        body.remove(index - 1);
        // The replacement moved left by one. Continue after it.
    }
}

/// Return the sole switch and its guarded unsigned view when eliminating the
/// wrapper is semantically justified by the case domain.
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
        | Stmt::Comment(_) => 0,
    }
}

fn count_reads_in_expr(expr: &Expr, target: &VReg) -> usize {
    match expr {
        Expr::Reg(register) => usize::from(register == target),
        Expr::Deref { addr, .. } | Expr::Un { src: addr, .. } | Expr::Cast { expr: addr, .. } => {
            count_reads_in_expr(addr, target)
        }
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
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            usize::from(base.as_ref() == Some(target)) + usize::from(index.as_ref() == Some(target))
        }
        Expr::StackAddr { object, .. } => usize::from(object == target),
        Expr::Const(_)
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
