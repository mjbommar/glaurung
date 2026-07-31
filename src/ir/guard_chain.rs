//! Recovery of source-level short-circuit validation guards.

use std::collections::HashMap;

use crate::ir::ast::{negate_cmp_expr, Expr, Function, Stmt};
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
    matches!(
        condition,
        Expr::Cmp {
            op: CmpOp::Eq | CmpOp::Ne | CmpOp::Ult | CmpOp::Ule | CmpOp::Slt | CmpOp::Sle,
            ..
        }
    )
    .then(|| negate_cmp_expr(condition))
}

#[cfg(test)]
mod tests {
    use crate::ir::ast::{render_decbench, Expr, Function, Stmt};
    use crate::ir::types::VReg;

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
}
