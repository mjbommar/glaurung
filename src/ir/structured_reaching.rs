//! Fail-closed reaching-write queries over the structured AST.
//!
//! These predicates do not rewrite the AST and do not assume physical names
//! are globally SSA. Joins union a monotone may-write state, and loops are
//! checked at their boolean fixed point so a later iteration can observe a
//! write from an earlier one.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Outcome {
    written: bool,
    observed: bool,
}

/// Whether a read of `read_value` may execute after `written_value` is written.
///
/// A `Store` whose address is exactly `read_value` is the promoted-local
/// assignment spelling, not a read. Unstructured label/goto bodies are rejected
/// conservatively when they contain both events because lexical order cannot
/// represent their backedges.
pub fn read_may_observe_prior_write(
    body: &[Stmt],
    read_value: &VReg,
    written_value: &VReg,
) -> bool {
    if contains_unstructured_control(body) {
        return body_writes(body, written_value) && body_reads(body, read_value);
    }
    analyze_body(body, read_value, written_value, false).observed
}

fn analyze_body(
    body: &[Stmt],
    read_value: &VReg,
    written_value: &VReg,
    initially_written: bool,
) -> Outcome {
    body.iter().fold(
        Outcome {
            written: initially_written,
            observed: false,
        },
        |mut accumulated, statement| {
            let next = analyze_statement(statement, read_value, written_value, accumulated.written);
            accumulated.written = next.written;
            accumulated.observed |= next.observed;
            accumulated
        },
    )
}

fn analyze_loop(
    body: &[Stmt],
    read_value: &VReg,
    written_value: &VReg,
    initially_written: bool,
) -> Outcome {
    let first = analyze_body(body, read_value, written_value, initially_written);
    if first.observed || first.written == initially_written {
        return first;
    }
    // The state is boolean and monotone, so this is the complete fixed point.
    let second = analyze_body(body, read_value, written_value, true);
    Outcome {
        written: true,
        observed: second.observed,
    }
}

fn observed(expression: &Expr, read_value: &VReg, written: bool) -> bool {
    written && expression_reads(expression, read_value)
}

fn analyze_statement(
    statement: &Stmt,
    read_value: &VReg,
    written_value: &VReg,
    initially_written: bool,
) -> Outcome {
    let mut written = initially_written;
    let mut saw_read = false;
    match statement {
        Stmt::Assign { dst, src } => {
            saw_read |= observed(src, read_value, written);
            written |= dst == written_value;
        }
        Stmt::Store { addr, src, .. } => {
            if !matches!(addr, Expr::Reg(register) if register == read_value) {
                saw_read |= observed(addr, read_value, written);
            }
            saw_read |= observed(src, read_value, written);
        }
        Stmt::Call {
            target, args, dst, ..
        } => {
            saw_read |= observed(target, read_value, written);
            saw_read |= args
                .iter()
                .any(|argument| observed(argument, read_value, written));
            written |= dst.as_ref() == Some(written_value);
        }
        Stmt::Return { value } => {
            saw_read |= value
                .as_ref()
                .is_some_and(|value| observed(value, read_value, written));
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            saw_read |= observed(cond, read_value, written);
            let then_outcome = analyze_body(then_body, read_value, written_value, written);
            let else_outcome = else_body.as_deref().map_or(
                Outcome {
                    written,
                    observed: false,
                },
                |body| analyze_body(body, read_value, written_value, written),
            );
            written = then_outcome.written || else_outcome.written;
            saw_read |= then_outcome.observed || else_outcome.observed;
        }
        Stmt::While { cond, body } => {
            saw_read |= observed(cond, read_value, written);
            let loop_outcome = analyze_loop(body, read_value, written_value, written);
            written |= loop_outcome.written;
            saw_read |= loop_outcome.observed || observed(cond, read_value, written);
        }
        Stmt::DoWhile { body, cond } => {
            let loop_outcome = analyze_loop(body, read_value, written_value, written);
            written |= loop_outcome.written;
            saw_read |= loop_outcome.observed || observed(cond, read_value, written);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            let init_outcome = analyze_statement(init, read_value, written_value, written);
            written = init_outcome.written;
            saw_read |= init_outcome.observed || observed(cond, read_value, written);
            let first_body = analyze_body(body, read_value, written_value, written);
            let first_step = analyze_statement(step, read_value, written_value, first_body.written);
            let iteration_written = first_step.written;
            saw_read |= first_body.observed || first_step.observed;
            if iteration_written && !written {
                let second_body = analyze_body(body, read_value, written_value, true);
                let second_step =
                    analyze_statement(step, read_value, written_value, second_body.written);
                saw_read |= second_body.observed || second_step.observed;
            }
            written |= iteration_written;
            saw_read |= observed(cond, read_value, written);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            saw_read |= observed(discriminant, read_value, written);
            let mut exits = cases
                .iter()
                .map(|(_, body)| analyze_body(body, read_value, written_value, written))
                .collect::<Vec<_>>();
            exits.push(default.as_deref().map_or(
                Outcome {
                    written,
                    observed: false,
                },
                |body| analyze_body(body, read_value, written_value, written),
            ));
            written = exits.iter().any(|outcome| outcome.written);
            saw_read |= exits.iter().any(|outcome| outcome.observed);
        }
        Stmt::TryCatch { try_body, catches } => {
            let try_outcome = analyze_body(try_body, read_value, written_value, written);
            let catch_entry = written || try_outcome.written;
            written = try_outcome.written;
            saw_read |= try_outcome.observed;
            for catch in catches {
                let catch_outcome =
                    analyze_body(&catch.body, read_value, written_value, catch_entry);
                written |= catch_outcome.written;
                saw_read |= catch_outcome.observed;
            }
        }
        Stmt::Push { value } | Stmt::Throw { value } => {
            saw_read |= observed(value, read_value, written);
        }
        Stmt::Pop { target } => written |= target == written_value,
        Stmt::IndirectGoto { target } => {
            saw_read |= observed(target, read_value, written);
        }
        Stmt::Label(_)
        | Stmt::Goto { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
    Outcome {
        written,
        observed: saw_read,
    }
}

fn expression_reads(expression: &Expr, value: &VReg) -> bool {
    match expression {
        Expr::Reg(register) => register == value,
        Expr::StackAddr { object, .. } => object == value,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref() == Some(value) || index.as_ref() == Some(value)
        }
        Expr::Deref { addr, .. } => expression_reads(addr, value),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expression_reads(lhs, value) || expression_reads(rhs, value)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expression_reads(cond, value)
                || expression_reads(if_true, value)
                || expression_reads(if_false, value)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => expression_reads(src, value),
        Expr::FunctionTableEntry { index, .. } => expression_reads(index, value),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|argument| expression_reads(argument, value)),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn body_writes(body: &[Stmt], value: &VReg) -> bool {
    fn statement_writes(statement: &Stmt, value: &VReg) -> bool {
        match statement {
            Stmt::Assign { dst, .. } => dst == value,
            Stmt::Call { dst, .. } => dst.as_ref() == Some(value),
            Stmt::Pop { target } => target == value,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                body_writes(then_body, value)
                    || else_body
                        .as_deref()
                        .is_some_and(|body| body_writes(body, value))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body_writes(body, value),
            Stmt::For {
                init, step, body, ..
            } => {
                statement_writes(init, value)
                    || body_writes(body, value)
                    || statement_writes(step, value)
            }
            Stmt::Switch { cases, default, .. } => {
                cases.iter().any(|(_, body)| body_writes(body, value))
                    || default
                        .as_deref()
                        .is_some_and(|body| body_writes(body, value))
            }
            Stmt::TryCatch { try_body, catches } => {
                body_writes(try_body, value)
                    || catches.iter().any(|catch| body_writes(&catch.body, value))
            }
            _ => false,
        }
    }
    body.iter()
        .any(|statement| statement_writes(statement, value))
}

fn body_reads(body: &[Stmt], value: &VReg) -> bool {
    fn statement_reads(statement: &Stmt, value: &VReg) -> bool {
        match statement {
            Stmt::Assign { src, .. } => expression_reads(src, value),
            Stmt::Store { addr, src, .. } => {
                (!matches!(addr, Expr::Reg(register) if register == value)
                    && expression_reads(addr, value))
                    || expression_reads(src, value)
            }
            Stmt::Call { target, args, .. } => {
                expression_reads(target, value)
                    || args
                        .iter()
                        .any(|argument| expression_reads(argument, value))
            }
            Stmt::Return { value: Some(expr) }
            | Stmt::Push { value: expr }
            | Stmt::Throw { value: expr }
            | Stmt::IndirectGoto { target: expr } => expression_reads(expr, value),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expression_reads(cond, value)
                    || body_reads(then_body, value)
                    || else_body
                        .as_deref()
                        .is_some_and(|body| body_reads(body, value))
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                expression_reads(cond, value) || body_reads(body, value)
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                statement_reads(init, value)
                    || expression_reads(cond, value)
                    || statement_reads(step, value)
                    || body_reads(body, value)
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                expression_reads(discriminant, value)
                    || cases.iter().any(|(_, body)| body_reads(body, value))
                    || default
                        .as_deref()
                        .is_some_and(|body| body_reads(body, value))
            }
            Stmt::TryCatch { try_body, catches } => {
                body_reads(try_body, value)
                    || catches.iter().any(|catch| body_reads(&catch.body, value))
            }
            _ => false,
        }
    }
    body.iter()
        .any(|statement| statement_reads(statement, value))
}

fn contains_unstructured_control(body: &[Stmt]) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Label(_) | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            contains_unstructured_control(then_body)
                || else_body
                    .as_deref()
                    .is_some_and(contains_unstructured_control)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            contains_unstructured_control(body)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| contains_unstructured_control(body))
                || default
                    .as_deref()
                    .is_some_and(contains_unstructured_control)
        }
        Stmt::TryCatch { try_body, catches } => {
            contains_unstructured_control(try_body)
                || catches
                    .iter()
                    .any(|catch| contains_unstructured_control(&catch.body))
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn read_home() -> Stmt {
        Stmt::Assign {
            dst: reg("sink"),
            src: Expr::Reg(reg("home")),
        }
    }

    fn write_value() -> Stmt {
        Stmt::Assign {
            dst: reg("value"),
            src: Expr::Const(1),
        }
    }

    #[test]
    fn linear_order_distinguishes_reads_before_and_after_a_write() {
        assert!(!read_may_observe_prior_write(
            &[read_home(), write_value()],
            &reg("home"),
            &reg("value")
        ));
        assert!(read_may_observe_prior_write(
            &[write_value(), read_home()],
            &reg("home"),
            &reg("value")
        ));
    }

    #[test]
    fn a_join_carries_a_possible_write_to_a_following_read() {
        let body = vec![
            Stmt::If {
                cond: Expr::Reg(reg("predicate")),
                then_body: vec![write_value()],
                else_body: Some(Vec::new()),
            },
            read_home(),
        ];
        assert!(read_may_observe_prior_write(
            &body,
            &reg("home"),
            &reg("value")
        ));
    }

    #[test]
    fn a_loop_read_observes_a_write_from_the_prior_iteration() {
        let body = vec![Stmt::While {
            cond: Expr::Reg(reg("predicate")),
            body: vec![read_home(), write_value()],
        }];
        assert!(read_may_observe_prior_write(
            &body,
            &reg("home"),
            &reg("value")
        ));
    }
}
