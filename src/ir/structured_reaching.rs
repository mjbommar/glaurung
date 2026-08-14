//! Fail-closed reaching-write queries over the structured AST.
//!
//! These predicates do not rewrite the AST and do not assume physical names
//! are globally SSA. Joins union a monotone may-write state, and loops are
//! checked at their boolean fixed point so a later iteration can observe a
//! write from an earlier one.

mod return_type;

pub(crate) use return_type::{returned_role_integer_fact, ReturnedIntegerFact};

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
        return unstructured_has_both_events(body, read_value, written_value);
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
            // A promoted local is still spelled as `store &local = value` at
            // this stage. Count that as a definition of the local. The exact
            // `local = arg` home initializer is the alias-establishing copy,
            // not a mutation; later stores to the same local are mutations
            // whose effect can reach subsequent reads of the original arg.
            let writes_promoted_value =
                matches!(addr, Expr::Reg(register) if register == written_value);
            let establishes_home = writes_promoted_value
                && matches!(src, Expr::Reg(register) if register == read_value);
            written |= writes_promoted_value && !establishes_home;
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
        Expr::Call { target, args, .. } => {
            expression_reads(target, value)
                || args
                    .iter()
                    .any(|argument| expression_reads(argument, value))
        }
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
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => expression_reads(src, value),
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

fn unstructured_has_both_events(body: &[Stmt], read: &VReg, written: &VReg) -> bool {
    fn scan(body: &[Stmt], read: &VReg, written: &VReg, events: &mut (bool, bool)) {
        for statement in body {
            match statement {
                Stmt::Assign { dst, src } => {
                    events.0 |= dst == written;
                    events.1 |= expression_reads(src, read);
                }
                Stmt::Store { addr, src, .. } => {
                    // `home = arg` establishes the alias under consideration;
                    // it is neither a conflicting mutation nor an independent
                    // read. Treating it as both made every goto-containing
                    // parameter home fail closed before any real conflict.
                    if matches!(addr, Expr::Reg(register) if register == written)
                        && matches!(src, Expr::Reg(register) if register == read)
                    {
                        continue;
                    }
                    events.0 |= matches!(addr, Expr::Reg(register) if register == written);
                    events.1 |= (!matches!(addr, Expr::Reg(register) if register == read)
                        && expression_reads(addr, read))
                        || expression_reads(src, read);
                }
                Stmt::Call {
                    target, args, dst, ..
                } => {
                    events.0 |= dst.as_ref() == Some(written);
                    events.1 |= expression_reads(target, read)
                        || args.iter().any(|argument| expression_reads(argument, read));
                }
                Stmt::Return { value } => {
                    events.1 |= value
                        .as_ref()
                        .is_some_and(|expression| expression_reads(expression, read));
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    events.1 |= expression_reads(cond, read);
                    scan(then_body, read, written, events);
                    if let Some(else_body) = else_body {
                        scan(else_body, read, written, events);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                    events.1 |= expression_reads(cond, read);
                    scan(body, read, written, events);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    scan(std::slice::from_ref(init.as_ref()), read, written, events);
                    events.1 |= expression_reads(cond, read);
                    scan(body, read, written, events);
                    scan(std::slice::from_ref(step.as_ref()), read, written, events);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    events.1 |= expression_reads(discriminant, read);
                    for (_, body) in cases {
                        scan(body, read, written, events);
                    }
                    if let Some(default) = default {
                        scan(default, read, written, events);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    scan(try_body, read, written, events);
                    for catch in catches {
                        events.0 |= &catch.binding == written;
                        scan(&catch.body, read, written, events);
                    }
                }
                Stmt::Pop { target } => events.0 |= target == written,
                Stmt::Push { value } | Stmt::Throw { value } => {
                    events.1 |= expression_reads(value, read)
                }
                Stmt::IndirectGoto { target } => events.1 |= expression_reads(target, read),
                Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_) => {}
            }
            if events.0 && events.1 {
                return;
            }
        }
    }

    let mut events = (false, false);
    scan(body, read, written, &mut events);
    events.0 && events.1
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

    #[test]
    fn a_promoted_home_reassignment_reaches_a_later_read_of_the_original_argument() {
        let body = vec![
            Stmt::Store {
                addr: Expr::Reg(reg("home")),
                src: Expr::Reg(reg("arg0")),
                size: 4,
            },
            Stmt::Store {
                addr: Expr::Reg(reg("home")),
                src: Expr::Const(7),
                size: 4,
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("arg0"))),
            },
        ];

        assert!(read_may_observe_prior_write(
            &body,
            &reg("arg0"),
            &reg("home")
        ));
    }

    #[test]
    fn an_unstructured_home_initializer_alone_is_not_a_conflicting_write() {
        let body = vec![
            Stmt::Label(0x1000),
            Stmt::Store {
                addr: Expr::Reg(reg("home")),
                src: Expr::Reg(reg("arg0")),
                size: 4,
            },
            Stmt::Goto { target: 0x1000 },
            Stmt::Return {
                value: Some(Expr::Reg(reg("arg0"))),
            },
        ];

        assert!(!read_may_observe_prior_write(
            &body,
            &reg("arg0"),
            &reg("home")
        ));
    }

    #[test]
    fn an_unstructured_home_mutation_and_argument_read_fail_closed() {
        let body = vec![
            Stmt::Label(0x1000),
            Stmt::Store {
                addr: Expr::Reg(reg("home")),
                src: Expr::Reg(reg("arg0")),
                size: 4,
            },
            Stmt::Store {
                addr: Expr::Reg(reg("home")),
                src: Expr::Const(7),
                size: 4,
            },
            Stmt::Goto { target: 0x1000 },
            Stmt::Return {
                value: Some(Expr::Reg(reg("arg0"))),
            },
        ];

        assert!(read_may_observe_prior_write(
            &body,
            &reg("arg0"),
            &reg("home")
        ));
    }
}
