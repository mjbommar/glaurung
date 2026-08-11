//! Recover explicit value edges around conditionally executed calls.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{CmpOp, VReg};

/// Make a guarded call overwrite's proven zero-valued false edge explicit.
///
/// A lazy source select such as `value ? transform(value) : 0` commonly lowers
/// to a one-sided conditional call: the surviving register already contains
/// `value`, and only the nonzero edge overwrites it with the call result. The
/// one-sided AST is semantically correct, but it hides the false-edge reaching
/// definition and loses the source diamond. When the guard is the exact
/// full-value comparison `destination != 0`, the fallthrough value is proven
/// to be zero. Materializing that assignment preserves call laziness and makes
/// both reaching values explicit without guessing an unobserved default.
pub fn materialize_false_edges(function: &mut Function) {
    materialize_body(&mut function.body);
}

fn materialize_body(body: &mut [Stmt]) {
    for index in 0..body.len() {
        visit_children(&mut body[index]);

        let Some(destination) = guarded_update_destination(&body[index]) else {
            continue;
        };
        let Stmt::If { cond, .. } = &body[index] else {
            unreachable!("guarded_update_destination accepts only if statements");
        };
        if !false_edge_proves_zero(&body[..index], cond, &destination) {
            continue;
        }
        let Stmt::If { else_body, .. } = &mut body[index] else {
            unreachable!("guarded_update_destination accepts only if statements");
        };
        *else_body = Some(vec![Stmt::Assign {
            dst: destination,
            src: Expr::Const(0),
        }]);
    }
}

fn visit_children(statement: &mut Stmt) {
    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            materialize_body(then_body);
            if let Some(else_body) = else_body {
                materialize_body(else_body);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            materialize_body(body);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, case_body) in cases {
                materialize_body(case_body);
            }
            if let Some(default_body) = default {
                materialize_body(default_body);
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            materialize_body(try_body);
            for catch in catches {
                materialize_body(&mut catch.body);
            }
        }
        _ => {}
    }
}

fn guarded_update_destination(statement: &Stmt) -> Option<VReg> {
    let Stmt::If {
        then_body,
        else_body: None,
        ..
    } = statement
    else {
        return None;
    };
    let [Stmt::Call {
        dst: Some(call_result),
        ..
    }, Stmt::Assign {
        dst: destination,
        src: copied_result,
    }] = then_body.as_slice()
    else {
        return None;
    };
    matches!(strip_integer_views(copied_result), Expr::Reg(register) if register == call_result)
        .then(|| destination.clone())
}

fn strip_integer_views(expression: &Expr) -> &Expr {
    match expression {
        Expr::Cast { expr, .. } => strip_integer_views(expr),
        _ => expression,
    }
}

fn false_edge_proves_zero(prefix: &[Stmt], condition: &Expr, destination: &VReg) -> bool {
    let Expr::Cmp {
        op: CmpOp::Ne,
        lhs,
        rhs,
    } = condition
    else {
        return false;
    };
    let tested = match (lhs.as_ref(), rhs.as_ref()) {
        (tested, Expr::Const(0)) | (Expr::Const(0), tested) => tested,
        _ => return false,
    };
    if matches!(tested, Expr::Reg(register) if register == destination) {
        return true;
    }

    // A distinct source value is accepted only when the nearest straight-line
    // definition copied the exact tested expression into the destination. An
    // intervening control-flow construct makes lexical order insufficient, so
    // the query fails closed instead of pretending the structured AST is SSA.
    for statement in prefix.iter().rev() {
        match statement {
            Stmt::Assign { dst, src } if dst == destination => return src == tested,
            Stmt::Call { dst: Some(dst), .. } | Stmt::Pop { target: dst } if dst == destination => {
                return false;
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                ..
            } if dst == destination => return false,
            Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::TryCatch { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Return { .. }
            | Stmt::Throw { .. }
            | Stmt::Break
            | Stmt::Unknown(_) => return false,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn assign(dst: &str, src: Expr) -> Stmt {
        Stmt::Assign { dst: reg(dst), src }
    }

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "guarded_call".into(),
            entry_va: 0x1000,
            body,
        }
    }

    fn guarded_update(condition: Expr) -> Stmt {
        Stmt::If {
            cond: condition,
            then_body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "transform".into(),
                    },
                    args: vec![Expr::Reg(reg("value"))],
                    dst: Some(reg("call_result")),
                    call_spec: None,
                },
                assign("value", Expr::Reg(reg("call_result"))),
            ],
            else_body: None,
        }
    }

    #[test]
    fn materializes_a_proven_false_edge() {
        let value = reg("value");
        let mut f = function(vec![
            assign("value", Expr::Reg(reg("input"))),
            guarded_update(Expr::Cmp {
                op: CmpOp::Ne,
                lhs: Box::new(Expr::Reg(value.clone())),
                rhs: Box::new(Expr::Const(0)),
            }),
            Stmt::Store {
                addr: Expr::Reg(reg("output")),
                src: Expr::Reg(value.clone()),
                size: 4,
            },
        ]);

        materialize_false_edges(&mut f);

        let Stmt::If {
            else_body: Some(else_body),
            ..
        } = &f.body[1]
        else {
            panic!("guarded call kept an implicit false edge: {:#?}", f.body);
        };
        assert_eq!(
            else_body,
            &[Stmt::Assign {
                dst: value,
                src: Expr::Const(0),
            }]
        );

        let mut copied_source = function(vec![
            assign("value", Expr::Reg(reg("input"))),
            guarded_update(Expr::Cmp {
                op: CmpOp::Ne,
                lhs: Box::new(Expr::Reg(reg("input"))),
                rhs: Box::new(Expr::Const(0)),
            }),
        ]);
        materialize_false_edges(&mut copied_source);
        assert!(matches!(
            copied_source.body.as_slice(),
            [
                Stmt::Assign { .. },
                Stmt::If {
                    else_body: Some(else_body),
                    ..
                }
            ] if else_body == &[assign("value", Expr::Const(0))]
        ));
    }

    #[test]
    fn refuses_unproven_false_edges() {
        let nonzero_false_edge = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(reg("value"))),
            rhs: Box::new(Expr::Const(1)),
        };
        let mut wrong_constant = function(vec![guarded_update(nonzero_false_edge)]);
        let wrong_constant_before = wrong_constant.clone();
        materialize_false_edges(&mut wrong_constant);
        assert_eq!(wrong_constant, wrong_constant_before);

        let source_zero_guard = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(reg("input"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let mut control_flow_barrier = function(vec![
            assign("value", Expr::Reg(reg("input"))),
            Stmt::If {
                cond: Expr::Reg(reg("unknown")),
                then_body: vec![],
                else_body: None,
            },
            guarded_update(source_zero_guard),
        ]);
        let barrier_before = control_flow_barrier.clone();
        materialize_false_edges(&mut control_flow_barrier);
        assert_eq!(control_flow_barrier, barrier_before);
    }
}
