//! Type-directed simplification at C value-consumption boundaries.
//!
//! Lossless lifting keeps architectural parent-register extensions in the AST.
//! Once declarations are recovered, a narrow C destination can prove that some
//! of those high bits are unobservable. This module owns those late, typed
//! proofs so the generic algebraic folder remains type-independent.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{is_promoted_local_reg, BinOp, VReg};
use crate::ir::types_recover::TypeMap;

/// Remove machine-parent zero extensions that a recovered narrow destination
/// cannot observe inside modular arithmetic.
///
/// Canonical x86 lowering retains `zext64(zext32(x))` even when the next
/// operation is stored back to a four-byte frame object. For add/sub/mul and
/// bitwise operations, the low N bits depend only on the low N bits of their
/// operands. Replacing `zextW(zextN(x))` with the inner *unsigned* N-bit view is
/// therefore exact and keeps C arithmetic defined modulo 2^N. Lone extensions,
/// signed inner views, division, and shifts remain untouched.
pub fn fold_consumed_extensions(function: &mut Function, types: &TypeMap) {
    fold_body(&mut function.body, types);
}

fn narrow_machine_parent(expression: &mut Expr, observed_width: u8) {
    let replacement = match expression {
        Expr::Cast {
            signed: false,
            width: outer_width,
            expr: inner,
        } if *outer_width > observed_width => match inner.as_ref() {
            inner_cast @ Expr::Cast {
                signed: false,
                width: inner_width,
                ..
            } if *inner_width == observed_width => Some(inner_cast.clone()),
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = replacement {
        *expression = replacement;
    }
}

fn fold_modular_expression(expression: &mut Expr, observed_width: u8) {
    let Expr::Bin { op, lhs, rhs } = expression else {
        return;
    };
    if !matches!(
        op,
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    ) {
        return;
    }
    fold_modular_expression(lhs, observed_width);
    fold_modular_expression(rhs, observed_width);
    narrow_machine_parent(lhs, observed_width);
    narrow_machine_parent(rhs, observed_width);
}

fn destination_width(register: &VReg, types: &TypeMap) -> Option<u8> {
    let VReg::Phys(name) = register else {
        return None;
    };
    crate::ir::ast::declared_int_type(name, Some(types)).map(|(_, width)| width)
}

fn fold_body(statements: &mut [Stmt], types: &TypeMap) {
    for statement in statements {
        match statement {
            Stmt::Assign { dst, src } => {
                if let Some(width) = destination_width(dst, types) {
                    fold_modular_expression(src, width);
                }
            }
            Stmt::Store {
                addr: Expr::Reg(destination),
                src,
                ..
            } if is_promoted_local_reg(destination) => {
                if let Some(width) = destination_width(destination, types) {
                    fold_modular_expression(src, width);
                }
            }
            Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_body(then_body, types);
                if let Some(else_body) = else_body {
                    fold_body(else_body, types);
                }
            }
            Stmt::While {
                body: loop_body, ..
            }
            | Stmt::DoWhile {
                body: loop_body, ..
            } => fold_body(loop_body, types),
            Stmt::For {
                init,
                step,
                body: loop_body,
                ..
            } => {
                fold_body(std::slice::from_mut(init.as_mut()), types);
                fold_body(loop_body, types);
                fold_body(std::slice::from_mut(step.as_mut()), types);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_body(case_body, types);
                }
                if let Some(default_body) = default {
                    fold_body(default_body, types);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                fold_body(try_body, types);
                for catch in catches {
                    fold_body(&mut catch.body, types);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types_recover::TypeHint;

    #[test]
    fn narrow_destination_consumes_machine_only_operand_extension() {
        let local = VReg::phys("local_c");
        let mut function = Function {
            name: "sum".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: Expr::Reg(local.clone()),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Deref {
                                addr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                                size: 4,
                            }),
                        }),
                    }),
                    rhs: Box::new(Expr::Reg(local.clone())),
                },
                // Canonical parent-register lowering can retain a machine-word
                // store even though the recovered frame object is an int.
                size: 8,
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            local,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        fold_consumed_extensions(&mut function, &types);

        assert!(
            matches!(
                &function.body[0],
                Stmt::Store {
                    src: Expr::Bin { lhs, .. },
                    ..
                } if matches!(lhs.as_ref(), Expr::Cast { width: 4, .. })
            ),
            "the four-byte destination must consume the low word directly: {function:#?}"
        );
    }
}
