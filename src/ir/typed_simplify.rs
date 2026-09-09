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
    fold_consumed_extensions_with_identities(function, types, None);
}

/// Remove consumed extensions using exact opaque SSA identities when available.
pub fn fold_consumed_extensions_with_identities(
    function: &mut Function,
    types: &TypeMap,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    fold_body(&mut function.body, types, identities);
}

fn narrow_machine_parent(expression: &mut Expr, observed_width: u8) {
    let replacement = match expression.semantic() {
        Expr::Cast {
            signed: false,
            width: outer_width,
            expr: inner,
        } if *outer_width > observed_width => match inner.semantic() {
            inner_cast @ Expr::Cast {
                signed: false,
                width: inner_width,
                ..
            } if *inner_width == observed_width => {
                let origins = expression
                    .origins()
                    .cloned()
                    .unwrap_or_default()
                    .union(&inner.origins().cloned().unwrap_or_default());
                Some(
                    inner_cast
                        .clone()
                        .with_optional_origins((!origins.is_empty()).then_some(origins)),
                )
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = replacement {
        *expression = replacement;
    }
}

fn fold_modular_expression(expression: &mut Expr, observed_width: u8) {
    if let Expr::Origin { expr, .. } = expression {
        fold_modular_expression(expr, observed_width);
        return;
    }
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

fn destination_width(
    register: &VReg,
    types: &TypeMap,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<u8> {
    let VReg::Phys(name) = register else {
        return None;
    };
    crate::ir::ast::declared_int_type_with_identities(name, Some(types), identities)
        .map(|(_, width)| width)
}

fn fold_body(
    statements: &mut [Stmt],
    types: &TypeMap,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    for statement in statements {
        match statement.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, src } => {
                if let Some(width) = destination_width(dst, types, identities) {
                    fold_modular_expression(src, width);
                }
            }
            Stmt::Store {
                addr: Expr::Reg(destination),
                src,
                ..
            } => {
                let promoted = identities.map_or_else(
                    || is_promoted_local_reg(destination),
                    |identities| identities.is_promoted_stack_object(destination),
                );
                if promoted {
                    if let Some(width) = destination_width(destination, types, identities) {
                        fold_modular_expression(src, width);
                    }
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
                fold_body(then_body, types, identities);
                if let Some(else_body) = else_body {
                    fold_body(else_body, types, identities);
                }
            }
            Stmt::While {
                body: loop_body, ..
            }
            | Stmt::DoWhile {
                body: loop_body, ..
            } => fold_body(loop_body, types, identities),
            Stmt::For {
                init,
                step,
                body: loop_body,
                ..
            } => {
                fold_body(std::slice::from_mut(init.as_mut()), types, identities);
                fold_body(loop_body, types, identities);
                fold_body(std::slice::from_mut(step.as_mut()), types, identities);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_body(case_body, types, identities);
                }
                if let Some(default_body) = default {
                    fold_body(default_body, types, identities);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                fold_body(try_body, types, identities);
                for catch in catches {
                    fold_body(&mut catch.body, types, identities);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::OriginSet;
    use crate::ir::types_recover::TypeHint;

    fn extended_add(destination: VReg) -> Function {
        Function {
            name: "sum".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: destination.clone(),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        }),
                    }),
                    rhs: Box::new(Expr::Reg(destination)),
                },
            }],
        }
    }

    fn extended_store(destination: VReg) -> Function {
        Function {
            name: "sum".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: Expr::Reg(destination.clone()),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        }),
                    }),
                    rhs: Box::new(Expr::Reg(destination)),
                },
                size: 8,
            }],
        }
    }

    fn int32_type(types: &mut TypeMap, destination: VReg) {
        types.upsert_public(
            destination,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
    }

    #[test]
    fn identity_owned_opaque_promoted_store_consumes_machine_extension() {
        let object_name = "frame_object".to_string();
        let destination = VReg::phys(&object_name);
        let mut function = extended_store(destination.clone());
        let mut types = TypeMap::default();
        int32_type(&mut types, destination.clone());
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.attach_promoted_stack_objects([&object_name]);

        fold_consumed_extensions_with_identities(&mut function, &types, Some(&identities));

        assert!(matches!(
            &function.body[0],
            Stmt::Store {
                src: Expr::Bin { lhs, .. },
                ..
            } if matches!(lhs.as_ref(), Expr::Cast { width: 4, .. })
        ));
    }

    #[test]
    fn identity_unowned_local_spelling_keeps_machine_extension() {
        let destination = VReg::phys("local_looks_promoted");
        let mut function = extended_store(destination.clone());
        let before = function.clone();
        let mut types = TypeMap::default();
        int32_type(&mut types, destination.clone());
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            destination,
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rax"),
                version: 3,
            },
        );

        fold_consumed_extensions_with_identities(&mut function, &types, Some(&identities));

        assert_eq!(function, before);
    }

    #[test]
    fn exact_opaque_destination_consumes_machine_only_extension() {
        let destination = VReg::phys("opaque_destination");
        let mut function = extended_add(destination.clone());
        let mut types = TypeMap::default();
        types.upsert_public(
            destination.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            destination,
            crate::ir::ssa::SsaValue {
                base: VReg::phys("eax"),
                version: 2,
            },
        );

        fold_consumed_extensions_with_identities(&mut function, &types, Some(&identities));

        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Bin { lhs, .. },
                ..
            } if matches!(lhs.as_ref(), Expr::Cast { width: 4, .. })
        ));
    }

    #[test]
    fn ambiguous_opaque_destination_keeps_machine_extension() {
        let destination = VReg::phys("opaque_destination");
        let mut function = extended_add(destination.clone());
        let before = function.clone();
        let mut types = TypeMap::default();
        types.upsert_public(
            destination.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        for (base, version) in [("eax", 1), ("ebx", 2)] {
            identities.record(
                destination.clone(),
                crate::ir::ssa::SsaValue {
                    base: VReg::phys(base),
                    version,
                },
            );
        }

        fold_consumed_extensions_with_identities(&mut function, &types, Some(&identities));

        assert_eq!(function, before);
    }

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

    #[test]
    fn attributed_machine_extension_folds_and_preserves_consumed_origins() {
        let destination = VReg::phys("local_c");
        let mut function = Function {
            name: "sum".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: destination.clone(),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(
                        Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(
                                Expr::Cast {
                                    signed: false,
                                    width: 4,
                                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                                }
                                .with_origins(OriginSet::one(0x1004)),
                            ),
                        }
                        .with_origins(OriginSet::one(0x1000)),
                    ),
                    rhs: Box::new(Expr::Reg(destination.clone())),
                }
                .with_origins(OriginSet::one(0x0ffc)),
            }],
        };
        let mut types = TypeMap::default();
        int32_type(&mut types, destination);

        fold_consumed_extensions(&mut function, &types);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected attributed modular assignment: {function:#?}");
        };
        assert_eq!(src.origins(), Some(&OriginSet::one(0x0ffc)));
        let Expr::Bin { lhs, .. } = src.semantic() else {
            panic!("expected modular expression: {function:#?}");
        };
        assert!(matches!(
            lhs.semantic(),
            Expr::Cast {
                signed: false,
                width: 4,
                ..
            }
        ));
        assert_eq!(lhs.origins(), Some(&OriginSet::from_iter([0x1000, 0x1004])));
    }
}
