use super::*;
use crate::ir::ast::{Expr, OriginSet, Stmt};
use crate::ir::types::{BinOp, CmpOp, VReg};

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn read(name: &str) -> Expr {
    Expr::Reg(reg(name))
}

fn opaque_carrier_candidate() -> (Function, VReg, VReg) {
    let seed = reg("opaque-seed");
    let carrier = reg("opaque-carrier");
    let function = Function {
        name: "opaque_carrier".to_string(),
        entry_va: 0x1100,
        body: vec![
            Stmt::Assign {
                dst: seed.clone(),
                src: Expr::Const(0),
            },
            Stmt::Assign {
                dst: carrier.clone(),
                src: Expr::Reg(seed.clone()),
            },
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: carrier.clone(),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(carrier.clone())),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }],
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Reg(carrier.clone())),
                    rhs: Box::new(read("limit")),
                },
            },
            Stmt::Return {
                value: Some(Expr::Reg(carrier.clone())),
            },
        ],
    };
    (function, seed, carrier)
}

fn candidate(extra: Vec<Stmt>) -> Function {
    let mut body = vec![
        Stmt::Assign {
            dst: reg("old"),
            src: read("current"),
        },
        Stmt::Assign {
            dst: reg("next"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(read("current")),
                rhs: Box::new(Expr::Const(1)),
            },
        },
    ];
    body.extend(extra);
    body.extend([
        Stmt::Assign {
            dst: reg("predicate"),
            src: Expr::Cmp {
                op: CmpOp::Ult,
                lhs: Box::new(read("next")),
                rhs: Box::new(read("current")),
            },
        },
        Stmt::Assign {
            dst: reg("current"),
            src: read("next"),
        },
    ]);
    Function {
        name: "iterative".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::DoWhile {
            body,
            cond: read("predicate"),
        }],
    }
}

#[test]
fn folds_predicate_across_final_carried_value_assignment() {
    let mut function = candidate(vec![]);
    let Stmt::DoWhile { body, cond } = &mut function.body[0] else {
        unreachable!()
    };
    let Stmt::Assign { src: snapshot, .. } = &mut body[0] else {
        unreachable!()
    };
    *snapshot = std::mem::replace(snapshot, Expr::Const(0)).with_origins(OriginSet::one(0x1014));
    let Stmt::Assign {
        src: predicate_expression,
        ..
    } = &mut body[2]
    else {
        unreachable!()
    };
    *predicate_expression = std::mem::replace(predicate_expression, Expr::Const(0))
        .with_origins(OriginSet::one(0x1018));
    *cond = std::mem::replace(cond, Expr::Const(0)).with_origins(OriginSet::one(0x101c));
    body[2] = std::mem::replace(&mut body[2], Stmt::Nop).with_origins(OriginSet::one(0x1010));
    function.body[0] =
        std::mem::replace(&mut function.body[0], Stmt::Nop).with_origins(OriginSet::one(0x1000));

    fold_latched_predicates(&mut function);

    let Stmt::DoWhile { body, cond } = function.body[0].semantic() else {
        panic!("expected do-while");
    };
    assert_eq!(body.len(), 3, "predicate assignment should be removed");
    assert_eq!(
        cond,
        &Expr::Cmp {
            op: CmpOp::Ult,
            lhs: Box::new(read("next")),
            rhs: Box::new(read("old")),
        }
        .with_origins(OriginSet::from_addresses([0x1018, 0x101c]))
    );
    let Stmt::Assign { src: snapshot, .. } = &body[0] else {
        panic!("expected saved-value copy")
    };
    assert_eq!(snapshot.semantic(), &read("current"));
    assert_eq!(snapshot.origins(), Some(&OriginSet::one(0x1014)));
    assert_eq!(
        function.body[0].origins(),
        Some(&OriginSet::from_addresses([0x1000, 0x1010]))
    );
}

#[test]
fn keeps_predicate_when_saved_value_is_overwritten() {
    let mut function = candidate(vec![Stmt::Assign {
        dst: reg("old"),
        src: Expr::Const(0),
    }]);
    let before = function.clone();

    fold_latched_predicates(&mut function);

    assert_eq!(function, before);
}

#[test]
fn keeps_predicate_when_attributed_next_value_is_the_saved_snapshot() {
    let mut function = candidate(vec![]);
    let Stmt::DoWhile { body, .. } = &mut function.body[0] else {
        unreachable!()
    };
    let Stmt::Assign { src, .. } = body.last_mut().expect("candidate tail") else {
        unreachable!()
    };
    *src = read("old").with_origins(OriginSet::one(0x1020));
    let before = function.clone();

    fold_latched_predicates(&mut function);

    assert_eq!(function, before);
}

#[test]
fn keeps_predicate_when_control_flow_can_bypass_the_snapshot() {
    let mut function = candidate(vec![Stmt::If {
        cond: read("guard"),
        then_body: vec![Stmt::Assign {
            dst: reg("next"),
            src: Expr::Const(0),
        }],
        else_body: None,
    }]);
    let before = function.clone();

    fold_latched_predicates(&mut function);

    assert_eq!(function, before);
}

#[test]
fn coalesces_dead_source_identity_with_immediately_entered_loop_carrier() {
    let mut function = Function {
        name: "carrier".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("var3"),
                src: Expr::Const(0),
            },
            Stmt::Assign {
                dst: reg("var5"),
                src: read("var3").with_origins(OriginSet::one(0x1024)),
            }
            .with_origins(OriginSet::one(0x1020)),
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("var5"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(read("var5")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }],
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(read("var5")),
                    rhs: Box::new(read("limit")),
                },
            }
            .with_origins(OriginSet::one(0x1030)),
            Stmt::Return {
                value: Some(read("var5")),
            },
        ],
    };

    let mut types = crate::ir::types_recover::TypeMap::default();
    types.upsert_public(
        reg("var3"),
        crate::ir::types_recover::TypeHint::Int {
            width: 8,
            signed: true,
        },
    );

    coalesce_loop_entry_copies(&mut function, &std::collections::HashSet::new(), &mut types);

    assert_eq!(function.body.len(), 3, "entry copy should be removed");
    let text = crate::ir::ast::render(&function);
    assert!(!text.contains("%var3"), "{text}");
    assert!(text.contains("%var5 = 0"), "{text}");
    assert!(text.contains("%var5 = (%var5 + 1)"), "{text}");
    assert!(text.contains("return %var5"), "{text}");
    assert!(types.get(&reg("var5")).is_some());
    assert_eq!(
        function.body[1].origins(),
        Some(&OriginSet::from_addresses([0x1020, 0x1024, 0x1030]))
    );
}

#[test]
fn opaque_exact_identities_authorize_loop_entry_coalescing() {
    let (mut function, seed, carrier) = opaque_carrier_candidate();
    let mut types = crate::ir::types_recover::TypeMap::default();
    types.upsert_public(
        seed.clone(),
        crate::ir::types_recover::TypeHint::Int {
            width: 8,
            signed: true,
        },
    );
    let mut identities = crate::ir::value_number::ValueIdentities::default();
    identities.record(
        seed.clone(),
        crate::ir::ssa::SsaValue {
            base: reg("rax"),
            version: 1,
        },
    );
    identities.record(
        carrier.clone(),
        crate::ir::ssa::SsaValue {
            base: reg("rbx"),
            version: 2,
        },
    );

    let renames = coalesce_loop_entry_copies_with_identities(
        &mut function,
        &std::collections::HashSet::new(),
        &mut types,
        Some(&identities),
    );
    identities.apply_renames(&renames);

    assert_eq!(
        function.body.len(),
        3,
        "exact opaque values should coalesce"
    );
    assert_eq!(renames.get(&seed), Some(&carrier));
    assert!(identities.candidates(&seed).is_none());
    assert_eq!(
        identities
            .candidates(&carrier)
            .map(std::collections::BTreeSet::len),
        Some(2)
    );
    assert!(identities.exact(&carrier).is_none());
    assert!(types.get(&carrier).is_some());
}

#[test]
fn ambiguous_opaque_identity_keeps_loop_entry_copy() {
    let (mut function, seed, carrier) = opaque_carrier_candidate();
    let before = function.clone();
    let mut types = crate::ir::types_recover::TypeMap::default();
    types.upsert_public(
        seed.clone(),
        crate::ir::types_recover::TypeHint::Int {
            width: 8,
            signed: true,
        },
    );
    let mut identities = crate::ir::value_number::ValueIdentities::default();
    identities.record(
        seed,
        crate::ir::ssa::SsaValue {
            base: reg("rax"),
            version: 1,
        },
    );
    identities.record(
        carrier.clone(),
        crate::ir::ssa::SsaValue {
            base: reg("rbx"),
            version: 2,
        },
    );
    identities.record(
        carrier,
        crate::ir::ssa::SsaValue {
            base: reg("rcx"),
            version: 3,
        },
    );

    let renames = coalesce_loop_entry_copies_with_identities(
        &mut function,
        &std::collections::HashSet::new(),
        &mut types,
        Some(&identities),
    );

    assert_eq!(function, before, "ambiguous values must fail closed");
    assert!(
        renames.is_empty(),
        "a refused rewrite must not move identities"
    );
}

#[test]
fn keeps_loop_entry_copy_when_source_remains_live() {
    let mut function = Function {
        name: "two_live_values".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("var5"),
                src: read("var3"),
            },
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("var5"),
                    src: Expr::Const(1),
                }],
                cond: read("var5"),
            },
            Stmt::Return {
                value: Some(read("var3")),
            },
        ],
    };
    let before = function.clone();

    let mut types = crate::ir::types_recover::TypeMap::default();
    coalesce_loop_entry_copies(&mut function, &std::collections::HashSet::new(), &mut types);

    assert_eq!(function, before);
}

#[test]
fn keeps_loop_entry_copy_without_positive_type_evidence() {
    let mut function = Function {
        name: "unknown_carrier".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("var5"),
                src: read("var3"),
            },
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("var5"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(read("var5")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }],
                cond: read("var5"),
            },
        ],
    };
    let before = function.clone();

    let mut types = crate::ir::types_recover::TypeMap::default();
    coalesce_loop_entry_copies(&mut function, &std::collections::HashSet::new(), &mut types);

    assert_eq!(function, before);
}

#[test]
fn keeps_loop_carrier_live_across_a_later_backward_goto() {
    let mut function = Function {
        name: "outer_loop_carrier".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("var32"),
                src: Expr::Const(0),
            },
            Stmt::Label(0x1000),
            Stmt::Assign {
                dst: reg("var6"),
                src: read("var32"),
            },
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("var6"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(read("var6")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }],
                cond: read("var6"),
            },
            Stmt::Goto { target: 0x1000 },
        ],
    };
    let before = function.clone();
    let mut types = crate::ir::types_recover::TypeMap::default();
    for register in [reg("var6"), reg("var32")] {
        types.upsert_public(
            register,
            crate::ir::types_recover::TypeHint::Int {
                width: 8,
                signed: true,
            },
        );
    }

    coalesce_loop_entry_copies(&mut function, &std::collections::HashSet::new(), &mut types);

    assert_eq!(function, before);
}

#[test]
fn keeps_loop_entry_copy_when_a_sibling_region_jumps_to_its_prefix() {
    let mut function = Function {
        name: "cross_region_entry".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::If {
            cond: read("guard"),
            then_body: vec![
                Stmt::Assign {
                    dst: reg("var3"),
                    src: Expr::Const(0),
                },
                Stmt::Label(0x1010),
                Stmt::Assign {
                    dst: reg("var5"),
                    src: read("var3"),
                },
                Stmt::DoWhile {
                    body: vec![Stmt::Assign {
                        dst: reg("var5"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(read("var5")),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }],
                    cond: read("var5"),
                },
            ],
            else_body: Some(vec![
                Stmt::Assign {
                    dst: reg("var3"),
                    src: Expr::Const(7),
                },
                Stmt::Goto { target: 0x1010 },
            ]),
        }],
    };
    let before = function.clone();
    let mut types = crate::ir::types_recover::TypeMap::default();
    types.upsert_public(
        reg("var3"),
        crate::ir::types_recover::TypeHint::Int {
            width: 8,
            signed: true,
        },
    );

    coalesce_loop_entry_copies(&mut function, &std::collections::HashSet::new(), &mut types);

    assert_eq!(function, before);
}

#[test]
fn keeps_authoritative_source_local_identity_at_loop_entry() {
    let mut function = Function {
        name: "source_local".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("local_x"),
                src: read("seed"),
            },
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("local_x"),
                    src: Expr::Const(1),
                }],
                cond: read("local_x"),
            },
        ],
    };
    let before = function.clone();
    let protected = std::collections::HashSet::from(["local_x".to_string()]);

    let mut types = crate::ir::types_recover::TypeMap::default();
    coalesce_loop_entry_copies(&mut function, &protected, &mut types);

    assert_eq!(function, before);
}

#[test]
fn coalesces_a_typed_loop_update_scratch_into_its_source_carrier() {
    let mut function = Function {
        name: "source_update_carrier".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("var4"),
                src: Expr::Const(0),
            },
            Stmt::DoWhile {
                body: vec![
                    Stmt::Assign {
                        dst: reg("ret"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(read("var4")),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("predicate"),
                        src: Expr::Cmp {
                            op: CmpOp::Ult,
                            lhs: Box::new(read("ret")),
                            rhs: Box::new(read("limit")),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("var4"),
                        src: read("ret").with_origins(OriginSet::one(0x1044)),
                    }
                    .with_origins(OriginSet::one(0x1040)),
                ],
                cond: read("predicate"),
            }
            .with_origins(OriginSet::one(0x1030)),
            Stmt::Return { value: None },
        ],
    };
    let mut types = crate::ir::types_recover::TypeMap::default();
    types.upsert_public(
        reg("var4"),
        crate::ir::types_recover::TypeHint::Int {
            width: 4,
            signed: true,
        },
    );
    types.upsert_public(
        reg("ret"),
        crate::ir::types_recover::TypeHint::Int {
            width: 8,
            signed: true,
        },
    );
    let exact_widths = std::collections::HashMap::from([("ret".to_string(), 4)]);
    let protected = std::collections::HashSet::from(["var4".to_string()]);

    coalesce_source_loop_updates(&mut function, &protected, &types, Some(&exact_widths));

    let text = crate::ir::ast::render(&function);
    assert!(!text.contains("%ret"), "{text}");
    assert!(text.contains("%var4 = (%var4 + 1)"), "{text}");
    assert!(text.contains("(%var4 u< %limit)"), "{text}");
    assert_eq!(
        function.body[1].origins(),
        Some(&OriginSet::from_addresses([0x1030, 0x1040, 0x1044]))
    );
}

#[test]
fn keeps_a_loop_update_scratch_when_the_old_carrier_is_still_needed() {
    let mut function = Function {
        name: "two_loop_values".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::DoWhile {
            body: vec![
                Stmt::Assign {
                    dst: reg("next"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(read("source")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Assign {
                    dst: reg("difference"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(read("next")),
                        rhs: Box::new(read("source")),
                    },
                },
                Stmt::Assign {
                    dst: reg("source"),
                    src: read("next"),
                },
            ],
            cond: read("difference"),
        }],
    };
    let before = function.clone();
    let mut types = crate::ir::types_recover::TypeMap::default();
    for register in [reg("source"), reg("next")] {
        types.upsert_public(
            register,
            crate::ir::types_recover::TypeHint::Int {
                width: 4,
                signed: true,
            },
        );
    }
    let protected = std::collections::HashSet::from(["source".to_string()]);

    coalesce_source_loop_updates(&mut function, &protected, &types, None);

    assert_eq!(function, before);
}

#[test]
fn keeps_a_loop_update_scratch_with_a_different_semantic_width() {
    let mut function = Function {
        name: "narrow_source".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::DoWhile {
            body: vec![
                Stmt::Assign {
                    dst: reg("wide_next"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(read("source")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Assign {
                    dst: reg("source"),
                    src: read("wide_next"),
                },
            ],
            cond: read("source"),
        }],
    };
    let before = function.clone();
    let mut types = crate::ir::types_recover::TypeMap::default();
    types.upsert_public(
        reg("source"),
        crate::ir::types_recover::TypeHint::Int {
            width: 4,
            signed: true,
        },
    );
    types.upsert_public(
        reg("wide_next"),
        crate::ir::types_recover::TypeHint::Int {
            width: 8,
            signed: true,
        },
    );
    let protected = std::collections::HashSet::from(["source".to_string()]);

    coalesce_source_loop_updates(&mut function, &protected, &types, None);

    assert_eq!(function, before);
}
