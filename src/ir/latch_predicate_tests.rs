use super::*;
use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::{BinOp, CmpOp, VReg};

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn read(name: &str) -> Expr {
    Expr::Reg(reg(name))
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

    fold_latched_predicates(&mut function);

    let Stmt::DoWhile { body, cond } = &function.body[0] else {
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
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(read("var5")),
                    rhs: Box::new(read("limit")),
                },
            },
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
                        src: read("ret"),
                    },
                ],
                cond: read("predicate"),
            },
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
