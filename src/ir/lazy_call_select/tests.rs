use super::*;
use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::{BinOp, VReg};

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn call(dst: &str) -> Stmt {
    Stmt::Call {
        target: Expr::Named {
            va: 0x2000,
            name: "saturating_add".into(),
        },
        args: vec![Expr::Reg(reg("capacity")), Expr::Const(1)],
        dst: Some(reg(dst)),
        call_spec: None,
    }
}

fn assign(dst: &str, src: Expr) -> Stmt {
    Stmt::Assign { dst: reg(dst), src }
}

fn function(statement: Stmt) -> Function {
    Function {
        name: "lazy_select".into(),
        entry_va: 0x1000,
        body: vec![statement],
    }
}

fn diamond(call_is_true_arm: bool, call_value: Expr) -> Stmt {
    let call_arm = vec![call("call_result"), assign("result", call_value)];
    let constant_arm = vec![assign("result", Expr::Const(-1))];
    let (then_body, else_body) = if call_is_true_arm {
        (call_arm, constant_arm)
    } else {
        (constant_arm, call_arm)
    };
    Stmt::If {
        cond: Expr::Reg(reg("fits")),
        then_body,
        else_body: Some(else_body),
    }
}

fn nonnegative_condition() -> Expr {
    Expr::Cmp {
        op: CmpOp::Sle,
        lhs: Box::new(Expr::Const(0)),
        rhs: Box::new(Expr::Reg(reg("sum"))),
    }
}

fn negative_condition() -> Expr {
    Expr::Cmp {
        op: CmpOp::Slt,
        lhs: Box::new(Expr::Reg(reg("sum"))),
        rhs: Box::new(Expr::Const(0)),
    }
}

fn saturation_diamond(call_is_true_arm: bool) -> Stmt {
    let call_result = Expr::Reg(reg("call_result"));
    let call_arm = vec![
        call("call_result"),
        assign(
            "result",
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(call_result.clone()),
                rhs: Box::new(call_result),
            },
        ),
    ];
    let constant_arm = vec![assign("result", Expr::Const(-1))];
    let (cond, then_body, else_body) = if call_is_true_arm {
        (nonnegative_condition(), call_arm, constant_arm)
    } else {
        (negative_condition(), constant_arm, call_arm)
    };
    Stmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    }
}

fn selected_expression(function: &Function) -> &Expr {
    let [Stmt::Assign {
        dst,
        src: selected @ Expr::Select { .. },
    }] = function.body.as_slice()
    else {
        panic!("call diamond was not collapsed: {:#?}", function.body);
    };
    assert_eq!(dst, &reg("result"));
    selected
}

fn count_calls(expression: &Expr) -> usize {
    match expression {
        Expr::Call { target, args, .. } => {
            1 + count_calls(target) + args.iter().map(count_calls).sum::<usize>()
        }
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::NumericConvert { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => count_calls(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_calls(lhs) + count_calls(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => count_calls(cond) + count_calls(if_true) + count_calls(if_false),
        Expr::WideArithmetic { args, .. } => args.iter().map(count_calls).sum(),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => 0,
    }
}

#[test]
fn preserves_direct_call_diamonds_without_saturation_proof() {
    for call_is_true_arm in [true, false] {
        let mut function = function(diamond(call_is_true_arm, Expr::Reg(reg("call_result"))));
        let before = function.clone();

        collapse_lazy_call_diamonds_with_pointer_width(&mut function, 8);

        assert_eq!(function, before);
    }
}

#[test]
fn rewrites_duplicate_addition_as_one_call_times_two() {
    let mut function = function(saturation_diamond(true));

    collapse_lazy_call_diamonds_with_pointer_width(&mut function, 8);

    let selected = selected_expression(&function);
    assert_eq!(count_calls(selected), 1);
    assert!(matches!(
        selected,
        Expr::Select { if_true, .. }
            if matches!(if_true.as_ref(), Expr::Bin {
                op: BinOp::Mul,
                rhs,
                ..
            } if matches!(rhs.as_ref(), Expr::Const(2)))
    ));
}

#[test]
fn refuses_extra_effects_and_nonrepresentable_multiple_uses() {
    let mut extra_effect = function(Stmt::If {
        cond: Expr::Reg(reg("fits")),
        then_body: vec![
            call("call_result"),
            Stmt::Store {
                addr: Expr::Reg(reg("output")),
                src: Expr::Const(1),
                size: 4,
            },
            assign("result", Expr::Reg(reg("call_result"))),
        ],
        else_body: Some(vec![assign("result", Expr::Const(-1))]),
    });
    let extra_effect_before = extra_effect.clone();
    collapse_lazy_call_diamonds_with_pointer_width(&mut extra_effect, 8);
    assert_eq!(extra_effect, extra_effect_before);

    let mut nonlinear = function(diamond(
        true,
        Expr::Bin {
            op: BinOp::Mul,
            lhs: Box::new(Expr::Reg(reg("call_result"))),
            rhs: Box::new(Expr::Reg(reg("call_result"))),
        },
    ));
    let nonlinear_before = nonlinear.clone();
    collapse_lazy_call_diamonds_with_pointer_width(&mut nonlinear, 8);
    assert_eq!(nonlinear, nonlinear_before);
}

#[test]
fn collapses_a_promoted_local_call_diamond() {
    let promoted_store = |src| Stmt::Store {
        addr: Expr::Reg(reg("local_10")),
        src,
        size: 8,
    };
    let mut function = function(Stmt::If {
        cond: negative_condition(),
        then_body: vec![promoted_store(Expr::Const(-1))],
        else_body: Some(vec![
            call("call_result"),
            promoted_store(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("call_result"))),
                rhs: Box::new(Expr::Reg(reg("call_result"))),
            }),
        ]),
    });

    collapse_lazy_call_diamonds_with_pointer_width(&mut function, 8);

    let [Stmt::Store {
        addr: Expr::Reg(destination),
        src: selected @ Expr::Select { .. },
        size: 8,
    }] = function.body.as_slice()
    else {
        panic!(
            "promoted call diamond was not collapsed: {:#?}",
            function.body
        );
    };
    assert_eq!(destination, &reg("local_10"));
    assert_eq!(count_calls(selected), 1);
}

#[test]
fn collapses_a_linearized_call_diamond_with_a_unique_join() {
    let join = 0x1010;
    let mut function = Function {
        name: "linear_lazy_select".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::If {
                cond: nonnegative_condition(),
                then_body: vec![
                    call("call_result"),
                    assign(
                        "result",
                        Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("call_result"))),
                            rhs: Box::new(Expr::Reg(reg("call_result"))),
                        },
                    ),
                    Stmt::Goto { target: join },
                ],
                else_body: None,
            },
            assign("result", Expr::Const(-1)),
            Stmt::Label(join),
            assign("consumer", Expr::Reg(reg("result"))),
        ],
    };

    collapse_lazy_call_diamonds_with_pointer_width(&mut function, 8);

    assert_eq!(function.body.len(), 2);
    let Stmt::Assign {
        src: selected @ Expr::Select { .. },
        ..
    } = &function.body[0]
    else {
        panic!(
            "linear call diamond was not collapsed: {:#?}",
            function.body
        );
    };
    assert_eq!(count_calls(selected), 1);

    let mut shared_join = Function {
        name: "shared_join".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Goto { target: join },
            Stmt::If {
                cond: Expr::Reg(reg("fits")),
                then_body: vec![
                    call("call_result"),
                    assign("result", Expr::Reg(reg("call_result"))),
                    Stmt::Goto { target: join },
                ],
                else_body: None,
            },
            assign("result", Expr::Const(-1)),
            Stmt::Label(join),
        ],
    };
    let shared_before = shared_join.clone();
    collapse_lazy_call_diamonds_with_pointer_width(&mut shared_join, 8);
    assert_eq!(shared_join, shared_before);
}

#[test]
fn collapses_a_conditional_jump_call_diamond() {
    let constant_label = 0x1010;
    let join_label = 0x1020;
    let mut function = Function {
        name: "jump_lazy_select".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: crate::ir::types::CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("sum"))),
                    rhs: Box::new(Expr::Const(0)),
                },
                then_body: vec![Stmt::Goto {
                    target: constant_label,
                }],
                else_body: None,
            },
            call("call_result"),
            assign(
                "result",
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("call_result"))),
                    rhs: Box::new(Expr::Reg(reg("call_result"))),
                },
            ),
            Stmt::Goto { target: join_label },
            Stmt::Label(constant_label),
            assign("result", Expr::Const(-1)),
            Stmt::Label(join_label),
            assign("consumer", Expr::Reg(reg("result"))),
        ],
    };

    collapse_lazy_call_diamonds_with_pointer_width(&mut function, 8);

    assert_eq!(function.body.len(), 2);
    let Stmt::Assign {
        src:
            selected @ Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            },
        ..
    } = &function.body[0]
    else {
        panic!("jump call diamond was not collapsed: {:#?}", function.body);
    };
    assert!(matches!(
        cond.as_ref(),
        Expr::Cmp {
            op: crate::ir::types::CmpOp::Sle,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Const(0))
            && matches!(rhs.as_ref(), Expr::Reg(register) if register == &reg("sum"))
    ));
    assert_eq!(count_calls(selected), 1);
    assert!(matches!(if_true.as_ref(), Expr::Bin { op: BinOp::Mul, .. }));
    assert!(matches!(
        if_false.as_ref(),
        Expr::Cast {
            signed: false,
            width: 8,
            expr,
        } if matches!(expr.as_ref(), Expr::Const(-1))
    ));
}

#[test]
fn unsigned_max_spelling_is_scoped_to_the_saturation_select() {
    let ordinary = Function {
        name: "ordinary_unsigned_cast".into(),
        entry_va: 0x1000,
        body: vec![assign(
            "result",
            Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Const(-1)),
            },
        )],
    };
    let ordinary_text = crate::ir::ast::render_decbench(&ordinary);
    assert!(
        ordinary_text.contains("(unsigned int)(-1)"),
        "ordinary unsigned cast was globally canonicalized:\n{ordinary_text}"
    );
    assert!(!ordinary_text.contains("0xffffffffU"), "{ordinary_text}");

    let mut saturation = Function {
        name: "saturation_select".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: crate::ir::types::CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("sum"))),
                    rhs: Box::new(Expr::Const(0)),
                },
                then_body: vec![Stmt::Goto { target: 0x1010 }],
                else_body: None,
            },
            call("call_result"),
            assign(
                "result",
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("call_result"))),
                    rhs: Box::new(Expr::Reg(reg("call_result"))),
                },
            ),
            Stmt::Goto { target: 0x1020 },
            Stmt::Label(0x1010),
            assign("result", Expr::Const(-1)),
            Stmt::Label(0x1020),
        ],
    };
    collapse_lazy_call_diamonds_with_pointer_width(&mut saturation, 8);
    let saturation_text = crate::ir::ast::render_decbench(&saturation);
    assert!(
        saturation_text.contains("0xffffffffffffffffULL"),
        "saturation sentinel lost its exact unsigned spelling:\n{saturation_text}"
    );
}

#[test]
fn machine_sized_call_result_uses_the_active_pointer_width() {
    let mut function = function(saturation_diamond(true));

    collapse_lazy_call_diamonds_with_pointer_width(&mut function, 4);

    assert!(matches!(
        selected_expression(&function),
        Expr::Select {
            width: 4,
            if_true,
            ..
        } if matches!(if_true.as_ref(), Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Call {
                result_width: Some(4),
                ..
            }) && matches!(rhs.as_ref(), Expr::Const(2)))
    ));
}

#[test]
fn adjacent_unique_call_result_moves_into_its_consumer() {
    let mut function = Function {
        name: "sum_lengths".into(),
        entry_va: 0x1000,
        body: vec![
            call("call_result#call_lifetime_0"),
            assign(
                "sum",
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("sum"))),
                    rhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(reg("call_result#call_lifetime_0"))),
                    }),
                },
            ),
        ],
    };

    fold_adjacent_single_use_call_results(&mut function, 8);

    assert_eq!(function.body.len(), 1, "{function:#?}");
    assert!(matches!(
        &function.body[0],
        Stmt::Assign {
            src: Expr::Bin { rhs, .. },
            ..
        } if matches!(rhs.as_ref(), Expr::Cast { expr, .. }
            if matches!(expr.as_ref(), Expr::Call { .. }))
    ));
}

#[test]
fn adjacent_unique_call_result_moves_into_promoted_commuted_update() {
    let result = "call_result#call_lifetime_0";
    let mut function = Function {
        name: "sum_lengths".into(),
        entry_va: 0x1000,
        body: vec![
            call(result),
            Stmt::Store {
                addr: Expr::Reg(reg("local_20")),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg(result))),
                    rhs: Box::new(Expr::Reg(reg("local_20"))),
                },
                size: 4,
            },
        ],
    };

    fold_adjacent_single_use_call_results(&mut function, 4);

    assert_eq!(function.body.len(), 1, "{function:#?}");
    assert!(matches!(
        &function.body[0],
        Stmt::Store {
            src: Expr::Bin { lhs, .. },
            ..
        } if matches!(lhs.as_ref(), Expr::Call { .. })
    ));
}

#[test]
fn shared_call_result_is_not_moved() {
    let result = "call_result#call_lifetime_0";
    let mut function = Function {
        name: "shared_result".into(),
        entry_va: 0x1000,
        body: vec![
            call(result),
            assign("first", Expr::Reg(reg(result))),
            Stmt::Return {
                value: Some(Expr::Reg(reg(result))),
            },
        ],
    };

    fold_adjacent_single_use_call_results(&mut function, 8);

    assert_eq!(function.body.len(), 3, "{function:#?}");
    assert!(matches!(function.body[0], Stmt::Call { .. }));
}

#[test]
fn adjacent_unique_call_result_moves_into_return() {
    let result = "call_result#call_lifetime_0";
    let mut function = Function {
        name: "forward_result".into(),
        entry_va: 0x1000,
        body: vec![
            call(result),
            Stmt::Return {
                value: Some(Expr::Reg(reg(result))),
            },
        ],
    };

    fold_adjacent_single_use_call_results(&mut function, 8);

    assert!(matches!(
        function.body.as_slice(),
        [Stmt::Return {
            value: Some(Expr::Call { .. })
        }]
    ));
}

#[test]
fn inert_nops_do_not_block_call_result_return_folding() {
    let result = "call_result#call_lifetime_0";
    let mut function = Function {
        name: "forward_result_after_nops".into(),
        entry_va: 0x1000,
        body: vec![
            call(result),
            Stmt::Nop,
            Stmt::Nop,
            Stmt::Return {
                value: Some(Expr::Reg(reg(result))),
            },
        ],
    };

    fold_adjacent_single_use_call_results(&mut function, 8);

    assert!(matches!(
        function.body.as_slice(),
        [Stmt::Return {
            value: Some(Expr::Call { .. })
        }]
    ));
}
