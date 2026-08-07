use super::*;
use crate::ir::types::BinOp;

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn stack_address(disp: i64) -> Expr {
    Expr::Lea {
        base: Some(reg("sp")),
        index: None,
        scale: 0,
        disp,
        segment: None,
    }
}

/// GCC may load a source byte through a machine-word view before extracting
/// only its low bits. The debug-proven byte object still owns that value; a
/// second scalar slot at the same address would be undefined in recovered C.
#[test]
fn aarch64_wide_load_at_a_bounded_byte_object_uses_the_object_value() {
    let mut function = Function {
        name: "decode_header".to_string(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: reg("sp"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("sp"))),
                    rhs: Box::new(Expr::Const(64)),
                },
            },
            Stmt::Store {
                addr: stack_address(56),
                src: Expr::Const(0x13),
                size: 1,
            },
            Stmt::Assign {
                dst: reg("x0"),
                src: Expr::Deref {
                    addr: Box::new(stack_address(56)),
                    size: 8,
                },
            },
        ],
    };
    let hints = [StackObjectHint {
        base: "entry_sp".to_string(),
        disp: -8,
        size: 1,
    }];

    promote_stack_locals_typed_with_parameter_count_and_objects(
        &mut function,
        Some(CallConv::Aarch64),
        None,
        &hints,
    );

    let Stmt::Store { addr, .. } = &function.body[1] else {
        panic!("expected byte store: {function:#?}");
    };
    let Expr::StackAddr {
        object: stored_object,
        size: 1,
    } = addr
    else {
        panic!("bounded byte store was not promoted: {function:#?}");
    };
    let Stmt::Assign { src, .. } = &function.body[2] else {
        panic!("expected wide load: {function:#?}");
    };
    assert_eq!(
        src,
        &Expr::Deref {
            addr: Box::new(Expr::StackAddr {
                object: stored_object.clone(),
                size: 1,
            }),
            size: 1,
        },
        "the source byte must own the overlapping machine-word view"
    );
}

#[test]
fn aarch64_interior_or_cross_frame_wide_loads_remain_conservative() {
    for (hint_disp, current_disp) in [(-16, 48), (-4, 60)] {
        let mut function = Function {
            name: "not_top_padding".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(64)),
                    },
                },
                Stmt::Store {
                    addr: stack_address(current_disp),
                    src: Expr::Const(0x13),
                    size: 1,
                },
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Deref {
                        addr: Box::new(stack_address(current_disp)),
                        size: 8,
                    },
                },
            ],
        };
        let hints = [StackObjectHint {
            base: "entry_sp".to_string(),
            disp: hint_disp,
            size: 1,
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut function,
            Some(CallConv::Aarch64),
            None,
            &hints,
        );

        let Stmt::Store {
            addr:
                Expr::StackAddr {
                    object: stored_object,
                    size: 1,
                },
            ..
        } = &function.body[1]
        else {
            panic!("bounded byte store was not promoted: {function:#?}");
        };
        let Stmt::Assign { src, .. } = &function.body[2] else {
            panic!("expected wide load: {function:#?}");
        };
        assert_ne!(
            src,
            &Expr::Deref {
                addr: Box::new(Expr::StackAddr {
                    object: stored_object.clone(),
                    size: 1,
                }),
                size: 1,
            },
            "only padding that ends exactly at entry SP is a proven scalar view"
        );
    }
}
