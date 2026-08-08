use super::*;

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn bin(op: crate::ir::types::BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Bin {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn lea(base: &str, displacement: i64) -> Expr {
    Expr::Lea {
        base: Some(reg(base)),
        index: None,
        scale: 0,
        disp: displacement,
        segment: None,
    }
}

#[test]
fn a32_frame_pointer_address_rejoins_the_entry_cfa_object() {
    // A32's canonical prologue establishes fp at entry_sp-4 before allocating
    // the local frame. DWARF says parents begins at CFA-332, while the machine
    // spells the same address fp-328. The terminal fp restore must not make the
    // earlier reaching frame definition globally ambiguous.
    let mut function = Function {
        name: "rb_validate_a32_o0".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(
                    crate::ir::types::BinOp::Sub,
                    Expr::Reg(reg("sp")),
                    Expr::Const(8),
                ),
            },
            Stmt::Assign {
                dst: reg("fp"),
                src: bin(
                    crate::ir::types::BinOp::Add,
                    Expr::Reg(reg("sp")),
                    Expr::Const(4),
                ),
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(
                    crate::ir::types::BinOp::Sub,
                    Expr::Reg(reg("sp")),
                    Expr::Const(384),
                ),
            },
            Stmt::Call {
                target: Expr::Addr(0x1000),
                args: vec![lea("fp", -328), Expr::Const(0), Expr::Const(64)],
                dst: None,
                call_spec: None,
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(
                    crate::ir::types::BinOp::Sub,
                    Expr::Reg(reg("fp")),
                    Expr::Const(4),
                ),
            },
            Stmt::Assign {
                dst: reg("fp"),
                src: Expr::Deref {
                    addr: Box::new(lea("sp", 0)),
                    size: 4,
                },
            },
            Stmt::Return { value: None },
        ],
    };

    promote_stack_locals_typed_with_parameter_count_and_objects(
        &mut function,
        Some(CallConv::ArmHardFloat),
        Some(3),
        &[StackObjectHint {
            base: "entry_sp".into(),
            disp: -332,
            size: 64,
        }],
    );

    assert!(
        matches!(
            &function.body[3],
            Stmt::Call { args, .. }
                if matches!(args.as_slice(), [
                    Expr::StackAddr { object, size: 64 },
                    Expr::Const(0),
                    Expr::Const(64),
                ] if object == &reg("local_14c"))
        ),
        "fp-relative call address did not rejoin CFA-332: {function:#?}"
    );
}

#[test]
fn a32_fallthrough_branch_restore_invalidates_the_frame_coordinate() {
    // A dead-looking fp overwrite at the end of a nested branch is not
    // terminal when the branch falls through to an outer fp-relative use.
    // Treating it like an epilogue restore would preserve a stale coordinate
    // on one path and unsafely promote the later access.
    let body = vec![
        Stmt::Assign {
            dst: reg("sp"),
            src: bin(
                crate::ir::types::BinOp::Sub,
                Expr::Reg(reg("sp")),
                Expr::Const(8),
            ),
        },
        Stmt::Assign {
            dst: reg("fp"),
            src: bin(
                crate::ir::types::BinOp::Add,
                Expr::Reg(reg("sp")),
                Expr::Const(4),
            ),
        },
        Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![Stmt::Assign {
                dst: reg("fp"),
                src: Expr::Deref {
                    addr: Box::new(lea("sp", 0)),
                    size: 4,
                },
            }],
            else_body: None,
        },
        Stmt::Call {
            target: Expr::Addr(0x1000),
            args: vec![lea("fp", -328)],
            dst: None,
            call_spec: None,
        },
        Stmt::Return { value: None },
    ];

    let definitions = collect_stack_address_defs(
        &body,
        StackContext {
            cc: Some(CallConv::ArmHardFloat),
            rbp_repurposed: false,
            frame_pointer_established: false,
            parameter_count: Some(3),
        },
    );

    assert!(
        !definitions.contains_key(&reg("fp")),
        "fall-through restore retained a stale frame coordinate: {definitions:#?}"
    );
}
