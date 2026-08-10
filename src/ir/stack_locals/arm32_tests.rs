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

fn deref(base: &str, displacement: i64, size: u8) -> Expr {
    Expr::Deref {
        addr: Box::new(lea(base, displacement)),
        size,
    }
}

#[test]
fn frame_epilogue_does_not_turn_the_frame_pointer_into_a_byte_array() {
    use crate::ir::types::BinOp;

    // The complete GCC Cortex-M -O0 frame shape copies r7 through a
    // temporary while calculating the epilogue SP. Once the body has exposed
    // several scalar frame slots, that bookkeeping copy must not be mistaken
    // for an escaping array cursor. Doing so collapses the spilled `int wait`
    // and byte local `char c` into one `local_18[24]`.
    let mut function = Function {
        name: "console_getc".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(BinOp::Sub, Expr::Reg(reg("sp")), Expr::Const(4)),
            },
            Stmt::Store {
                addr: lea("sp", 0),
                src: Expr::Reg(reg("r7")),
                size: 4,
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(BinOp::Sub, Expr::Reg(reg("sp")), Expr::Const(20)),
            },
            Stmt::Assign {
                dst: reg("r7#1"),
                src: bin(BinOp::Add, Expr::Reg(reg("sp")), Expr::Const(0)),
            },
            Stmt::Store {
                addr: lea("r7#1", 4),
                src: Expr::Reg(reg("r0")),
                size: 4,
            },
            Stmt::Store {
                addr: lea("r7#1", 15),
                src: Expr::Const(0),
                size: 1,
            },
            Stmt::Assign {
                dst: reg("r3#1"),
                src: deref("r7#1", 15, 1),
            },
            Stmt::Assign {
                dst: reg("t43"),
                src: Expr::Reg(reg("r7#1")),
            },
            Stmt::Assign {
                dst: reg("t44"),
                src: Expr::Const(20),
            },
            Stmt::Assign {
                dst: reg("r7#2"),
                src: bin(BinOp::Add, Expr::Reg(reg("t43")), Expr::Reg(reg("t44"))),
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: Expr::Reg(reg("r7#2")),
            },
            Stmt::Assign {
                dst: reg("r7#3"),
                src: deref("sp", 0, 4),
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(BinOp::Add, Expr::Reg(reg("sp")), Expr::Const(4)),
            },
            Stmt::Return { value: None },
        ],
    };

    let sizes = promote_stack_locals_typed(&mut function, Some(CallConv::Arm));

    assert!(
        matches!(
            &function.body[5],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_9"
        ),
        "the byte local was absorbed into the machine frame: {function:#?}"
    );
    assert_eq!(sizes.get("local_9"), Some(&1));
    assert!(
        !sizes.contains_key("local_18"),
        "the machine frame must not become a source byte array: {function:#?}"
    );
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
            aggregate: true,
            source_name: None,
            c_type: None,
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
        &HashMap::new(),
    );

    assert!(
        !definitions.contains_key(&reg("fp")),
        "fall-through restore retained a stale frame coordinate: {definitions:#?}"
    );
}
