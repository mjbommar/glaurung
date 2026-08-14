use super::*;

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn assign(name: &str, src: Expr) -> Stmt {
    Stmt::Assign {
        dst: reg(name),
        src,
    }
}

fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Bin {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn load_through(name: &str, displacement: i64) -> Stmt {
    assign(
        "value",
        Expr::Deref {
            addr: Box::new(Expr::Lea {
                base: Some(reg(name)),
                index: None,
                scale: 0,
                disp: displacement,
                segment: None,
            }),
            size: 4,
        },
    )
}

fn arm_context() -> StackContext {
    StackContext {
        cc: Some(CallConv::ArmHardFloat),
        rbp_repurposed: false,
        frame_pointer_established: false,
        arm_frame_register: Some("fp"),
        parameter_count: Some(3),
    }
}

fn loaded_address(body: &[Stmt]) -> &Expr {
    let Stmt::Assign {
        src: Expr::Deref { addr, .. },
        ..
    } = body.last().expect("load")
    else {
        panic!("last statement is not a load: {body:#?}");
    };
    addr
}

#[test]
fn a32_split_index_constant_is_expanded_into_the_frame_address() {
    // GCC -O0: lsl r3, side, #2; sub r3, #4; add r3, fp;
    // ldr r3, [r3, #-132]. The -4 is part of the effective displacement,
    // not a negative C array subscript.
    let mut body = vec![
        Stmt::Label(0x59c),
        assign(
            "r3#38",
            bin(BinOp::Shl, Expr::Reg(reg("side")), Expr::Const(2)),
        ),
        assign(
            "r3#39",
            bin(BinOp::Sub, Expr::Reg(reg("r3#38")), Expr::Const(4)),
        ),
        assign(
            "r3#40",
            bin(BinOp::Add, Expr::Reg(reg("r3#39")), Expr::Reg(reg("fp"))),
        ),
        load_through("r3#40", -132),
    ];

    expand(&mut body, arm_context());

    let address = loaded_address(&body);
    for transient in ["r3#38", "r3#39", "r3#40"] {
        assert!(
            !contains_register(address, &reg(transient)),
            "split affine component survived in {address:#?}"
        );
    }
    assert!(contains_register(address, &reg("fp")), "{address:#?}");
    assert!(contains_register(address, &reg("side")), "{address:#?}");
}

#[test]
fn thumb_split_large_constant_is_expanded_before_frame_resolution() {
    // GCC Thumb O0: index <<= 2; index += 384; index += r7;
    // ldr ..., [index, #-132]. r7#1 is resolved by the parent pass's stable
    // address-definition map, but only after this local split chain is exposed.
    let mut body = vec![
        Stmt::Label(0x5c4),
        assign(
            "r3#77",
            bin(BinOp::Shl, Expr::Reg(reg("side")), Expr::Const(2)),
        ),
        assign(
            "r3#78",
            bin(BinOp::Add, Expr::Reg(reg("r3#77")), Expr::Const(384)),
        ),
        assign(
            "r3#79",
            bin(BinOp::Add, Expr::Reg(reg("r3#78")), Expr::Reg(reg("r7#1"))),
        ),
        load_through("r3#79", -132),
    ];

    expand(&mut body, arm_context());

    let address = loaded_address(&body);
    for transient in ["r3#77", "r3#78", "r3#79"] {
        assert!(
            !contains_register(address, &reg(transient)),
            "split affine component survived in {address:#?}"
        );
    }
    assert!(contains_register(address, &reg("r7#1")), "{address:#?}");
    assert!(contains_register(address, &reg("side")), "{address:#?}");
}

#[test]
fn affine_preheader_value_is_not_frozen_across_a_loop() {
    // `cursor = arg0 - 4; while (...) { load [cursor + 4]; cursor += 4; }`.
    // Expanding the preheader definition in the loop body would read arg0[0]
    // forever even though the architectural cursor is loop-carried.
    let mut body = vec![
        assign(
            "r3#1",
            bin(BinOp::Sub, Expr::Reg(reg("arg0")), Expr::Const(4)),
        ),
        Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                load_through("r3#1", 4),
                assign(
                    "r3#1",
                    bin(BinOp::Add, Expr::Reg(reg("r3#1")), Expr::Const(4)),
                ),
            ],
        },
    ];

    expand(&mut body, arm_context());

    let Stmt::While {
        body: loop_body, ..
    } = &body[1]
    else {
        panic!("expected loop: {body:#?}");
    };
    assert!(
        contains_register(loaded_address(&loop_body[..1]), &reg("r3#1")),
        "loop-carried cursor was frozen to its preheader value: {body:#?}"
    );
}

#[test]
fn pre_shift_index_expression_remains_the_affine_atom() {
    // KMP's `prefix[matched - 1]` is lowered as a subtraction, shift, another
    // frame adjustment, and the memory displacement. Preserve the subtraction
    // result as the scaled index instead of turning it into a negative object
    // displacement.
    let mut body = vec![
        Stmt::Label(0x4f4),
        assign("r3#25", Expr::Reg(reg("matched"))),
        assign(
            "r3#26",
            bin(BinOp::Sub, Expr::Reg(reg("r3#25")), Expr::Const(1)),
        ),
        assign(
            "r3#27",
            bin(BinOp::Shl, Expr::Reg(reg("r3#26")), Expr::Const(2)),
        ),
        assign(
            "r3#28",
            bin(BinOp::Sub, Expr::Reg(reg("r3#27")), Expr::Const(4)),
        ),
        assign(
            "r3#29",
            bin(BinOp::Add, Expr::Reg(reg("r3#28")), Expr::Reg(reg("fp"))),
        ),
        load_through("r3#29", -68),
    ];

    expand(&mut body, arm_context());

    let address = loaded_address(&body);
    assert!(contains_register(address, &reg("r3#26")), "{address:#?}");
    for transient in ["r3#27", "r3#28", "r3#29"] {
        assert!(
            !contains_register(address, &reg(transient)),
            "split affine component survived in {address:#?}"
        );
    }
}

#[test]
fn affine_component_growth_is_hard_bounded() {
    let mut expression = Expr::Reg(reg("index"));
    for _ in 0..MAX_AFFINE_COMPONENT_NODES {
        expression = bin(BinOp::Add, expression, Expr::Const(1));
    }

    assert_eq!(affine_component_size(&expression), None);
}
