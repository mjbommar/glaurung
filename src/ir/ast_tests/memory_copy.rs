use super::*;

/// `rep movs` lowers to the loop it IS, not to a marker.
///
/// The intrinsic's three register inputs are the lifter's PRIVATE cursors, not
/// RDI/RSI/RCX: the loop mutates them, and the architectural registers get
/// their post-operation values from ordinary LLIR emitted beside this. That is
/// what lets the copy be an exact loop instead of an opaque call.
#[test]
fn repeated_memory_copy_lowers_to_an_exact_directional_loop() {
    let statements = lower_op(
        &Op::Intrinsic {
            name: "memory.copy.8.word8".to_string(),
            ins: vec![
                Value::Reg(VReg::phys("copy_destination")),
                Value::Reg(VReg::phys("copy_source")),
                Value::Reg(VReg::phys("copy_count")),
                Value::Reg(VReg::Flag(Flag::D)),
            ],
            outs: Vec::new(),
            reads_mem: true,
            writes_mem: true,
        },
        false,
    );

    assert!(
        matches!(
            statements.as_slice(),
            [Stmt::While { cond: Expr::Cmp { op: CmpOp::Ne, .. }, body }]
                if matches!(body.as_slice(), [
                    Stmt::Store { size: 8, src: Expr::Deref { size: 8, .. }, .. },
                    Stmt::Assign { dst: first, src: Expr::Bin { op: BinOp::Add, .. } },
                    Stmt::Assign { dst: second, src: Expr::Bin { op: BinOp::Add, .. } },
                    Stmt::Assign { src: Expr::Bin { op: BinOp::Sub, .. }, .. },
                ] if first == &VReg::phys("copy_destination")
                    && second == &VReg::phys("copy_source"))
        ),
        "{statements:#?}"
    );

    let rendered = render_decbench(&Function {
        name: "copy".to_string(),
        entry_va: 0x1000,
        body: statements,
    });
    assert!(rendered.contains("while ((copy_count != 0))"), "{rendered}");
    assert!(
        rendered.contains("*(long *)(copy_destination) = *(long *)(copy_source);"),
        "{rendered}"
    );
    // BOTH cursors step, and both by the direction flag's sign -- x86 has one
    // direction flag, not one per pointer.
    assert_eq!(
        rendered.matches("? -8 : 8").count(),
        2,
        "both cursors must carry the directional step: {rendered}"
    );
    assert!(rendered.contains("df"), "{rendered}");
}

/// An `outs` on this intrinsic means it is not the shape this lowering knows,
/// and a width the string moves cannot encode is not one either. Both fall
/// through to the generic intrinsic rendering rather than being silently
/// reinterpreted.
#[test]
fn only_the_declared_memory_copy_shape_lowers_to_a_loop() {
    let with_output = lower_op(
        &Op::Intrinsic {
            name: "memory.copy.8.word8".to_string(),
            ins: vec![
                Value::Reg(VReg::phys("a")),
                Value::Reg(VReg::phys("b")),
                Value::Reg(VReg::phys("c")),
                Value::Reg(VReg::Flag(Flag::D)),
            ],
            outs: vec![(VReg::phys("d"), Width::W64)],
            reads_mem: true,
            writes_mem: true,
        },
        false,
    );
    assert!(
        !matches!(with_output.as_slice(), [Stmt::While { .. }]),
        "{with_output:#?}"
    );

    let bad_width = lower_op(
        &Op::Intrinsic {
            name: "memory.copy.3.word8".to_string(),
            ins: vec![
                Value::Reg(VReg::phys("a")),
                Value::Reg(VReg::phys("b")),
                Value::Reg(VReg::phys("c")),
                Value::Reg(VReg::Flag(Flag::D)),
            ],
            outs: Vec::new(),
            reads_mem: true,
            writes_mem: true,
        },
        false,
    );
    assert!(
        !matches!(bad_width.as_slice(), [Stmt::While { .. }]),
        "{bad_width:#?}"
    );
}
