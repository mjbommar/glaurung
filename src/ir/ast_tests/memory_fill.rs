use super::*;

#[test]
fn repeated_memory_fill_lowers_to_an_exact_directional_loop() {
    let statements = lower_op(
        &Op::Intrinsic {
            name: "memory.fill.4.word4".to_string(),
            ins: vec![
                Value::Reg(VReg::phys("fill_pointer")),
                Value::Reg(VReg::phys("fill_count")),
                Value::Reg(VReg::phys("fill_value")),
                Value::Reg(VReg::Flag(Flag::D)),
            ],
            outs: Vec::new(),
            reads_mem: false,
            writes_mem: true,
        },
        false,
    );

    assert!(matches!(
        statements.as_slice(),
        [Stmt::While { cond: Expr::Cmp { op: CmpOp::Ne, .. }, body }]
            if matches!(body.as_slice(), [
                Stmt::Store { size: 4, .. },
                Stmt::Assign { dst, src: Expr::Bin { op: BinOp::Add, .. } },
                Stmt::Assign { src: Expr::Bin { op: BinOp::Sub, .. }, .. },
            ] if dst == &VReg::phys("fill_pointer"))
    ));

    let rendered = render_decbench(&Function {
        name: "fill".to_string(),
        entry_va: 0x1000,
        body: statements,
    });
    assert!(rendered.contains("while ((fill_count != 0))"), "{rendered}");
    assert!(
        rendered.contains("*(int *)(fill_pointer) = fill_value;"),
        "{rendered}"
    );
    assert!(
        rendered.contains("df") && rendered.contains("? -4 : 4"),
        "{rendered}"
    );
}
