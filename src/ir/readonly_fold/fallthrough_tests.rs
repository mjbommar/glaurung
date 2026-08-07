use super::*;

#[test]
fn terminating_upper_bound_guard_materialises_the_fallthrough_lookup() {
    let data = ReadonlyData {
        regions: vec![ReadonlyRegion {
            base: 0xc28,
            bytes: [303u32, 399, 301, 300, 399, 302]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        }],
        little_endian: true,
    };
    let lookup = || Expr::Deref {
        addr: Box::new(Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Addr(0xc28)),
            rhs: Box::new(Expr::Bin {
                op: BinOp::Mul,
                lhs: Box::new(Expr::Reg(VReg::phys("index"))),
                rhs: Box::new(Expr::Const(4)),
            }),
        }),
        size: 4,
    };
    let guard = Stmt::If {
        cond: Expr::Cmp {
            op: CmpOp::Ult,
            lhs: Box::new(Expr::Const(5)),
            rhs: Box::new(Expr::Reg(VReg::phys("index"))),
        },
        then_body: vec![Stmt::Return {
            value: Some(Expr::Const(399)),
        }],
        else_body: None,
    };
    let mut function = Function {
        name: "negative_cases".into(),
        entry_va: 0,
        body: vec![
            guard.clone(),
            Stmt::Return {
                value: Some(lookup()),
            },
        ],
    };
    let mut nonterminal_guard = guard.clone();
    let Stmt::If { then_body, .. } = &mut nonterminal_guard else {
        unreachable!("the test guard is an if")
    };
    *then_body = vec![Stmt::Assign {
        dst: VReg::phys("observed"),
        src: Expr::Const(399),
    }];
    let mut nonterminal = Function {
        name: "nonterminal_guard".into(),
        entry_va: 0,
        body: vec![
            nonterminal_guard,
            Stmt::Return {
                value: Some(lookup()),
            },
        ],
    };
    let mut signed_guard = guard.clone();
    let Stmt::If { cond, .. } = &mut signed_guard else {
        unreachable!("the test guard is an if")
    };
    let Expr::Cmp { op, .. } = cond else {
        unreachable!("the test condition is a comparison")
    };
    *op = CmpOp::Slt;
    let mut signed = Function {
        name: "signed_guard".into(),
        entry_va: 0,
        body: vec![
            signed_guard,
            Stmt::Return {
                value: Some(lookup()),
            },
        ],
    };

    fold_guarded_readonly_lookups(&mut function, &data);
    fold_guarded_readonly_lookups(&mut nonterminal, &data);
    fold_guarded_readonly_lookups(&mut signed, &data);

    let rendered = crate::ir::ast::render(&function);
    for value in [303, 399, 301, 300, 302] {
        assert!(
            rendered.contains(&value.to_string()),
            "missing {value}:\n{rendered}"
        );
    }
    assert!(
        rendered.contains('?'),
        "table was not materialised:\n{rendered}"
    );
    let nonterminal = crate::ir::ast::render(&nonterminal);
    assert!(
        !nonterminal.contains('?'),
        "a nonterminating guard invented a fallthrough bound:\n{nonterminal}"
    );
    let signed = crate::ir::ast::render(&signed);
    assert!(
        !signed.contains('?'),
        "a signed guard cannot exclude negative table indices:\n{signed}"
    );
}
