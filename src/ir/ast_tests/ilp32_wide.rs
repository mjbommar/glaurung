use super::*;
use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};
use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

fn render_ilp32(function: &Function, types: &TypeMap) -> String {
    render_decbench_typed_with_output_and_prototype_and_dwarf_types(
        function,
        Some(types),
        Some(types),
        RecoveredOutputKind::Direct,
        None,
        &[],
        4,
        &std::collections::HashMap::new(),
    )
}

fn int_types(name: &str, signed: bool, width: u8) -> TypeMap {
    let mut types = TypeMap::default();
    types.upsert_public(VReg::phys(name), TypeHint::Int { signed, width });
    types
}

#[test]
fn decbench_ilp32_uses_long_long_for_an_eight_byte_integer() {
    let function = Function {
        name: "widen_identity".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::Return {
            value: Some(Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
            }),
        }],
    };
    let text = render_ilp32(&function, &int_types("arg0", false, 4));

    assert!(
        text.contains("unsigned long long widen_identity(unsigned int arg0)"),
        "an eight-byte integer must not collapse to ILP32 unsigned long:\n{text}"
    );
    assert!(
        text.contains("return (unsigned long long)(arg0);"),
        "the computation cast must use the same target-parametric width:\n{text}"
    );
}

#[test]
fn decbench_ilp32_logical_shift_keeps_an_explicit_wide_operand_wide() {
    let function = Function {
        name: "wide_shift".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::Return {
            value: Some(Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(Expr::Cast {
                    signed: true,
                    width: 8,
                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                }),
                rhs: Box::new(Expr::Const(32)),
            }),
        }],
    };
    let text = render_ilp32(&function, &int_types("arg0", true, 4));

    assert!(
        text.contains("return ((unsigned long long)((long)(arg0)) >> 32);"),
        "the logical shift must not truncate an explicit eight-byte value on ILP32:\n{text}"
    );
}

#[test]
fn decbench_ilp32_declares_a_prototype_proven_wide_call_result_exactly() {
    let prototype = CallPrototype {
        return_type: "unsigned long long".to_string(),
        parameter_types: Vec::new(),
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    let result = VReg::phys("var0");
    let function = Function {
        name: "wide_caller".to_string(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "widen_mul".to_string(),
                },
                args: Vec::new(),
                dst: Some(result.clone()),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: Some(prototype.clone()),
                    call_prototype: prototype,
                }),
            },
            Stmt::Return {
                value: Some(Expr::Bin {
                    op: BinOp::Shr,
                    lhs: Box::new(Expr::Reg(result.clone())),
                    rhs: Box::new(Expr::Const(32)),
                }),
            },
        ],
    };
    let text = render_ilp32(&function, &int_types("var0", false, 8));

    assert!(
        text.contains("unsigned long long var0;"),
        "the source-level call prototype must outrank a logical-parent TypeHint:\n{text}"
    );
    assert!(
        text.contains("var0 = widen_mul();"),
        "the exact destination declaration must remain attached to its call:\n{text}"
    );
    assert!(
        text.contains("((unsigned long long)(var0) >> 32)"),
        "a logical shift must use the prototype-proven destination width:\n{text}"
    );
}

/// ARM32's `-O0` signed divide-by-two takes the sign bit out of the **32-bit**
/// register holding a sign-extended byte:
///
/// ```text
/// ldrsb.w r3,[r7,#15]
/// lsrs    r2,r3,#31
/// ```
///
/// The AST states that width exactly — `Shr((int)((signed char)narrowed), 31)`
/// — but `expr_machine_width` used to look straight past `Expr::Cast` and
/// answer `None`, so the render fell through to its eight-byte default and
/// emitted `(unsigned long long)(narrowed) >> 31`. For a negative byte that is
/// `0x1ffffffff`, not the sign bit, and the bias it feeds is wrong by four
/// billion. The cast is the machine width; the shift must be spelled at it.
#[test]
fn decbench_ilp32_logical_shift_uses_the_cast_width_not_the_wide_default() {
    let narrowed = Expr::Cast {
        signed: true,
        width: 4,
        expr: Box::new(Expr::Cast {
            signed: true,
            width: 1,
            expr: Box::new(Expr::Reg(VReg::phys("narrowed"))),
        }),
    };
    let function = Function {
        name: "sign_bias".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::Return {
            value: Some(Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(narrowed),
                rhs: Box::new(Expr::Const(31)),
            }),
        }],
    };
    let text = render_ilp32(&function, &int_types("narrowed", true, 1));

    assert!(
        text.contains("((unsigned int)((int)((signed char)(narrowed))) >> 31)"),
        "a logical shift over a 32-bit sign extension must shift 32 bits:\n{text}"
    );
    assert!(
        !text.contains("unsigned long long"),
        "the eight-byte default must not survive an explicit four-byte cast:\n{text}"
    );
}

/// The dual of the case above, one width up and unsigned: a 16-bit cast is a
/// width statement too, and a shift over it happens at 16 bits.
#[test]
fn decbench_ilp32_logical_shift_uses_a_two_byte_cast_width() {
    let function = Function {
        name: "halfword_top_bit".to_string(),
        entry_va: 0x1000,
        body: vec![Stmt::Return {
            value: Some(Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(Expr::Cast {
                    signed: false,
                    width: 2,
                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                }),
                rhs: Box::new(Expr::Const(15)),
            }),
        }],
    };
    let text = render_ilp32(&function, &int_types("arg0", true, 4));

    assert!(
        text.contains("((unsigned short)(arg0) >> 15)"),
        "a two-byte cast is the shift's operand width:\n{text}"
    );
}
