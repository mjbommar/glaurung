//! Materialise source integers split across 32-bit ABI storage locations.
//!
//! A `uint64_t` parameter occupies an aligned `rN:rN+1` pair under AAPCS32 and
//! two adjacent incoming stack words under cdecl32. Prototype recovery
//! historically retained only the first word; naming then presented the upper
//! word as an undefined local. This pass consumes explicit prototype and stack-
//! coordinate facts and replaces machine-word reads with width-exact
//! projections of the one source argument.

use std::collections::HashMap;

use crate::core::binary::Endianness;

use super::ast::{CatchClause, Expr, Function, Stmt};
use super::stack_locals::StackLocalFacts;
use super::types::{BinOp, VReg};
use super::types_recover::RecoveredPrototype;

/// Replace exact entry-word reads for little-endian 32-bit ABI wide integers.
///
/// This runs after value splitting: later scratch definitions have distinct
/// versioned identities, while bare AAPCS registers and promoted cdecl stack
/// coordinates still denote the entry values recorded by the prototype. Big-
/// endian ordering is deliberately refused until target-owned evidence states
/// its word order.
pub(crate) fn materialize_32bit_wide_parameters(
    function: &mut Function,
    prototype: &RecoveredPrototype,
    stack_facts: &StackLocalFacts,
    endianness: Endianness,
) -> usize {
    if endianness != Endianness::Little {
        return 0;
    }
    let mut replacements = HashMap::new();
    for (slot, [low, high]) in prototype.wide_integer_parameter_parts() {
        let argument = || Expr::Reg(VReg::phys(format!("arg{slot}")));
        replacements.insert(
            low,
            Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(argument()),
            },
        );
        replacements.insert(
            high,
            Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Bin {
                    op: BinOp::Shr,
                    lhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(argument()),
                    }),
                    rhs: Box::new(Expr::Const(32)),
                }),
            },
        );
    }
    for (slot, [low_offset, high_offset]) in prototype.wide_integer_stack_parameter_parts() {
        let argument = || Expr::Reg(VReg::phys(format!("arg{slot}")));
        for (offset, replacement, is_low_word) in [
            (
                low_offset,
                Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(argument()),
                },
                true,
            ),
            (
                high_offset,
                Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(Expr::Bin {
                        op: BinOp::Shr,
                        lhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(argument()),
                        }),
                        rhs: Box::new(Expr::Const(32)),
                    }),
                },
                false,
            ),
        ] {
            let incoming_coordinates = [
                ("entry_rsp", 4 + offset),
                ("ebp", 8 + offset),
                ("rbp", 8 + offset),
                ("bp", 8 + offset),
            ];
            for (name, (base, displacement)) in &stack_facts.frame_coordinates {
                // Stack promotion already gives the low slot the whole source
                // role. Replacing `argN` with its 32-bit machine projection
                // would truncate every ordinary whole-value use of that role.
                if is_low_word && name == &format!("arg{slot}") {
                    continue;
                }
                if incoming_coordinates
                    .iter()
                    .any(|coordinate| coordinate == &(base.as_str(), *displacement))
                {
                    replacements.insert(VReg::phys(name), replacement.clone());
                }
            }
        }
    }
    if replacements.is_empty() {
        return 0;
    }
    let mut changed = 0;
    rewrite_body(&mut function.body, &replacements, &mut changed);
    changed
}

fn rewrite_expr(expr: &mut Expr, replacements: &HashMap<VReg, Expr>, changed: &mut usize) {
    if let Expr::Reg(register) = expr {
        if let Some(replacement) = replacements.get(register) {
            *expr = replacement.clone();
            *changed += 1;
        }
        return;
    }
    match expr {
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::NumericConvert { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => rewrite_expr(addr, replacements, changed),
        Expr::Call { target, args, .. } => {
            rewrite_expr(target, replacements, changed);
            for argument in args {
                rewrite_expr(argument, replacements, changed);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, replacements, changed);
            rewrite_expr(rhs, replacements, changed);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond, replacements, changed);
            rewrite_expr(if_true, replacements, changed);
            rewrite_expr(if_false, replacements, changed);
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                rewrite_expr(argument, replacements, changed);
            }
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => {}
    }
}

fn rewrite_catches(
    catches: &mut [CatchClause],
    replacements: &HashMap<VReg, Expr>,
    changed: &mut usize,
) {
    for catch in catches {
        rewrite_body(&mut catch.body, replacements, changed);
    }
}

fn rewrite_body(body: &mut [Stmt], replacements: &HashMap<VReg, Expr>, changed: &mut usize) {
    for statement in body {
        match statement {
            Stmt::IndirectGoto { target } | Stmt::Throw { value: target } => {
                rewrite_expr(target, replacements, changed)
            }
            Stmt::Assign { src, .. } => rewrite_expr(src, replacements, changed),
            Stmt::Store { addr, src, .. } => {
                rewrite_expr(addr, replacements, changed);
                rewrite_expr(src, replacements, changed);
            }
            Stmt::Call { target, args, .. } => {
                rewrite_expr(target, replacements, changed);
                for argument in args {
                    rewrite_expr(argument, replacements, changed);
                }
            }
            Stmt::Return { value: Some(value) } | Stmt::Push { value } => {
                rewrite_expr(value, replacements, changed)
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, replacements, changed);
                rewrite_body(then_body, replacements, changed);
                if let Some(else_body) = else_body {
                    rewrite_body(else_body, replacements, changed);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                rewrite_expr(cond, replacements, changed);
                rewrite_body(body, replacements, changed);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rewrite_body(std::slice::from_mut(init.as_mut()), replacements, changed);
                rewrite_expr(cond, replacements, changed);
                rewrite_body(std::slice::from_mut(step.as_mut()), replacements, changed);
                rewrite_body(body, replacements, changed);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(discriminant, replacements, changed);
                for (_, body) in cases {
                    rewrite_body(body, replacements, changed);
                }
                if let Some(default) = default {
                    rewrite_body(default, replacements, changed);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                rewrite_body(try_body, replacements, changed);
                rewrite_catches(catches, replacements, changed);
            }
            Stmt::Return { value: None }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Continue
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::call_args::CallConv;
    use crate::ir::stack_locals::StackLocalFacts;
    use crate::ir::types_recover::TypeHint;

    fn wide_prototype() -> RecoveredPrototype {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(
            CallConv::Arm,
            &[Some(TypeHint::Int {
                signed: false,
                width: 8,
            })],
        );
        prototype
    }

    #[test]
    fn little_endian_pair_becomes_two_views_of_one_source_argument() {
        let mut function = Function {
            name: "wide".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("local_low"),
                    src: Expr::Reg(VReg::phys("r0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("local_high"),
                    src: Expr::Reg(VReg::phys("r1")),
                },
            ],
        };

        assert_eq!(
            materialize_32bit_wide_parameters(
                &mut function,
                &wide_prototype(),
                &StackLocalFacts::default(),
                Endianness::Little,
            ),
            2
        );
        let rendered = crate::ir::ast::render(&function);
        assert!(rendered.contains("(unsigned int)(%arg0)"), "{rendered}");
        assert!(rendered.contains(">> 32"), "{rendered}");
        assert!(!rendered.contains("= %r0"), "{rendered}");
        assert!(!rendered.contains("= %r1"), "{rendered}");
    }

    #[test]
    fn big_endian_pair_declines_without_a_word_order_fact() {
        let mut function = Function {
            name: "wide".into(),
            entry_va: 0,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("r1"))),
            }],
        };
        assert_eq!(
            materialize_32bit_wide_parameters(
                &mut function,
                &wide_prototype(),
                &StackLocalFacts::default(),
                Endianness::Big,
            ),
            0
        );
        assert!(matches!(
            &function.body[0],
            Stmt::Return {
                value: Some(Expr::Reg(register))
            } if register == &VReg::phys("r1")
        ));
    }

    #[test]
    fn cdecl32_stack_pair_becomes_two_views_of_one_source_argument() {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(
            CallConv::Cdecl32,
            &[
                Some(TypeHint::Int {
                    signed: true,
                    width: 4,
                }),
                Some(TypeHint::Int {
                    signed: false,
                    width: 8,
                }),
            ],
        );
        let mut facts = StackLocalFacts::default();
        facts
            .frame_coordinates
            .insert("stack_high".into(), ("entry_rsp".into(), 12));
        let mut function = Function {
            name: "wide_stack".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("whole_copy"),
                    src: Expr::Reg(VReg::phys("arg1")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("stack_high"))),
                },
            ],
        };

        assert_eq!(
            materialize_32bit_wide_parameters(
                &mut function,
                &prototype,
                &facts,
                Endianness::Little,
            ),
            1
        );
        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Reg(source),
                ..
            } if source == &VReg::phys("arg1")
        ));
        let rendered = crate::ir::ast::render(&function);
        assert!(rendered.contains("%arg1"), "{rendered}");
        assert!(rendered.contains(">> 32"), "{rendered}");
        assert!(!rendered.contains("%stack_high"), "{rendered}");
    }

    #[test]
    fn cdecl32_layout_declines_after_an_unknown_parameter() {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(
            CallConv::Cdecl32,
            &[
                None,
                Some(TypeHint::Int {
                    signed: false,
                    width: 8,
                }),
            ],
        );
        let mut facts = StackLocalFacts::default();
        facts
            .frame_coordinates
            .insert("candidate_high".into(), ("entry_rsp".into(), 12));
        let mut function = Function {
            name: "unknown_prefix".into(),
            entry_va: 0,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("candidate_high"))),
            }],
        };

        assert_eq!(
            materialize_32bit_wide_parameters(
                &mut function,
                &prototype,
                &facts,
                Endianness::Little,
            ),
            0
        );
        assert!(matches!(
            &function.body[0],
            Stmt::Return {
                value: Some(Expr::Reg(source))
            } if source == &VReg::phys("candidate_high")
        ));
    }
}
