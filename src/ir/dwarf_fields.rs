//! Authoritative DWARF aggregate fields carried into the structured AST.
//!
//! Function prototypes and aggregate layouts come from the same debug contract.
//! Once a parameter is known to be `struct T *`, exact copy/cast chains and
//! pointer-valued fields can carry that identity to high variables.  Loads and
//! stores through those values are then annotated with the one matching DWARF
//! member.  The renderer remains responsible only for spelling that semantic
//! field access as C.

use std::collections::HashMap;

use crate::debug::dwarf::{DwarfType, DwarfTypeKind};
use crate::ir::ast::{Expr, Function, PdbFieldHint, Stmt};
use crate::ir::call_contracts::CallPrototype;
use crate::ir::types::{BinOp, VReg};

/// Attach exact DWARF field identities to memory accesses in `function`.
pub fn annotate_function_fields(
    function: &mut Function,
    prototype: Option<&CallPrototype>,
    types: &[DwarfType],
    pointer_width: u8,
) -> HashMap<VReg, String> {
    let Some(prototype) = prototype else {
        return HashMap::new();
    };
    let layouts = types
        .iter()
        .filter(|layout| layout.kind == DwarfTypeKind::Struct && !layout.fields.is_empty())
        .map(|layout| (layout.name.clone(), layout))
        .collect::<HashMap<_, _>>();
    if layouts.is_empty() {
        return HashMap::new();
    }

    let mut pointer_types = HashMap::<VReg, String>::new();
    for (slot, c_type) in prototype.parameter_types.iter().enumerate() {
        if let Some(name) = pointed_struct_name(c_type).filter(|name| layouts.contains_key(*name)) {
            pointer_types.insert(VReg::phys(format!("arg{slot}")), name.to_string());
        }
    }

    // Pointer identity is monotone here: the AST's high variables are already
    // value-numbered, and only an authoritative parameter, an exact copy/cast,
    // or a pointer-valued member can add a fact.  A small fixpoint handles loop
    // carried `p = p->next` regardless of structured statement order.
    for _ in 0..8 {
        if !infer_body(&function.body, &layouts, pointer_width, &mut pointer_types) {
            break;
        }
    }
    // A candidate is not a declaration until every definition agrees. This
    // rejects machine-register reuse such as `p = arg0; ...; p = 7` and then
    // iterates because removing `p` may invalidate a copy derived from it.
    loop {
        let invalid = pointer_types
            .iter()
            .filter(|(register, _)| !is_parameter_role(register))
            .filter_map(|(register, type_name)| {
                (!all_definitions_compatible(
                    &function.body,
                    register,
                    type_name,
                    &layouts,
                    pointer_width,
                    &pointer_types,
                ))
                .then_some(register.clone())
            })
            .collect::<Vec<_>>();
        if invalid.is_empty() {
            break;
        }
        for register in invalid {
            pointer_types.remove(&register);
        }
    }
    annotate_body(&mut function.body, &layouts, pointer_width, &pointer_types);
    pointer_types
}

fn is_parameter_role(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if name.strip_prefix("arg").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    }))
}

fn all_definitions_compatible(
    body: &[Stmt],
    target: &VReg,
    expected: &str,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
) -> bool {
    let mut seen = false;
    let mut compatible = true;
    visit_definitions(body, target, &mut |source| {
        seen = true;
        compatible &= source.is_some_and(|source| {
            pointer_expression_compatible(source, expected, layouts, pointer_width, pointer_types)
        });
    });
    seen && compatible
}

fn visit_definitions<'a>(
    body: &'a [Stmt],
    target: &VReg,
    visitor: &mut impl FnMut(Option<&'a Expr>),
) {
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } if dst == target => visitor(Some(src)),
            Stmt::Call { dst: Some(dst), .. } if dst == target => visitor(None),
            Stmt::Pop { target: dst } if dst == target => visitor(None),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                visit_definitions(then_body, target, visitor);
                if let Some(else_body) = else_body {
                    visit_definitions(else_body, target, visitor);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                visit_definitions(body, target, visitor)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                visit_definitions(std::slice::from_ref(init.as_ref()), target, visitor);
                visit_definitions(body, target, visitor);
                visit_definitions(std::slice::from_ref(step.as_ref()), target, visitor);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    visit_definitions(body, target, visitor);
                }
                if let Some(default) = default {
                    visit_definitions(default, target, visitor);
                }
            }
            _ => {}
        }
    }
}

fn pointer_expression_compatible(
    expression: &Expr,
    expected: &str,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
) -> bool {
    match expression {
        Expr::Const(0) => true,
        Expr::Cast { expr, .. } => {
            pointer_expression_compatible(expr, expected, layouts, pointer_width, pointer_types)
        }
        Expr::Select {
            if_true, if_false, ..
        } => {
            pointer_expression_compatible(if_true, expected, layouts, pointer_width, pointer_types)
                && pointer_expression_compatible(
                    if_false,
                    expected,
                    layouts,
                    pointer_width,
                    pointer_types,
                )
        }
        _ => pointer_source_type(expression, layouts, pointer_width, pointer_types)
            .is_some_and(|actual| actual == expected),
    }
}

fn pointed_struct_name(c_type: &str) -> Option<&str> {
    let normalized = c_type.trim();
    let pointee = normalized.strip_suffix('*')?.trim();
    let pointee = pointee
        .strip_prefix("const ")
        .or_else(|| pointee.strip_prefix("volatile "))
        .unwrap_or(pointee)
        .trim();
    pointee.strip_prefix("struct ").map(str::trim)
}

fn infer_body(
    body: &[Stmt],
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &mut HashMap<VReg, String>,
) -> bool {
    let mut changed = false;
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                if let Some(name) = pointer_source_type(src, layouts, pointer_width, pointer_types)
                {
                    if pointer_types.get(dst) != Some(&name) {
                        pointer_types.insert(dst.clone(), name);
                        changed = true;
                    }
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= infer_body(then_body, layouts, pointer_width, pointer_types);
                if let Some(else_body) = else_body {
                    changed |= infer_body(else_body, layouts, pointer_width, pointer_types);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                changed |= infer_body(body, layouts, pointer_width, pointer_types);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    changed |= infer_body(body, layouts, pointer_width, pointer_types);
                }
                if let Some(default) = default {
                    changed |= infer_body(default, layouts, pointer_width, pointer_types);
                }
            }
            Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
    changed
}

fn pointer_source_type(
    expression: &Expr,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
) -> Option<String> {
    if let Some(register) = direct_register(expression) {
        return pointer_types.get(register).cloned();
    }
    let Expr::Deref { addr, size } = expression else {
        return None;
    };
    let (base, offset) = address_base_offset(addr)?;
    let offset = u64::try_from(offset).ok()?;
    let base_type = pointer_types.get(&base)?;
    let layout = layouts.get(base_type)?;
    let field = layout.fields.iter().find(|field| {
        field.offset == offset
            && c_type_width(&field.c_type, pointer_width).is_some_and(|width| width == *size)
    })?;
    pointed_struct_name(&field.c_type)
        .filter(|name| layouts.contains_key(*name))
        .map(str::to_string)
}

fn direct_register(expression: &Expr) -> Option<&VReg> {
    match expression {
        Expr::Reg(register) => Some(register),
        Expr::Cast { expr, .. } => direct_register(expr),
        _ => None,
    }
}

fn address_base_offset(expression: &Expr) -> Option<(VReg, i64)> {
    match expression {
        Expr::Reg(register) => Some((register.clone(), 0)),
        Expr::Cast { expr, .. } => address_base_offset(expr),
        Expr::Lea {
            base: Some(base),
            index: None,
            disp,
            ..
        }
        | Expr::PdbFieldAddr {
            base: Some(base),
            index: None,
            disp,
            ..
        } => Some((base.clone(), *disp)),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Const(offset), other) | (other, Expr::Const(offset)) => {
                address_base_offset(other)
                    .map(|(base, prior)| (base, prior.saturating_add(*offset)))
            }
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(offset) => {
                address_base_offset(lhs).map(|(base, prior)| (base, prior.saturating_sub(*offset)))
            }
            _ => None,
        },
        _ => None,
    }
}

fn c_type_width(c_type: &str, pointer_width: u8) -> Option<u8> {
    let normalized = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.ends_with('*') {
        return Some(pointer_width);
    }
    match normalized.as_str() {
        "char" | "signed char" | "unsigned char" | "_Bool" | "bool" => Some(1),
        "short" | "short int" | "signed short" | "signed short int" | "unsigned short"
        | "unsigned short int" => Some(2),
        "int" | "signed" | "signed int" | "unsigned" | "unsigned int" | "float" => Some(4),
        "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "double" => Some(8),
        // `long` varies between LP64 and LLP64. This pass has the pointer
        // width but not enough object-format context to choose safely.
        _ => None,
    }
}

fn annotate_body(
    body: &mut [Stmt],
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
) {
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } => annotate_expr(src, layouts, pointer_width, pointer_types),
            Stmt::Store { addr, src, size } => {
                annotate_expr(src, layouts, pointer_width, pointer_types);
                annotate_address(addr, *size, layouts, pointer_width, pointer_types);
            }
            Stmt::Call { target, args, .. } => {
                annotate_expr(target, layouts, pointer_width, pointer_types);
                for argument in args {
                    annotate_expr(argument, layouts, pointer_width, pointer_types);
                }
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    annotate_expr(value, layouts, pointer_width, pointer_types);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                annotate_expr(cond, layouts, pointer_width, pointer_types);
                annotate_body(then_body, layouts, pointer_width, pointer_types);
                if let Some(else_body) = else_body {
                    annotate_body(else_body, layouts, pointer_width, pointer_types);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                annotate_expr(cond, layouts, pointer_width, pointer_types);
                annotate_body(body, layouts, pointer_width, pointer_types);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                annotate_body(
                    std::slice::from_mut(init.as_mut()),
                    layouts,
                    pointer_width,
                    pointer_types,
                );
                annotate_expr(cond, layouts, pointer_width, pointer_types);
                annotate_body(body, layouts, pointer_width, pointer_types);
                annotate_body(
                    std::slice::from_mut(step.as_mut()),
                    layouts,
                    pointer_width,
                    pointer_types,
                );
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                annotate_expr(discriminant, layouts, pointer_width, pointer_types);
                for (_, body) in cases {
                    annotate_body(body, layouts, pointer_width, pointer_types);
                }
                if let Some(default) = default {
                    annotate_body(default, layouts, pointer_width, pointer_types);
                }
            }
            Stmt::Push { value } => annotate_expr(value, layouts, pointer_width, pointer_types),
            Stmt::IndirectGoto { target } => {
                annotate_expr(target, layouts, pointer_width, pointer_types)
            }
            Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

fn annotate_expr(
    expression: &mut Expr,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
) {
    match expression {
        Expr::Deref { addr, size } => {
            annotate_expr(addr, layouts, pointer_width, pointer_types);
            annotate_address(addr, *size, layouts, pointer_width, pointer_types);
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            annotate_expr(lhs, layouts, pointer_width, pointer_types);
            annotate_expr(rhs, layouts, pointer_width, pointer_types);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            annotate_expr(cond, layouts, pointer_width, pointer_types);
            annotate_expr(if_true, layouts, pointer_width, pointer_types);
            annotate_expr(if_false, layouts, pointer_width, pointer_types);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            annotate_expr(src, layouts, pointer_width, pointer_types)
        }
        Expr::FunctionTableEntry { index, .. } => {
            annotate_expr(index, layouts, pointer_width, pointer_types)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                annotate_expr(argument, layouts, pointer_width, pointer_types);
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

fn annotate_address(
    address: &mut Expr,
    access_width: u8,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
) {
    let Some((base, offset_i64)) = address_base_offset(address) else {
        return;
    };
    let Ok(offset) = u64::try_from(offset_i64) else {
        return;
    };
    let Some(type_name) = pointer_types.get(&base) else {
        return;
    };
    let Some(layout) = layouts.get(type_name) else {
        return;
    };
    let Some(field) = layout.fields.iter().find(|field| {
        field.offset == offset
            && c_type_width(&field.c_type, pointer_width).is_some_and(|width| width == access_width)
    }) else {
        return;
    };
    *address = Expr::PdbFieldAddr {
        base: Some(base),
        index: None,
        scale: 1,
        disp: offset_i64,
        segment: None,
        hints: vec![PdbFieldHint {
            type_name: type_name.clone(),
            field_name: field.name.clone(),
            field_type: Some(field.c_type.clone()),
            offset: field.offset,
            renderable: true,
        }],
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::dwarf::DwarfField;
    use crate::ir::call_contracts::CallPrototypeAuthority;

    fn node_layout() -> DwarfType {
        DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "node".to_string(),
            byte_size: 16,
            fields: vec![
                DwarfField {
                    offset: 0,
                    name: "next".to_string(),
                    c_type: "struct node *".to_string(),
                    size: 0,
                },
                DwarfField {
                    offset: 8,
                    name: "val".to_string(),
                    c_type: "int".to_string(),
                    size: 0,
                },
            ],
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("linkedlist.c".to_string()),
        }
    }

    fn node_prototype() -> CallPrototype {
        CallPrototype {
            return_type: "struct node *".to_string(),
            parameter_types: vec!["struct node *".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        }
    }

    fn field_hint(expression: &Expr) -> Option<&PdbFieldHint> {
        let Expr::Deref { addr, .. } = expression else {
            return None;
        };
        let Expr::PdbFieldAddr { hints, .. } = addr.as_ref() else {
            return None;
        };
        let [hint] = hints.as_slice() else {
            return None;
        };
        Some(hint)
    }

    #[test]
    fn authoritative_parameter_and_next_copy_annotate_exact_members() {
        let mut function = Function {
            name: "list_find".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                            rhs: Box::new(Expr::Const(8)),
                        }),
                        size: 4,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("var0"))),
                        size: 8,
                    },
                },
            ],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::Assign { src: value, .. } = &function.body[1] else {
            panic!("expected value assignment");
        };
        assert_eq!(
            field_hint(value).map(|hint| hint.field_name.as_str()),
            Some("val")
        );
        let Stmt::Assign { src: next, .. } = &function.body[2] else {
            panic!("expected next assignment");
        };
        assert_eq!(
            field_hint(next).map(|hint| hint.field_name.as_str()),
            Some("next")
        );
    }

    #[test]
    fn mismatched_access_width_stays_raw() {
        let mut function = Function {
            name: "bad_width".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(8)),
                    }),
                    size: 8,
                },
            }],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment");
        };
        assert!(field_hint(src).is_none());
    }

    #[test]
    fn mixed_integer_and_pointer_definitions_reject_struct_identity() {
        let mut function = Function {
            name: "mixed_reuse".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("value"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                            rhs: Box::new(Expr::Const(8)),
                        }),
                        size: 4,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Const(7),
                },
            ],
        };

        let pointer_types =
            annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        assert!(!pointer_types.contains_key(&VReg::phys("var0")));
        let Stmt::Assign { src, .. } = &function.body[1] else {
            panic!("expected field load");
        };
        assert!(field_hint(src).is_none());
    }
}
