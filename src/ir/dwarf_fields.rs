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
use crate::ir::types::{is_promoted_local_reg, BinOp, VReg};

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
    let type_env = crate::ir::dwarf_type_env::DwarfTypeEnv::new(types);
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
        if let Some(pointer) = type_env
            .aggregate_pointer(c_type)
            .filter(|pointer| pointer.layout.is_some())
        {
            pointer_types.insert(
                VReg::phys(format!("arg{slot}")),
                pointer.tag_name.to_string(),
            );
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
    annotate_body(
        &mut function.body,
        &layouts,
        pointer_width,
        &pointer_types,
        &mut HashMap::new(),
    );
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
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                ..
            } if dst == target && is_promoted_local_reg(dst) => visitor(Some(src)),
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
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                ..
            } if is_promoted_local_reg(dst) => {
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
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
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
    crate::ir::dwarf_type_env::pointed_type_name(&field.c_type)
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
        "char" | "signed char" | "unsigned char" | "_Bool" | "bool" | "int8_t" | "uint8_t" => {
            Some(1)
        }
        "short" | "short int" | "signed short" | "signed short int" | "unsigned short"
        | "unsigned short int" | "int16_t" | "uint16_t" => Some(2),
        "int" | "signed" | "signed int" | "unsigned" | "unsigned int" | "float" | "int32_t"
        | "uint32_t" => Some(4),
        "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "double"
        | "int64_t"
        | "uint64_t" => Some(8),
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
    definitions: &mut HashMap<VReg, Expr>,
) {
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                annotate_expr(src, layouts, pointer_width, pointer_types, definitions);
                if expression_reads(src, dst) {
                    definitions.remove(dst);
                } else {
                    definitions.insert(dst.clone(), src.clone());
                }
            }
            Stmt::Store { addr, src, size } => {
                annotate_expr(src, layouts, pointer_width, pointer_types, definitions);
                // A bare promoted stack-slot address is the storage identity of
                // a source local, not a dereference through that local.  Once
                // type propagation proves the slot contains `struct T *`,
                // annotating offset zero here would turn `local = value` into
                // the unrelated field store `local->first_field = value`.
                if !matches!(addr, Expr::Reg(register) if is_promoted_local_reg(register)) {
                    annotate_address(
                        addr,
                        *size,
                        layouts,
                        pointer_width,
                        pointer_types,
                        definitions,
                    );
                }
            }
            Stmt::Call {
                dst, target, args, ..
            } => {
                annotate_expr(target, layouts, pointer_width, pointer_types, definitions);
                for argument in args {
                    annotate_expr(argument, layouts, pointer_width, pointer_types, definitions);
                }
                if let Some(dst) = dst {
                    definitions.remove(dst);
                }
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    annotate_expr(value, layouts, pointer_width, pointer_types, definitions);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                annotate_expr(cond, layouts, pointer_width, pointer_types, definitions);
                let mut then_definitions = definitions.clone();
                annotate_body(
                    then_body,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &mut then_definitions,
                );
                if let Some(else_body) = else_body {
                    let mut else_definitions = definitions.clone();
                    annotate_body(
                        else_body,
                        layouts,
                        pointer_width,
                        pointer_types,
                        &mut else_definitions,
                    );
                }
                invalidate_written_definitions(statement, definitions);
            }
            Stmt::While { cond, body } => {
                let mut written = Vec::new();
                for nested in body.iter() {
                    collect_written_registers(nested, &mut written);
                }
                let mut loop_definitions = definitions.clone();
                invalidate_registers(&written, &mut loop_definitions);
                // A While condition executes after every backedge. Expand only
                // definitions invariant across the body; using `cursor = arg0`
                // here turns every later `cursor->field` into `arg0->field`.
                annotate_expr(
                    cond,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &loop_definitions,
                );
                annotate_body(
                    body,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &mut loop_definitions,
                );
                invalidate_registers(&written, definitions);
            }
            Stmt::DoWhile { cond, body } => {
                let mut written = Vec::new();
                for nested in body.iter() {
                    collect_written_registers(nested, &mut written);
                }
                let mut loop_definitions = definitions.clone();
                invalidate_registers(&written, &mut loop_definitions);
                annotate_body(
                    body,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &mut loop_definitions,
                );
                annotate_expr(
                    cond,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &loop_definitions,
                );
                invalidate_registers(&written, definitions);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                let mut written = Vec::new();
                for nested in body.iter() {
                    collect_written_registers(nested, &mut written);
                }
                collect_written_registers(step, &mut written);
                annotate_body(
                    std::slice::from_mut(init.as_mut()),
                    layouts,
                    pointer_width,
                    pointer_types,
                    definitions,
                );
                let mut loop_definitions = definitions.clone();
                invalidate_registers(&written, &mut loop_definitions);
                annotate_expr(
                    cond,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &loop_definitions,
                );
                annotate_body(
                    body,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &mut loop_definitions,
                );
                annotate_body(
                    std::slice::from_mut(step.as_mut()),
                    layouts,
                    pointer_width,
                    pointer_types,
                    &mut loop_definitions,
                );
                invalidate_registers(&written, definitions);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                annotate_expr(
                    discriminant,
                    layouts,
                    pointer_width,
                    pointer_types,
                    definitions,
                );
                for (_, body) in cases {
                    annotate_body(
                        body,
                        layouts,
                        pointer_width,
                        pointer_types,
                        &mut definitions.clone(),
                    );
                }
                if let Some(default) = default {
                    annotate_body(
                        default,
                        layouts,
                        pointer_width,
                        pointer_types,
                        &mut definitions.clone(),
                    );
                }
                invalidate_written_definitions(statement, definitions);
            }
            Stmt::Push { value } => {
                annotate_expr(value, layouts, pointer_width, pointer_types, definitions)
            }
            Stmt::IndirectGoto { target } => {
                annotate_expr(target, layouts, pointer_width, pointer_types, definitions)
            }
            Stmt::TryCatch { try_body, catches } => {
                annotate_body(
                    try_body,
                    layouts,
                    pointer_width,
                    pointer_types,
                    &mut definitions.clone(),
                );
                for catch in catches {
                    annotate_body(
                        &mut catch.body,
                        layouts,
                        pointer_width,
                        pointer_types,
                        &mut definitions.clone(),
                    );
                }
                invalidate_written_definitions(statement, definitions);
            }
            Stmt::Pop { target } => {
                definitions.remove(target);
            }
            Stmt::Label(_) => {
                // A residual label is a control-flow join. The linear walk
                // does not have predecessor-specific reaching definitions,
                // so expanding any expression recorded before this point can
                // substitute a value from the wrong path. Keep authoritative
                // pointer types, but fail closed on expression provenance.
                definitions.clear();
            }
            Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
        }
    }
}

fn annotate_expr(
    expression: &mut Expr,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
    definitions: &HashMap<VReg, Expr>,
) {
    match expression {
        Expr::Deref { addr, size } => {
            annotate_expr(addr, layouts, pointer_width, pointer_types, definitions);
            annotate_address(
                addr,
                *size,
                layouts,
                pointer_width,
                pointer_types,
                definitions,
            );
        }
        Expr::Call { target, args, .. } => {
            annotate_expr(target, layouts, pointer_width, pointer_types, definitions);
            for argument in args {
                annotate_expr(argument, layouts, pointer_width, pointer_types, definitions);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            annotate_expr(lhs, layouts, pointer_width, pointer_types, definitions);
            annotate_expr(rhs, layouts, pointer_width, pointer_types, definitions);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            annotate_expr(cond, layouts, pointer_width, pointer_types, definitions);
            annotate_expr(if_true, layouts, pointer_width, pointer_types, definitions);
            annotate_expr(if_false, layouts, pointer_width, pointer_types, definitions);
        }
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => {
            annotate_expr(src, layouts, pointer_width, pointer_types, definitions)
        }
        Expr::FunctionTableEntry { index, .. } => {
            annotate_expr(index, layouts, pointer_width, pointer_types, definitions)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                annotate_expr(argument, layouts, pointer_width, pointer_types, definitions);
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
    definitions: &HashMap<VReg, Expr>,
) {
    let Some((base, index, scale, offset_i64, index_view)) =
        affine_struct_address(address, layouts, pointer_width, pointer_types, definitions)
    else {
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
        index,
        scale,
        disp: offset_i64,
        segment: None,
        hints: vec![PdbFieldHint {
            type_name: type_name.clone(),
            field_name: field.name.clone(),
            field_type: Some(field.c_type.clone()),
            offset: field.offset,
            index_signed: index_view.map(|view| view.0),
            index_width: index_view.map(|view| view.1),
            renderable: true,
        }],
    };
}

#[derive(Default)]
struct AffineForm {
    terms: HashMap<VReg, i64>,
    views: HashMap<VReg, (bool, u8)>,
    constant: i64,
}

fn affine_struct_address(
    expression: &Expr,
    layouts: &HashMap<String, &DwarfType>,
    pointer_width: u8,
    pointer_types: &HashMap<VReg, String>,
    definitions: &HashMap<VReg, Expr>,
) -> Option<(VReg, Option<VReg>, u8, i64, Option<(bool, u8)>)> {
    let form = affine_form(expression, definitions, &mut Vec::new())?;
    let mut bases = form
        .terms
        .iter()
        .filter(|(register, coefficient)| {
            **coefficient == 1 && pointer_types.contains_key(*register)
        })
        .map(|(register, _)| register.clone())
        .collect::<Vec<_>>();
    if bases.len() != 1 {
        return None;
    }
    let base = bases.pop()?;
    if form
        .views
        .get(&base)
        .is_some_and(|(_, width)| *width != pointer_width)
    {
        return None;
    }
    let type_name = pointer_types.get(&base)?;
    let layout = layouts.get(type_name)?;
    let scale = u8::try_from(layout.byte_size)
        .ok()
        .filter(|scale| *scale > 0)?;
    let mut remaining = form
        .terms
        .into_iter()
        .filter(|(register, _)| register != &base)
        .collect::<Vec<_>>();
    let index = match remaining.as_slice() {
        [] => None,
        [(register, coefficient)] if *coefficient == i64::from(scale) => Some(register.clone()),
        _ => return None,
    };
    remaining.clear();
    let address_scale = if index.is_some() { scale } else { 1 };
    let index_view = index
        .as_ref()
        .and_then(|register| form.views.get(register).copied());
    Some((base, index, address_scale, form.constant, index_view))
}

fn affine_form(
    expression: &Expr,
    definitions: &HashMap<VReg, Expr>,
    expanding: &mut Vec<VReg>,
) -> Option<AffineForm> {
    match expression {
        Expr::Const(value) => Some(AffineForm {
            terms: HashMap::new(),
            views: HashMap::new(),
            constant: *value,
        }),
        Expr::Reg(register) => {
            if let Some(definition) = definitions.get(register) {
                if !expanding.contains(register) {
                    expanding.push(register.clone());
                    let expanded = affine_form(definition, definitions, expanding);
                    expanding.pop();
                    if expanded.is_some() {
                        return expanded;
                    }
                }
            }
            Some(AffineForm {
                terms: HashMap::from([(register.clone(), 1)]),
                views: HashMap::new(),
                constant: 0,
            })
        }
        cast @ Expr::Cast { .. } => {
            let (register, signed, width) = casted_register_view(cast)?;
            Some(AffineForm {
                terms: HashMap::from([(register.clone(), 1)]),
                views: HashMap::from([(register.clone(), (signed, width))]),
                constant: 0,
            })
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => combine_affine(
            affine_form(lhs, definitions, expanding)?,
            affine_form(rhs, definitions, expanding)?,
            1,
        ),
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => combine_affine(
            affine_form(lhs, definitions, expanding)?,
            affine_form(rhs, definitions, expanding)?,
            -1,
        ),
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Const(factor), value) | (value, Expr::Const(factor)) => {
                scale_affine(affine_form(value, definitions, expanding)?, *factor)
            }
            _ => None,
        },
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            ..
        }
        | Expr::PdbFieldAddr {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            let mut form = AffineForm {
                terms: HashMap::new(),
                views: HashMap::new(),
                constant: *disp,
            };
            if let Some(base) = base {
                form = combine_affine(
                    form,
                    affine_form(&Expr::Reg(base.clone()), definitions, expanding)?,
                    1,
                )?;
            }
            if let Some(index) = index {
                let index = affine_form(&Expr::Reg(index.clone()), definitions, expanding)?;
                // MemOp/Lea use zero for an ordinary one-times index. Treating
                // it as a mathematical zero discards the index and can turn
                // `base + byte_offset` into the unrelated `base->field0`.
                form = combine_affine(form, scale_affine(index, i64::from((*scale).max(1)))?, 1)?;
            }
            Some(form)
        }
        _ => None,
    }
}

fn casted_register_view(expression: &Expr) -> Option<(&VReg, bool, u8)> {
    let mut current = expression;
    let mut selected = None::<(bool, u8)>;
    while let Expr::Cast {
        signed,
        width,
        expr,
    } = current
    {
        if selected.is_none_or(|(_, selected_width)| *width < selected_width) {
            selected = Some((*signed, *width));
        }
        current = expr;
    }
    let Expr::Reg(register) = current else {
        return None;
    };
    selected.map(|(signed, width)| (register, signed, width))
}

fn combine_affine(mut lhs: AffineForm, rhs: AffineForm, sign: i64) -> Option<AffineForm> {
    lhs.constant = lhs.constant.checked_add(rhs.constant.checked_mul(sign)?)?;
    for (register, coefficient) in rhs.terms {
        if lhs.terms.contains_key(&register) {
            match (lhs.views.get(&register), rhs.views.get(&register)) {
                (Some(lhs_view), Some(rhs_view)) if lhs_view == rhs_view => {}
                (None, None) => {}
                _ => return None,
            }
        }
        let contribution = coefficient.checked_mul(sign)?;
        let slot = lhs.terms.entry(register).or_insert(0);
        *slot = slot.checked_add(contribution)?;
    }
    lhs.views.extend(rhs.views);
    lhs.terms.retain(|_, coefficient| *coefficient != 0);
    lhs.views
        .retain(|register, _| lhs.terms.contains_key(register));
    Some(lhs)
}

fn scale_affine(mut form: AffineForm, factor: i64) -> Option<AffineForm> {
    form.constant = form.constant.checked_mul(factor)?;
    for coefficient in form.terms.values_mut() {
        *coefficient = coefficient.checked_mul(factor)?;
    }
    form.terms.retain(|_, coefficient| *coefficient != 0);
    form.views
        .retain(|register, _| form.terms.contains_key(register));
    Some(form)
}

fn expression_reads(expression: &Expr, target: &VReg) -> bool {
    affine_form(expression, &HashMap::new(), &mut Vec::new())
        .is_some_and(|form| form.terms.contains_key(target))
}

fn invalidate_written_definitions(statement: &Stmt, definitions: &mut HashMap<VReg, Expr>) {
    let mut written = Vec::new();
    collect_written_registers(statement, &mut written);
    for register in written {
        definitions.remove(&register);
    }
}

fn invalidate_registers(written: &[VReg], definitions: &mut HashMap<VReg, Expr>) {
    for register in written {
        definitions.remove(register);
    }
}

fn collect_written_registers(statement: &Stmt, written: &mut Vec<VReg>) {
    match statement {
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => written.push(dst.clone()),
        Stmt::Call { dst: Some(dst), .. } => written.push(dst.clone()),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for statement in then_body {
                collect_written_registers(statement, written);
            }
            if let Some(else_body) = else_body {
                for statement in else_body {
                    collect_written_registers(statement, written);
                }
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            for statement in body {
                collect_written_registers(statement, written);
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            collect_written_registers(init, written);
            for statement in body {
                collect_written_registers(statement, written);
            }
            collect_written_registers(step, written);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for statement in body {
                    collect_written_registers(statement, written);
                }
            }
            if let Some(default) = default {
                for statement in default {
                    collect_written_registers(statement, written);
                }
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            for statement in try_body {
                collect_written_registers(statement, written);
            }
            for catch in catches {
                for statement in &catch.body {
                    collect_written_registers(statement, written);
                }
            }
        }
        _ => {}
    }
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
    fn promoted_stack_result_preserves_authoritative_struct_pointer_type() {
        let local = VReg::phys("local_8");
        let mut function = Function {
            name: "list_find".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(local.clone()),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Reg(local.clone()),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(local.clone())),
                },
            ],
        };

        let pointer_types =
            annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        assert_eq!(pointer_types.get(&local).map(String::as_str), Some("node"));
        assert!(matches!(
            &function.body[0],
            Stmt::Store {
                addr: Expr::Reg(dst),
                ..
            } if dst == &local
        ));
        assert!(matches!(
            &function.body[1],
            Stmt::Store {
                addr: Expr::Reg(dst),
                ..
            } if dst == &local
        ));
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
    fn narrowed_pointer_base_stays_raw() {
        let mut function = Function {
            name: "narrow_base".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("value"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        }),
                        rhs: Box::new(Expr::Const(8)),
                    }),
                    size: 4,
                },
            }],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment");
        };
        assert!(
            field_hint(src).is_none(),
            "a 32-bit base cast cannot become a 64-bit pointer access"
        );
    }

    #[test]
    fn affine_index_through_reaching_temporary_annotates_member() {
        let mut function = Function {
            name: "indexed_value".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("stride"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(VReg::phys("index"))),
                            }),
                        }),
                        rhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(VReg::phys("index"))),
                            }),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("value"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(VReg::phys("arg0")),
                            index: Some(VReg::phys("stride")),
                            scale: 8,
                            disp: 8,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
            ],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::Assign { src, .. } = &function.body[1] else {
            panic!("expected indexed load");
        };
        assert_eq!(
            field_hint(src).map(|hint| hint.field_name.as_str()),
            Some("val"),
            "{src:#?}"
        );
        let Expr::Deref { addr, .. } = src else {
            panic!("expected indexed load");
        };
        assert!(matches!(
            addr.as_ref(),
            Expr::PdbFieldAddr {
                base: Some(base),
                index: Some(index),
                scale: 16,
                disp: 8,
                ..
            } if base == &VReg::phys("arg0") && index == &VReg::phys("index")
        ));
    }

    #[test]
    fn unscaled_lea_index_is_not_discarded_as_a_zero_coefficient() {
        let mut function = Function {
            name: "byte_offset_member".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("value"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Lea {
                        base: Some(VReg::phys("arg0")),
                        index: Some(VReg::phys("byte_offset")),
                        // MemOp uses zero for an ordinary, one-times index.
                        scale: 0,
                        disp: 0,
                        segment: None,
                    }),
                    size: 8,
                },
            }],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected indexed load");
        };
        assert!(
            field_hint(src).is_none(),
            "an unknown byte offset must not collapse to arg0->next: {src:#?}"
        );
        assert!(matches!(
            src,
            Expr::Deref { addr, .. }
                if matches!(
                    addr.as_ref(),
                    Expr::Lea {
                        index: Some(index),
                        scale: 0,
                        ..
                    } if index == &VReg::phys("byte_offset")
                )
        ));
    }

    #[test]
    fn field_annotation_does_not_expand_definitions_across_cfg_labels() {
        let index = VReg::phys("index");
        let pointer = VReg::phys("pointer");
        let mut function = Function {
            name: "joined_pointer".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: index.clone(),
                    src: Expr::Reg(VReg::phys("good_index")),
                },
                Stmt::Assign {
                    dst: pointer.clone(),
                    src: Expr::Lea {
                        base: Some(VReg::phys("arg0")),
                        index: Some(index.clone()),
                        scale: 16,
                        disp: 0,
                        segment: None,
                    },
                },
                Stmt::Goto { target: 0x1020 },
                Stmt::Label(0x1010),
                Stmt::Assign {
                    dst: index,
                    src: Expr::Reg(VReg::phys("wrong_path_index")),
                },
                Stmt::Label(0x1020),
                Stmt::Assign {
                    dst: VReg::phys("value"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(pointer)),
                            rhs: Box::new(Expr::Const(8)),
                        }),
                        size: 4,
                    },
                },
            ],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::Assign { src, .. } = &function.body[6] else {
            panic!("expected field load");
        };
        assert!(
            field_hint(src).is_none(),
            "a linear definition map must not invent an index across a CFG join: {src:#?}"
        );
    }

    #[test]
    fn field_annotation_keeps_a_loop_carried_pointer_as_the_member_base() {
        let cursor = VReg::phys("cursor");
        let mut function = Function {
            name: "list_find".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: cursor.clone(),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::While {
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Ne,
                        lhs: Box::new(Expr::Deref {
                            addr: Box::new(Expr::Bin {
                                op: BinOp::Add,
                                lhs: Box::new(Expr::Reg(cursor.clone())),
                                rhs: Box::new(Expr::Const(8)),
                            }),
                            size: 4,
                        }),
                        rhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                    },
                    body: vec![Stmt::Assign {
                        dst: cursor.clone(),
                        src: Expr::Deref {
                            addr: Box::new(Expr::Reg(cursor.clone())),
                            size: 8,
                        },
                    }],
                },
            ],
        };

        annotate_function_fields(&mut function, Some(&node_prototype()), &[node_layout()], 8);

        let Stmt::While { cond, .. } = &function.body[1] else {
            panic!("expected pointer scan loop")
        };
        let Expr::Cmp { lhs, .. } = cond else {
            panic!("expected field comparison")
        };
        let Expr::Deref { addr, .. } = lhs.as_ref() else {
            panic!("expected field load")
        };
        assert!(matches!(
            addr.as_ref(),
            Expr::PdbFieldAddr {
                base: Some(base),
                hints,
                ..
            } if base == &cursor && hints[0].field_name == "val"
        ));
    }

    #[test]
    fn mixed_reuse_rejects_declaration_but_keeps_reaching_field_identity() {
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
        assert_eq!(
            field_hint(src).map(|hint| hint.field_name.as_str()),
            Some("val")
        );
        let Expr::Deref { addr, .. } = src else {
            panic!("expected field load");
        };
        assert!(matches!(
            addr.as_ref(),
            Expr::PdbFieldAddr {
                base: Some(base),
                ..
            } if base == &VReg::phys("arg0")
        ));
    }
}
