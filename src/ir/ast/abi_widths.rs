//! Integer-width recovery for the DecBench declaration plan.
//!
//! Raw-register type recovery reports the narrowest sub-register signal it saw
//! (`edi` -> 4 bytes). That rule is right for the register bank and wrong for a
//! C declaration: if the body shifts the same incoming eightbyte by 32, masks
//! above bit 31, or assembles a result from 64-bit operations, narrowing the
//! declared parameter or return type would discard live bits at the ABI
//! boundary. This module owns the proof that a high half is semantically live
//! ([`collect_high_half_requirements`], [`propagate_required_widths`]), the
//! definition-width fixed point that backs it ([`collect_definition_widths`]),
//! and the two smaller refinements that share the same evidence — signed
//! comparison operands and pointer access widths.
//!
//! [`refine_decbench_abi_widths_with_value_widths`] is the single production
//! front door; it mutates the `TypeMap` in place before the declaration plan is
//! computed. It lives beside `ast.rs` rather than inside it because it is a
//! self-contained width question over an already-built AST, and `ast.rs` is the
//! crate's largest file.

use super::{
    is_high_variable, is_promoted_local, parse_arg_index, BinOp, CmpOp, Expr, Function, Stmt,
    TypeHint, TypeMap, VReg,
};

/// Correct declaration widths when the AST proves that the high half of an ABI
/// value is semantically live. Raw-register type recovery deliberately prefers a
/// narrow sub-register signal (`edi` -> 4 bytes), but that rule is wrong for a
/// packed SysV aggregate when the same incoming eightbyte is also shifted by 32
/// or masked above bit 31. The high-bit consumer is stronger evidence: narrowing
/// the C parameter would discard input bits before the body can inspect them.
///
/// The same dataflow supplies the return width. A result assembled from 64-bit
/// casts/operations must not inherit a stray final `eax` hint and render as
/// `int`, which truncates a valid machine `long` at the C ABI boundary.
///
/// Test scaffolding only. The shipped pipeline always has exact per-SSA-value
/// widths to hand and calls [`refine_decbench_abi_widths_with_value_widths`]
/// directly; this no-evidence form exists so unit tests can exercise the
/// AST-only inference path without building a value map. It is `cfg(test)` so
/// that a reader grepping for the live width pass cannot land on the wrong one.
#[cfg(test)]
pub(crate) fn refine_decbench_abi_widths(f: &Function, tm: &mut TypeMap) {
    refine_decbench_abi_widths_with_value_widths(f, tm, None);
}

/// Refine declarations after source-level preparation while retaining exact
/// per-SSA-value width evidence from value numbering.
pub(crate) fn refine_decbench_abi_widths_with_value_widths(
    f: &Function,
    tm: &mut TypeMap,
    value_widths: Option<&std::collections::HashMap<String, u8>>,
) {
    refine_signed_comparison_operands(&f.body, tm);

    let mut required_wide = std::collections::HashSet::new();
    collect_high_half_requirements(&f.body, &mut required_wide);

    // Carry a high-half requirement backwards through copy/definition chains:
    // `local_18 = arg0; y = (unsigned long)local_18 >> 32` proves `arg0` wide.
    loop {
        let before = required_wide.len();
        propagate_required_widths(&f.body, &mut required_wide);
        if required_wide.len() == before {
            break;
        }
    }
    for name in required_wide
        .iter()
        .filter(|name| parse_arg_index(name).is_some())
    {
        tm.force_int_width(VReg::phys(name), 8);
    }

    let mut defs = std::collections::HashMap::new();
    // AST names are almost SSA after value numbering, but promoted locals can
    // have multiple assignments. A bounded monotone fixed point handles both.
    loop {
        let before = defs.clone();
        collect_definition_widths(&f.body, tm, &mut defs);
        if defs == before {
            break;
        }
    }
    for (name, &ast_definition_width) in &defs {
        if !is_high_variable(name) || !all_definitions_proven_scalar(&f.body, name, tm) {
            continue;
        }
        let value = VReg::phys(name);
        if let Some(TypeHint::Int { signed, width }) = tm.get(&value) {
            let definition_width = value_widths
                .and_then(|widths| widths.get(name).copied())
                .unwrap_or(ast_definition_width);
            if definition_width > width {
                // The per-value semantic map belongs to the final rendered
                // identity and therefore outranks a prepared expression whose
                // copy/cast history no longer exposes its machine width.
                tm.force_scalar_int(value, signed, definition_width);
            }
        }
    }
    if let Some(width) = widest_return_value(&f.body, tm, &defs) {
        let reaching = crate::ir::structured_reaching::returned_role_integer_fact(f, "ret", tm);
        let proven_width = match reaching {
            crate::ir::structured_reaching::ReturnedIntegerFact::Proven(reaching_width) => {
                Some(reaching_width)
            }
            crate::ir::structured_reaching::ReturnedIntegerFact::Unsupported
                if all_definitions_proven_scalar(&f.body, "ret", tm) =>
            {
                // Preserve the established fallback for honest residual gotos.
                // Unsupported predecessor recovery is not pointer evidence.
                Some(width)
            }
            crate::ir::structured_reaching::ReturnedIntegerFact::Refuted
            | crate::ir::structured_reaching::ReturnedIntegerFact::Unsupported => None,
        };
        if let Some(proven_width) = proven_width {
            // Raw rax reuse can attach an earlier address-computation pointer
            // hint to the final return role. Prepared value flow is stronger:
            // when every definition is explicitly scalar, the function cannot
            // have a pointer return merely because one physical register once
            // held an address.
            let ret = VReg::phys("ret");
            if let Some(TypeHint::Int {
                signed,
                width: recovered_width,
            }) = tm.get(&ret)
            {
                tm.force_scalar_int(ret, signed, recovered_width.max(proven_width));
            } else {
                tm.force_scalar_int(ret, true, proven_width);
            }
        } else if width >= 8 {
            tm.force_int_width(VReg::phys("ret"), 8);
        }
    }
    refine_pointer_access_widths(&f.body, tm);
}

/// Signed comparison operators carry source-level signedness evidence that is
/// lost when raw-register recovery also observes a zero-extended/index use.
/// Apply that evidence only to direct integer operands: signed arithmetic over
/// a composite expression does not prove every leaf has a signed declaration,
/// and semantic pointer hints must remain pointers.
fn refine_signed_comparison_operands(body: &[Stmt], tm: &mut TypeMap) {
    fn direct_signed_value(expr: &Expr) -> Option<&VReg> {
        match expr {
            Expr::Reg(reg) => Some(reg),
            Expr::Cast {
                signed: true, expr, ..
            } => direct_signed_value(expr),
            _ => None,
        }
    }

    fn expression(expr: &Expr, tm: &mut TypeMap) {
        match expr {
            Expr::Cmp { op, lhs, rhs } => {
                if matches!(op, CmpOp::Slt | CmpOp::Sle) {
                    for operand in [lhs.as_ref(), rhs.as_ref()] {
                        if let Some(reg) = direct_signed_value(operand) {
                            tm.force_int_signedness(reg.clone(), true);
                        }
                    }
                }
                expression(lhs, tm);
                expression(rhs, tm);
            }
            Expr::Deref { addr, .. } => expression(addr, tm),
            Expr::Call { target, args, .. } => {
                expression(target, tm);
                for argument in args {
                    expression(argument, tm);
                }
            }
            Expr::Bin { lhs, rhs, .. } => {
                expression(lhs, tm);
                expression(rhs, tm);
            }
            Expr::Un { src, .. } => expression(src, tm),
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression(cond, tm);
                expression(if_true, tm);
                expression(if_false, tm);
            }
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => expression(expr, tm),
            Expr::FunctionTableEntry { index, .. } => expression(index, tm),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expression(argument, tm);
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

    fn statements(body: &[Stmt], tm: &mut TypeMap) {
        for statement in body {
            match statement {
                Stmt::Assign { src, .. } | Stmt::Return { value: Some(src) } => expression(src, tm),
                Stmt::Store { addr, src, .. } => {
                    expression(addr, tm);
                    expression(src, tm);
                }
                Stmt::Call { target, args, .. } => {
                    expression(target, tm);
                    for arg in args {
                        expression(arg, tm);
                    }
                }
                Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                    expression(target, tm);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    expression(cond, tm);
                    statements(then_body, tm);
                    if let Some(else_body) = else_body {
                        statements(else_body, tm);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                    expression(cond, tm);
                    statements(body, tm);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    statements(std::slice::from_ref(init.as_ref()), tm);
                    expression(cond, tm);
                    statements(std::slice::from_ref(step.as_ref()), tm);
                    statements(body, tm);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    expression(discriminant, tm);
                    for (_, case_body) in cases {
                        statements(case_body, tm);
                    }
                    if let Some(default) = default {
                        statements(default, tm);
                    }
                }
                Stmt::Return { value: None }
                | Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::Break
                | Stmt::Continue
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Pop { .. } => {}
                Stmt::Throw { value } => expression(value, tm),
                Stmt::TryCatch { try_body, catches } => {
                    statements(try_body, tm);
                    for catch in catches {
                        statements(&catch.body, tm);
                    }
                }
            }
        }
    }

    statements(body, tm);
}

fn all_definitions_proven_scalar(body: &[Stmt], target: &str, tm: &TypeMap) -> bool {
    fn walk(body: &[Stmt], target: &str, tm: &TypeMap, found: &mut bool, valid: &mut bool) {
        for statement in body {
            match statement {
                Stmt::Assign {
                    dst: VReg::Phys(name),
                    src,
                } if name == target => {
                    *found = true;
                    *valid &= expression_proven_scalar(src, tm);
                }
                Stmt::Call {
                    dst: Some(VReg::Phys(name)),
                    ..
                } if name == target => {
                    // Without a recovered callee prototype, a call result may
                    // legitimately be a pointer.
                    *found = true;
                    *valid = false;
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    walk(then_body, target, tm, found, valid);
                    if let Some(else_body) = else_body {
                        walk(else_body, target, tm, found, valid);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    walk(body, target, tm, found, valid)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    walk(
                        std::slice::from_ref(init.as_ref()),
                        target,
                        tm,
                        found,
                        valid,
                    );
                    walk(
                        std::slice::from_ref(step.as_ref()),
                        target,
                        tm,
                        found,
                        valid,
                    );
                    walk(body, target, tm, found, valid);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        walk(case, target, tm, found, valid);
                    }
                    if let Some(default) = default {
                        walk(default, target, tm, found, valid);
                    }
                }
                _ => {}
            }
        }
    }

    let mut found = false;
    let mut valid = true;
    walk(body, target, tm, &mut found, &mut valid);
    found && valid
}

fn expression_proven_scalar(expr: &Expr, tm: &TypeMap) -> bool {
    match expr {
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Cmp { .. }
        | Expr::Cast { .. }
        | Expr::NumericConvert { .. } => true,
        Expr::Reg(VReg::Phys(name)) => matches!(
            tm.get(&VReg::phys(name)),
            Some(TypeHint::Int { .. } | TypeHint::BoolLike)
        ),
        Expr::Bin { lhs, rhs, .. } => {
            expression_proven_scalar(lhs, tm) && expression_proven_scalar(rhs, tm)
        }
        Expr::Un { src, .. } => expression_proven_scalar(src, tm),
        Expr::Select {
            if_true, if_false, ..
        } => expression_proven_scalar(if_true, tm) && expression_proven_scalar(if_false, tm),
        Expr::WideArithmetic { .. } => true,
        Expr::Call { call_spec, .. } => call_spec.as_ref().is_some_and(|spec| {
            crate::ir::call_contracts::call_return_hint(&spec.call_prototype.return_type)
                .is_some_and(|hint| {
                    !matches!(hint, TypeHint::Pointer { .. } | TypeHint::CodePointer)
                })
        }),
        Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Deref { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::FunctionTableEntry { .. } => false,
    }
}

fn refine_pointer_access_widths(body: &[Stmt], tm: &mut TypeMap) {
    let mut observed: std::collections::HashMap<String, std::collections::BTreeSet<u8>> =
        std::collections::HashMap::new();
    collect_pointer_accesses_body(body, tm, &mut observed);
    for (name, widths) in observed {
        if widths.len() == 1 {
            tm.force_pointer_width(
                VReg::phys(&name),
                *widths.first().expect("one observed pointer width"),
            );
        }
    }
}

fn collect_pointer_accesses_body(
    body: &[Stmt],
    tm: &TypeMap,
    observed: &mut std::collections::HashMap<String, std::collections::BTreeSet<u8>>,
) {
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } | Stmt::Push { value: src } => {
                collect_pointer_accesses_expr(src, tm, observed)
            }
            Stmt::Store { addr, src, size } => {
                if !matches!(addr, Expr::Reg(VReg::Phys(name)) if is_promoted_local(name)) {
                    record_pointer_access(addr, *size, tm, observed);
                }
                collect_pointer_accesses_expr(addr, tm, observed);
                collect_pointer_accesses_expr(src, tm, observed);
            }
            Stmt::Call { target, args, .. } => {
                collect_pointer_accesses_expr(target, tm, observed);
                for arg in args {
                    collect_pointer_accesses_expr(arg, tm, observed);
                }
            }
            Stmt::Return { value: Some(value) } | Stmt::IndirectGoto { target: value } => {
                collect_pointer_accesses_expr(value, tm, observed)
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_pointer_accesses_expr(cond, tm, observed);
                collect_pointer_accesses_body(then_body, tm, observed);
                if let Some(else_body) = else_body {
                    collect_pointer_accesses_body(else_body, tm, observed);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                collect_pointer_accesses_expr(cond, tm, observed);
                collect_pointer_accesses_body(body, tm, observed);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_pointer_accesses_body(std::slice::from_ref(init.as_ref()), tm, observed);
                collect_pointer_accesses_expr(cond, tm, observed);
                collect_pointer_accesses_body(std::slice::from_ref(step.as_ref()), tm, observed);
                collect_pointer_accesses_body(body, tm, observed);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_pointer_accesses_expr(discriminant, tm, observed);
                for (_, case) in cases {
                    collect_pointer_accesses_body(case, tm, observed);
                }
                if let Some(default) = default {
                    collect_pointer_accesses_body(default, tm, observed);
                }
            }
            _ => {}
        }
    }
}

fn collect_pointer_accesses_expr(
    expr: &Expr,
    tm: &TypeMap,
    observed: &mut std::collections::HashMap<String, std::collections::BTreeSet<u8>>,
) {
    match expr {
        Expr::Deref { addr, size } => {
            record_pointer_access(addr, *size, tm, observed);
            collect_pointer_accesses_expr(addr, tm, observed);
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_pointer_accesses_expr(lhs, tm, observed);
            collect_pointer_accesses_expr(rhs, tm, observed);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_pointer_accesses_expr(cond, tm, observed);
            collect_pointer_accesses_expr(if_true, tm, observed);
            collect_pointer_accesses_expr(if_false, tm, observed);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            collect_pointer_accesses_expr(src, tm, observed)
        }
        _ => {}
    }
}

fn record_pointer_access(
    addr: &Expr,
    size: u8,
    tm: &TypeMap,
    observed: &mut std::collections::HashMap<String, std::collections::BTreeSet<u8>>,
) {
    if let Some(name) = direct_pointer_base(addr, tm) {
        observed.entry(name.to_string()).or_default().insert(size);
    }
}

fn direct_pointer_base<'a>(addr: &'a Expr, tm: &TypeMap) -> Option<&'a str> {
    let is_pointer =
        |name: &str| matches!(tm.get(&VReg::phys(name)), Some(TypeHint::Pointer { .. }));
    match addr {
        Expr::Reg(VReg::Phys(name)) if is_pointer(name) => Some(name),
        Expr::Lea {
            base: Some(VReg::Phys(name)),
            segment: None,
            ..
        }
        | Expr::PdbFieldAddr {
            base: Some(VReg::Phys(name)),
            segment: None,
            ..
        } if is_pointer(name) => Some(name),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            let lhs = match lhs.as_ref() {
                Expr::Reg(VReg::Phys(name)) if is_pointer(name) => Some(name.as_str()),
                _ => None,
            };
            let rhs = match rhs.as_ref() {
                Expr::Reg(VReg::Phys(name)) if is_pointer(name) => Some(name.as_str()),
                _ => None,
            };
            match (lhs, rhs) {
                (Some(name), None) | (None, Some(name)) => Some(name),
                _ => None,
            }
        }
        _ => None,
    }
}

fn constant_needs_wide_word(value: i64) -> bool {
    value < i64::from(i32::MIN) || value > i64::from(u32::MAX)
}

fn collect_high_half_requirements(body: &[Stmt], required: &mut std::collections::HashSet<String>) {
    for stmt in body {
        match stmt {
            Stmt::Assign { src, .. } | Stmt::Push { value: src } => {
                collect_high_half_expr(src, required)
            }
            Stmt::Store { addr, src, .. } => {
                collect_high_half_expr(addr, required);
                collect_high_half_expr(src, required);
            }
            Stmt::Call { target, args, .. } => {
                collect_high_half_expr(target, required);
                for arg in args {
                    collect_high_half_expr(arg, required);
                }
            }
            Stmt::Return { value: Some(expr) } | Stmt::IndirectGoto { target: expr } => {
                collect_high_half_expr(expr, required)
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_high_half_expr(cond, required);
                collect_high_half_requirements(then_body, required);
                if let Some(else_body) = else_body {
                    collect_high_half_requirements(else_body, required);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                collect_high_half_expr(cond, required);
                collect_high_half_requirements(body, required);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_high_half_requirements(std::slice::from_ref(init.as_ref()), required);
                collect_high_half_expr(cond, required);
                collect_high_half_requirements(std::slice::from_ref(step.as_ref()), required);
                collect_high_half_requirements(body, required);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_high_half_expr(discriminant, required);
                for (_, case) in cases {
                    collect_high_half_requirements(case, required);
                }
                if let Some(default) = default {
                    collect_high_half_requirements(default, required);
                }
            }
            _ => {}
        }
    }
}

fn collect_high_half_expr(expr: &Expr, required: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Bin { op, lhs, rhs } => {
            let high_shift = matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar)
                && matches!(rhs.as_ref(), Expr::Const(count) if *count >= 32);
            if high_shift {
                require_wide_expr(lhs, required);
            }
            if matches!(lhs.as_ref(), Expr::Const(value) if constant_needs_wide_word(*value)) {
                require_wide_expr(rhs, required);
            }
            if matches!(rhs.as_ref(), Expr::Const(value) if constant_needs_wide_word(*value)) {
                require_wide_expr(lhs, required);
            }
            collect_high_half_expr(lhs, required);
            collect_high_half_expr(rhs, required);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } | Expr::Deref { addr: src, .. } => {
            collect_high_half_expr(src, required)
        }
        Expr::Cmp { lhs, rhs, .. } => {
            collect_high_half_expr(lhs, required);
            collect_high_half_expr(rhs, required);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_high_half_expr(cond, required);
            collect_high_half_expr(if_true, required);
            collect_high_half_expr(if_false, required);
        }
        _ => {}
    }
}

fn require_wide_expr(expr: &Expr, required: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Reg(VReg::Phys(name)) => {
            required.insert(name.clone());
        }
        Expr::Bin { op, lhs, rhs } => {
            require_wide_expr(lhs, required);
            if !matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                require_wide_expr(rhs, required);
            }
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => require_wide_expr(src, required),
        Expr::Select {
            if_true, if_false, ..
        } => {
            require_wide_expr(if_true, required);
            require_wide_expr(if_false, required);
        }
        _ => {}
    }
}

fn propagate_required_widths(body: &[Stmt], required: &mut std::collections::HashSet<String>) {
    for stmt in body {
        match stmt {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            } if required.contains(name) => require_wide_expr(src, required),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                propagate_required_widths(then_body, required);
                if let Some(else_body) = else_body {
                    propagate_required_widths(else_body, required);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                propagate_required_widths(body, required)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                propagate_required_widths(std::slice::from_ref(init.as_ref()), required);
                propagate_required_widths(std::slice::from_ref(step.as_ref()), required);
                propagate_required_widths(body, required);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    propagate_required_widths(case, required);
                }
                if let Some(default) = default {
                    propagate_required_widths(default, required);
                }
            }
            _ => {}
        }
    }
}

fn type_hint_width(hint: TypeHint) -> Option<u8> {
    match hint {
        TypeHint::Int { width, .. } => Some(width),
        TypeHint::Float { width } => Some(width),
        TypeHint::Pointer { .. } | TypeHint::CodePointer => Some(8),
        TypeHint::BoolLike => Some(4),
    }
}

fn expression_value_width(
    expr: &Expr,
    tm: &TypeMap,
    defs: &std::collections::HashMap<String, u8>,
) -> Option<u8> {
    match expr {
        Expr::Reg(VReg::Phys(name)) => defs
            .get(name)
            .copied()
            .or_else(|| tm.get(&VReg::phys(name)).and_then(type_hint_width)),
        Expr::Const(value) => Some(if constant_needs_wide_word(*value) {
            8
        } else {
            4
        }),
        Expr::FloatConst { width, .. } => Some(*width),
        Expr::NumericConvert { to, .. } => Some(to.width()),
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => Some(8),
        Expr::FunctionTableEntry { pointer_size, .. } => Some(*pointer_size),
        Expr::Call { result_width, .. } => *result_width,
        Expr::Deref { size, .. } => Some(*size),
        // x86's ordinary 32-bit return write is represented after
        // canonicalisation as a zero-extension into the 64-bit parent. That
        // machine housekeeping does not turn a C `int` return into `long`.
        // When the inner expression is explicitly narrowed first, keep its
        // semantic width and let the recovered return hint decide the ABI.
        Expr::Cast {
            signed: false,
            width: 8,
            expr: inner,
        } if matches!(inner.as_ref(), Expr::Cast { width: 1..=4, .. }) => {
            expression_value_width(inner, tm, defs)
        }
        Expr::Cast { width, .. } => Some(*width),
        Expr::Bin { op, lhs, rhs } => {
            let lhs_width = expression_value_width(lhs, tm, defs);
            if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                if matches!(rhs.as_ref(), Expr::Const(count) if *count >= 32) {
                    Some(lhs_width.unwrap_or(8).max(8))
                } else {
                    lhs_width
                }
            } else {
                let rhs_width = expression_value_width(rhs, tm, defs);
                lhs_width.into_iter().chain(rhs_width).max()
            }
        }
        Expr::Un { src, .. } => expression_value_width(src, tm, defs),
        Expr::Cmp { .. } => Some(4),
        Expr::Select { width, .. } => Some(*width),
        Expr::WideArithmetic { width, .. } => Some(*width),
        Expr::Unknown(_) | Expr::Reg(_) => None,
    }
}

fn collect_definition_widths(
    body: &[Stmt],
    tm: &TypeMap,
    defs: &mut std::collections::HashMap<String, u8>,
) {
    for stmt in body {
        match stmt {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            } => {
                if let Some(width) = expression_value_width(src, tm, defs) {
                    defs.entry(name.clone())
                        .and_modify(|old| *old = (*old).max(width))
                        .or_insert(width);
                }
            }
            Stmt::Call {
                dst: Some(VReg::Phys(name)),
                ..
            } => {
                if let Some(width) = tm.get(&VReg::phys(name)).and_then(type_hint_width) {
                    defs.entry(name.clone())
                        .and_modify(|old| *old = (*old).max(width))
                        .or_insert(width);
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_definition_widths(then_body, tm, defs);
                if let Some(else_body) = else_body {
                    collect_definition_widths(else_body, tm, defs);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_definition_widths(body, tm, defs)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_definition_widths(std::slice::from_ref(init.as_ref()), tm, defs);
                collect_definition_widths(std::slice::from_ref(step.as_ref()), tm, defs);
                collect_definition_widths(body, tm, defs);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_definition_widths(case, tm, defs);
                }
                if let Some(default) = default {
                    collect_definition_widths(default, tm, defs);
                }
            }
            _ => {}
        }
    }
}

fn widest_return_value(
    body: &[Stmt],
    tm: &TypeMap,
    defs: &std::collections::HashMap<String, u8>,
) -> Option<u8> {
    body.iter()
        .filter_map(|stmt| match stmt {
            Stmt::Return { value: Some(expr) } => expression_value_width(expr, tm, defs),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => widest_return_value(then_body, tm, defs)
                .into_iter()
                .chain(
                    else_body
                        .as_deref()
                        .and_then(|body| widest_return_value(body, tm, defs)),
                )
                .max(),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                widest_return_value(body, tm, defs)
            }
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .filter_map(|(_, case)| widest_return_value(case, tm, defs))
                .chain(
                    default
                        .as_deref()
                        .and_then(|body| widest_return_value(body, tm, defs)),
                )
                .max(),
            _ => None,
        })
        .max()
}
