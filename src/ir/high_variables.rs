//! Conservative source-level type propagation across prepared AST values.
//!
//! Value numbering gives non-structural machine definitions their own source
//! identities (`varN`). Earlier type recovery runs on raw LLIR, where operand
//! widths still exist, so it cannot key facts by those final identities. This
//! pass bridges that boundary after AST preparation: authoritative call
//! contracts and literal addresses seed values, and COPY/select edges propagate
//! the facts to a bounded fixed point.
//!
//! The pass is deliberately fail-closed: every definition of a candidate must
//! resolve to a compatible pointer, and any use in integer/address arithmetic
//! prevents changing its C declaration.

use std::collections::{HashMap, HashSet};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{is_promoted_local_name as is_promoted_local, VReg};
use crate::ir::types_recover::{TypeHint, TypeMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueClass {
    Pointer(u8),
    Scalar,
    Unknown,
}

/// Refine exact source-value locals using the prepared AST's definition graph.
///
/// Each successful iteration adds at least one fact, so the number of named
/// definitions is a strict convergence bound. Scalar facts remain the job of
/// width-aware LLIR recovery, which has stronger signedness evidence.
pub(crate) fn refine_pointer_high_variables(function: &Function, types: &mut TypeMap) {
    let mut definitions: HashMap<String, Vec<Definition>> = HashMap::new();
    collect_definitions(&function.body, &mut definitions);

    // The legacy map is keyed by raw storage. Before exact SSA definition-width
    // recovery the renderer intentionally ignored all scalar `varN` facts. The
    // integer and float facts reaching this pass are now projected from exact
    // value identities, so preserve them; pointer-like classifications still
    // need the prepared definition graph below to rule out storage collisions.
    let stale_high_variables: Vec<_> = types
        .iter()
        .filter_map(|(reg, hint)| match reg {
            // Semantic FP operations and numbered machine definitions prove
            // their source class/width. Only pointer-like or boolean residue
            // requires prepared-AST revalidation here.
            VReg::Phys(name)
                if is_high_variable(name)
                    && !matches!(hint, TypeHint::Float { .. } | TypeHint::Int { .. }) =>
            {
                Some(reg.clone())
            }
            _ => None,
        })
        .collect();
    for reg in stale_high_variables {
        types.clear_value_fact(&reg);
    }

    let mut unsafe_uses = HashSet::new();
    collect_unsafe_pointer_uses(&function.body, &mut unsafe_uses);
    refine_authoritative_pointer_parameters(&function.body, &definitions, &unsafe_uses, types);

    for _ in 0..=definitions.len() {
        let mut learned = Vec::new();
        for (name, defs) in &definitions {
            if !is_source_value_local(name)
                || unsafe_uses.contains(name)
                || matches!(types.get(&VReg::phys(name)), Some(TypeHint::Pointer { .. }))
            {
                continue;
            }
            let Some(width) = compatible_pointer_definitions(defs, types) else {
                continue;
            };
            learned.push((
                VReg::phys(name),
                TypeHint::Pointer {
                    pointee_width: width,
                },
            ));
        }
        if learned.is_empty() {
            break;
        }
        for (reg, hint) in learned {
            types.refine_from_value(reg, hint);
        }
    }
}

/// Refine direct source parameters from authoritative callee boundaries.
///
/// A function argument passed unchanged to `strcmp(const char *, ...)` is
/// stronger pointer evidence than the integer width of the ABI register that
/// transported it.  The same is true for a project-local direct callee whose
/// body recovered a pointer parameter: the caller may only forward that value,
/// so the callee is the sole intraprocedural source of its type. Conflicting
/// pointee types, indirect expressions, and any integer/arithmetic use remain
/// fail-closed.
fn refine_authoritative_pointer_parameters(
    body: &[Stmt],
    definitions: &HashMap<String, Vec<Definition>>,
    unsafe_uses: &HashSet<String>,
    types: &mut TypeMap,
) {
    fn collect(body: &[Stmt], out: &mut HashMap<String, Vec<u8>>) {
        for statement in body {
            match statement {
                Stmt::Call {
                    target,
                    args,
                    call_spec,
                    ..
                } => {
                    let recovered = call_spec
                        .as_ref()
                        .and_then(|spec| spec.callee_prototype.as_ref());
                    let catalog = match target {
                        Expr::Named { name, .. } => crate::ir::call_contracts::lookup(name),
                        _ => None,
                    };
                    for (index, argument) in args.iter().enumerate() {
                        let Expr::Reg(VReg::Phys(argument_name)) = argument else {
                            continue;
                        };
                        if !is_trusted_copy_source(argument_name) {
                            continue;
                        }
                        let c_type = recovered
                            .and_then(|prototype| prototype.parameter_types.get(index))
                            .map(String::as_str)
                            .or_else(|| {
                                catalog
                                    .as_ref()
                                    .and_then(|contract| contract.params.get(index))
                                    .map(|parameter| parameter.c_type.as_str())
                            });
                        if let Some(width) = c_type.and_then(pointer_width_from_c_type) {
                            out.entry(argument_name.clone()).or_default().push(width);
                        }
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect(then_body, out);
                    if let Some(else_body) = else_body {
                        collect(else_body, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => collect(body, out),
                Stmt::For {
                    init, step, body, ..
                } => {
                    collect(std::slice::from_ref(init.as_ref()), out);
                    collect(body, out);
                    collect(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        collect(case, out);
                    }
                    if let Some(default) = default {
                        collect(default, out);
                    }
                }
                _ => {}
            }
        }
    }

    let mut candidates = HashMap::new();
    collect(body, &mut candidates);
    for (name, widths) in candidates {
        let width = widths.iter().copied().max().unwrap_or(0);
        if !widths
            .iter()
            .all(|candidate| *candidate == 0 || width == 0 || *candidate == width)
        {
            continue;
        }
        let Some(origin) = single_exact_parameter_origin(&name, definitions) else {
            continue;
        };
        if unsafe_uses.contains(&origin) {
            continue;
        }
        types.refine_from_value(
            VReg::phys(origin),
            TypeHint::Pointer {
                pointee_width: width,
            },
        );
    }
}

#[derive(Debug)]
enum Definition {
    Assignment(Expr),
    Call {
        target: Expr,
        return_type: Option<String>,
    },
}

impl Definition {
    fn classify(&self, types: &TypeMap) -> ValueClass {
        match self {
            Self::Assignment(value) => classify_expr(value, types),
            Self::Call {
                target,
                return_type,
            } => classify_call(target, return_type.as_deref()),
        }
    }

    fn is_null_initializer(&self) -> bool {
        matches!(self, Self::Assignment(Expr::Const(0)))
    }
}

/// Resolve one prepared value to a unique source parameter through pure copies.
///
/// This is deliberately not generic reaching definitions. Multiple distinct
/// origins, arithmetic, calls, and cycles all fail closed: without dominance
/// information, an overwritten copy must not type a parameter that never
/// reaches the authoritative call boundary.
fn single_exact_parameter_origin(
    name: &str,
    definitions: &HashMap<String, Vec<Definition>>,
) -> Option<String> {
    fn visit(
        name: &str,
        definitions: &HashMap<String, Vec<Definition>>,
        visiting: &mut HashSet<String>,
    ) -> Option<String> {
        if crate::ir::ast::parse_arg_index(name).is_some() {
            return Some(name.to_string());
        }
        if !is_source_value_local(name) || !visiting.insert(name.to_string()) {
            return None;
        }
        let result = (|| {
            let value_definitions = definitions.get(name)?;
            let mut origin: Option<String> = None;
            for definition in value_definitions {
                let Definition::Assignment(Expr::Reg(VReg::Phys(source))) = definition else {
                    return None;
                };
                if !is_trusted_copy_source(source) {
                    return None;
                }
                let next = visit(source, definitions, visiting)?;
                if origin.as_ref().is_some_and(|current| current != &next) {
                    return None;
                }
                origin = Some(next);
            }
            origin
        })();
        visiting.remove(name);
        result
    }

    visit(name, definitions, &mut HashSet::new())
}

fn collect_definitions(body: &[Stmt], out: &mut HashMap<String, Vec<Definition>>) {
    for statement in body {
        match statement {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            } => out
                .entry(name.clone())
                .or_default()
                .push(Definition::Assignment(src.clone())),
            // Stack promotion keeps a source local's write as a Store whose
            // address is the promoted identity. The C renderer emits this as a
            // plain assignment, so it is a definition here as well. A `varN`
            // address remains a genuine memory write and must not define varN.
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                src,
                ..
            } if is_promoted_local(name) => out
                .entry(name.clone())
                .or_default()
                .push(Definition::Assignment(src.clone())),
            Stmt::Call {
                target,
                dst: Some(VReg::Phys(name)),
                call_spec,
                ..
            } => out.entry(name.clone()).or_default().push(Definition::Call {
                target: target.clone(),
                return_type: call_spec
                    .as_ref()
                    .map(|spec| spec.call_prototype.return_type.clone()),
            }),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_definitions(then_body, out);
                if let Some(else_body) = else_body {
                    collect_definitions(else_body, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => collect_definitions(body, out),
            Stmt::For {
                init, step, body, ..
            } => {
                collect_definitions(std::slice::from_ref(init.as_ref()), out);
                collect_definitions(body, out);
                collect_definitions(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_definitions(case, out);
                }
                if let Some(default) = default {
                    collect_definitions(default, out);
                }
            }
            _ => {}
        }
    }
}

fn compatible_pointer_definitions(definitions: &[Definition], types: &TypeMap) -> Option<u8> {
    let mut width = 0;
    let mut has_pointer = false;
    for definition in definitions {
        // C pointers are routinely initialized to NULL before a conditional
        // allocation.  The zero is compatible with a later proven pointer but
        // is not, by itself, evidence that an otherwise scalar local is one.
        if definition.is_null_initializer() {
            continue;
        }
        match definition.classify(types) {
            ValueClass::Pointer(next) if width == 0 || next == 0 || width == next => {
                width = width.max(next);
                has_pointer = true;
            }
            // Unknown is not evidence. This prevents one pointer-looking branch
            // from typing a multiply-defined local.
            ValueClass::Pointer(_) | ValueClass::Scalar | ValueClass::Unknown => return None,
        }
    }
    has_pointer.then_some(width)
}

fn classify_expr(expression: &Expr, types: &TypeMap) -> ValueClass {
    match expression {
        Expr::StringLit { .. } => ValueClass::Pointer(1),
        Expr::StackAddr { .. } => ValueClass::Pointer(0),
        Expr::FunctionTableEntry { .. } => ValueClass::Pointer(0),
        Expr::Reg(reg @ VReg::Phys(name)) if is_trusted_copy_source(name) => match types.get(reg) {
            Some(TypeHint::Pointer { pointee_width }) => ValueClass::Pointer(pointee_width),
            Some(TypeHint::CodePointer) => ValueClass::Pointer(0),
            Some(_) => ValueClass::Scalar,
            None => ValueClass::Unknown,
        },
        Expr::Reg(_) => ValueClass::Unknown,
        Expr::Select {
            if_true, if_false, ..
        } => merge_selected_values(
            classify_expr(if_true, types),
            classify_expr(if_false, types),
            if_true,
            if_false,
        ),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Deref { .. }
        | Expr::Bin { .. }
        | Expr::Un { .. }
        | Expr::Cmp { .. }
        | Expr::Cast { .. }
        | Expr::WideArithmetic { .. } => ValueClass::Scalar,
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => ValueClass::Unknown,
    }
}

fn merge_selected_values(
    left: ValueClass,
    right: ValueClass,
    left_expr: &Expr,
    right_expr: &Expr,
) -> ValueClass {
    match (left, right) {
        (ValueClass::Pointer(a), ValueClass::Pointer(b)) if a == 0 || b == 0 || a == b => {
            ValueClass::Pointer(a.max(b))
        }
        (ValueClass::Pointer(width), ValueClass::Scalar)
            if is_null_pointer_constant(right_expr) =>
        {
            ValueClass::Pointer(width)
        }
        (ValueClass::Scalar, ValueClass::Pointer(width)) if is_null_pointer_constant(left_expr) => {
            ValueClass::Pointer(width)
        }
        (ValueClass::Scalar, _) | (_, ValueClass::Scalar) => ValueClass::Scalar,
        _ => ValueClass::Unknown,
    }
}

fn is_null_pointer_constant(expression: &Expr) -> bool {
    matches!(expression, Expr::Const(0))
}

fn classify_call(target: &Expr, recovered_return_type: Option<&str>) -> ValueClass {
    if let Some(c_type) = recovered_return_type {
        return pointer_width_from_c_type(c_type)
            .map(ValueClass::Pointer)
            .unwrap_or(ValueClass::Scalar);
    }
    let Expr::Named { name, .. } = target else {
        return ValueClass::Unknown;
    };
    let Some(contract) = crate::ir::call_contracts::lookup(name) else {
        return ValueClass::Unknown;
    };
    pointer_width_from_c_type(&contract.return_type)
        .map(ValueClass::Pointer)
        .unwrap_or(ValueClass::Scalar)
}

fn pointer_width_from_c_type(c_type: &str) -> Option<u8> {
    let normal = c_type.to_ascii_lowercase();
    let stars = normal.bytes().filter(|byte| *byte == b'*').count();
    if stars == 0 {
        return None;
    }
    if stars > 1 {
        return Some(8);
    }
    let base = normal.split('*').next().unwrap_or_default();
    Some(if base.contains("char") {
        1
    } else if base.contains("short") {
        2
    } else if base.contains("wchar_t") || base.contains("int") || base.contains("float") {
        4
    } else if base.contains("long") || base.contains("double") {
        8
    } else {
        // void*, FILE*, handles, and incomplete structs remain opaque.
        0
    })
}

fn is_source_value_local(name: &str) -> bool {
    is_high_variable(name) || is_promoted_local(name)
}

fn is_high_variable(name: &str) -> bool {
    name.strip_prefix("var").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn is_trusted_copy_source(name: &str) -> bool {
    is_source_value_local(name) || crate::ir::ast::parse_arg_index(name).is_some()
}

/// Mark names below integer/address operations. Declaring these as pointers
/// could scale byte arithmetic or make bitwise operators ill-typed. Direct
/// copies, returns, call arguments, comparisons, and dereferences stay eligible.
fn collect_unsafe_pointer_uses(body: &[Stmt], out: &mut HashSet<String>) {
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } | Stmt::Return { value: Some(src) } => {
                collect_unsafe_expr(src, false, out)
            }
            Stmt::Store { addr, src, .. } => {
                collect_unsafe_expr(addr, false, out);
                collect_unsafe_expr(src, false, out);
            }
            Stmt::Call { target, args, .. } => {
                collect_unsafe_expr(target, false, out);
                for argument in args {
                    collect_unsafe_expr(argument, false, out);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_unsafe_expr(cond, false, out);
                collect_unsafe_pointer_uses(then_body, out);
                if let Some(else_body) = else_body {
                    collect_unsafe_pointer_uses(else_body, out);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                collect_unsafe_expr(cond, false, out);
                collect_unsafe_pointer_uses(body, out);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_unsafe_pointer_uses(std::slice::from_ref(init.as_ref()), out);
                collect_unsafe_expr(cond, false, out);
                collect_unsafe_pointer_uses(body, out);
                collect_unsafe_pointer_uses(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_unsafe_expr(discriminant, false, out);
                for (_, case) in cases {
                    collect_unsafe_pointer_uses(case, out);
                }
                if let Some(default) = default {
                    collect_unsafe_pointer_uses(default, out);
                }
            }
            Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                collect_unsafe_expr(target, true, out)
            }
            _ => {}
        }
    }
}

fn collect_unsafe_expr(expression: &Expr, integer_context: bool, out: &mut HashSet<String>) {
    match expression {
        Expr::Reg(VReg::Phys(name)) if integer_context => {
            out.insert(name.clone());
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::StackAddr { object, .. } => {
            if integer_context {
                if let VReg::Phys(name) = object {
                    out.insert(name.clone());
                }
            }
        }
        Expr::Deref { addr, .. } => collect_unsafe_expr(addr, false, out),
        Expr::Cmp { lhs, rhs, .. } => {
            collect_unsafe_expr(lhs, false, out);
            collect_unsafe_expr(rhs, false, out);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_unsafe_expr(cond, false, out);
            collect_unsafe_expr(if_true, integer_context, out);
            collect_unsafe_expr(if_false, integer_context, out);
        }
        Expr::Bin { lhs, rhs, .. } => {
            collect_unsafe_expr(lhs, true, out);
            collect_unsafe_expr(rhs, true, out);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => collect_unsafe_expr(src, true, out),
        Expr::FunctionTableEntry { index, .. } => collect_unsafe_expr(index, true, out),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                collect_unsafe_expr(argument, true, out);
            }
        }
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            for reg in base.iter().chain(index.iter()) {
                if let VReg::Phys(name) = reg {
                    out.insert(name.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::refine_pointer_high_variables;
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};
    use crate::ir::types::{BinOp, VReg};
    use crate::ir::types_recover::{TypeHint, TypeMap};

    fn pointer_width(types: &TypeMap, name: &str) -> Option<u8> {
        match types.get(&VReg::phys(name)) {
            Some(TypeHint::Pointer { pointee_width }) => Some(pointee_width),
            _ => None,
        }
    }

    #[test]
    fn exact_integer_value_width_survives_pointer_refinement() {
        let function = Function {
            name: "negative_cases".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(3)),
                },
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(
            types.get(&VReg::phys("var0")),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );
    }

    #[test]
    fn known_call_and_literal_flow_through_exact_copy_chain() {
        let function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "getenv@plt".into(),
                    },
                    args: vec![Expr::StringLit {
                        value: "PATH".into(),
                    }],
                    dst: Some(VReg::phys("var1")),
                    call_spec: None,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_8")),
                    src: Expr::Reg(VReg::phys("var1")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::StringLit {
                        value: "/tmp/fallback".into(),
                    },
                },
            ],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "var1"), Some(1));
        assert_eq!(pointer_width(&types, "local_8"), Some(1));
        assert_eq!(pointer_width(&types, "var2"), Some(1));
    }

    #[test]
    fn recovered_callee_pointer_result_flows_through_an_exact_copy() {
        let recovered = CallPrototype {
            return_type: "void *".into(),
            parameter_types: vec![],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "copy_project_pointer".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "project_device".into(),
                    },
                    args: vec![],
                    dst: Some(VReg::phys("var1")),
                    call_spec: Some(CallSiteSpec {
                        callee_prototype: Some(recovered.clone()),
                        call_prototype: recovered,
                    }),
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Reg(VReg::phys("var1")),
                },
            ],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "var1"), Some(0));
        assert_eq!(pointer_width(&types, "var2"), Some(0));
    }

    #[test]
    fn null_initialized_local_accepts_a_later_character_pointer() {
        let function = Function {
            name: "save_locale".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("local_8"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strdup@plt".into(),
                    },
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    dst: Some(VReg::phys("var1")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("local_8"),
                    src: Expr::Reg(VReg::phys("var1")),
                },
            ],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "var1"), Some(1));
        assert_eq!(pointer_width(&types, "local_8"), Some(1));
    }

    #[test]
    fn authoritative_call_parameter_refines_a_direct_function_argument() {
        let function = Function {
            name: "find_name".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strcmp@plt".into(),
                },
                args: vec![
                    Expr::Reg(VReg::phys("arg0")),
                    Expr::StringLit {
                        value: "known".into(),
                    },
                ],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            }],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "arg0"), Some(1));
    }

    #[test]
    fn recovered_direct_callee_parameter_refines_a_forwarded_argument() {
        let recovered = CallPrototype {
            return_type: "int".into(),
            parameter_types: vec!["int *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "forward_pointer".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "read_first".into(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0"))],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    call_prototype: recovered.clone(),
                    callee_prototype: Some(recovered),
                }),
            }],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "arg0"), Some(4));
    }

    #[test]
    fn recovered_callee_pointer_flows_back_through_one_exact_parameter_copy() {
        // Real shape: diffutils `lf_skip(struct line_filter *lf, lin lines)`.
        // The incoming pointer is copied to a numbered value, used in raw byte
        // address arithmetic, and passed to a helper whose recovered contract
        // is the only source-level pointer witness. Keep the numbered value a
        // machine word so `+ 8` remains byte-addressed, but recover the source
        // parameter transported into it.
        let recovered = CallPrototype {
            return_type: "int".into(),
            parameter_types: vec!["long *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "lf_skip_shape".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "refill".into(),
                    },
                    args: vec![Expr::Reg(VReg::phys("var2"))],
                    dst: Some(VReg::phys("ret")),
                    call_spec: Some(CallSiteSpec {
                        call_prototype: recovered.clone(),
                        callee_prototype: Some(recovered),
                    }),
                },
                Stmt::Assign {
                    dst: VReg::phys("var3"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("var2"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
            ],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "arg0"), Some(8));
        assert_eq!(pointer_width(&types, "var2"), None);
    }

    #[test]
    fn recovered_callee_pointer_rejects_a_copy_with_conflicting_origins() {
        let recovered = CallPrototype {
            return_type: "int".into(),
            parameter_types: vec!["long *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "overwritten_forwarder".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Reg(VReg::phys("arg1")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "consume_pointer".into(),
                    },
                    args: vec![Expr::Reg(VReg::phys("var2"))],
                    dst: None,
                    call_spec: Some(CallSiteSpec {
                        call_prototype: recovered.clone(),
                        callee_prototype: Some(recovered),
                    }),
                },
            ],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "arg0"), None);
        assert_eq!(pointer_width(&types, "arg1"), None);
    }

    #[test]
    fn integer_arithmetic_blocks_call_parameter_pointer_refinement() {
        let function = Function {
            name: "tagged_name".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strcmp@plt".into(),
                    },
                    args: vec![
                        Expr::Reg(VReg::phys("arg0")),
                        Expr::StringLit {
                            value: "known".into(),
                        },
                    ],
                    dst: Some(VReg::phys("var1")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Bin {
                        op: BinOp::And,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(7)),
                    },
                },
            ],
        };
        let mut types = TypeMap::default();

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "arg0"), None);
    }

    #[test]
    fn conflicting_definition_or_integer_use_blocks_pointer_declaration() {
        let function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::StringLit { value: "a".into() },
                },
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Const(7),
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::StringLit { value: "b".into() },
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Bin {
                        op: BinOp::And,
                        lhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                        rhs: Box::new(Expr::Const(-16)),
                    },
                },
            ],
        };
        let mut types = TypeMap::default();
        // A legacy storage-keyed collision must not bypass the exact
        // multi-definition proof merely because it is already a pointer.
        types.upsert_public(VReg::phys("var0"), TypeHint::Pointer { pointee_width: 1 });

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "var0"), None);
        assert_eq!(pointer_width(&types, "var1"), None);
    }

    #[test]
    fn structural_stack_register_type_does_not_seed_a_source_pointer() {
        let function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Reg(VReg::phys("sp")),
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("sp"), TypeHint::Pointer { pointee_width: 4 });

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "var0"), None);
    }

    #[test]
    fn select_accepts_null_but_rejects_incompatible_pointer_arms() {
        let function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Select {
                        cond: Box::new(Expr::Const(1)),
                        if_true: Box::new(Expr::StringLit { value: "p".into() }),
                        if_false: Box::new(Expr::Const(0)),
                        width: 8,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("local_8"),
                    src: Expr::Select {
                        cond: Box::new(Expr::Const(1)),
                        if_true: Box::new(Expr::Reg(VReg::phys("var0"))),
                        if_false: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        width: 8,
                    },
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });

        refine_pointer_high_variables(&function, &mut types);

        assert_eq!(pointer_width(&types, "var0"), Some(1));
        assert_eq!(pointer_width(&types, "local_8"), None);
    }

    #[test]
    fn pointer_copy_into_conflicted_word_keeps_explicit_machine_cast() {
        let function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::StringLit { value: "p".into() },
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Reg(VReg::phys("var0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Const(1),
                },
            ],
        };
        let mut types = TypeMap::default();
        refine_pointer_high_variables(&function, &mut types);

        let rendered = crate::ir::ast::render_decbench_typed(&function, Some(&types), None);

        assert!(rendered.contains("char * var0;"), "{rendered}");
        assert!(rendered.contains("long var1;"), "{rendered}");
        assert!(rendered.contains("var1 = (long)var0;"), "{rendered}");
    }

    #[test]
    fn pointer_stored_through_width_only_memory_is_explicitly_represented() {
        let function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::StringLit { value: "p".into() },
                },
                Stmt::Store {
                    addr: Expr::Addr(0x1000),
                    src: Expr::Reg(VReg::phys("var0")),
                    size: 4,
                },
            ],
        };
        let mut types = TypeMap::default();
        refine_pointer_high_variables(&function, &mut types);

        let rendered = crate::ir::ast::render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains(
                "static unsigned char glaurung_global_1000[16] __attribute__((aligned(16)));"
            ),
            "the original image address needs portable storage:\n{rendered}"
        );
        assert!(
            rendered.contains("*(int *)(&glaurung_global_1000[0]) = (int)((long)var0);"),
            "the 4-byte pointer-to-integer store must remain explicit:\n{rendered}"
        );
        assert!(!rendered.contains("*(int *)(0x1000)"), "{rendered}");
    }
}
