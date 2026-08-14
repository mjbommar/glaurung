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
//! resolve to a compatible pointer, and any arithmetic use that cannot preserve
//! byte-level semantics prevents changing its C declaration.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::memory_objects::{infer_from_ast, MemoryObjectModel};
use crate::ir::types::{is_promoted_local_name as is_promoted_local, BinOp, VReg};
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
    let object_model = infer_from_ast(function);
    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
        eprintln!("\n===== inferred memory objects =====\n{object_model:#?}");
    }

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

    let baseline_types = types.clone();
    let mut unsafe_uses = HashSet::new();
    collect_unsafe_pointer_uses(&function.body, None, &mut unsafe_uses);
    unsafe_uses.retain(|name| !is_proven_promoted_object_cursor(name, &object_model));
    refine_pointer_facts(
        &function.body,
        &definitions,
        &unsafe_uses,
        &object_model,
        types,
    );
    // Add/sub can be either integer arithmetic or valid C pointer arithmetic.
    // Resolve the candidate pointer classes first, then reject any additive use
    // that cannot be represented without changing byte-level semantics. If a
    // rejection appears, replay from the pre-pass map so provisional pointer
    // facts cannot survive their failed proof.
    let mut validated_unsafe_uses = unsafe_uses.clone();
    collect_unsafe_pointer_uses(&function.body, Some(types), &mut validated_unsafe_uses);
    validated_unsafe_uses.retain(|name| !is_proven_promoted_object_cursor(name, &object_model));
    if validated_unsafe_uses != unsafe_uses {
        *types = baseline_types;
        refine_pointer_facts(
            &function.body,
            &definitions,
            &validated_unsafe_uses,
            &object_model,
            types,
        );
    }
}

fn refine_pointer_facts(
    body: &[Stmt],
    definitions: &HashMap<String, Vec<Definition>>,
    unsafe_uses: &HashSet<String>,
    object_model: &MemoryObjectModel,
    types: &mut TypeMap,
) {
    refine_authoritative_pointer_values(body, definitions, unsafe_uses, types);

    for _ in 0..=definitions.len() {
        let object_values_learned =
            refine_object_cursor_values(definitions, unsafe_uses, object_model, types);
        let mut learned = Vec::new();
        for (name, defs) in definitions {
            if !is_source_value_local(name)
                || unsafe_uses.contains(name)
                || defs
                    .iter()
                    .any(|definition| definition.transports_unsafe_source(unsafe_uses))
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
        if learned.is_empty() && object_values_learned == 0 {
            break;
        }
        for (reg, hint) in learned {
            types.refine_from_value(reg, hint);
        }
    }
}

/// Project a layout-proven cursor as a byte pointer without inventing a source
/// aggregate name.
///
/// The object model proves that every observed access fits within one exact
/// repeated stride. A character pointer is the only portable C declaration
/// that preserves those byte displacements until semantic Field/Index HIR can
/// carry the recovered layout. Authoritative declarations remain locked, and
/// every definition of the promoted identity must be either a pointer origin,
/// a null initializer, or its exact constant cursor step.
fn refine_object_cursor_values(
    definitions: &HashMap<String, Vec<Definition>>,
    unsafe_uses: &HashSet<String>,
    object_model: &MemoryObjectModel,
    types: &mut TypeMap,
) -> usize {
    let mut learned = 0;
    let mut candidates = definitions.keys().cloned().collect::<Vec<_>>();
    candidates.sort();
    for name in candidates {
        let register = VReg::phys(&name);
        if !is_proven_promoted_object_cursor(&name, object_model)
            || unsafe_uses.contains(&name)
            || types.is_locked(&register)
        {
            continue;
        }
        let Some(value_definitions) = definitions.get(&name) else {
            continue;
        };
        if object_cursor_definitions_are_compatible(&name, value_definitions, types)
            && types.get(&register) != Some(TypeHint::Pointer { pointee_width: 1 })
        {
            types.refine_from_value(register, TypeHint::Pointer { pointee_width: 1 });
            learned += 1;
        }
    }
    learned
}

fn is_proven_promoted_object_cursor(name: &str, object_model: &MemoryObjectModel) -> bool {
    is_promoted_local(name) && object_model.has_conflict_free_extent(&VReg::phys(name))
}

fn object_cursor_definitions_are_compatible(
    name: &str,
    definitions: &[Definition],
    types: &TypeMap,
) -> bool {
    let mut has_origin = false;
    for definition in definitions {
        if definition.is_null_initializer() {
            continue;
        }
        match definition {
            Definition::Assignment(Expr::Bin {
                op: BinOp::Add | BinOp::Sub,
                lhs,
                rhs,
            }) if matches!(lhs.as_ref(), Expr::Reg(VReg::Phys(source)) if source == name)
                && matches!(rhs.as_ref(), Expr::Const(_)) => {}
            Definition::Assignment(
                Expr::Deref { .. } | Expr::Addr(_) | Expr::Named { .. } | Expr::StackAddr { .. },
            ) => has_origin = true,
            Definition::Assignment(Expr::Reg(source))
                if matches!(
                    types.get(source),
                    Some(TypeHint::Pointer { .. } | TypeHint::CodePointer)
                ) =>
            {
                has_origin = true;
            }
            Definition::Call { return_type, .. }
                if return_type.as_ref().is_none_or(|(c_type, authority)| {
                    pointer_width_from_c_type(c_type).is_some()
                        || *authority
                            == crate::ir::call_contracts::CallPrototypeAuthority::Recovered
                }) =>
            {
                has_origin = true;
            }
            _ => return false,
        }
    }
    has_origin
}

/// Refine direct source parameters from authoritative callee boundaries.
///
/// A function argument passed unchanged to `strcmp(const char *, ...)` is
/// stronger pointer evidence than the integer width of the ABI register that
/// transported it.  The same is true for a project-local direct callee whose
/// body recovered a pointer parameter: the caller may only forward that value,
/// so the callee is the sole intraprocedural source of its type. Conflicting
/// pointee types, indirect expressions, and incompatible integer/arithmetic
/// uses remain fail-closed.
fn refine_authoritative_pointer_values(
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
    let mut direct_values = Vec::new();
    let mut widths_by_origin: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, widths) in candidates {
        let Some(width) = compatible_pointer_width(&widths) else {
            continue;
        };
        // A consumer boundary alone does not recover the declaration of an
        // ephemeral SSA temporary or the pointee of an opaque/non-character
        // object.  The defensible direct-use exception is a promoted source
        // local used consistently as a byte cursor: C character-pointer
        // arithmetic preserves the machine's byte offsets, and every local
        // definition is checked below before the fact is admitted.
        if is_promoted_local(&name)
            && width == 1
            && !unsafe_uses.contains(&name)
            && definitions.get(&name).is_some_and(|value_definitions| {
                definitions_accept_authoritative_pointer_use(
                    &name,
                    value_definitions,
                    width,
                    types,
                    definitions,
                )
            })
        {
            direct_values.push((name.clone(), width));
        }
        let Some(origin) = single_exact_parameter_origin(&name, definitions) else {
            continue;
        };
        if unsafe_uses.contains(&origin) {
            continue;
        }
        widths_by_origin.entry(origin).or_default().push(width);
    }
    direct_values.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (name, width) in &direct_values {
        types.refine_from_value(
            VReg::phys(name),
            TypeHint::Pointer {
                pointee_width: *width,
            },
        );
    }
    for (origin, widths) in widths_by_origin {
        let Some(width) = compatible_pointer_width(&widths) else {
            continue;
        };
        types.refine_from_value(
            VReg::phys(origin),
            TypeHint::Pointer {
                pointee_width: width,
            },
        );
    }
}

fn definitions_accept_authoritative_pointer_use(
    name: &str,
    definitions: &[Definition],
    width: u8,
    types: &TypeMap,
    all_definitions: &HashMap<String, Vec<Definition>>,
) -> bool {
    fn accepts(
        definition: &Definition,
        name: &str,
        width: u8,
        types: &TypeMap,
        all_definitions: &HashMap<String, Vec<Definition>>,
        visiting: &mut HashSet<String>,
    ) -> bool {
        if definition.is_null_initializer() {
            return true;
        }
        if width == 1
            && matches!(
                definition,
                Definition::Assignment(Expr::Bin {
                    op: BinOp::Add | BinOp::Sub,
                    lhs,
                    rhs,
                }) if matches!(lhs.as_ref(), Expr::Reg(VReg::Phys(source)) if source == name)
                    && matches!(rhs.as_ref(), Expr::Const(_))
            )
        {
            return true;
        }
        match (definition.classify(types), definition) {
            (ValueClass::Pointer(candidate), _) => {
                candidate == 0 || width == 0 || candidate == width
            }
            (
                ValueClass::Scalar | ValueClass::Unknown,
                Definition::Assignment(Expr::Reg(VReg::Phys(source))),
            ) if is_trusted_copy_source(source) => {
                let Some(source_definitions) = all_definitions.get(source) else {
                    return false;
                };
                if !visiting.insert(source.clone()) {
                    return false;
                }
                let accepted = source_definitions.iter().all(|source_definition| {
                    accepts(
                        source_definition,
                        source,
                        width,
                        types,
                        all_definitions,
                        visiting,
                    )
                });
                visiting.remove(source);
                accepted
            }
            (ValueClass::Unknown, Definition::Call { return_type, .. }) => {
                return_type.as_ref().is_none_or(|(_, authority)| {
                    *authority == crate::ir::call_contracts::CallPrototypeAuthority::Recovered
                })
            }
            (ValueClass::Scalar | ValueClass::Unknown, _) => false,
        }
    }

    definitions.iter().all(|definition| {
        accepts(
            definition,
            name,
            width,
            types,
            all_definitions,
            &mut HashSet::new(),
        )
    })
}

fn compatible_pointer_width(widths: &[u8]) -> Option<u8> {
    let width = widths.iter().copied().max()?;
    widths
        .iter()
        .all(|candidate| *candidate == 0 || width == 0 || *candidate == width)
        .then_some(width)
}

#[derive(Debug)]
enum Definition {
    Assignment(Expr),
    Call {
        target: Expr,
        return_type: Option<(String, crate::ir::call_contracts::CallPrototypeAuthority)>,
    },
}

impl Definition {
    fn classify(&self, types: &TypeMap) -> ValueClass {
        match self {
            Self::Assignment(value) => classify_expr(value, types),
            Self::Call {
                target,
                return_type,
            } => classify_call(
                target,
                return_type
                    .as_ref()
                    .map(|(c_type, authority)| (c_type.as_str(), *authority)),
            ),
        }
    }

    fn is_null_initializer(&self) -> bool {
        matches!(self, Self::Assignment(Expr::Const(0)))
    }

    fn transports_unsafe_source(&self, unsafe_uses: &HashSet<String>) -> bool {
        matches!(
            self,
            Self::Assignment(Expr::Reg(VReg::Phys(source))) if unsafe_uses.contains(source)
        )
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
                return_type: call_spec.as_ref().map(|spec| {
                    (
                        spec.call_prototype.return_type.clone(),
                        spec.call_prototype.authority,
                    )
                }),
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
    let mut has_opaque_pointer = false;
    let mut has_concrete_pointer = false;
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
                has_opaque_pointer |= next == 0;
                has_concrete_pointer |= next != 0;
            }
            // Unknown is not evidence. This prevents one pointer-looking branch
            // from typing a multiply-defined local.
            ValueClass::Pointer(_) | ValueClass::Scalar | ValueClass::Unknown => return None,
        }
    }
    if definitions.len() > 1 && has_opaque_pointer && has_concrete_pointer {
        // A multiply-defined promoted identity may cover distinct source
        // lifetimes. Opaque and concrete pointer definitions are compatible at
        // a single C conversion boundary, but merging them flow-insensitively
        // invents one concrete declaration for all lifetimes.
        return None;
    }
    has_pointer.then_some(width)
}

fn classify_expr(expression: &Expr, types: &TypeMap) -> ValueClass {
    match expression {
        Expr::StringLit { .. } => ValueClass::Pointer(1),
        Expr::StackAddr { .. } => ValueClass::Pointer(0),
        Expr::FunctionTableEntry { .. } => ValueClass::Pointer(0),
        Expr::Call { call_spec, .. } => call_spec
            .as_ref()
            .and_then(|spec| {
                crate::ir::call_contracts::call_return_hint(&spec.call_prototype.return_type)
            })
            .map_or(ValueClass::Unknown, |hint| match hint {
                TypeHint::Pointer { pointee_width } => ValueClass::Pointer(pointee_width),
                TypeHint::CodePointer => ValueClass::Pointer(0),
                TypeHint::Int { .. } | TypeHint::Float { .. } | TypeHint::BoolLike => {
                    ValueClass::Scalar
                }
            }),
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
        | Expr::NumericConvert { .. }
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

fn classify_call(
    target: &Expr,
    recovered_return_type: Option<(&str, crate::ir::call_contracts::CallPrototypeAuthority)>,
) -> ValueClass {
    if let Some((c_type, authority)) = recovered_return_type {
        if let Some(width) = pointer_width_from_c_type(c_type) {
            return ValueClass::Pointer(width);
        }
        if authority == crate::ir::call_contracts::CallPrototypeAuthority::Authoritative {
            return ValueClass::Scalar;
        }
        // A recovered machine-word spelling is not authoritative evidence that
        // the source result was scalar. A locked pointer use may refine it.
        return ValueClass::Unknown;
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

/// Mark names below incompatible integer/address operations. Declaring these
/// as pointers could scale byte arithmetic or make bitwise operators ill-typed.
/// Direct copies, returns, call arguments, comparisons, identity addresses, and
/// byte-scaled character-pointer arithmetic stay eligible.
fn collect_unsafe_pointer_uses(body: &[Stmt], types: Option<&TypeMap>, out: &mut HashSet<String>) {
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } | Stmt::Return { value: Some(src) } => {
                collect_unsafe_expr(src, false, types, out)
            }
            Stmt::Store { addr, src, .. } => {
                collect_unsafe_expr(addr, false, types, out);
                collect_unsafe_expr(src, false, types, out);
            }
            Stmt::Call { target, args, .. } => {
                collect_unsafe_expr(target, false, types, out);
                for argument in args {
                    collect_unsafe_expr(argument, false, types, out);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_unsafe_expr(cond, false, types, out);
                collect_unsafe_pointer_uses(then_body, types, out);
                if let Some(else_body) = else_body {
                    collect_unsafe_pointer_uses(else_body, types, out);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                collect_unsafe_expr(cond, false, types, out);
                collect_unsafe_pointer_uses(body, types, out);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_unsafe_pointer_uses(std::slice::from_ref(init.as_ref()), types, out);
                collect_unsafe_expr(cond, false, types, out);
                collect_unsafe_pointer_uses(body, types, out);
                collect_unsafe_pointer_uses(std::slice::from_ref(step.as_ref()), types, out);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_unsafe_expr(discriminant, false, types, out);
                for (_, case) in cases {
                    collect_unsafe_pointer_uses(case, types, out);
                }
                if let Some(default) = default {
                    collect_unsafe_pointer_uses(default, types, out);
                }
            }
            Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                collect_unsafe_expr(target, true, types, out)
            }
            _ => {}
        }
    }
}

fn collect_unsafe_expr(
    expression: &Expr,
    integer_context: bool,
    types: Option<&TypeMap>,
    out: &mut HashSet<String>,
) {
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
        Expr::Deref { addr, .. } => collect_unsafe_expr(addr, false, types, out),
        Expr::Call { target, args, .. } => {
            collect_unsafe_expr(target, false, types, out);
            for argument in args {
                collect_unsafe_expr(argument, false, types, out);
            }
        }
        Expr::Cmp { lhs, rhs, .. } => {
            collect_unsafe_expr(lhs, false, types, out);
            collect_unsafe_expr(rhs, false, types, out);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_unsafe_expr(cond, false, types, out);
            collect_unsafe_expr(if_true, integer_context, types, out);
            collect_unsafe_expr(if_false, integer_context, types, out);
        }
        Expr::Bin { op, lhs, rhs }
            if matches!(op, BinOp::Add | BinOp::Sub)
                && types.is_none_or(|types| additive_pointer_use_is_safe(*op, lhs, rhs, types)) =>
        {
            collect_unsafe_expr(lhs, false, types, out);
            collect_unsafe_expr(rhs, false, types, out);
        }
        Expr::Bin { lhs, rhs, .. } => {
            collect_unsafe_expr(lhs, true, types, out);
            collect_unsafe_expr(rhs, true, types, out);
        }
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => collect_unsafe_expr(src, true, types, out),
        Expr::FunctionTableEntry { index, .. } => collect_unsafe_expr(index, true, types, out),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                collect_unsafe_expr(argument, true, types, out);
            }
        }
        Expr::Lea {
            base: Some(VReg::Phys(name)),
            index: None,
            scale: 1,
            disp: 0,
            segment: None,
        } => {
            if integer_context {
                out.insert(name.clone());
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

fn additive_pointer_use_is_safe(op: BinOp, lhs: &Expr, rhs: &Expr, types: &TypeMap) -> bool {
    fn is_character_pointer(expression: &Expr, types: &TypeMap) -> bool {
        let Expr::Reg(VReg::Phys(name)) = expression else {
            return false;
        };
        is_promoted_local(name)
            && matches!(
                types.get(&VReg::phys(name)),
                Some(TypeHint::Pointer { pointee_width: 1 })
            )
    }

    match op {
        BinOp::Add => {
            (is_character_pointer(lhs, types) && matches!(rhs, Expr::Const(_)))
                || (matches!(lhs, Expr::Const(_)) && is_character_pointer(rhs, types))
        }
        BinOp::Sub => {
            is_character_pointer(lhs, types)
                && (matches!(rhs, Expr::Const(_)) || is_character_pointer(rhs, types))
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "high_variables_tests.rs"]
mod tests;
