//! Known external-call contracts applied to recovered AST calls.
//!
//! ABI liveness can suggest candidate arguments and result registers, but it
//! cannot override an authoritative prototype.  This pass is deliberately
//! placed after call reconstruction: it caps fixed-arity calls and removes
//! impossible destinations from declared-void callees.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types_recover::{c_type_for_hint, TypeMap};

#[derive(Debug, Deserialize)]
struct PrototypeBundle {
    prototypes: Vec<CallContract>,
}

/// A source-level function contract from a canonical library bundle.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CallContract {
    pub name: String,
    pub return_type: String,
    #[serde(default)]
    pub params: Vec<CallParameter>,
    #[serde(default)]
    pub is_variadic: bool,
}

/// One declared parameter in a [`CallContract`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CallParameter {
    pub name: String,
    pub c_type: String,
}

/// Provenance of a prototype rendered at a call boundary.
///
/// Reference decompilers keep locked declarations distinct from call-site
/// guesses so later inference cannot overwrite authoritative ABI facts.  The
/// renderer needs the same distinction even before the full call-spec model is
/// attached to every [`Stmt::Call`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPrototypeAuthority {
    /// A declaration loaded from the canonical library catalogs.
    Authoritative,
    /// A conservative contract inferred from this function's call sites.
    Recovered,
}

/// One self-contained C prototype selected for a resolved call target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallPrototype {
    pub return_type: String,
    pub parameter_types: Vec<String>,
    pub variadic: bool,
    pub authority: CallPrototypeAuthority,
}

/// Prototype facts owned by one concrete call statement.
///
/// `callee_prototype` describes the resolved function symbol and therefore
/// remains stable across every call to that symbol. `call_prototype` describes
/// the values actually recovered at this machine call boundary. They are
/// compatible for an ordinary call, but deliberately differ in arity or type
/// when the binary contains an incomplete or otherwise incompatible call. This
/// is the same ownership split
/// represented by Ghidra/Kuna `FuncCallSpecs` and angr's AIL call-site
/// prototype: a malformed call must not erase the callee's true declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSiteSpec {
    pub callee_prototype: Option<CallPrototype>,
    pub call_prototype: CallPrototype,
}

impl CallSiteSpec {
    /// Whether the recovered arguments can be emitted directly through the
    /// resolved callee declaration. Return-type differences do not make a call
    /// invalid: C permits ignoring a non-void result, and the renderer handles
    /// representation-changing assignments separately.
    pub fn accepts_callee_declaration(&self) -> bool {
        self.callee_prototype
            .as_ref()
            .is_some_and(|callee| prototype_accepts(callee, &self.call_prototype))
    }
}

/// Whether `declaration` accepts the recovered parameter list in `call`.
pub fn prototype_accepts(declaration: &CallPrototype, call: &CallPrototype) -> bool {
    if call.parameter_types.len() < declaration.parameter_types.len()
        || !call
            .parameter_types
            .iter()
            .zip(&declaration.parameter_types)
            .all(|(actual, expected)| actual == expected)
    {
        return false;
    }
    declaration.variadic || call.parameter_types.len() == declaration.parameter_types.len()
}

impl CallContract {
    /// Convert a catalog declaration into a headerless C prototype.
    ///
    /// Catalog strings intentionally retain source typedefs such as `size_t`
    /// and `FILE`.  A standalone decompilation cannot assume their headers were
    /// included, so every type must first have a representation-preserving C
    /// spelling.  If any type is not safely representable, the declaration is
    /// withheld rather than guessed.
    pub fn standalone_prototype(&self) -> Option<CallPrototype> {
        let return_type = standalone_c_type(&self.return_type)?;
        let parameter_types = self
            .params
            .iter()
            .map(|parameter| standalone_c_type(&parameter.c_type))
            .collect::<Option<Vec<_>>>()?;
        if self.is_variadic && parameter_types.is_empty() {
            return None;
        }
        Some(CallPrototype {
            return_type,
            parameter_types,
            variadic: self.is_variadic,
            authority: CallPrototypeAuthority::Authoritative,
        })
    }
}

/// Give a catalog C type a self-contained, ABI-preserving spelling.
///
/// The GCC-family predefined pointer-width types are deliberate: unlike
/// spelling `size_t` as `unsigned long`, they remain correct on both LP64 and
/// LLP64 targets without requiring a source header.  Opaque object pointers
/// are represented as `void *`, which preserves the call ABI.  Unknown scalar
/// typedefs return `None`; silently widening an unknown 32-bit status type to a
/// machine word would be worse than omitting its prototype.
pub fn standalone_c_type(c_type: &str) -> Option<String> {
    let c_type = c_type.trim();
    let exact = match c_type {
        "void" | "char" | "signed char" | "unsigned char" | "short" | "unsigned short" | "int"
        | "unsigned int" | "long" | "unsigned long" | "long long" | "unsigned long long"
        | "float" | "double" | "long double" | "char *" | "char **" | "const char *" | "void *"
        | "void **" | "const void *" | "int *" | "unsigned int *" | "long *"
        | "unsigned long *" | "void *(*)(void *)" => c_type,
        "char *const *" => "char *const *",
        "size_t" | "uintptr_t" | "SIZE_T" => "__SIZE_TYPE__",
        "ssize_t" | "intptr_t" | "SSIZE_T" => "__PTRDIFF_TYPE__",
        "off_t" | "time_t" | "clock_t" => "long",
        "pid_t" => "int",
        "socklen_t" | "useconds_t" => "unsigned int",
        "pthread_t" => "unsigned long",
        "FILE *" | "struct sockaddr *" | "struct stat *" | "struct timeval *" => "void *",
        "const struct sockaddr *" => "const void *",
        "uint8_t" => "unsigned char",
        "int8_t" => "signed char",
        "uint16_t" => "unsigned short",
        "int16_t" => "short",
        "uint32_t" | "DWORD" | "ULONG" | "UINT" => "unsigned int",
        "int32_t" | "BOOL" | "LONG" | "HRESULT" | "NTSTATUS" => "int",
        "uint64_t" | "DWORD64" => "unsigned long long",
        "int64_t" | "LONGLONG" => "long long",
        "PWSTR" | "PSTR" | "PVOID" | "LPVOID" | "LPCVOID" | "PCWSTR" | "PCSTR" | "HANDLE"
        | "HWND" | "HDC" | "HKEY" | "HINSTANCE" => "void *",
        _ => {
            if let Some(base) = c_type.strip_suffix('*') {
                let base = base.trim();
                if base.starts_with("const struct ") {
                    return Some("const void *".to_string());
                }
                if base.starts_with("struct ")
                    || base.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
                {
                    let normalized_base = standalone_c_type(base);
                    return Some(match normalized_base {
                        Some(base) => format!("{base} *"),
                        None => "void *".to_string(),
                    });
                }
            }
            return None;
        }
    };
    Some(exact.to_string())
}

static LIBC_PROTOTYPES: OnceLock<HashMap<String, CallContract>> = OnceLock::new();

fn libc_prototypes() -> &'static HashMap<String, CallContract> {
    LIBC_PROTOTYPES.get_or_init(|| {
        let raw = include_str!("../../data/types/stdlib-libc-protos.json");
        let bundle = serde_json::from_str::<PrototypeBundle>(raw)
            .expect("stdlib-libc-protos.json must parse");
        bundle
            .prototypes
            .into_iter()
            .map(|prototype| (prototype.name.to_ascii_lowercase(), prototype))
            .collect()
    })
}

/// Resolve a decorated import name against the native libc and WinAPI catalogs.
pub fn lookup(name: &str) -> Option<CallContract> {
    let clean = clean_symbol_name(name);
    let key = clean.to_ascii_lowercase();
    if let Some(prototype) = libc_prototypes().get(&key) {
        return Some(prototype.clone());
    }
    // Mach-O's C ABI prefixes symbols with one underscore. Try the exact name
    // first so genuine identifiers such as `_exit` keep their own contract.
    if let Some(unprefixed) = clean.strip_prefix('_') {
        if let Some(prototype) = libc_prototypes().get(&unprefixed.to_ascii_lowercase()) {
            return Some(prototype.clone());
        }
    }
    crate::ir::winapi_prototypes::lookup(name).map(|prototype| CallContract {
        name: prototype.name.clone(),
        return_type: prototype.return_type.clone(),
        params: prototype
            .params
            .iter()
            .map(|param| CallParameter {
                name: param.name.clone(),
                c_type: param.c_type.clone(),
            })
            .collect(),
        is_variadic: prototype.is_variadic,
    })
}

fn clean_symbol_name(name: &str) -> String {
    let mut clean = name.trim();
    if let Some((_, rhs)) = clean.rsplit_once('!') {
        clean = rhs;
    }
    if let Some((_, rhs)) = clean.rsplit_once("::") {
        clean = rhs;
    }
    for prefix in ["__imp_", "_imp_", "__imp__", "__imp"] {
        if let Some(rest) = clean.strip_prefix(prefix) {
            clean = rest;
            break;
        }
    }
    for marker in ["@@", "@"] {
        if let Some((base, suffix)) = clean.rsplit_once(marker) {
            if suffix.eq_ignore_ascii_case("plt")
                || suffix.starts_with("GLIBC_")
                || suffix.chars().all(|ch| ch.is_ascii_digit())
            {
                clean = base;
                break;
            }
        }
    }
    clean.strip_suffix(".plt").unwrap_or(clean).to_string()
}

/// Apply authoritative library contracts to named calls in `function`.
pub fn apply_known_call_contracts(function: &mut Function) {
    apply_body(&mut function.body);
}

/// Build the call-owned prototype pair after ABI argument reconstruction.
///
/// The recovered prototype is intentionally exact-arity. A known callee lends
/// its return type and the types of the argument prefix that actually exists;
/// values beyond that prefix retain conservative machine-level spellings.
/// Missing arguments are never invented.
pub fn recover_call_site_spec(
    target: &Expr,
    args: &[Expr],
    dst: Option<&crate::ir::VReg>,
) -> CallSiteSpec {
    recover_call_site_spec_with_types(target, args, dst, None)
}

fn recover_call_site_spec_with_types(
    target: &Expr,
    args: &[Expr],
    dst: Option<&crate::ir::VReg>,
    types: Option<&TypeMap>,
) -> CallSiteSpec {
    let callee_prototype = match target {
        Expr::Named { name, .. } => {
            lookup(name).and_then(|contract| contract.standalone_prototype())
        }
        _ => None,
    };
    let return_type = callee_prototype
        .as_ref()
        .map(|prototype| prototype.return_type.clone())
        .unwrap_or_else(|| {
            dst.and_then(|register| types.and_then(|types| types.get(register)))
                .map(c_type_for_hint)
                .unwrap_or(if dst.is_some() { "long" } else { "void" })
                .to_string()
        });
    let parameter_types = args
        .iter()
        .enumerate()
        .map(|(index, arg)| {
            callee_prototype
                .as_ref()
                .and_then(|prototype| prototype.parameter_types.get(index))
                .cloned()
                .unwrap_or_else(|| recovered_argument_type(arg, types).to_string())
        })
        .collect();
    let recovered = CallPrototype {
        return_type,
        parameter_types,
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    CallSiteSpec {
        callee_prototype,
        call_prototype: recovered,
    }
}

fn recovered_argument_type(argument: &Expr, types: Option<&TypeMap>) -> &'static str {
    fn arithmetic_type(left: &'static str, right: &'static str) -> &'static str {
        if left == "double" || right == "double" {
            "double"
        } else if left == "float" || right == "float" {
            "float"
        } else if left == right {
            left
        } else {
            "long"
        }
    }

    match argument {
        Expr::Reg(register) => types
            .and_then(|types| types.get(register))
            .map(c_type_for_hint)
            .unwrap_or("long"),
        Expr::StringLit { .. } => "const char *",
        Expr::StackAddr { .. } => "void *",
        Expr::Deref { size: 1, .. } => "signed char",
        Expr::Deref { size: 2, .. } => "short",
        Expr::Deref { size: 4, .. } => "int",
        Expr::Cast {
            signed: false,
            width: 1,
            ..
        } => "unsigned char",
        Expr::Cast {
            signed: false,
            width: 2,
            ..
        } => "unsigned short",
        Expr::Cast {
            signed: false,
            width: 4,
            ..
        } => "unsigned int",
        Expr::Cast {
            signed: true,
            width: 1,
            ..
        } => "signed char",
        Expr::Cast {
            signed: true,
            width: 2,
            ..
        } => "short",
        Expr::Cast {
            signed: true,
            width: 4,
            ..
        } => "int",
        Expr::Cmp { .. } => "int",
        Expr::Const(value) if i32::try_from(*value).is_ok() => "int",
        Expr::FloatConst { width: 4, .. } => "float",
        Expr::FloatConst { .. } => "double",
        Expr::Select { width: 1, .. } => "signed char",
        Expr::Select { width: 2, .. } => "short",
        Expr::Select { width: 4, .. } => "int",
        Expr::Bin { lhs, rhs, .. } => arithmetic_type(
            recovered_argument_type(lhs, types),
            recovered_argument_type(rhs, types),
        ),
        Expr::Select {
            if_true, if_false, ..
        } => arithmetic_type(
            recovered_argument_type(if_true, types),
            recovered_argument_type(if_false, types),
        ),
        Expr::Un { src, .. } => recovered_argument_type(src, types),
        _ => "long",
    }
}

/// Refresh every attached call specification from the final AST and recovered
/// value types immediately before verification/rendering.
///
/// Earlier passes may fold an address into a string literal, promote a stack
/// object, rename a register role, or refine a pointer type. Rebuilding only
/// call-owned metadata here prevents those semantic improvements from leaving a
/// stale machine-word prototype behind.
pub fn refine_call_site_specs(function: &mut Function, types: Option<&TypeMap>) {
    refine_body(&mut function.body, types);
}

fn refine_body(body: &mut [Stmt], types: Option<&TypeMap>) {
    for statement in body {
        match statement {
            Stmt::Call {
                target,
                args,
                dst,
                call_spec,
            } => {
                *call_spec = Some(recover_call_site_spec_with_types(
                    target,
                    args,
                    dst.as_ref(),
                    types,
                ));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                refine_body(then_body, types);
                if let Some(else_body) = else_body {
                    refine_body(else_body, types);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                refine_body(body, types);
            }
            Stmt::For {
                init, step, body, ..
            } => {
                refine_body(std::slice::from_mut(init.as_mut()), types);
                refine_body(body, types);
                refine_body(std::slice::from_mut(step.as_mut()), types);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    refine_body(case, types);
                }
                if let Some(default) = default {
                    refine_body(default, types);
                }
            }
            _ => {}
        }
    }
}

fn apply_body(body: &mut [Stmt]) {
    for statement in body {
        match statement {
            Stmt::Call {
                target,
                args,
                dst,
                call_spec,
            } => {
                if let Expr::Named { name, .. } = target {
                    if let Some(contract) = lookup(name) {
                        if !contract.is_variadic {
                            args.truncate(contract.params.len());
                        }
                        if contract.return_type.trim().eq_ignore_ascii_case("void") {
                            *dst = None;
                        }
                    }
                }
                *call_spec = Some(recover_call_site_spec(target, args, dst.as_ref()));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                apply_body(then_body);
                if let Some(else_body) = else_body {
                    apply_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => apply_body(body),
            Stmt::For {
                init, step, body, ..
            } => {
                apply_body(std::slice::from_mut(init));
                apply_body(body);
                apply_body(std::slice::from_mut(step));
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    apply_body(body);
                }
                if let Some(body) = default {
                    apply_body(body);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_known_call_contracts, libc_prototypes, lookup, standalone_c_type, CallPrototype,
        CallPrototypeAuthority,
    };
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::types_recover::{TypeHint, TypeMap};
    use crate::ir::VReg;

    fn named_call(name: &str, args: Vec<Expr>, dst: Option<VReg>) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args,
            dst,
            call_spec: None,
        }
    }

    #[test]
    fn void_fixed_arity_contract_caps_arguments_and_removes_result() {
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![named_call(
                "perror@plt",
                vec![Expr::Const(1), Expr::Const(2), Expr::Const(3)],
                Some(VReg::phys("rax")),
            )],
        };

        apply_known_call_contracts(&mut function);

        let Stmt::Call { args, dst, .. } = &function.body[0] else {
            panic!("expected call")
        };
        assert_eq!(args, &[Expr::Const(1)]);
        assert_eq!(*dst, None);
    }

    #[test]
    fn variadic_contract_preserves_recovered_tail_arguments_and_result() {
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![named_call(
                "printf",
                vec![Expr::Const(1), Expr::Const(2), Expr::Const(3)],
                Some(VReg::phys("rax")),
            )],
        };

        apply_known_call_contracts(&mut function);

        let Stmt::Call {
            args,
            dst,
            call_spec: Some(call_spec),
            ..
        } = &function.body[0]
        else {
            panic!("expected call")
        };
        assert_eq!(args.len(), 3);
        assert_eq!(*dst, Some(VReg::phys("rax")));
        assert!(call_spec
            .callee_prototype
            .as_ref()
            .is_some_and(|prototype| prototype.variadic));
        assert_eq!(call_spec.call_prototype.parameter_types.len(), 3);
        assert!(!call_spec.call_prototype.variadic);
        assert_eq!(
            call_spec.call_prototype.authority,
            CallPrototypeAuthority::Recovered
        );
    }

    #[test]
    fn unknown_call_attaches_recovered_spec_without_changing_values() {
        let original_target = Expr::Named {
            va: 0,
            name: "project_specific_callback".into(),
        };
        let original_args = vec![Expr::Const(1), Expr::Const(2)];
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: original_target.clone(),
                args: original_args.clone(),
                dst: Some(VReg::phys("rax")),
                call_spec: None,
            }],
        };

        apply_known_call_contracts(&mut function);

        let Stmt::Call {
            target,
            args,
            dst,
            call_spec: Some(call_spec),
        } = &function.body[0]
        else {
            panic!("expected a call with an attached call-site spec")
        };
        assert_eq!(target, &original_target);
        assert_eq!(args, &original_args);
        assert_eq!(*dst, Some(VReg::phys("rax")));
        assert_eq!(call_spec.callee_prototype, None);
        assert_eq!(
            call_spec.call_prototype,
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["int".into(), "int".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            }
        );
    }

    #[test]
    fn typed_refresh_moves_recovered_pointer_facts_onto_the_call_site() {
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "project_lookup".into(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0"))],
                dst: Some(VReg::phys("ret")),
                call_spec: None,
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });
        types.upsert_public(VReg::phys("ret"), TypeHint::Pointer { pointee_width: 1 });

        super::refine_call_site_specs(&mut function, Some(&types));

        let Stmt::Call {
            call_spec: Some(call_spec),
            ..
        } = &function.body[0]
        else {
            panic!("expected a typed call-site spec")
        };
        assert_eq!(
            call_spec.call_prototype,
            CallPrototype {
                return_type: "char *".into(),
                parameter_types: vec!["char *".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            }
        );
    }

    #[test]
    fn resolves_elf_and_macho_import_decorations() {
        assert_eq!(lookup("perror@@GLIBC_2.2.5").unwrap().name, "perror");
        assert_eq!(lookup("_free").unwrap().name, "free");
    }

    #[test]
    fn locale_contract_preserves_its_returned_character_pointer() {
        let contract = lookup("setlocale@plt").expect("setlocale belongs in the libc catalog");

        assert_eq!(contract.return_type, "char *");
        assert_eq!(
            contract
                .params
                .iter()
                .map(|parameter| parameter.c_type.as_str())
                .collect::<Vec<_>>(),
            ["int", "const char *"]
        );
        assert!(!contract.is_variadic);
    }

    #[test]
    fn math_contract_preserves_unary_float_storage_class() {
        let contract = lookup("asinf@plt").expect("asinf belongs in the libc catalog");

        assert_eq!(contract.return_type, "float");
        assert_eq!(
            contract
                .params
                .iter()
                .map(|parameter| parameter.c_type.as_str())
                .collect::<Vec<_>>(),
            ["float"]
        );
        assert!(!contract.is_variadic);
    }

    #[test]
    fn recovered_composite_float_argument_retains_its_storage_class() {
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![named_call(
                "arm_sqrt",
                vec![Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("s14"))),
                    rhs: Box::new(Expr::Reg(VReg::phys("s15"))),
                }],
                Some(VReg::phys("s0")),
            )],
        };
        let mut types = TypeMap::default();
        for register in ["s0", "s14", "s15"] {
            types.upsert_public(VReg::phys(register), TypeHint::Float { width: 4 });
        }

        super::refine_call_site_specs(&mut function, Some(&types));

        let Stmt::Call {
            call_spec: Some(call_spec),
            ..
        } = &function.body[0]
        else {
            panic!("expected a refined call specification")
        };
        assert_eq!(call_spec.call_prototype.return_type, "float");
        assert_eq!(call_spec.call_prototype.parameter_types, ["float"]);
    }

    #[test]
    fn decbench_call_uses_declared_parameter_types_at_the_boundary() {
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![named_call(
                "free",
                vec![Expr::Reg(VReg::phys("arg0"))],
                Some(VReg::phys("ret")),
            )],
        };
        apply_known_call_contracts(&mut function);

        let rendered = crate::ir::ast::render_decbench(&function);

        assert!(
            rendered.contains("free((void *)(arg0));"),
            "known call parameter type was not preserved in C: {rendered}"
        );
        assert!(
            !rendered.contains("ret = free"),
            "void contract must still suppress the destination: {rendered}"
        );
        assert!(
            rendered.contains("extern void free(void *);"),
            "the authoritative contract must be declared in standalone C: {rendered}"
        );
    }

    #[test]
    fn standalone_types_preserve_abi_width_without_source_headers() {
        assert_eq!(standalone_c_type("size_t"), Some("__SIZE_TYPE__".into()));
        assert_eq!(
            standalone_c_type("ssize_t"),
            Some("__PTRDIFF_TYPE__".into())
        );
        assert_eq!(standalone_c_type("FILE *"), Some("void *".into()));
        assert_eq!(
            standalone_c_type("const struct sockaddr *"),
            Some("const void *".into())
        );
    }

    #[test]
    fn every_canonical_libc_contract_has_a_self_contained_spelling() {
        for contract in libc_prototypes().values() {
            assert!(
                standalone_c_type(&contract.return_type).is_some(),
                "unrenderable return type in {}: {}",
                contract.name,
                contract.return_type
            );
            for parameter in &contract.params {
                assert!(
                    standalone_c_type(&parameter.c_type).is_some(),
                    "unrenderable parameter type in {}: {}",
                    contract.name,
                    parameter.c_type
                );
            }
        }
    }
}
