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

fn apply_body(body: &mut [Stmt]) {
    for statement in body {
        match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                dst,
            } => {
                let Some(contract) = lookup(name) else {
                    continue;
                };
                if !contract.is_variadic {
                    args.truncate(contract.params.len());
                }
                if contract.return_type.trim().eq_ignore_ascii_case("void") {
                    *dst = None;
                }
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
    use super::{apply_known_call_contracts, libc_prototypes, lookup, standalone_c_type};
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::VReg;

    fn named_call(name: &str, args: Vec<Expr>, dst: Option<VReg>) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args,
            dst,
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

        let Stmt::Call { args, dst, .. } = &function.body[0] else {
            panic!("expected call")
        };
        assert_eq!(args.len(), 3);
        assert_eq!(*dst, Some(VReg::phys("rax")));
    }

    #[test]
    fn unknown_call_is_unchanged() {
        let original = named_call(
            "project_specific_callback",
            vec![Expr::Const(1), Expr::Const(2)],
            Some(VReg::phys("rax")),
        );
        let mut function = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        apply_known_call_contracts(&mut function);

        assert_eq!(function.body, vec![original]);
    }

    #[test]
    fn resolves_elf_and_macho_import_decorations() {
        assert_eq!(lookup("perror@@GLIBC_2.2.5").unwrap().name, "perror");
        assert_eq!(lookup("_free").unwrap().name, "free");
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
