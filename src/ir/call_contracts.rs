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
    use super::{apply_known_call_contracts, lookup};
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
    }
}
