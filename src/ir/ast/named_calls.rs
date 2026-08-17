//! Call-site prototype recovery for named callees.
//!
//! A rendered translation unit must declare every symbol it calls, and the
//! declaration has to agree with the callee's real signature or the recompile
//! fails. [`recover_named_call_prototypes`] answers that per function: it walks
//! the body, records what each call site *observed* about a named callee, and
//! turns those observations into one [`CallPrototype`] per symbol.
//!
//! The environment answers first. A record in [`crate::ir::symbol_env`] is a
//! property of the callee — its DWARF declaration, its catalog contract, or the
//! recovery run over its own body — so every caller in the image agrees.
//! Call-site inference is the fallback for symbols the environment cannot
//! reach, and it is deliberately conservative: conflicting observations widen
//! to the machine word, mixed arities become a variadic common prefix, and a
//! symbol seen only as an address-taken value gets no prototype at all.

use super::{callee_display_name, sanitize_c_ident, Expr, Stmt};
use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};
use crate::ir::types::VReg;

/// Record every `Expr::Named` reached from `expression` as an ADDRESS-TAKEN
/// symbol: observed, but with no call-site prototype of its own.
///
/// A symbol whose address is used as a value tells us nothing about its
/// signature — there is no argument list to infer one from. Registering it with
/// an empty observation list is exactly right: `recover_named_call_prototypes`
/// fills a prototype only from `symbol_env` (the callee's own contract), and
/// leaves the name undeclared when no such contract exists. That gate is what
/// makes rendering the identifier safe, and it is what the 2026-08-05 attempt
/// lacked — it emitted `extern void <name>(void);`, which conflicted with the
/// callee's real signature once the whole unit was compiled.
fn observe_address_taken_symbols(
    expression: &Expr,
    current_name: &str,
    observations: &mut std::collections::BTreeMap<String, Vec<CallPrototype>>,
) {
    match expression {
        Expr::Named { name, .. } => {
            let displayed = sanitize_c_ident(callee_display_name(name));
            if displayed != current_name {
                observations.entry(displayed).or_default();
            }
        }
        Expr::Deref { addr, .. } => observe_address_taken_symbols(addr, current_name, observations),
        Expr::Un { src, .. } => observe_address_taken_symbols(src, current_name, observations),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            observe_address_taken_symbols(expr, current_name, observations)
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            observe_address_taken_symbols(lhs, current_name, observations);
            observe_address_taken_symbols(rhs, current_name, observations);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            observe_address_taken_symbols(cond, current_name, observations);
            observe_address_taken_symbols(if_true, current_name, observations);
            observe_address_taken_symbols(if_false, current_name, observations);
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                observe_address_taken_symbols(argument, current_name, observations);
            }
        }
        Expr::FunctionTableEntry { index, .. } => {
            observe_address_taken_symbols(index, current_name, observations)
        }
        _ => {}
    }
}

fn collect_named_call_observations(
    body: &[Stmt],
    current_name: &str,
    observations: &mut std::collections::BTreeMap<String, Vec<CallPrototype>>,
    authoritative: &mut std::collections::BTreeMap<String, CallPrototype>,
    conflicts: &mut std::collections::BTreeSet<String>,
) {
    for statement in body {
        // A code symbol can appear as a VALUE as well as a call target —
        // `__libc_start_main(main, ...)` passes `main`'s address — and only the
        // call-target form was ever collected here.
        match statement {
            Stmt::Assign { src, .. } => {
                observe_address_taken_symbols(src, current_name, observations)
            }
            Stmt::Store { addr, src, .. } => {
                observe_address_taken_symbols(addr, current_name, observations);
                observe_address_taken_symbols(src, current_name, observations);
            }
            Stmt::Return { value: Some(value) } => {
                observe_address_taken_symbols(value, current_name, observations)
            }
            Stmt::Call { args, .. } => {
                for argument in args {
                    observe_address_taken_symbols(argument, current_name, observations);
                }
            }
            _ => {}
        }
        match statement {
            Stmt::Call {
                target,
                args,
                dst,
                call_spec,
            } => {
                record_named_call_observation(
                    target,
                    args,
                    dst.as_ref(),
                    call_spec.as_ref(),
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                collect_named_call_expr(
                    target,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                for argument in args {
                    collect_named_call_expr(
                        argument,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_named_call_expr(cond, current_name, observations, authoritative, conflicts);
                collect_named_call_observations(
                    then_body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                if let Some(else_body) = else_body {
                    collect_named_call_observations(
                        else_body,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                collect_named_call_expr(cond, current_name, observations, authoritative, conflicts);
                collect_named_call_observations(
                    body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_named_call_expr(cond, current_name, observations, authoritative, conflicts);
                collect_named_call_observations(
                    std::slice::from_ref(init.as_ref()),
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                collect_named_call_observations(
                    body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                collect_named_call_observations(
                    std::slice::from_ref(step.as_ref()),
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_named_call_expr(
                    discriminant,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                for (_, case) in cases {
                    collect_named_call_observations(
                        case,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
                if let Some(default) = default {
                    collect_named_call_observations(
                        default,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_named_call_observations(
                    try_body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                for catch in catches {
                    collect_named_call_observations(
                        &catch.body,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            Stmt::Assign { src, .. } => {
                collect_named_call_expr(src, current_name, observations, authoritative, conflicts)
            }
            Stmt::Store { addr, src, .. } => {
                collect_named_call_expr(addr, current_name, observations, authoritative, conflicts);
                collect_named_call_expr(src, current_name, observations, authoritative, conflicts);
            }
            Stmt::Return { value: Some(value) }
            | Stmt::Push { value }
            | Stmt::IndirectGoto { target: value }
            | Stmt::Throw { value } => {
                collect_named_call_expr(value, current_name, observations, authoritative, conflicts)
            }
            Stmt::Return { value: None }
            | Stmt::Pop { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

fn record_named_call_observation(
    target: &Expr,
    args: &[Expr],
    dst: Option<&VReg>,
    call_spec: Option<&CallSiteSpec>,
    current_name: &str,
    observations: &mut std::collections::BTreeMap<String, Vec<CallPrototype>>,
    authoritative: &mut std::collections::BTreeMap<String, CallPrototype>,
    conflicts: &mut std::collections::BTreeSet<String>,
) {
    let Expr::Named { name, .. } = target else {
        return;
    };
    let displayed = sanitize_c_ident(callee_display_name(name));
    if displayed == current_name {
        return;
    }
    let call_spec = call_spec
        .cloned()
        .unwrap_or_else(|| crate::ir::call_contracts::recover_call_site_spec(target, args, dst));
    observations
        .entry(displayed.clone())
        .or_default()
        .push(call_spec.call_prototype);
    if let Some(prototype) = call_spec.callee_prototype {
        if let Some(existing) = authoritative.get(&displayed) {
            if existing != &prototype {
                conflicts.insert(displayed);
            }
        } else {
            authoritative.insert(displayed, prototype);
        }
    }
}

fn collect_named_call_expr(
    expression: &Expr,
    current_name: &str,
    observations: &mut std::collections::BTreeMap<String, Vec<CallPrototype>>,
    authoritative: &mut std::collections::BTreeMap<String, CallPrototype>,
    conflicts: &mut std::collections::BTreeSet<String>,
) {
    macro_rules! visit {
        ($nested:expr) => {
            collect_named_call_expr(
                $nested,
                current_name,
                observations,
                authoritative,
                conflicts,
            )
        };
    }
    match expression {
        Expr::Call {
            target,
            args,
            call_spec,
            ..
        } => {
            record_named_call_observation(
                target,
                args,
                None,
                call_spec.as_ref(),
                current_name,
                observations,
                authoritative,
                conflicts,
            );
            visit!(target);
            for argument in args {
                visit!(argument);
            }
        }
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::NumericConvert { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => visit!(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            visit!(lhs);
            visit!(rhs);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            visit!(cond);
            visit!(if_true);
            visit!(if_false);
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                visit!(argument);
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

fn infer_named_call_prototype(observations: &[CallPrototype]) -> Option<CallPrototype> {
    let first = observations.first()?;
    let mut observed_returns = observations
        .iter()
        .filter(|observation| observation.return_type != "void")
        .map(|observation| observation.return_type.as_str());
    let return_type = match observed_returns.next() {
        None => "void",
        Some(first_return) if observed_returns.all(|observed| observed == first_return) => {
            first_return
        }
        // Conflicting recovered result representations have no authoritative
        // winner. Keep the declaration at the machine-word boundary; each
        // pointer-returning use will carry its own call-site cast.
        Some(_) => "long",
    };

    if observations
        .iter()
        .all(|observation| observation.parameter_types == first.parameter_types)
    {
        return Some(CallPrototype {
            return_type: return_type.to_string(),
            parameter_types: first.parameter_types.iter().cloned().collect(),
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        });
    }

    let common_len = observations
        .iter()
        .map(|observation| observation.parameter_types.len())
        .min()
        .unwrap_or(0);
    let prefix_len = (0..common_len)
        .take_while(|index| {
            let expected = &first.parameter_types[*index];
            observations
                .iter()
                .all(|observation| &observation.parameter_types[*index] == expected)
        })
        .count();
    if prefix_len == 0 {
        let mut selected = observations
            .iter()
            .max_by_key(|observation| observation.parameter_types.len())?
            .clone();
        selected.return_type = return_type.to_string();
        selected.authority = CallPrototypeAuthority::Recovered;
        return Some(selected);
    }

    Some(CallPrototype {
        return_type: return_type.to_string(),
        parameter_types: first.parameter_types[..prefix_len]
            .iter()
            .cloned()
            .collect(),
        variadic: true,
        authority: CallPrototypeAuthority::Recovered,
    })
}

/// Select one declaration per callee named by `body`.
///
/// The program-level environment answers first. A record there is a property of
/// the *callee* — its DWARF declaration, its catalog contract, or the recovery
/// run over its own body — so every caller in the image selects the same
/// declaration for the same symbol, and a callee defined in this unit is
/// declared as what it actually is.
///
/// Call-site inference remains for the symbols the environment cannot reach:
/// imports with no body in this image and no catalog entry. Those are still
/// per-function and can still disagree between functions; measured on dpkg
/// (816 rendered functions) they are 1,210 of 3,609 declaration sites, of which
/// 96 disagree.
pub(super) fn recover_named_call_prototypes(
    body: &[Stmt],
    current_name: &str,
) -> std::collections::BTreeMap<String, CallPrototype> {
    let mut observations = std::collections::BTreeMap::new();
    let mut prototypes = std::collections::BTreeMap::new();
    let mut conflicts = std::collections::BTreeSet::new();
    collect_named_call_observations(
        body,
        current_name,
        &mut observations,
        &mut prototypes,
        &mut conflicts,
    );
    for conflict in &conflicts {
        prototypes.remove(conflict);
    }
    for name in observations.keys() {
        if let Some(record) = crate::ir::symbol_env::lookup(name) {
            prototypes.insert(name.clone(), record.prototype);
        }
    }
    for (name, observations) in observations {
        if let std::collections::btree_map::Entry::Vacant(entry) = prototypes.entry(name) {
            if let Some(prototype) = infer_named_call_prototype(&observations) {
                entry.insert(prototype);
            }
        }
    }
    prototypes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_call_prototype_preserves_an_exact_observed_contract() {
        let observations = vec![CallPrototype {
            return_type: "long".into(),
            parameter_types: vec!["long".into(), "char *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        }];

        assert_eq!(
            infer_named_call_prototype(&observations),
            Some(CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["long".into(), "char *".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            })
        );
    }

    #[test]
    fn named_call_prototype_uses_a_variadic_common_prefix_for_mixed_arities() {
        let observations = vec![
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["char *".into(), "long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["char *".into(), "long".into(), "int".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
        ];

        assert_eq!(
            infer_named_call_prototype(&observations),
            Some(CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["char *".into(), "long".into()],
                variadic: true,
                authority: CallPrototypeAuthority::Recovered,
            })
        );
    }

    #[test]
    fn named_call_prototype_uses_machine_word_for_conflicting_return_types() {
        let observations = vec![
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
            CallPrototype {
                return_type: "char *".into(),
                parameter_types: vec!["long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
        ];

        assert_eq!(
            infer_named_call_prototype(&observations),
            Some(CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            })
        );
    }
}
