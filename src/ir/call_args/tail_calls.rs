//! Recover terminal machine jumps that implement a source-level tail call.
//!
//! A tail transfer does not return to this machine frame, but its C meaning is
//! `return callee(...)`. Both entry points here rewrite one such jump into
//! adjacent `Call` + `Return` nodes so the parent module's ordinary argument and
//! result reconstruction, and the renderer after it, keep normal value identity.
//!
//! Two jump shapes qualify, and only those two:
//!
//! * [`recover_resolved_tail_calls`] — an indirect jump through a slot that name
//!   resolution already proved to be a GOT/IAT-style symbol, or a resolved
//!   function-table entry.
//! * [`recover_resolved_direct_tail_calls`] — a direct jump whose target has no
//!   `Label` in this function but does name a callable entry in the binary's
//!   address map.
//!
//! Everything else stays an `IndirectGoto`/`Goto`, which is what preserves the
//! explicit unrecovered-control-flow warning downstream.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};
use crate::ir::value_number::ValueIdentities;

use super::{arg_slots, mark_slot_write_with_identities, return_reg, CallConv};

/// Recover a terminal jump through a resolved import slot as the source-level
/// tail call it implements.
///
/// This is intentionally narrower than generic indirect-call recovery. Only
/// `IndirectGoto(Deref(Named(...)))` qualifies: name resolution proved the memory
/// slot is a GOT/IAT-style symbol. Register/vtable/jump-table targets remain
/// `IndirectGoto`, preserving the explicit unrecovered-control-flow warning.
///
/// A tail transfer does not return to this machine frame, but its C meaning is
/// `return callee(...)`. We express that as adjacent Call + Return nodes so the
/// existing argument/result reconstruction and renderer can retain normal value
/// identity. When no argument register was set up locally, the jump forwards the
/// complete ABI register state. Logical `argN` names record that fact without
/// guessing a source prototype or a callee arity.
pub fn recover_resolved_tail_calls(f: &mut Function, arch: CallConv) {
    recover_resolved_tail_calls_with_identities(f, arch, None);
}

pub(crate) fn recover_resolved_tail_calls_with_identities(
    f: &mut Function,
    arch: CallConv,
    identities: Option<&ValueIdentities>,
) {
    recover_tail_calls_in_body(&mut f.body, arch, identities);
}

/// Recover a Rust trait-object terminal dispatch backed by a proven fat-pointer
/// result from the preceding direct call.
pub fn recover_proven_vtable_tail_calls(
    f: &mut Function,
    arch: CallConv,
    prototypes: &std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
) {
    recover_proven_vtable_tail_calls_with_identities(f, arch, prototypes, None);
}

pub(crate) fn recover_proven_vtable_tail_calls_with_identities(
    f: &mut Function,
    arch: CallConv,
    prototypes: &std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
    identities: Option<&ValueIdentities>,
) {
    recover_vtable_tail_calls_in_body(&mut f.body, arch, prototypes, identities);
}

/// Recover a direct jump whose target is a named entry outside the current AST
/// as a source-level tail call.
///
/// Authoritative function ranges deliberately keep PLT stubs and neighboring
/// functions out of the lifted LLIR. The terminal machine jump therefore has
/// no local `Label`, but the binary address map still proves which callable
/// entry it targets. Converting only that exact combination avoids both a
/// dangling `goto` and the old workaround of importing the callee's basic
/// blocks into the caller.
pub fn recover_resolved_direct_tail_calls(
    f: &mut Function,
    arch: CallConv,
    names: &std::collections::HashMap<u64, String>,
) {
    recover_resolved_direct_tail_calls_with_identities(f, arch, names, None);
}

pub(crate) fn recover_resolved_direct_tail_calls_with_identities(
    f: &mut Function,
    arch: CallConv,
    names: &std::collections::HashMap<u64, String>,
    identities: Option<&ValueIdentities>,
) {
    let mut local_labels = std::collections::HashSet::new();
    collect_labels(&f.body, &mut local_labels);
    recover_direct_tail_calls_in_body(&mut f.body, arch, names, &local_labels, identities);
}

fn collect_labels(body: &[Stmt], labels: &mut std::collections::HashSet<u64>) {
    for statement in body {
        match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Label(va) => {
                labels.insert(*va);
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_labels(then_body, labels);
                if let Some(else_body) = else_body {
                    collect_labels(else_body, labels);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collect_labels(body, labels)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_labels(case, labels);
                }
                if let Some(default) = default {
                    collect_labels(default, labels);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_labels(try_body, labels);
                for catch in catches {
                    collect_labels(&catch.body, labels);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Push { .. }
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
        }
    }
}

fn recover_direct_tail_calls_in_body(
    body: &mut Vec<Stmt>,
    arch: CallConv,
    names: &std::collections::HashMap<u64, String>,
    local_labels: &std::collections::HashSet<u64>,
    identities: Option<&ValueIdentities>,
) {
    for statement in body.iter_mut() {
        match statement.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_direct_tail_calls_in_body(then_body, arch, names, local_labels, identities);
                if let Some(else_body) = else_body {
                    recover_direct_tail_calls_in_body(
                        else_body,
                        arch,
                        names,
                        local_labels,
                        identities,
                    );
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                recover_direct_tail_calls_in_body(body, arch, names, local_labels, identities)
            }
            Stmt::For { body, .. } => {
                recover_direct_tail_calls_in_body(body, arch, names, local_labels, identities)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_direct_tail_calls_in_body(case, arch, names, local_labels, identities);
                }
                if let Some(default) = default {
                    recover_direct_tail_calls_in_body(
                        default,
                        arch,
                        names,
                        local_labels,
                        identities,
                    );
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_direct_tail_calls_in_body(try_body, arch, names, local_labels, identities);
                for catch in catches {
                    recover_direct_tail_calls_in_body(
                        &mut catch.body,
                        arch,
                        names,
                        local_labels,
                        identities,
                    );
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Push { .. }
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let callee = match body[index].semantic() {
            Stmt::Goto { target } if !local_labels.contains(target) => {
                names.get(target).map(|name| Expr::Named {
                    va: *target,
                    name: name.clone(),
                })
            }
            _ => None,
        };
        let Some(callee) = callee else {
            index += 1;
            continue;
        };

        let has_local_setup = body[..index]
            .iter()
            .any(|statement| statement_writes_argument_slot(statement, arch, identities));
        let args = if has_local_setup {
            Vec::new()
        } else {
            (0..arg_slots(arch).len())
                .map(|slot| Expr::Reg(VReg::phys(format!("arg{slot}"))))
                .collect()
        };
        let origins = body[index].origins().cloned();
        body[index] = Stmt::Call {
            target: callee,
            args,
            dst: None,
            call_spec: None,
        }
        .with_optional_origins(origins.clone());
        body.insert(
            index + 1,
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys(return_reg(arch)))),
            }
            .with_optional_origins(origins),
        );
        index += 2;
    }
}

fn recover_tail_calls_in_body(
    body: &mut Vec<Stmt>,
    arch: CallConv,
    identities: Option<&ValueIdentities>,
) {
    for stmt in body.iter_mut() {
        match stmt.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_tail_calls_in_body(then_body, arch, identities);
                if let Some(else_body) = else_body {
                    recover_tail_calls_in_body(else_body, arch, identities);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                recover_tail_calls_in_body(body, arch, identities)
            }
            Stmt::For { body, .. } => recover_tail_calls_in_body(body, arch, identities),
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_tail_calls_in_body(case, arch, identities);
                }
                if let Some(default) = default {
                    recover_tail_calls_in_body(default, arch, identities);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_tail_calls_in_body(try_body, arch, identities);
                for catch in catches {
                    recover_tail_calls_in_body(&mut catch.body, arch, identities);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Push { .. }
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let callee = match body[index].semantic() {
            Stmt::IndirectGoto {
                target: Expr::Deref { addr, .. },
            } => match addr.as_ref() {
                Expr::Named { .. } => Some((**addr).clone()),
                _ => None,
            },
            Stmt::IndirectGoto {
                target: target @ Expr::FunctionTableEntry { .. },
            } => Some(target.clone()),
            _ => None,
        };
        let Some(callee) = callee else {
            index += 1;
            continue;
        };

        let has_local_setup = body[..index]
            .iter()
            .any(|stmt| statement_writes_argument_slot(stmt, arch, identities));
        let args = if has_local_setup {
            Vec::new()
        } else {
            (0..arg_slots(arch).len())
                .map(|slot| Expr::Reg(VReg::phys(format!("arg{slot}"))))
                .collect()
        };
        let origins = body[index].origins().cloned();
        body[index] = Stmt::Call {
            target: callee,
            args,
            dst: None,
            call_spec: None,
        }
        .with_optional_origins(origins.clone());
        body.insert(
            index + 1,
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys(return_reg(arch)))),
            }
            .with_optional_origins(origins),
        );
        index += 2;
    }
}

fn recover_vtable_tail_calls_in_body(
    body: &mut Vec<Stmt>,
    arch: CallConv,
    prototypes: &std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
    identities: Option<&ValueIdentities>,
) {
    for statement in body.iter_mut() {
        match statement.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_vtable_tail_calls_in_body(then_body, arch, prototypes, identities);
                if let Some(else_body) = else_body {
                    recover_vtable_tail_calls_in_body(else_body, arch, prototypes, identities);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_vtable_tail_calls_in_body(body, arch, prototypes, identities)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_vtable_tail_calls_in_body(case, arch, prototypes, identities);
                }
                if let Some(default) = default {
                    recover_vtable_tail_calls_in_body(default, arch, prototypes, identities);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_vtable_tail_calls_in_body(try_body, arch, prototypes, identities);
                for catch in catches {
                    recover_vtable_tail_calls_in_body(
                        &mut catch.body,
                        arch,
                        prototypes,
                        identities,
                    );
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Push { .. }
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
        }
    }

    let Some(Stmt::IndirectGoto {
        target: Expr::Reg(target_register),
    }) = body.last().map(Stmt::semantic)
    else {
        return;
    };
    let target_register = target_register.clone();
    let Some((definition_index, target)) = body[..body.len() - 1]
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, statement)| match statement.semantic() {
            Stmt::Assign { dst, src }
                if registers_are_same_value(dst, &target_register, identities) =>
            {
                Some((index, src.clone()))
            }
            _ => None,
        })
    else {
        return;
    };
    if !is_rust_vtable_slot_load(&target, arch, identities) {
        return;
    }
    let Some((call_index, callee_va)) =
        body[..definition_index]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, statement)| match statement.semantic() {
                Stmt::Call {
                    target: Expr::Named { va, .. },
                    ..
                } => Some((index, *va)),
                _ => None,
            })
    else {
        return;
    };
    let Some(prototype) = prototypes.get(&callee_va) else {
        return;
    };
    let word = crate::ir::abi::machine_word_bytes(arch);
    if crate::ir::call_contracts::integer_c_type_width(&prototype.return_type, word)
        != Some(crate::ir::abi::wide_integer_return_width(arch))
        || body[call_index + 1..definition_index]
            .iter()
            .any(|statement| statement_writes_high_result(statement, arch, identities))
    {
        return;
    }

    let tail_index = body.len() - 1;
    let origins = body[tail_index].origins().cloned();
    body[tail_index] = Stmt::Call {
        target,
        args: Vec::new(),
        dst: None,
        call_spec: None,
    }
    .with_optional_origins(origins.clone());
    body.push(
        Stmt::Return {
            value: Some(Expr::Reg(VReg::phys(return_reg(arch)))),
        }
        .with_optional_origins(origins),
    );
}

fn registers_are_same_value(
    left: &VReg,
    right: &VReg,
    identities: Option<&ValueIdentities>,
) -> bool {
    match identities {
        Some(identities) => identities
            .exact(left)
            .zip(identities.exact(right))
            .is_some_and(|(left, right)| left == right),
        None => left == right,
    }
}

fn register_is_wide_result_part(
    register: &VReg,
    arch: CallConv,
    part: usize,
    identities: Option<&ValueIdentities>,
) -> bool {
    match identities {
        Some(identities) => identities.candidates(register).is_some_and(|candidates| {
            !candidates.is_empty()
                && candidates.iter().all(|identity| {
                    identity.canonical_physical_base().is_some_and(|name| {
                        crate::ir::abi::wide_integer_return_part(arch, name) == Some(part)
                    })
                })
        }),
        None => matches!(
            register,
            VReg::Phys(name)
                if crate::ir::abi::wide_integer_return_part(arch, name) == Some(part)
        ),
    }
}

fn statement_writes_high_result(
    statement: &Stmt,
    arch: CallConv,
    identities: Option<&ValueIdentities>,
) -> bool {
    match statement.semantic() {
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            register_is_wide_result_part(dst, arch, 1, identities)
        }
        _ => false,
    }
}

/// Recognise the machine shape of a Rust trait-object method slot.
///
/// A Rust fat pointer transports its vtable pointer in the high machine word.
/// The first three vtable words are metadata (`drop`, size, alignment), so a
/// method dispatch is a pointer-sized load at an aligned offset of at least
/// three words from that extracted high half. Requiring this complete shape and
/// a terminal statement keeps generic computed jumps explicitly unrecovered.
fn is_rust_vtable_slot_load(
    target: &Expr,
    arch: CallConv,
    identities: Option<&ValueIdentities>,
) -> bool {
    let word = crate::ir::abi::machine_word_bytes(arch);
    let Expr::Deref { addr, size } = target else {
        return false;
    };
    if *size != word {
        return false;
    }
    let (base_is_high_result, offset) = match addr.as_ref() {
        Expr::Lea {
            base: Some(base),
            index: None,
            disp,
            ..
        } => (
            register_is_wide_result_part(base, arch, 1, identities),
            *disp,
        ),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            let (base, offset) = match (lhs.as_ref(), rhs.as_ref()) {
                (base, Expr::Const(offset)) | (Expr::Const(offset), base) => (base, *offset),
                _ => return false,
            };
            (
                contains_high_word_extract(base, u32::from(word) * 8),
                offset,
            )
        }
        _ => return false,
    };
    let minimum_method_offset = i64::from(word) * 3;
    base_is_high_result && offset >= minimum_method_offset && offset % i64::from(word) == 0
}

fn contains_high_word_extract(expr: &Expr, word_bits: u32) -> bool {
    match expr {
        Expr::Bin {
            op: BinOp::Shr,
            lhs: _,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(bits) if *bits == i64::from(word_bits)) => true,
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            contains_high_word_extract(expr, word_bits)
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_high_word_extract(lhs, word_bits) || contains_high_word_extract(rhs, word_bits)
        }
        Expr::Un { src, .. } | Expr::Deref { addr: src, .. } => {
            contains_high_word_extract(src, word_bits)
        }
        _ => false,
    }
}

fn statement_writes_argument_slot(
    stmt: &Stmt,
    arch: CallConv,
    identities: Option<&ValueIdentities>,
) -> bool {
    match stmt.semantic() {
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            let mut written = vec![false; arg_slots(arch).len()];
            mark_slot_write_with_identities(dst, arch, &mut written, identities);
            written.into_iter().any(|slot| slot)
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .iter()
                .any(|stmt| statement_writes_argument_slot(stmt, arch, identities))
                || else_body.as_ref().is_some_and(|body| {
                    body.iter()
                        .any(|stmt| statement_writes_argument_slot(stmt, arch, identities))
                })
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => body
            .iter()
            .any(|stmt| statement_writes_argument_slot(stmt, arch, identities)),
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| {
                body.iter()
                    .any(|stmt| statement_writes_argument_slot(stmt, arch, identities))
            }) || default.as_ref().is_some_and(|body| {
                body.iter()
                    .any(|stmt| statement_writes_argument_slot(stmt, arch, identities))
            })
        }
        Stmt::TryCatch { try_body, catches } => {
            try_body
                .iter()
                .any(|stmt| statement_writes_argument_slot(stmt, arch, identities))
                || catches.iter().any(|catch| {
                    catch
                        .body
                        .iter()
                        .any(|stmt| statement_writes_argument_slot(stmt, arch, identities))
                })
        }
        Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
        Stmt::Store { .. }
        | Stmt::Call { .. }
        | Stmt::Return { .. }
        | Stmt::Goto { .. }
        | Stmt::IndirectGoto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Push { .. }
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{CatchClause, OriginSet};
    use crate::ir::call_args::reconstruct_args_with_params;

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn got_tail(name: &str, va: u64) -> Stmt {
        Stmt::IndirectGoto {
            target: Expr::Deref {
                addr: Box::new(Expr::Named {
                    va,
                    name: name.to_string(),
                }),
                size: 8,
            },
        }
    }

    fn vtable_load(slot: i64) -> Expr {
        Expr::Deref {
            addr: Box::new(Expr::Lea {
                base: Some(reg("rdx#result")),
                index: None,
                scale: 1,
                disp: slot,
                segment: None,
            }),
            size: 8,
        }
    }

    fn wide_prototypes() -> std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>
    {
        std::collections::HashMap::from([(
            0x1000,
            crate::ir::call_contracts::CallPrototype {
                return_type: "unsigned __int128".into(),
                parameter_types: vec!["unsigned int".into()],
                variadic: false,
                authority: crate::ir::call_contracts::CallPrototypeAuthority::Recovered,
            },
        )])
    }

    fn vtable_tail_function(slot: i64) -> Function {
        Function {
            name: "rust_dyn_apply".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "choose".into(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rcx#method"),
                    src: vtable_load(slot),
                },
                Stmt::IndirectGoto {
                    target: Expr::Reg(reg("rcx#method")),
                },
            ],
        }
    }

    #[test]
    fn resolved_got_tail_jump_becomes_a_call_and_return() {
        let mut f = Function {
            name: "reverse".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("r8#1"),
                    src: Expr::Reg(reg("rdi#0")),
                },
                Stmt::Assign {
                    dst: reg("rax#1"),
                    src: Expr::Reg(reg("rsi#0")),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rcx#0")),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Reg(reg("rdx#0")),
                },
                Stmt::Assign {
                    dst: reg("rcx#1"),
                    src: Expr::Reg(reg("r8#1")),
                },
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Reg(reg("rax#1")),
                },
                got_tail("sum_arg4", 0x4000),
            ],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);
        reconstruct_args_with_params(
            &mut f,
            CallConv::SysVAmd64,
            &[0, 1, 2, 3].into_iter().collect(),
        );

        let (target, args, dst) = f
            .body
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Call {
                    target, args, dst, ..
                } => Some((target, args, dst)),
                _ => None,
            })
            .expect("the resolved terminal transfer must become a call");
        assert!(matches!(target, Expr::Named { name, .. } if name == "sum_arg4"));
        assert_eq!(
            args,
            &vec![
                Expr::Reg(reg("rcx#0")),
                Expr::Reg(reg("rdx#0")),
                Expr::Reg(reg("rax#1")),
                Expr::Reg(reg("r8#1")),
            ]
        );
        assert_eq!(dst, &Some(reg("rax")));
        assert!(matches!(
            f.body.last(),
            Some(Stmt::Return {
                value: Some(Expr::Reg(VReg::Phys(name)))
            }) if name == "rax"
        ));
    }

    #[test]
    fn untouched_tail_jump_forwards_the_complete_abi_register_state() {
        let mut f = Function {
            name: "forward".into(),
            entry_va: 0,
            body: vec![got_tail("sum_arg6", 0x4008)],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { target, args, .. } = &f.body[0] else {
            panic!("expected recovered call, got {:#?}", f.body);
        };
        assert!(matches!(target, Expr::Named { name, .. } if name == "sum_arg6"));
        assert_eq!(
            args,
            &(0..6)
                .map(|slot| Expr::Reg(reg(&format!("arg{slot}"))))
                .collect::<Vec<_>>()
        );
        assert!(matches!(f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn unresolved_direct_jump_to_a_named_external_entry_becomes_a_tail_call() {
        let mut f = Function {
            name: "forward_sum6".into(),
            entry_va: 0x17b0,
            body: vec![Stmt::Goto { target: 0x1070 }],
        };
        let names = [(0x1070, "sum_arg6@plt".to_string())].into_iter().collect();

        recover_resolved_direct_tail_calls(&mut f, CallConv::SysVAmd64, &names);

        let Stmt::Call { target, args, .. } = &f.body[0] else {
            panic!("expected recovered direct tail call, got {:#?}", f.body);
        };
        assert!(matches!(target, Expr::Named { va: 0x1070, name } if name == "sum_arg6@plt"));
        assert_eq!(
            args,
            &(0..6)
                .map(|slot| Expr::Reg(reg(&format!("arg{slot}"))))
                .collect::<Vec<_>>()
        );
        assert!(matches!(f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn tail_setup_uses_exact_identity_not_display_spelling() {
        let caller = |dst: &str| Function {
            name: "forward".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg(dst),
                    src: Expr::Const(7),
                },
                Stmt::Goto { target: 0x1070 },
            ],
        };
        let names = [(0x1070, "sum_arg6@plt".to_string())].into_iter().collect();
        let mut identities = ValueIdentities::default();
        identities.record(
            reg("opaque_arg"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        identities.record(
            reg("rdi#1"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 1,
            },
        );

        let mut exact = caller("opaque_arg");
        recover_resolved_direct_tail_calls_with_identities(
            &mut exact,
            CallConv::SysVAmd64,
            &names,
            Some(&identities),
        );
        assert!(matches!(&exact.body[1], Stmt::Call { args, .. } if args.is_empty()));

        let mut misleading = caller("rdi#1");
        recover_resolved_direct_tail_calls_with_identities(
            &mut misleading,
            CallConv::SysVAmd64,
            &names,
            Some(&identities),
        );
        assert!(matches!(&misleading.body[1], Stmt::Call { args, .. } if args.len() == 6));
    }

    #[test]
    fn attributed_got_tail_and_argument_setup_keep_the_transfer_owner() {
        let setup_owner = OriginSet::one(0x1010);
        let transfer_owner = OriginSet::one(0x1014);
        let mut f = Function {
            name: "forward".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rsi#0")),
                }
                .with_origins(setup_owner.clone()),
                got_tail("sum_arg6", 0x4008).with_origins(transfer_owner.clone()),
            ],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { args, .. } = f.body[1].semantic() else {
            panic!("expected attributed recovered call, got {:#?}", f.body)
        };
        assert!(args.is_empty(), "the attributed local setup was ignored");
        assert_eq!(f.body[0].origins(), Some(&setup_owner));
        assert_eq!(f.body[1].origins(), Some(&transfer_owner));
        assert!(matches!(f.body[2].semantic(), Stmt::Return { .. }));
        assert_eq!(f.body[2].origins(), Some(&transfer_owner));
    }

    #[test]
    fn attributed_direct_tail_inside_a_catch_keeps_the_transfer_owner() {
        let transfer_owner = OriginSet::one(0x1020);
        let mut f = Function {
            name: "catch_forward".into(),
            entry_va: 0,
            body: vec![Stmt::TryCatch {
                try_body: vec![Stmt::Throw {
                    value: Expr::Const(1),
                }],
                catches: vec![CatchClause {
                    type_name: "int".into(),
                    binding: reg("caught"),
                    body: vec![Stmt::Goto { target: 0x1070 }.with_origins(transfer_owner.clone())],
                }],
            }],
        };
        let names = [(0x1070, "sum_arg6@plt".to_string())].into_iter().collect();

        recover_resolved_direct_tail_calls(&mut f, CallConv::SysVAmd64, &names);

        let Stmt::TryCatch { catches, .. } = f.body[0].semantic() else {
            panic!("exception shape changed")
        };
        assert!(matches!(catches[0].body[0].semantic(), Stmt::Call { .. }));
        assert_eq!(catches[0].body[0].origins(), Some(&transfer_owner));
        assert!(matches!(catches[0].body[1].semantic(), Stmt::Return { .. }));
        assert_eq!(catches[0].body[1].origins(), Some(&transfer_owner));
    }

    #[test]
    fn attributed_local_label_prevents_a_false_external_tail_call() {
        let mut f = Function {
            name: "loop".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Goto { target: 0x1070 }.with_origins(OriginSet::one(0x1004)),
                Stmt::Label(0x1070).with_origins(OriginSet::one(0x1070)),
                Stmt::Return { value: None },
            ],
        };
        let names = [(0x1070, "other_symbol".to_string())].into_iter().collect();

        recover_resolved_direct_tail_calls(&mut f, CallConv::SysVAmd64, &names);

        assert!(matches!(
            f.body[0].semantic(),
            Stmt::Goto { target: 0x1070 }
        ));
        assert_eq!(f.body.len(), 3);
    }

    #[test]
    fn direct_jump_with_an_in_function_label_stays_a_goto() {
        let mut f = Function {
            name: "loop".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Goto { target: 0x1070 },
                Stmt::Label(0x1070),
                Stmt::Return { value: None },
            ],
        };
        let names = [(0x1070, "other_symbol".to_string())].into_iter().collect();

        recover_resolved_direct_tail_calls(&mut f, CallConv::SysVAmd64, &names);

        assert!(matches!(f.body[0], Stmt::Goto { target: 0x1070 }));
    }

    #[test]
    fn unresolved_computed_jump_is_not_relabelled_as_a_call() {
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0,
            body: vec![Stmt::IndirectGoto {
                target: Expr::Reg(reg("rax")),
            }],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);
        assert!(matches!(f.body.as_slice(), [Stmt::IndirectGoto { .. }]));
    }

    #[test]
    fn terminal_aligned_vtable_slot_becomes_an_indirect_tail_call() {
        let mut f = vtable_tail_function(24);

        recover_proven_vtable_tail_calls(&mut f, CallConv::SysVAmd64, &wide_prototypes());

        assert!(matches!(
            &f.body[2..],
            [
                Stmt::Call {
                    target: Expr::Deref { .. },
                    ..
                },
                Stmt::Return { .. }
            ]
        ));
    }

    #[test]
    fn vtable_tail_uses_exact_high_result_identity_not_display_spelling() {
        let set_vtable_base = |function: &mut Function, base: &str| {
            let Stmt::Assign {
                src: Expr::Deref { addr, .. },
                ..
            } = &mut function.body[1]
            else {
                panic!("expected vtable load")
            };
            let Expr::Lea {
                base: load_base, ..
            } = addr.as_mut()
            else {
                panic!("expected vtable address")
            };
            *load_base = Some(reg(base));
        };
        let mut identities = ValueIdentities::default();
        identities.record(
            reg("rcx#method"),
            crate::ir::ssa::SsaValue {
                base: reg("rcx"),
                version: 2,
            },
        );
        identities.record(
            reg("opaque_high"),
            crate::ir::ssa::SsaValue {
                base: reg("rdx"),
                version: 1,
            },
        );
        identities.record(
            reg("rdx#result"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 1,
            },
        );

        let mut exact = vtable_tail_function(24);
        set_vtable_base(&mut exact, "opaque_high");
        recover_proven_vtable_tail_calls_with_identities(
            &mut exact,
            CallConv::SysVAmd64,
            &wide_prototypes(),
            Some(&identities),
        );
        assert!(matches!(exact.body.last(), Some(Stmt::Return { .. })));

        let mut misleading = vtable_tail_function(24);
        recover_proven_vtable_tail_calls_with_identities(
            &mut misleading,
            CallConv::SysVAmd64,
            &wide_prototypes(),
            Some(&identities),
        );
        assert!(matches!(
            misleading.body.last(),
            Some(Stmt::IndirectGoto { .. })
        ));
    }

    #[test]
    fn attributed_vtable_tail_keeps_the_transfer_owner() {
        let call_owner = OriginSet::one(0x1100);
        let load_owner = OriginSet::one(0x1104);
        let transfer_owner = OriginSet::one(0x1108);
        let mut f = vtable_tail_function(24);
        f.body[0] = std::mem::replace(&mut f.body[0], Stmt::Nop).with_origins(call_owner.clone());
        f.body[1] = std::mem::replace(&mut f.body[1], Stmt::Nop).with_origins(load_owner.clone());
        f.body[2] =
            std::mem::replace(&mut f.body[2], Stmt::Nop).with_origins(transfer_owner.clone());

        recover_proven_vtable_tail_calls(&mut f, CallConv::SysVAmd64, &wide_prototypes());

        assert!(matches!(f.body[2].semantic(), Stmt::Call { .. }));
        assert_eq!(f.body[0].origins(), Some(&call_owner));
        assert_eq!(f.body[1].origins(), Some(&load_owner));
        assert_eq!(f.body[2].origins(), Some(&transfer_owner));
        assert!(matches!(f.body[3].semantic(), Stmt::Return { .. }));
        assert_eq!(f.body[3].origins(), Some(&transfer_owner));
    }

    #[test]
    fn unaligned_dynamic_dereference_stays_explicitly_unrecovered() {
        let mut f = vtable_tail_function(3);

        recover_proven_vtable_tail_calls(&mut f, CallConv::SysVAmd64, &wide_prototypes());

        assert!(matches!(f.body.last(), Some(Stmt::IndirectGoto { .. })));
    }

    #[test]
    fn vtable_shape_after_a_scalar_call_stays_explicitly_unrecovered() {
        let mut f = vtable_tail_function(24);
        let mut prototypes = wide_prototypes();
        prototypes.get_mut(&0x1000).unwrap().return_type = "long".into();

        recover_proven_vtable_tail_calls(&mut f, CallConv::SysVAmd64, &prototypes);

        assert!(matches!(f.body.last(), Some(Stmt::IndirectGoto { .. })));
    }

    #[test]
    fn overwritten_high_result_before_vtable_load_stays_unrecovered() {
        let mut f = vtable_tail_function(24);
        f.body.insert(
            1,
            Stmt::Assign {
                dst: reg("rdx#result"),
                src: Expr::Const(0),
            },
        );

        recover_proven_vtable_tail_calls(&mut f, CallConv::SysVAmd64, &wide_prototypes());

        assert!(matches!(f.body.last(), Some(Stmt::IndirectGoto { .. })));
    }
}
