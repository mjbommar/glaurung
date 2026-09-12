//! Projection of machine return storage onto source-level AST returns.
//!
//! Lowering preserves a bare machine `RET` as `Return { value: None }`. This
//! module materializes a value only when either the body writes a known return
//! register or an authoritative prototype proves that the live-in parameter is
//! itself the direct result. Keeping that policy outside the renderer prevents
//! `return 0` fabrication while leaving void and unknown outputs untouched.
//!
//! WHICH registers count as result storage is not decided here. This module
//! owns the AST walk; [`crate::ir::abi::result_projection`] owns the two tiers
//! of names it walks for, why they are two tiers rather than one, and the test
//! that cross-checks both against the per-convention ABI tables. Keeping a
//! private copy of that list here is what let x86-64's `xmm0` go missing while
//! ARM32's `s0`/`d0` were present, and cost eleven fixture cells.

use crate::ir::abi::result_projection::{
    is_fallback_result_register, is_projected_result_register, is_projected_result_storage,
};
use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;
use crate::ir::types_recover::{RecoveredOutputKind, RecoveredPrototype};

/// Project a body-written return register onto every remaining bare return.
pub(crate) fn materialize_direct_output(function: &mut Function) {
    materialize_direct_output_with_live_in(
        function,
        None,
        &|value| matches!(value, VReg::Phys(name) if name == "ret"),
    );
}

/// Project body-written output using pipeline-owned role authority.
pub(crate) fn materialize_direct_output_with_identities(
    function: &mut Function,
    identities: &crate::ir::value_number::ValueIdentities,
) {
    materialize_direct_output_with_live_in(function, None, &|value| {
        identities.is_result_role(value)
            || identities
                .unambiguous_physical_base(value)
                .is_some_and(is_projected_result_register)
    });
}

/// Project a prototype-proven direct output, including identity functions whose
/// machine body is only `ret` and therefore has no in-function result write.
pub(crate) fn materialize_prototype_output(
    function: &mut Function,
    cc: CallConv,
    prototype: Option<&RecoveredPrototype>,
) {
    let live_in_result = prototype.and_then(|prototype| {
        if prototype.output_kind() != RecoveredOutputKind::Direct
            || !prototype.output_is_locked()
            || !prototype.parameter_arity_is_locked()
        {
            return None;
        }
        let result = prototype.result()?;
        if !result.values.is_empty() {
            return None;
        }
        let parameter = prototype.parameter(0)?;
        match &parameter.value.base {
            VReg::Phys(name) if crate::ir::abi::is_return_register(cc, name) => {
                Some(&parameter.value.base)
            }
            _ => None,
        }
    });
    let live_in_result =
        live_in_result.filter(|_| !body_writes_abi_return_storage(&function.body, cc));
    // This pass runs before role naming. A literal `ret` here may be a source
    // or debug spelling and is not evidence of machine result storage.
    materialize_direct_output_with_live_in(function, live_in_result, &|_| false);
}

fn body_writes_abi_return_storage(body: &[Stmt], cc: CallConv) -> bool {
    body.iter().any(|statement| match statement.semantic() {
        Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
        Stmt::Assign {
            dst: VReg::Phys(name),
            ..
        }
        | Stmt::Call {
            dst: Some(VReg::Phys(name)),
            ..
        } => crate::ir::abi::is_return_register(cc, name),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_writes_abi_return_storage(then_body, cc)
                || else_body
                    .as_deref()
                    .is_some_and(|body| body_writes_abi_return_storage(body, cc))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body_writes_abi_return_storage(body, cc)
        }
        Stmt::For {
            init, step, body, ..
        } => {
            body_writes_abi_return_storage(std::slice::from_ref(init), cc)
                || body_writes_abi_return_storage(std::slice::from_ref(step), cc)
                || body_writes_abi_return_storage(body, cc)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body_writes_abi_return_storage(body, cc))
                || default
                    .as_deref()
                    .is_some_and(|body| body_writes_abi_return_storage(body, cc))
        }
        Stmt::TryCatch { try_body, catches } => {
            body_writes_abi_return_storage(try_body, cc)
                || catches
                    .iter()
                    .any(|catch| body_writes_abi_return_storage(&catch.body, cc))
        }
        _ => false,
    })
}

fn materialize_direct_output_with_live_in(
    function: &mut Function,
    live_in_result: Option<&VReg>,
    canonical_role_is_result: &impl Fn(&VReg) -> bool,
) {
    let written = find_written_return_reg(&function.body, canonical_role_is_result)
        .or_else(|| find_written_float_result_reg(&function.body));
    if let Some(return_register) = written {
        apply_default_return(&mut function.body, &return_register);
    } else if let Some(return_register) = live_in_result.filter(|value| is_return_reg(value)) {
        apply_default_return(&mut function.body, return_register);
    }
}

/// Remove machine output operands once prototype recovery has established that
/// the source function is `void`.
pub(crate) fn clear_return_values(function: &mut Function) {
    clear_body_return_values(&mut function.body);
}

/// Remove the source-redundant fallthrough return of a proven-void function.
///
/// Every machine function ends in a return instruction, but C permits control
/// to reach the closing brace of a `void` function.  Keeping the final bare
/// `return;` therefore exposes machine structure that carries no source-level
/// distinction.  Only the outermost terminal statement is removed: returns in
/// branches and loops still control execution and must remain explicit.
pub(crate) fn prune_void_fallthrough_return(function: &mut Function) {
    if function
        .body
        .last()
        .is_some_and(|statement| matches!(statement.semantic(), Stmt::Return { value: None }))
    {
        function.body.pop();
    }
}

/// Remove promoted stack locals whose value is never observed.
///
/// Clang reserves and zeroes a four-byte `main` return slot at `-O0` even when
/// every source return writes the ABI result directly.  Stack promotion makes
/// that bookkeeping look like `local_4 = 0`; retaining it invents a source
/// local and prevents warning-clean recompilation.  Only pure assignments to
/// anonymous promoted locals are eligible.  Debug-proven source locals are
/// protected, and reads through any expression keep the assignment.
pub(crate) fn prune_unread_promoted_locals(
    function: &mut Function,
    protected_locals: &std::collections::HashSet<String>,
) {
    prune_unread_promoted_locals_where(function, protected_locals, &|value| {
        crate::ir::types::is_promoted_local_reg(value)
    });
}

/// Remove unread stack objects using stack-promotion's typed ownership facts.
pub(crate) fn prune_unread_promoted_locals_with_identities(
    function: &mut Function,
    protected_locals: &std::collections::HashSet<String>,
    identities: &crate::ir::value_number::ValueIdentities,
) {
    prune_unread_promoted_locals_where(function, protected_locals, &|value| {
        identities.is_promoted_stack_object(value)
    });
}

fn prune_unread_promoted_locals_where(
    function: &mut Function,
    protected_locals: &std::collections::HashSet<String>,
    is_promoted_stack_object: &impl Fn(&VReg) -> bool,
) {
    fn pure(expression: &Expr) -> bool {
        match expression {
            Expr::Origin { expr, .. } => pure(expr),
            Expr::Reg(_)
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::StackAddr { .. } => true,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => pure(lhs) && pure(rhs),
            Expr::Un { src, .. }
            | Expr::Cast { expr: src, .. }
            | Expr::NumericConvert { expr: src, .. } => pure(src),
            Expr::Lea { .. } | Expr::PdbFieldAddr { .. } => true,
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => pure(cond) && pure(if_true) && pure(if_false),
            Expr::WideArithmetic { args, .. } => args.iter().all(pure),
            // Loads, calls, unresolved expressions, and function-table reads
            // may be volatile, trapping, or effectful. Keep them even when the
            // destination itself is unread.
            Expr::Deref { .. }
            | Expr::Call { .. }
            | Expr::FunctionTableEntry { .. }
            | Expr::Unknown(_) => false,
        }
    }

    fn prune(body: &mut Vec<Stmt>, unread: &std::collections::HashSet<VReg>) -> usize {
        let mut removed = 0;
        for statement in body.iter_mut() {
            match statement.semantic_mut() {
                Stmt::Origin { .. } => {
                    unreachable!("semantic statement cannot be an origin wrapper")
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    removed += prune(then_body, unread);
                    if let Some(else_body) = else_body {
                        removed += prune(else_body, unread);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    removed += prune(body, unread);
                }
                Stmt::For { body, .. } => removed += prune(body, unread),
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        removed += prune(case, unread);
                    }
                    if let Some(default) = default {
                        removed += prune(default, unread);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    removed += prune(try_body, unread);
                    for catch in catches {
                        removed += prune(&mut catch.body, unread);
                    }
                }
                _ => {}
            }
        }
        let before = body.len();
        body.retain(|statement| {
            !matches!(statement.semantic(), Stmt::Assign { dst, src } if unread.contains(dst) && pure(src))
                && !matches!(statement.semantic(), Stmt::Store { addr: Expr::Reg(dst), src, .. }
                    if unread.contains(dst) && pure(src))
        });
        removed + before - body.len()
    }

    fn observes(statement: &Stmt, target: &VReg) -> bool {
        match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { src, .. } => src.contains_reg(target),
            Stmt::Store { addr, src, .. } => {
                (!matches!(addr, Expr::Reg(register) if register == target)
                    && addr.contains_reg(target))
                    || src.contains_reg(target)
            }
            Stmt::Call {
                target: callee,
                args,
                ..
            } => {
                callee.contains_reg(target)
                    || args.iter().any(|argument| argument.contains_reg(target))
            }
            Stmt::Return { value } => value
                .as_ref()
                .is_some_and(|value| value.contains_reg(target)),
            Stmt::Throw { value } | Stmt::Push { value } => value.contains_reg(target),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.contains_reg(target)
                    || then_body
                        .iter()
                        .any(|statement| observes(statement, target))
                    || else_body.as_deref().is_some_and(|body| {
                        body.iter().any(|statement| observes(statement, target))
                    })
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                cond.contains_reg(target)
                    || body.iter().any(|statement| observes(statement, target))
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                observes(init, target)
                    || cond.contains_reg(target)
                    || observes(step, target)
                    || body.iter().any(|statement| observes(statement, target))
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                discriminant.contains_reg(target)
                    || cases
                        .iter()
                        .any(|(_, body)| body.iter().any(|statement| observes(statement, target)))
                    || default.as_deref().is_some_and(|body| {
                        body.iter().any(|statement| observes(statement, target))
                    })
            }
            Stmt::TryCatch { try_body, catches } => {
                try_body.iter().any(|statement| observes(statement, target))
                    || catches.iter().any(|catch| {
                        catch
                            .body
                            .iter()
                            .any(|statement| observes(statement, target))
                    })
            }
            Stmt::IndirectGoto { target: value } => value.contains_reg(target),
            Stmt::Pop { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => false,
        }
    }

    loop {
        let candidates = function
            .body
            .iter()
            .flat_map(|statement| {
                fn collect(
                    statement: &Stmt,
                    out: &mut Vec<VReg>,
                    is_promoted_stack_object: &impl Fn(&VReg) -> bool,
                ) {
                    match statement.semantic() {
                        Stmt::Origin { .. } => {
                            unreachable!("semantic statement cannot be an origin wrapper")
                        }
                        Stmt::Assign { dst, .. } if is_promoted_stack_object(dst) => {
                            out.push(dst.clone())
                        }
                        Stmt::Store {
                            addr: Expr::Reg(dst),
                            ..
                        } if is_promoted_stack_object(dst) => out.push(dst.clone()),
                        Stmt::If {
                            then_body,
                            else_body,
                            ..
                        } => {
                            then_body.iter().for_each(|statement| {
                                collect(statement, out, is_promoted_stack_object)
                            });
                            if let Some(else_body) = else_body {
                                else_body.iter().for_each(|statement| {
                                    collect(statement, out, is_promoted_stack_object)
                                });
                            }
                        }
                        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                            body.iter().for_each(|statement| {
                                collect(statement, out, is_promoted_stack_object)
                            });
                        }
                        Stmt::For { init, step, body, .. } => {
                            collect(init, out, is_promoted_stack_object);
                            body.iter().for_each(|statement| {
                                collect(statement, out, is_promoted_stack_object)
                            });
                            collect(step, out, is_promoted_stack_object);
                        }
                        Stmt::Switch { cases, default, .. } => {
                            for (_, body) in cases {
                                body.iter().for_each(|statement| {
                                    collect(statement, out, is_promoted_stack_object)
                                });
                            }
                            if let Some(default) = default {
                                default.iter().for_each(|statement| {
                                    collect(statement, out, is_promoted_stack_object)
                                });
                            }
                        }
                        Stmt::TryCatch { try_body, catches } => {
                            try_body.iter().for_each(|statement| {
                                collect(statement, out, is_promoted_stack_object)
                            });
                            for catch in catches {
                                catch.body.iter().for_each(|statement| {
                                    collect(statement, out, is_promoted_stack_object)
                                });
                            }
                        }
                        _ => {}
                    }
                }
                let mut found = Vec::new();
                collect(statement, &mut found, is_promoted_stack_object);
                found
            })
            .filter(|candidate| {
                !matches!(candidate, VReg::Phys(name) if protected_locals.contains(name))
            })
            .collect::<std::collections::HashSet<_>>();
        let unread = candidates
            .into_iter()
            .filter(|candidate| {
                !function
                    .body
                    .iter()
                    .any(|statement| observes(statement, candidate))
            })
            .collect::<std::collections::HashSet<_>>();
        if unread.is_empty() {
            break;
        }
        if prune(&mut function.body, &unread) == 0 {
            break;
        }
    }
}

/// Remove a void function's caller-owned result-register save/restore pair.
///
/// Clang sometimes spells an eight-byte stack adjustment as `push rax` before
/// a call and `pop rax` afterwards. Stack promotion turns that into
/// `local = ret; ...; ret = local`. Once prototype recovery has proved the
/// function void, retaining the pair fabricates an uninitialized source local.
/// Only the exact single-use promoted-slot bridge is removed; ordinary locals
/// and result-register values used by any other statement are left alone.
pub(crate) fn prune_void_entry_result_restores(function: &mut Function) {
    prune_void_entry_result_restores_where(
        function,
        &crate::ir::types::is_promoted_local_reg,
        &is_exact_return_storage,
    );
}

/// Remove a void result save/restore using typed stack and SSA ownership.
pub(crate) fn prune_void_entry_result_restores_with_identities(
    function: &mut Function,
    identities: &crate::ir::value_number::ValueIdentities,
) {
    prune_void_entry_result_restores_where(
        function,
        &|value| identities.is_promoted_stack_object(value),
        &|value| {
            identities.candidates(value).is_some_and(|candidates| {
                !candidates.is_empty()
                    && candidates.iter().all(|identity| {
                        identity
                            .canonical_physical_base()
                            .is_some_and(is_projected_result_register)
                    })
            })
        },
    );
}

fn prune_void_entry_result_restores_where(
    function: &mut Function,
    is_promoted_stack_object: &impl Fn(&VReg) -> bool,
    is_machine_result_value: &impl Fn(&VReg) -> bool,
) {
    fn reads(expr: &Expr, target: &VReg) -> bool {
        match expr {
            Expr::Origin { expr, .. } => reads(expr, target),
            Expr::Reg(register)
            | Expr::StackAddr {
                object: register, ..
            } => register == target,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                reads(lhs, target) || reads(rhs, target)
            }
            Expr::Un { src: expr, .. }
            | Expr::Deref { addr: expr, .. }
            | Expr::Cast { expr, .. }
            | Expr::NumericConvert { expr, .. }
            | Expr::FunctionTableEntry { index: expr, .. } => reads(expr, target),
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                base.as_ref().is_some_and(|base| base == target)
                    || index.as_ref().is_some_and(|index| index == target)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => reads(cond, target) || reads(if_true, target) || reads(if_false, target),
            Expr::WideArithmetic { args, .. } => {
                args.iter().any(|argument| reads(argument, target))
            }
            Expr::Call {
                target: callee,
                args,
                ..
            } => reads(callee, target) || args.iter().any(|argument| reads(argument, target)),
            Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => false,
        }
    }

    fn direct_reads(statement: &Stmt, target: &VReg) -> bool {
        match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { src, .. } => reads(src, target),
            Stmt::Store { addr, src, .. } => {
                (!matches!(addr, Expr::Reg(register) if register == target) && reads(addr, target))
                    || reads(src, target)
            }
            Stmt::Call {
                target: callee,
                args,
                ..
            } => reads(callee, target) || args.iter().any(|argument| reads(argument, target)),
            Stmt::Return { value } => value.as_ref().is_some_and(|value| reads(value, target)),
            Stmt::If { cond, .. }
            | Stmt::While { cond, .. }
            | Stmt::DoWhile { cond, .. }
            | Stmt::For { cond, .. } => reads(cond, target),
            Stmt::Switch { discriminant, .. } => reads(discriminant, target),
            Stmt::Push { value } | Stmt::Throw { value } => reads(value, target),
            Stmt::IndirectGoto { target: value } => reads(value, target),
            Stmt::Pop { target: value } => value == target,
            Stmt::TryCatch { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => false,
        }
    }

    fn prune(
        body: &mut Vec<Stmt>,
        is_promoted_stack_object: &impl Fn(&VReg) -> bool,
        is_machine_result_value: &impl Fn(&VReg) -> bool,
    ) {
        for statement in body.iter_mut() {
            match statement.semantic_mut() {
                Stmt::Origin { .. } => {
                    unreachable!("semantic statement cannot be an origin wrapper")
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    prune(then_body, is_promoted_stack_object, is_machine_result_value);
                    if let Some(else_body) = else_body {
                        prune(else_body, is_promoted_stack_object, is_machine_result_value);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    prune(body, is_promoted_stack_object, is_machine_result_value)
                }
                Stmt::For { body, .. } => {
                    prune(body, is_promoted_stack_object, is_machine_result_value)
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        prune(case, is_promoted_stack_object, is_machine_result_value);
                    }
                    if let Some(default) = default {
                        prune(default, is_promoted_stack_object, is_machine_result_value);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    prune(try_body, is_promoted_stack_object, is_machine_result_value);
                    for catch in catches {
                        prune(
                            &mut catch.body,
                            is_promoted_stack_object,
                            is_machine_result_value,
                        );
                    }
                }
                _ => {}
            }
        }

        let mut remove = std::collections::HashSet::new();
        for (store_index, statement) in body.iter().enumerate() {
            let Stmt::Store {
                addr: Expr::Reg(slot),
                src: Expr::Reg(saved),
                ..
            } = statement.semantic()
            else {
                continue;
            };
            if !is_promoted_stack_object(slot) || !is_machine_result_value(saved) {
                continue;
            }
            let restores = body
                .iter()
                .enumerate()
                .filter(|(index, candidate)| {
                    *index > store_index
                        && matches!(candidate.semantic(), Stmt::Assign { dst, src: Expr::Reg(source) }
                            if dst == saved && source == slot)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let [restore_index] = restores.as_slice() else {
                continue;
            };
            let slot_reads = body
                .iter()
                .enumerate()
                .filter(|(index, candidate)| *index != store_index && direct_reads(candidate, slot))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if slot_reads.as_slice() != [*restore_index]
                || body
                    .iter()
                    .skip(*restore_index + 1)
                    .any(|candidate| direct_reads(candidate, saved))
            {
                continue;
            }
            remove.insert(store_index);
            remove.insert(*restore_index);
        }
        if !remove.is_empty() {
            let mut index = 0usize;
            body.retain(|_| {
                let keep = !remove.contains(&index);
                index += 1;
                keep
            });
        }
    }

    prune(
        &mut function.body,
        is_promoted_stack_object,
        is_machine_result_value,
    );
}

fn clear_body_return_values(body: &mut [Stmt]) {
    for statement in body {
        match statement.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Return { value } => *value = None,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                clear_body_return_values(then_body);
                if let Some(else_body) = else_body {
                    clear_body_return_values(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => clear_body_return_values(body),
            Stmt::For { body, .. } => clear_body_return_values(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    clear_body_return_values(body);
                }
                if let Some(body) = default {
                    clear_body_return_values(body);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                clear_body_return_values(try_body);
                for catch in catches {
                    clear_body_return_values(&mut catch.body);
                }
            }
            _ => {}
        }
    }
}

/// The latest first-tier result value written before a bare fallthrough return.
///
/// `ret` — the canonical role name `apply_role_names` leaves behind — is one of
/// the first-tier names, so [`is_return_reg`] already covers it. It was also
/// restated as a second disjunct on both arms below until 2026-08-18, which was
/// dead in a way that read as load-bearing.
fn find_written_return_reg(
    body: &[Stmt],
    canonical_role_is_result: &impl Fn(&VReg) -> bool,
) -> Option<VReg> {
    let is_result = |value: &VReg| match value {
        // `ret` can be a user/source spelling, so only pipeline ownership may
        // authorize it. Other values may be the unversioned compatibility
        // spelling or an exact SSA identity proved to occupy result storage.
        VReg::Phys(name) if name == "ret" => canonical_role_is_result(value),
        _ => is_return_reg(value) || canonical_role_is_result(value),
    };
    // SSA-numbered names distinguish successive values in the same machine
    // carrier. Search backwards so a pre-call argument transport in `rax`
    // cannot beat the later `rax#N` value that actually reaches the return.
    for statement in body.iter().rev() {
        let found = match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, .. } if is_result(dst) => Some(dst.clone()),
            Stmt::Call { dst: Some(dst), .. } if is_result(dst) => Some(dst.clone()),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => else_body
                .as_deref()
                .and_then(|body| find_written_return_reg(body, canonical_role_is_result))
                .or_else(|| find_written_return_reg(then_body, canonical_role_is_result)),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                find_written_return_reg(body, canonical_role_is_result)
            }
            Stmt::For { body, .. } => find_written_return_reg(body, canonical_role_is_result),
            Stmt::Switch { cases, default, .. } => default
                .as_deref()
                .and_then(|body| find_written_return_reg(body, canonical_role_is_result))
                .or_else(|| {
                    cases.iter().rev().find_map(|(_, body)| {
                        find_written_return_reg(body, canonical_role_is_result)
                    })
                }),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn apply_default_return(body: &mut [Stmt], return_register: &VReg) {
    for statement in body {
        match statement.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Return { value } if value.is_none() => {
                *value = Some(Expr::Reg(return_register.clone()));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                apply_default_return(then_body, return_register);
                if let Some(else_body) = else_body {
                    apply_default_return(else_body, return_register);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                apply_default_return(body, return_register)
            }
            Stmt::For { body, .. } => apply_default_return(body, return_register),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    apply_default_return(body, return_register);
                }
                if let Some(body) = default {
                    apply_default_return(body, return_register);
                }
            }
            _ => {}
        }
    }
}

/// The fallback-tier result register, if the body writes it.
///
/// Only consulted after [`find_written_return_reg`] has found no first-tier
/// result storage anywhere in the body. Both tiers, the reason there are two of
/// them, and the census that keeps them honest against the per-convention ABI
/// tables live in [`crate::ir::abi::result_projection`].
fn find_written_float_result_reg(body: &[Stmt]) -> Option<VReg> {
    fn is_float_result_reg(value: &VReg) -> bool {
        matches!(value, VReg::Phys(name) if is_fallback_result_register(name))
    }
    for statement in body {
        let found = match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, .. } if is_float_result_reg(dst) => Some(dst.clone()),
            Stmt::Call { dst: Some(dst), .. } if is_float_result_reg(dst) => Some(dst.clone()),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => find_written_float_result_reg(then_body)
                .or_else(|| else_body.as_deref().and_then(find_written_float_result_reg)),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                find_written_float_result_reg(body)
            }
            Stmt::For { body, .. } => find_written_float_result_reg(body),
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .find_map(|(_, body)| find_written_float_result_reg(body))
                .or_else(|| default.as_deref().and_then(find_written_float_result_reg)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Whether a `VReg` is first-tier result storage, unversioned.
///
/// The table is [`crate::ir::abi::result_projection::PROJECTED_RESULT_REGISTERS`];
/// this is only its `VReg` shape.
pub(crate) fn is_return_reg(value: &VReg) -> bool {
    matches!(value, VReg::Phys(name) if is_projected_result_register(name))
}

/// Whether an exact value identity is backed by machine result storage.
///
/// Unlike [`is_return_reg`], this accepts an SSA version. The distinction is
/// intentional: a compatibility path projecting a bare machine return must not
/// infer a value merely because it sees a versioned write, while a return whose
/// operand already names that exact version may safely fold its adjacent writer.
pub(crate) fn is_exact_return_storage(value: &VReg) -> bool {
    matches!(value, VReg::Phys(name) if is_projected_result_storage(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::SsaValue;
    use crate::ir::types_recover::TypeHint;
    use std::collections::HashMap;

    fn bare_return_function() -> Function {
        Function {
            name: "identity".into(),
            entry_va: 0,
            body: vec![Stmt::Return { value: None }],
        }
    }

    fn int32() -> TypeHint {
        TypeHint::Int {
            signed: false,
            width: 4,
        }
    }

    #[test]
    fn exact_ssa_result_storage_is_distinct_from_the_bare_return_fallback() {
        assert!(!is_return_reg(&VReg::phys("rax#7")));
        assert!(!is_return_reg(&VReg::phys("x0#2")));
        assert!(is_exact_return_storage(&VReg::phys("rax#7")));
        assert!(is_exact_return_storage(&VReg::phys("x0#2")));
        assert!(!is_exact_return_storage(&VReg::phys("local_18")));
    }

    #[test]
    fn locked_aarch64_identity_materializes_the_live_in_result() {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(CallConv::Aarch64, &[Some(int32())]);
        prototype.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        let mut function = bare_return_function();

        materialize_prototype_output(&mut function, CallConv::Aarch64, Some(&prototype));

        assert_eq!(
            function.body,
            vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("x0"))),
            }]
        );
    }

    /// x86-64 returns a `float` in `xmm0` and nowhere else, so a body that
    /// writes it and no integer result register returns THAT value. GCC's `-O0`
    /// `return -value;` is exactly this shape, and it rendered `return 0;`.
    #[test]
    fn a_written_sse_result_register_is_the_output_when_no_integer_one_is() {
        let mut function = Function {
            name: "negate_binary32".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("xmm0"),
                    src: Expr::Const(1),
                },
                Stmt::Return { value: None },
            ],
        };
        materialize_direct_output(&mut function);
        assert_eq!(
            function.body.last(),
            Some(&Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("xmm0"))),
            })
        );
    }

    #[test]
    fn origin_wrapped_sse_result_materializes_into_origin_wrapped_return() {
        let mut function = Function {
            name: "negate_binary32".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("xmm0"),
                    src: Expr::Const(1),
                }
                .with_origins(crate::ir::ast::OriginSet::one(0x1000)),
                Stmt::Return { value: None }.with_origins(crate::ir::ast::OriginSet::one(0x1004)),
            ],
        };

        materialize_direct_output(&mut function);

        assert!(matches!(
            function.body[1].semantic(),
            Stmt::Return { value: Some(Expr::Reg(returned)) }
                if returned == &VReg::phys("xmm0")
        ));
    }

    /// ...and it is a FALLBACK, not a peer. `xmm0` is also the first float
    /// argument register and the ordinary float scratch, so a body that writes
    /// both returns through the integer register no matter which comes first.
    #[test]
    fn an_integer_result_register_outranks_the_sse_one_in_either_order() {
        for (first, second) in [("xmm0", "rax"), ("rax", "xmm0")] {
            let mut function = Function {
                name: "scratch_float".into(),
                entry_va: 0,
                body: vec![
                    Stmt::Assign {
                        dst: VReg::phys(first),
                        src: Expr::Const(1),
                    },
                    Stmt::Assign {
                        dst: VReg::phys(second),
                        src: Expr::Const(2),
                    },
                    Stmt::Return { value: None },
                ],
            };
            materialize_direct_output(&mut function);
            assert_eq!(
                function.body.last(),
                Some(&Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                }),
                "written in the order {first} then {second}"
            );
        }
    }

    #[test]
    fn identity_fallback_requires_locked_output_and_aliased_parameter_storage() {
        let mut function = bare_return_function();
        materialize_direct_output(&mut function);
        assert_eq!(function, bare_return_function());

        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(CallConv::SysVAmd64, &[Some(int32())]);
        prototype.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        materialize_prototype_output(&mut function, CallConv::SysVAmd64, Some(&prototype));
        assert_eq!(
            function,
            bare_return_function(),
            "SysV arg0 is rdi and cannot be invented as the rax result"
        );

        let mut aarch64 = RecoveredPrototype::default();
        aarch64.apply_locked_parameters(CallConv::Aarch64, &[Some(int32())]);
        aarch64.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        let mut written_version = Function {
            name: "written_result".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("x0#1"),
                    src: Expr::Const(42),
                },
                Stmt::Return { value: None },
            ],
        };
        materialize_prototype_output(&mut written_version, CallConv::Aarch64, Some(&aarch64));
        assert_eq!(
            written_version.body.last(),
            Some(&Stmt::Return { value: None }),
            "a versioned output write must block the live-in fallback rather than return stale arg0"
        );
    }

    #[test]
    fn prototype_output_does_not_trust_an_unowned_ret_spelling() {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(CallConv::Aarch64, &[Some(int32())]);
        prototype.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        let mut function = Function {
            name: "identity_with_ret_local".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(7),
                },
                Stmt::Return { value: None },
            ],
        };

        materialize_prototype_output(&mut function, CallConv::Aarch64, Some(&prototype));

        assert_eq!(
            function.body.last(),
            Some(&Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("x0"))),
            }),
            "a source spelling is not proof that the body overwrote ABI result storage"
        );
    }

    #[test]
    fn attributed_output_does_not_trust_an_unowned_ret_spelling() {
        let mut function = Function {
            name: "unowned_ret".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(7),
                },
                Stmt::Return { value: None },
            ],
        };

        materialize_direct_output_with_identities(
            &mut function,
            &crate::ir::value_number::ValueIdentities::default(),
        );

        assert_eq!(function.body.last(), Some(&Stmt::Return { value: None }));
    }

    #[test]
    fn attributed_output_accepts_a_pipeline_owned_ret_role() {
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            VReg::phys("rax"),
            SsaValue {
                base: VReg::phys("rax"),
                version: 1,
            },
        );
        identities =
            identities.with_role_aliases(&HashMap::from([("rax".to_string(), "ret".to_string())]));
        let mut function = Function {
            name: "owned_ret".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(7),
                },
                Stmt::Return { value: None },
            ],
        };

        materialize_direct_output_with_identities(&mut function, &identities);

        assert_eq!(
            function.body.last(),
            Some(&Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("ret"))),
            })
        );
    }

    #[test]
    fn attributed_output_uses_the_latest_reaching_result_identity() {
        let incoming = VReg::phys("rax");
        let call_result = VReg::phys("rax#2");
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            incoming.clone(),
            SsaValue {
                base: VReg::phys("rax"),
                version: 0,
            },
        );
        identities.record(
            call_result.clone(),
            SsaValue {
                base: VReg::phys("rax"),
                version: 2,
            },
        );
        let mut function = Function {
            name: "forward_double_call".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: incoming,
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Assign {
                    dst: call_result.clone(),
                    src: Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "helper".into(),
                        }),
                        args: vec![Expr::Reg(VReg::phys("arg0"))],
                        call_spec: None,
                        result_width: Some(8),
                    },
                },
                Stmt::Return { value: None },
            ],
        };

        materialize_direct_output_with_identities(&mut function, &identities);

        assert_eq!(
            function.body.last(),
            Some(&Stmt::Return {
                value: Some(Expr::Reg(call_result)),
            })
        );
    }

    #[test]
    fn unread_promoted_return_slot_is_removed() {
        let mut function = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_4")),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        prune_unread_promoted_locals(&mut function, &std::collections::HashSet::new());

        assert_eq!(
            function.body,
            vec![Stmt::Return {
                value: Some(Expr::Const(0)),
            }]
        );
    }

    #[test]
    fn unread_opaque_stack_object_is_removed_by_typed_ownership() {
        let object = "opaque_frame_object".to_string();
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.attach_promoted_stack_objects([&object]);
        let mut function = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys(&object)),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        prune_unread_promoted_locals_with_identities(
            &mut function,
            &std::collections::HashSet::new(),
            &identities,
        );

        assert_eq!(
            function.body,
            vec![Stmt::Return {
                value: Some(Expr::Const(0)),
            }]
        );
    }

    #[test]
    fn an_unowned_local_spelling_is_not_treated_as_stack_storage() {
        let original = Stmt::Store {
            addr: Expr::Reg(VReg::phys("local_4")),
            src: Expr::Const(0),
            size: 4,
        };
        let mut function = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                original.clone(),
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        prune_unread_promoted_locals_with_identities(
            &mut function,
            &std::collections::HashSet::new(),
            &crate::ir::value_number::ValueIdentities::default(),
        );

        assert_eq!(function.body.first(), Some(&original));
    }

    #[test]
    fn attributed_unread_promoted_return_slot_is_removed() {
        let mut function = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_4")),
                    src: Expr::Const(0),
                    size: 4,
                }
                .with_origins(crate::ir::ast::OriginSet::one(0x1000)),
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        prune_unread_promoted_locals(&mut function, &std::collections::HashSet::new());

        assert_eq!(
            function.body,
            vec![Stmt::Return {
                value: Some(Expr::Const(0)),
            }]
        );
    }

    #[test]
    fn attributed_void_result_save_restore_is_removed() {
        let mut function = Function {
            name: "print_message".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_8")),
                    src: Expr::Reg(VReg::phys("rax")),
                    size: 8,
                }
                .with_origins(crate::ir::ast::OriginSet::one(0x1000)),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "puts".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Reg(VReg::phys("local_8")),
                }
                .with_origins(crate::ir::ast::OriginSet::one(0x1008)),
            ],
        };

        prune_void_entry_result_restores(&mut function);

        assert_eq!(function.body.len(), 1);
        assert!(matches!(function.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn opaque_void_result_bridge_is_removed_by_typed_identities() {
        let object_name = "opaque_void_save".to_string();
        let object = VReg::phys(&object_name);
        let saved = VReg::phys("opaque_machine_value");
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.attach_promoted_stack_objects([&object_name]);
        identities.record(
            saved.clone(),
            SsaValue {
                base: VReg::phys("rax"),
                version: 3,
            },
        );
        let mut function = Function {
            name: "print_message".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(object.clone()),
                    src: Expr::Reg(saved.clone()),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "puts".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: saved,
                    src: Expr::Reg(object),
                },
            ],
        };

        prune_void_entry_result_restores_with_identities(&mut function, &identities);

        assert_eq!(function.body.len(), 1);
        assert!(matches!(function.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn unowned_local_spelling_does_not_authorize_void_bridge_cleanup() {
        let slot = VReg::phys("local_8");
        let saved = VReg::phys("opaque_machine_value");
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            saved.clone(),
            SsaValue {
                base: VReg::phys("rax"),
                version: 3,
            },
        );
        let mut function = Function {
            name: "print_message".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(slot.clone()),
                    src: Expr::Reg(saved.clone()),
                    size: 8,
                },
                Stmt::Assign {
                    dst: saved,
                    src: Expr::Reg(slot),
                },
            ],
        };

        prune_void_entry_result_restores_with_identities(&mut function, &identities);

        assert_eq!(function.body.len(), 2);
    }

    #[test]
    fn misleading_result_spelling_does_not_authorize_void_bridge_cleanup() {
        let object_name = "opaque_void_save".to_string();
        let object = VReg::phys(&object_name);
        let saved = VReg::phys("rax#3");
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.attach_promoted_stack_objects([&object_name]);
        identities.record(
            saved.clone(),
            SsaValue {
                base: VReg::phys("rdi"),
                version: 3,
            },
        );
        let mut function = Function {
            name: "print_message".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(object.clone()),
                    src: Expr::Reg(saved.clone()),
                    size: 8,
                },
                Stmt::Assign {
                    dst: saved,
                    src: Expr::Reg(object),
                },
            ],
        };

        prune_void_entry_result_restores_with_identities(&mut function, &identities);

        assert_eq!(function.body.len(), 2);
    }

    #[test]
    fn attributed_return_value_is_cleared_without_losing_its_owner() {
        let owner = crate::ir::ast::OriginSet::one(0x1004);
        let mut function = Function {
            name: "print_message".into(),
            entry_va: 0,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("rax"))),
            }
            .with_origins(owner.clone())],
        };

        clear_return_values(&mut function);

        assert_eq!(function.body[0].origins(), Some(&owner));
        assert!(matches!(
            function.body[0].semantic(),
            Stmt::Return { value: None }
        ));
    }

    #[test]
    fn proven_void_terminal_return_becomes_source_fallthrough() {
        let mut function = Function {
            name: "print_message".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "puts".into(),
                    },
                    args: vec![Expr::StringLit {
                        value: "hello".into(),
                    }],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Return { value: None },
            ],
        };

        prune_void_fallthrough_return(&mut function);

        assert_eq!(function.body.len(), 1);
        assert!(matches!(function.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn nonterminal_bare_return_keeps_its_control_effect() {
        let mut function = Function {
            name: "maybe_print".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("arg0")),
                    then_body: vec![Stmt::Return { value: None }],
                    else_body: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "puts".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        prune_void_fallthrough_return(&mut function);

        assert!(matches!(
            &function.body[0],
            Stmt::If { then_body, .. }
                if matches!(then_body.as_slice(), [Stmt::Return { value: None }])
        ));
    }

    #[test]
    fn unread_promoted_local_keeps_effectful_or_source_proven_writes() {
        let protected = VReg::phys("local_8");
        let mut function = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("local_4"),
                    src: Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x1000,
                            name: "side_effect".into(),
                        }),
                        args: Vec::new(),
                        result_width: Some(4),
                        call_spec: None,
                    },
                },
                Stmt::Assign {
                    dst: protected.clone(),
                    src: Expr::Const(0),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_unread_promoted_locals(
            &mut function,
            &std::collections::HashSet::from(["local_8".to_string()]),
        );

        assert_eq!(function.body.len(), 3);
        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Call { .. },
                ..
            }
        ));
        assert!(matches!(&function.body[1], Stmt::Assign { dst, .. } if dst == &protected));
    }
}
