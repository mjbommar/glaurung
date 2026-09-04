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
    materialize_direct_output_with_live_in(function, None);
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
    materialize_direct_output_with_live_in(function, live_in_result);
}

fn body_writes_abi_return_storage(body: &[Stmt], cc: CallConv) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Assign {
            dst: VReg::Phys(name),
            ..
        }
        | Stmt::Call {
            dst: Some(VReg::Phys(name)),
            ..
        } => crate::ir::abi::is_return_register(cc, name) || name == "ret",
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

fn materialize_direct_output_with_live_in(function: &mut Function, live_in_result: Option<&VReg>) {
    let written = find_written_return_reg(&function.body)
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
    if matches!(function.body.last(), Some(Stmt::Return { value: None })) {
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
    fn pure(expression: &Expr) -> bool {
        match expression {
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
            match statement {
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
            !matches!(statement, Stmt::Assign { dst, src } if unread.contains(dst) && pure(src))
                && !matches!(statement, Stmt::Store { addr: Expr::Reg(dst), src, .. }
                    if unread.contains(dst) && pure(src))
        });
        removed + before - body.len()
    }

    fn observes(statement: &Stmt, target: &VReg) -> bool {
        match statement {
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
                fn collect(statement: &Stmt, out: &mut Vec<VReg>) {
                    match statement {
                        Stmt::Assign {
                            dst: VReg::Phys(name),
                            ..
                        } if name.starts_with("local_") => out.push(VReg::phys(name)),
                        Stmt::Store {
                            addr: Expr::Reg(VReg::Phys(name)),
                            ..
                        } if name.starts_with("local_") => out.push(VReg::phys(name)),
                        Stmt::If {
                            then_body,
                            else_body,
                            ..
                        } => {
                            then_body.iter().for_each(|statement| collect(statement, out));
                            if let Some(else_body) = else_body {
                                else_body.iter().for_each(|statement| collect(statement, out));
                            }
                        }
                        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                            body.iter().for_each(|statement| collect(statement, out));
                        }
                        Stmt::For { init, step, body, .. } => {
                            collect(init, out);
                            body.iter().for_each(|statement| collect(statement, out));
                            collect(step, out);
                        }
                        Stmt::Switch { cases, default, .. } => {
                            for (_, body) in cases {
                                body.iter().for_each(|statement| collect(statement, out));
                            }
                            if let Some(default) = default {
                                default.iter().for_each(|statement| collect(statement, out));
                            }
                        }
                        Stmt::TryCatch { try_body, catches } => {
                            try_body.iter().for_each(|statement| collect(statement, out));
                            for catch in catches {
                                catch.body.iter().for_each(|statement| collect(statement, out));
                            }
                        }
                        _ => {}
                    }
                }
                let mut found = Vec::new();
                collect(statement, &mut found);
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
    fn reads(expr: &Expr, target: &VReg) -> bool {
        match expr {
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
        match statement {
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

    fn prune(body: &mut Vec<Stmt>) {
        for statement in body.iter_mut() {
            match statement {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    prune(then_body);
                    if let Some(else_body) = else_body {
                        prune(else_body);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => prune(body),
                Stmt::For { body, .. } => prune(body),
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        prune(case);
                    }
                    if let Some(default) = default {
                        prune(default);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    prune(try_body);
                    for catch in catches {
                        prune(&mut catch.body);
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
            } = statement
            else {
                continue;
            };
            let promoted = matches!(slot, VReg::Phys(name)
                if name.starts_with("local_") || name.starts_with("stack_"));
            if !promoted || !is_exact_return_storage(saved) {
                continue;
            }
            let restores = body
                .iter()
                .enumerate()
                .filter(|(index, candidate)| {
                    *index > store_index
                        && matches!(candidate, Stmt::Assign { dst, src: Expr::Reg(source) }
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

    prune(&mut function.body);
}

fn clear_body_return_values(body: &mut [Stmt]) {
    for statement in body {
        match statement {
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

/// The first-tier result register the body writes, in body order.
///
/// `ret` — the canonical role name `apply_role_names` leaves behind — is one of
/// the first-tier names, so [`is_return_reg`] already covers it. It was also
/// restated as a second disjunct on both arms below until 2026-08-18, which was
/// dead in a way that read as load-bearing.
fn find_written_return_reg(body: &[Stmt]) -> Option<VReg> {
    for statement in body {
        let found = match statement {
            Stmt::Assign { dst, .. } if is_return_reg(dst) => Some(dst.clone()),
            Stmt::Call { dst: Some(dst), .. } if is_return_reg(dst) => Some(dst.clone()),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => find_written_return_reg(then_body)
                .or_else(|| else_body.as_deref().and_then(find_written_return_reg)),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => find_written_return_reg(body),
            Stmt::For { body, .. } => find_written_return_reg(body),
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .find_map(|(_, body)| find_written_return_reg(body))
                .or_else(|| default.as_deref().and_then(find_written_return_reg)),
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
        match statement {
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
        let found = match statement {
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
    use crate::ir::types_recover::TypeHint;

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
