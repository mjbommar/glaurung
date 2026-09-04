//! Folding a parameter's spill slot back into the parameter itself.
//!
//! At `-O0` a compiler stores each incoming argument to a frame slot and reads
//! it back from there. Lifting turns that slot into a *separate* named local,
//! so the recovered source declares an object the original function never had
//! and recompiles to stack traffic the original never emitted — extra `mov`s
//! and a shifted frame layout that diverges `byte_match`.
//!
//! Two shapes reach the same conclusion, and both are proof obligations rather
//! than heuristics:
//!
//! * a **named promoted slot** whose only register-sourced store is `local_X =
//!   argN`, where the two names are additionally proven interchangeable in both
//!   directions by [`crate::ir::structured_reaching`] — a later slot write must
//!   not reach an argument read, and an ABI-register overwrite must not reach a
//!   later reload of the slot;
//! * an **offset inside a recovered frame byte-array**, which ARM32 `-O0`
//!   produces when saved-register and local ranges overlap and no named slot
//!   exists at all. Exactly one store, sourced from an entry argument, makes
//!   the address an immutable home; any second store disqualifies it, so
//!   mutable stack state cannot be erased.
//!
//! Neither rewrite is safe for a debug-proven source local, which stays a
//! distinct C object even when its first value is copied from a parameter —
//! hence the protected-name set threaded through both entry points.
//!
//! The order inside the module matters and is load-bearing:
//! [`slot_stores_to_assigns`] must run while the slot is still *named*
//! `local_`/`stack_`, because that name is the renderer's only signal that the
//! statement is an assignment rather than a store through a pointer.

use super::{is_promoted_local, parse_arg_index, Expr, Stmt, VReg};

/// Coalesce a parameter's spill slot with the parameter. At `-O0` the compiler
/// spills each parameter to a frame slot and reads it back; our lifting turns
/// that slot into a *separate* named local and emits `local_X = argN`, so the
/// recompiled code copies the parameter into a second stack slot the original
/// never used (extra `mov`s + a shifted stack layout that diverges byte_match).
///
/// When a promoted local is the home of exactly one argument — its only
/// register-sourced store is `local_X = argN` — that local *is* the parameter:
/// rename every `local_X` to `argN` and drop the resulting self-assignment. The
/// parameter is then used directly, matching the compiler's own `-O0` codegen.
pub(super) fn coalesce_param_spills(
    body: &mut Vec<Stmt>,
    protected_locals: &std::collections::HashSet<String>,
) {
    coalesce_frame_object_param_spills(body);
    coalesce_named_param_spills(body, protected_locals);
}

/// Coalesce promoted named slots without reopening frame-object alias proofs.
pub(super) fn coalesce_named_param_spills(
    body: &mut Vec<Stmt>,
    protected_locals: &std::collections::HashSet<String>,
) {
    // local name -> the single argument it is spilled from ("" = disqualified).
    let mut home: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    collect_param_homes(body, &mut home);
    let map: std::collections::HashMap<String, String> = home
        .into_iter()
        .filter(|(_, arg)| !arg.is_empty())
        // An authoritative source local remains a distinct C object even when
        // its first value is copied from a parameter. Collapsing `child = n`
        // into the parameter is unsound when `child` is later mutated and the
        // original `n` is still read (for example heap insertion's return).
        .filter(|(slot, _)| !protected_locals.contains(slot))
        .filter(|(slot, arg)| {
            let slot = VReg::phys(slot.clone());
            let argument = VReg::phys(arg.clone());
            // Substitution is safe only while the two names remain
            // interchangeable in both directions. A later slot write must not
            // reach an argument read, and an ABI-register overwrite (for
            // example a recursive call result in arg0) must not reach a later
            // reload of the saved slot.
            !crate::ir::structured_reaching::read_may_observe_prior_write(body, &argument, &slot)
                && !crate::ir::structured_reaching::read_may_observe_prior_write(
                    body, &slot, &argument,
                )
        })
        .collect();
    if map.is_empty() {
        return;
    }
    // Convert the slot's own stores to assignments BEFORE renaming, while the name
    // still says `local_`/`stack_` — see `slot_stores_to_assigns`.
    slot_stores_to_assigns(body, &map);
    rename_phys_in_body(body, &map);
    drop_self_stores(body);
}

#[derive(Clone)]
struct FrameParamHome {
    addr: Expr,
    size: u8,
    arg: Option<String>,
    stores: usize,
}

/// Coalesce an immutable parameter home that lives at a fixed offset inside a
/// recovered frame byte-array.
///
/// ARM32 `-O0` frames are intentionally represented as one byte object when
/// saved-register and local ranges overlap. That prevents the ordinary
/// promoted-local coalescer above from seeing `frame + 4` as a named slot. A
/// pointer parameter then round-trips through a four-byte C integer in that
/// byte array and is truncated when the recovered source is executed on LP64.
/// An address with exactly one store, sourced from an entry argument, is an
/// immutable home: replace exact same-width reloads by the argument and remove
/// the redundant store. Any second store disqualifies the address, including a
/// source-level reassignment, so this cannot erase mutable stack state.
fn coalesce_frame_object_param_spills(body: &mut Vec<Stmt>) {
    let mut homes = Vec::new();
    collect_frame_param_homes(body, &mut homes);
    homes.retain(|home| {
        home.stores == 1 && home.arg.is_some() && body_reads_exact_frame_home(body, home)
    });
    if homes.is_empty() {
        return;
    }
    rewrite_frame_param_homes(body, &homes);
}

fn expr_reads_exact_frame_home(expr: &Expr, home: &FrameParamHome) -> bool {
    if matches!(expr, Expr::Deref { addr, size } if *size == home.size && **addr == home.addr) {
        return true;
    }
    match expr {
        Expr::Deref { addr, .. } => expr_reads_exact_frame_home(addr, home),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads_exact_frame_home(lhs, home) || expr_reads_exact_frame_home(rhs, home)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            expr_reads_exact_frame_home(src, home)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expr_reads_exact_frame_home(cond, home)
                || expr_reads_exact_frame_home(if_true, home)
                || expr_reads_exact_frame_home(if_false, home)
        }
        Expr::FunctionTableEntry { index, .. } => expr_reads_exact_frame_home(index, home),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|arg| expr_reads_exact_frame_home(arg, home)),
        _ => false,
    }
}

fn body_reads_exact_frame_home(body: &[Stmt], home: &FrameParamHome) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Assign { src, .. } => expr_reads_exact_frame_home(src, home),
        Stmt::Store { addr, src, .. } => {
            expr_reads_exact_frame_home(addr, home) || expr_reads_exact_frame_home(src, home)
        }
        Stmt::Call { target, args, .. } => {
            expr_reads_exact_frame_home(target, home)
                || args
                    .iter()
                    .any(|arg| expr_reads_exact_frame_home(arg, home))
        }
        Stmt::Return { value: Some(value) } => expr_reads_exact_frame_home(value, home),
        Stmt::Push { value } | Stmt::Throw { value } => expr_reads_exact_frame_home(value, home),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_reads_exact_frame_home(cond, home)
                || body_reads_exact_frame_home(then_body, home)
                || else_body
                    .as_deref()
                    .is_some_and(|body| body_reads_exact_frame_home(body, home))
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            expr_reads_exact_frame_home(cond, home) || body_reads_exact_frame_home(body, home)
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            body_reads_exact_frame_home(std::slice::from_ref(init.as_ref()), home)
                || expr_reads_exact_frame_home(cond, home)
                || body_reads_exact_frame_home(body, home)
                || body_reads_exact_frame_home(std::slice::from_ref(step.as_ref()), home)
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            expr_reads_exact_frame_home(discriminant, home)
                || cases
                    .iter()
                    .any(|(_, body)| body_reads_exact_frame_home(body, home))
                || default
                    .as_deref()
                    .is_some_and(|body| body_reads_exact_frame_home(body, home))
        }
        Stmt::IndirectGoto { target } => expr_reads_exact_frame_home(target, home),
        Stmt::TryCatch { try_body, catches } => {
            body_reads_exact_frame_home(try_body, home)
                || catches
                    .iter()
                    .any(|catch| body_reads_exact_frame_home(&catch.body, home))
        }
        _ => false,
    })
}

fn expression_contains_stack_object(expr: &Expr) -> bool {
    match expr {
        Expr::StackAddr { .. } => true,
        Expr::Deref { addr, .. } => expression_contains_stack_object(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expression_contains_stack_object(lhs) || expression_contains_stack_object(rhs)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            expression_contains_stack_object(src)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expression_contains_stack_object(cond)
                || expression_contains_stack_object(if_true)
                || expression_contains_stack_object(if_false)
        }
        Expr::FunctionTableEntry { index, .. } => expression_contains_stack_object(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(expression_contains_stack_object),
        _ => false,
    }
}

fn parameter_source(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reg(VReg::Phys(name)) if parse_arg_index(name).is_some() => Some(name.clone()),
        Expr::Cast { expr, .. } => parameter_source(expr),
        _ => None,
    }
}

fn record_frame_store(addr: &Expr, size: u8, src: &Expr, homes: &mut Vec<FrameParamHome>) {
    if !expression_contains_stack_object(addr) {
        return;
    }
    if let Some(home) = homes.iter_mut().find(|home| home.addr == *addr) {
        home.stores += 1;
        if home.size != size || home.arg.as_deref() != parameter_source(src).as_deref() {
            home.arg = None;
        }
        return;
    }
    homes.push(FrameParamHome {
        addr: addr.clone(),
        size,
        arg: parameter_source(src),
        stores: 1,
    });
}

fn collect_frame_param_homes(body: &[Stmt], homes: &mut Vec<FrameParamHome>) {
    for statement in body {
        match statement {
            Stmt::Store { addr, src, size } => record_frame_store(addr, *size, src, homes),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_frame_param_homes(then_body, homes);
                if let Some(else_body) = else_body {
                    collect_frame_param_homes(else_body, homes);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_frame_param_homes(body, homes)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_frame_param_homes(std::slice::from_ref(init.as_ref()), homes);
                collect_frame_param_homes(body, homes);
                collect_frame_param_homes(std::slice::from_ref(step.as_ref()), homes);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_frame_param_homes(case, homes);
                }
                if let Some(default) = default {
                    collect_frame_param_homes(default, homes);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_frame_param_homes(try_body, homes);
                for catch in catches {
                    collect_frame_param_homes(&catch.body, homes);
                }
            }
            _ => {}
        }
    }
}

fn rewrite_frame_home_expr(expr: &mut Expr, homes: &[FrameParamHome]) {
    if let Expr::Deref { addr, size } = expr {
        if let Some(arg) = homes.iter().find_map(|home| {
            (home.size == *size && home.addr == **addr)
                .then(|| home.arg.clone())
                .flatten()
        }) {
            *expr = Expr::Reg(VReg::phys(arg));
            return;
        }
    }
    match expr {
        Expr::Deref { addr, .. } => rewrite_frame_home_expr(addr, homes),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_frame_home_expr(lhs, homes);
            rewrite_frame_home_expr(rhs, homes);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => rewrite_frame_home_expr(src, homes),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_frame_home_expr(cond, homes);
            rewrite_frame_home_expr(if_true, homes);
            rewrite_frame_home_expr(if_false, homes);
        }
        Expr::FunctionTableEntry { index, .. } => rewrite_frame_home_expr(index, homes),
        Expr::WideArithmetic { args, .. } => {
            for arg in args {
                rewrite_frame_home_expr(arg, homes);
            }
        }
        _ => {}
    }
}

fn rewrite_frame_param_homes(body: &mut Vec<Stmt>, homes: &[FrameParamHome]) {
    body.retain(|statement| {
        !matches!(statement,
            Stmt::Store { addr, size, .. }
                if homes.iter().any(|home| home.size == *size && home.addr == *addr))
    });
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } => rewrite_frame_home_expr(src, homes),
            Stmt::Store { addr, src, .. } => {
                rewrite_frame_home_expr(addr, homes);
                rewrite_frame_home_expr(src, homes);
            }
            Stmt::Call { target, args, .. } => {
                rewrite_frame_home_expr(target, homes);
                for arg in args {
                    rewrite_frame_home_expr(arg, homes);
                }
            }
            Stmt::Return { value: Some(value) } => rewrite_frame_home_expr(value, homes),
            Stmt::Push { value } | Stmt::Throw { value } => rewrite_frame_home_expr(value, homes),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_frame_home_expr(cond, homes);
                rewrite_frame_param_homes(then_body, homes);
                if let Some(else_body) = else_body {
                    rewrite_frame_param_homes(else_body, homes);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                rewrite_frame_home_expr(cond, homes);
                rewrite_frame_param_homes(body, homes);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                let mut init_body = vec![(**init).clone()];
                rewrite_frame_param_homes(&mut init_body, homes);
                **init = init_body.pop().unwrap_or(Stmt::Nop);
                rewrite_frame_home_expr(cond, homes);
                rewrite_frame_param_homes(body, homes);
                let mut step_body = vec![(**step).clone()];
                rewrite_frame_param_homes(&mut step_body, homes);
                **step = step_body.pop().unwrap_or(Stmt::Nop);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_frame_home_expr(discriminant, homes);
                for (_, case) in cases {
                    rewrite_frame_param_homes(case, homes);
                }
                if let Some(default) = default {
                    rewrite_frame_param_homes(default, homes);
                }
            }
            Stmt::IndirectGoto { target } => rewrite_frame_home_expr(target, homes),
            Stmt::TryCatch { try_body, catches } => {
                rewrite_frame_param_homes(try_body, homes);
                for catch in catches {
                    rewrite_frame_param_homes(&mut catch.body, homes);
                }
            }
            _ => {}
        }
    }
}

/// Rewrite `Store { addr: Reg(slot), src }` as `Assign { dst: slot, src }` for every
/// slot about to be renamed to its parameter.
///
/// The renderer can only recognise a slot assignment by its `local_`/`stack_` NAME
/// (`write_stmt_dec`'s `is_promoted_local` arm). Once coalescing renames the slot to
/// `argN`, that test fails and the same statement prints as a store *through* the
/// parameter — a write through a value that is not a pointer. That is how `rotr32`
/// segfaulted: `n &= 31u` on a spilled parameter is an `-O0` in-place memory update,
/// and it rendered as `*(int *)(arg1) = (arg1 & 31)`.
///
/// Doing this before the rename is what makes it unambiguous: afterwards,
/// `Store { addr: Reg(arg0) }` could equally be a genuine `*arg0 = v` through a
/// pointer parameter, and converting that would silently turn a memory write into a
/// local assignment. The pre-rename name cannot be confused that way.
fn slot_stores_to_assigns(body: &mut Vec<Stmt>, slots: &std::collections::HashMap<String, String>) {
    for s in body.iter_mut() {
        match s {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                src,
                ..
            } if slots.contains_key(name) => {
                if slots
                    .get(name)
                    .is_some_and(|argument| parameter_source(src).as_ref() == Some(argument))
                {
                    // The defining spill is redundant even when the machine
                    // width made it `local = (uint32_t)arg0`.  Retaining that
                    // cast as `arg0 = (uint32_t)arg0` truncates a pointer when a
                    // foreign-width host recompiles the recovered C.
                    *s = Stmt::Nop;
                } else {
                    *s = Stmt::Assign {
                        dst: VReg::phys(name.clone()),
                        src: src.clone(),
                    };
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                slot_stores_to_assigns(then_body, slots);
                if let Some(eb) = else_body {
                    slot_stores_to_assigns(eb, slots);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                slot_stores_to_assigns(body, slots)
            }
            Stmt::For { body, .. } => slot_stores_to_assigns(body, slots),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    slot_stores_to_assigns(b, slots);
                }
                if let Some(b) = default {
                    slot_stores_to_assigns(b, slots);
                }
            }
            _ => {}
        }
    }
}

/// Populate `home[local] = arg` for promoted parameter-home candidates.
///
/// The first store must carry an incoming parameter identity. Repeated stores
/// from a different parameter disqualify it; ordinary in-place updates remain
/// candidates because the symmetric reaching-definitions check at the caller
/// can prove whether the original argument and slot are still interchangeable.
fn collect_param_homes(body: &[Stmt], home: &mut std::collections::HashMap<String, String>) {
    collect_param_homes_with_aliases(body, home, &mut std::collections::HashMap::new());
}

fn parameter_alias(
    expr: &Expr,
    aliases: &std::collections::HashMap<VReg, String>,
) -> Option<String> {
    match expr {
        Expr::Reg(register) => aliases
            .get(register)
            .cloned()
            .or_else(|| parameter_source(expr)),
        Expr::Cast { expr, .. } => parameter_alias(expr, aliases),
        _ => None,
    }
}

/// Find parameter homes without rewriting the scratch chain that carries the
/// incoming value to the spill.  In particular, i386 commonly spells it
/// ``eax = arg0; local = (uint32_t)eax``.  Running the general copy propagator
/// first would also rewrite a later ``Store { addr: eax }`` to
/// ``Store { addr: local }``, erasing the distinction between the home address
/// and the pointer value loaded from it.  This tiny straight-line provenance
/// map proves only parameter identity and leaves every address untouched.
fn collect_param_homes_with_aliases(
    body: &[Stmt],
    home: &mut std::collections::HashMap<String, String>,
    aliases: &mut std::collections::HashMap<VReg, String>,
) {
    for s in body {
        match s {
            Stmt::Assign { dst, src } => {
                if let Some(argument) = parameter_alias(src, aliases) {
                    aliases.insert(dst.clone(), argument);
                } else {
                    aliases.remove(dst);
                }
            }
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(local)),
                src,
                ..
            } if is_promoted_local(local) => {
                let argument = parameter_alias(src, aliases);
                let entry = home.entry(local.clone());
                match entry {
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(argument.unwrap_or_default());
                    }
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        // Only a direct repeated store from the same source
                        // parameter remains a home initialization. Alias state
                        // is intentionally insufficient here: a branch-local
                        // status temporary can share one incoming provenance on
                        // another path, yet its store reuses the stack bytes for
                        // a different source object.
                        let same_parameter = parameter_source(src)
                            .as_ref()
                            .is_some_and(|candidate| candidate == o.get());
                        let in_place_update = src.contains_reg(&VReg::phys(local.clone()));
                        if !same_parameter && !in_place_update {
                            o.insert(String::new());
                        }
                    }
                }
                aliases.remove(&VReg::phys(local.clone()));
            }
            // Recurse into nested bodies. Any store seen on any path contributes
            // to the shared, fail-closed home decision.
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_param_homes_with_aliases(then_body, home, &mut aliases.clone());
                if let Some(eb) = else_body {
                    collect_param_homes_with_aliases(eb, home, &mut aliases.clone());
                }
                aliases.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_param_homes_with_aliases(body, home, &mut aliases.clone());
                aliases.clear();
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_param_homes_with_aliases(
                    std::slice::from_ref(init.as_ref()),
                    home,
                    &mut aliases.clone(),
                );
                collect_param_homes_with_aliases(body, home, &mut aliases.clone());
                collect_param_homes_with_aliases(
                    std::slice::from_ref(step.as_ref()),
                    home,
                    &mut aliases.clone(),
                );
                aliases.clear();
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    collect_param_homes_with_aliases(b, home, &mut aliases.clone());
                }
                if let Some(b) = default {
                    collect_param_homes_with_aliases(b, home, &mut aliases.clone());
                }
                aliases.clear();
            }
            Stmt::Call { .. } | Stmt::Label(_) | Stmt::Goto { .. } => aliases.clear(),
            _ => {}
        }
    }
}

/// Rename physical-register names per `map` throughout `body` (all positions).
fn rename_phys_in_body(body: &mut [Stmt], map: &std::collections::HashMap<String, String>) {
    fn rn(v: &mut VReg, map: &std::collections::HashMap<String, String>) {
        if let VReg::Phys(n) = v {
            if let Some(nn) = map.get(n) {
                *n = nn.clone();
            }
        }
    }
    fn re(e: &mut Expr, map: &std::collections::HashMap<String, String>) {
        match e {
            Expr::Reg(v) => rn(v, map),
            Expr::StackAddr { object, .. } => rn(object, map),
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                if let Some(v) = base {
                    rn(v, map);
                }
                if let Some(v) = index {
                    rn(v, map);
                }
            }
            Expr::Deref { addr, .. } => re(addr, map),
            Expr::Call { target, args, .. } => {
                re(target, map);
                for argument in args {
                    re(argument, map);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                re(lhs, map);
                re(rhs, map);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                re(cond, map);
                re(if_true, map);
                re(if_false, map);
            }
            Expr::Un { src, .. } => re(src, map),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => re(expr, map),
            Expr::FunctionTableEntry { index, .. } => re(index, map),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    re(argument, map);
                }
            }
            Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
        }
    }
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                rn(dst, map);
                re(src, map);
            }
            Stmt::Store { addr, src, .. } => {
                re(addr, map);
                re(src, map);
            }
            Stmt::Call { target, args, .. } => {
                re(target, map);
                for a in args.iter_mut() {
                    re(a, map);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    re(e, map);
                }
            }
            Stmt::Push { value } => re(value, map),
            Stmt::Pop { target } => rn(target, map),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                re(cond, map);
                rename_phys_in_body(then_body, map);
                if let Some(eb) = else_body {
                    rename_phys_in_body(eb, map);
                }
            }
            Stmt::While { cond, body } => {
                re(cond, map);
                rename_phys_in_body(body, map);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rename_phys_in_body(std::slice::from_mut(init.as_mut()), map);
                re(cond, map);
                rename_phys_in_body(body, map);
                rename_phys_in_body(std::slice::from_mut(step.as_mut()), map);
            }
            Stmt::DoWhile { body, cond } => {
                rename_phys_in_body(body, map);
                re(cond, map);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                re(discriminant, map);
                for (_, b) in cases.iter_mut() {
                    rename_phys_in_body(b, map);
                }
                if let Some(b) = default {
                    rename_phys_in_body(b, map);
                }
            }
            Stmt::IndirectGoto { target } => re(target, map),
            Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
            Stmt::Throw { value } => re(value, map),
            Stmt::TryCatch { try_body, catches } => {
                rename_phys_in_body(try_body, map);
                for catch in catches {
                    rn(&mut catch.binding, map);
                    rename_phys_in_body(&mut catch.body, map);
                }
            }
        }
    }
}

/// Drop `Store { addr: Reg(x), src: Reg(x) }` self-assignments (recursively) —
/// what a coalesced spill `local = arg` collapses to once `local` became `arg`.
pub(super) fn drop_self_stores(body: &mut Vec<Stmt>) {
    body.retain(|s| {
        !matches!(
            s,
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(a)),
                src: Expr::Reg(VReg::Phys(b)),
                ..
            } if a == b
        ) && !matches!(
            // Same collapse, in assignment form: the spill store is now an Assign
            // (see `slot_stores_to_assigns`), so `arg0 = arg0` must go too.
            s,
            Stmt::Assign {
                dst: VReg::Phys(a),
                src: Expr::Reg(VReg::Phys(b)),
            } if a == b
        )
    });
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                drop_self_stores(then_body);
                if let Some(eb) = else_body {
                    drop_self_stores(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => drop_self_stores(body),
            Stmt::For { body, .. } => drop_self_stores(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    drop_self_stores(b);
                }
                if let Some(b) = default {
                    drop_self_stores(b);
                }
            }
            _ => {}
        }
    }
}
