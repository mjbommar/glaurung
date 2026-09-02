//! Fold the argument setup preceding one call into that call.
//!
//! This is the register-ABI half of the pass and the dispatcher for every other
//! half: 32-bit cdecl, the ARM hard-float window, the catalog core-register
//! arity and the proven function-pointer-table layout are all entered from here
//! and return immediately. What remains is the backward scan itself -- walk the
//! statements preceding a `Stmt::Call`, capture what each argument slot holds,
//! and stop at the first thing that would make a capture unsound: an
//! intervening read of the slot, a clobber, a call barrier, a join.
//!
//! Two rules shape what the scan does with what it found. ABI arguments are a
//! contiguous prefix, so the recovered list is trimmed at the first gap; and a
//! slot this body never wrote may still be filled from what the enclosing scope
//! proved about it (`super::EnclosingSlots`), which is how a call inside a
//! branch arm can still name the function's own incoming parameter.
//!
//! Integer arguments past the register prefix are admitted only against an
//! exact post-call cleanup that balances the complete outgoing allocation. That
//! balance is what separates outgoing arguments from callee-save pushes and
//! local frame storage.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::{
    aapcs_core_register_arity, aapcs_integer_stack_suffix, arg_slots, direct_call_target_va,
    fold_one_arm_hard_float_call, fold_one_cdecl32_call, fold_one_recovered_layout_call,
    fold_one_table_call, incoming_arg_expr, is_frame_coordinate_storage, is_pure_arg_normalisation,
    is_stable_frame_arg_definition, known_arm_core_register_arity, known_arm_hard_float_layout,
    layout_matches_abi_allocation_order, mark_arg_reads_in_expr, mark_arg_reads_in_stmt,
    mark_arg_writes_in_stmt, outgoing_aapcs_stack_area, outgoing_stack_cleanup,
    outgoing_sysv_stack_area, outgoing_sysv_stack_push, reads_reg_in_expr,
    resolve_captured_definition, resolve_captured_definition_in, return_reg, return_value_is_read,
    slot_of, ssa_base, stack_pointer_sub_width, substitute_exact_reg, table_call_may_use_layout,
    versioned_operand_is_reassigned, CallConv, CalleeLayouts, EnclosingSlots, KEEP_ARG_SETUP,
};

pub(super) fn fold_one_call(
    body: &mut Vec<Stmt>,
    call_idx: usize,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: CalleeLayouts<'_>,
    enclosing: &EnclosingSlots,
    string_pool: &std::collections::HashMap<u64, String>,
) {
    let incoming_overrides = enclosing.overrides.as_slice();
    let format_proven_arity = format_proven_arity(body, call_idx, arch, string_pool);
    if arch == CallConv::Cdecl32 {
        fold_one_cdecl32_call(body, call_idx);
        return;
    }
    // Before any register-liveness recovery: a call through a proven
    // function-pointer table has a complete callee set, so its ABI may-use
    // registers are known even though its target is not. Recovering them here
    // means the setup is READ, and therefore survives every later dead-store
    // and dead-copy pass on its own — rather than being reintroduced afterwards
    // as register names that no longer denote the values they held.
    if let Some(layout) =
        table_call_may_use_layout(&body[call_idx], arch, callee_layouts.table_entry)
    {
        if fold_one_table_call(body, call_idx, arch, &layout, param_slots, enclosing) {
            return;
        }
    }
    let known_arm_hard_float_layout = (arch == CallConv::ArmHardFloat)
        .then(|| known_arm_hard_float_layout(&body[call_idx]))
        .flatten();
    let known_arm_core_arity = match arch {
        CallConv::Arm => known_arm_core_register_arity(&body[call_idx]),
        CallConv::ArmHardFloat => known_arm_hard_float_layout
            .as_deref()
            .and_then(aapcs_core_register_arity),
        _ => None,
    };
    if known_arm_core_arity == Some(0) {
        return;
    }
    let recovered_layout = direct_call_target_va(&body[call_idx])
        .and_then(|target| callee_layouts.direct.get(&target))
        .filter(|layout| layout_matches_abi_allocation_order(arch, layout));
    let aapcs_stack = matches!(arch, CallConv::Arm | CallConv::ArmHardFloat)
        .then(|| {
            recovered_layout
                .and_then(|layout| aapcs_integer_stack_suffix(layout))
                .and_then(|count| outgoing_aapcs_stack_area(body, call_idx, count))
        })
        .flatten();
    if let Some(layout) = recovered_layout.filter(|_| aapcs_stack.is_none()) {
        if fold_one_recovered_layout_call(body, call_idx, layout) {
            return;
        }
        // An optimized call may pass the values already occupying ABI storage,
        // leaving no adjacent setup assignments to fold. The callee layout
        // proves which storage is read, but it does not prove the reaching
        // value: require a source parameter slot, preserve a structured-loop
        // incoming override when one exists, and reject the whole fallback
        // after any intervening write or call.
        let mut blocked_live_ins = vec![false; arg_slots(arch).len()];
        for statement in &body[..call_idx] {
            mark_arg_writes_in_stmt(statement, arch, &mut blocked_live_ins);
        }
        let reaching_inputs = layout
            .iter()
            .map(|storage| {
                let VReg::Phys(name) = storage else {
                    return None;
                };
                let slot = crate::ir::abi::argument_slot_of(arch, name)?;
                (param_slots.contains(&slot)
                    && !blocked_live_ins[slot]
                    && enclosing.entry_value_reaches(slot))
                .then(|| {
                    incoming_overrides
                        .get(slot)
                        .and_then(Clone::clone)
                        .unwrap_or_else(|| Expr::Reg(storage.clone()))
                })
            })
            .collect::<Option<Vec<_>>>();
        if let Some(arguments) = reaching_inputs {
            if let Stmt::Call { args, .. } = &mut body[call_idx] {
                *args = arguments;
            }
            return;
        }
        // A locked callee layout says which architectural storage the callee
        // reads even when optimization left no adjacent setup assignment (an
        // incoming argument reused directly, or an epilogue between setup and
        // a tail call). Keep the current register values explicit instead of
        // degrading the proven fixed-arity call to `callee(void)`.
        if matches!(arch, CallConv::Arm | CallConv::ArmHardFloat) {
            if let Stmt::Call { args, .. } = &mut body[call_idx] {
                if args.is_empty() {
                    *args = layout.iter().cloned().map(Expr::Reg).collect();
                }
            }
            return;
        }
    }
    if arch == CallConv::ArmHardFloat {
        if let Some(layout) = known_arm_hard_float_layout
            .as_ref()
            .filter(|_| known_arm_core_arity.is_none())
        {
            if !layout.is_empty() {
                let _ = fold_one_recovered_layout_call(body, call_idx, layout);
            }
            // A locked fixed-arity declaration is stronger than a scratch
            // register prefix even when the setup was not locally foldable.
            return;
        }
        if fold_one_arm_hard_float_call(body, call_idx) {
            return;
        }
    }
    // Map slot → (stmt_index, expression) for assignments we will eat.
    let mut found: Vec<Option<(usize, Expr)>> = vec![None; arg_slots(arch).len()];
    let mut read_between: Vec<bool> = vec![false; arg_slots(arch).len()];
    let mut blocked_incoming: Vec<bool> = vec![false; arg_slots(arch).len()];
    let preallocated_stack = (arch == CallConv::SysVAmd64)
        .then(|| outgoing_sysv_stack_area(body, call_idx))
        .flatten();
    let proven_aapcs_stack = aapcs_stack.is_some();
    let (mut stack_args, mut stack_setup_indices) = aapcs_stack
        .clone()
        .or_else(|| preallocated_stack.clone())
        .unwrap_or_else(|| (Vec::new(), Vec::new()));
    let mut stack_arg_bytes =
        i64::try_from(stack_args.len()).unwrap_or(0) * if proven_aapcs_stack { 4 } else { 8 };
    let mut stack_padding = None;
    let stack_setup_set: std::collections::HashSet<usize> =
        stack_setup_indices.iter().copied().collect();
    // An argument that reaches an impure definition must remain rooted at that
    // statement. Continue scanning for other slots, but never bind its same
    // unversioned register use to an older definition beyond this root.
    let mut opaque_reaching_defs = std::collections::HashSet::new();

    // Walk backwards from the call.
    let mut i = call_idx;
    while i > 0 {
        i -= 1;
        // These exact stores have already been captured as outgoing stack
        // arguments. Treating them as arbitrary statements marks their r2/r3
        // sources as intervening reads and prevents the same scan from finding
        // the final core-register prefix.
        if stack_setup_set.contains(&i) {
            continue;
        }
        // A label is a potential multi-predecessor join, and an explicit
        // transfer has no fall-through into the call.  Consuming assignments
        // across either boundary steals state from an unrelated predecessor
        // (notably the stack-pop edge immediately before a labelled canary
        // failure block). Reaching definitions across CFG edges require dataflow
        // proof; this local backward fold deliberately stops here.
        if matches!(
            &body[i],
            Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::IndirectGoto { .. }
                | Stmt::Return { .. }
                | Stmt::Break
        ) {
            // The local scan cannot prove what reaches the call across this
            // control-flow boundary. In particular, do not interpret an
            // unwritten leading ABI slot as the function-entry value — unless
            // the whole function proves the slot never stops being that value
            // on ANY path. See `entry_constant_slots`.
            for (slot, blocked) in blocked_incoming.iter_mut().enumerate() {
                *blocked = *blocked || !enclosing.is_entry_constant(slot);
            }
            break;
        }
        if arch == CallConv::SysVAmd64 && preallocated_stack.is_none() {
            if let Some((value, width)) = outgoing_sysv_stack_push(body, i) {
                stack_args.push(value.clone());
                stack_arg_bytes += width;
                stack_setup_indices.extend([i, i - 1]);
                mark_arg_reads_in_expr(value, arch, &mut read_between);
                i -= 1;
                continue;
            }
            // An odd number of eight-byte stack arguments needs one alignment
            // word. It is call setup only when the matching post-call cleanup
            // proves the complete outgoing allocation; otherwise leave it and
            // every candidate push untouched.
            if !stack_args.is_empty()
                && stack_padding.is_none()
                && stack_pointer_sub_width(&body[i]) == Some(8)
            {
                stack_padding = Some(i);
                continue;
            }
            // Never scan from a call setup into the function's own frame-save
            // sequence. Without this boundary a first call with six register
            // arguments could mistake `push rbp` for a seventh argument.
            if matches!(
                &body[i],
                Stmt::Assign {
                    dst: VReg::Phys(frame),
                    src: Expr::Reg(VReg::Phys(stack)),
                } if matches!(ssa_base(frame), "ebp" | "rbp")
                    && matches!(ssa_base(stack), "esp" | "rsp")
            ) {
                break;
            }
        }
        let stop = matches!(&body[i], Stmt::Call { .. });
        if let Stmt::Assign { dst, src } = &body[i] {
            if let VReg::Phys(name) = dst {
                if let Some(slot) = slot_of(arch, name.as_str()) {
                    if known_arm_core_arity.is_some_and(|arity| slot >= arity) {
                        // The fixed declaration proves this is caller-local
                        // scratch state, not an additional call argument.
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                    if found[slot].is_none() {
                        // Before claiming this slot, make sure no already-
                        // captured arg expression reads this register. If
                        // one does, folding this assignment would leave a
                        // dangling reference in the higher slot's expr.
                        let substitutable = (is_pure_arg_normalisation(src)
                            || is_stable_frame_arg_definition(src, body, i, call_idx))
                            && !versioned_operand_is_reassigned(src, body, i, call_idx);
                        let feeds_captured_register_argument = found
                            .iter()
                            .any(|f| f.as_ref().is_some_and(|(_, e)| reads_reg_in_expr(e, dst)));
                        let feeds_balanced_stack_argument = stack_args
                            .iter()
                            .any(|argument| reads_reg_in_expr(argument, dst))
                            && substitutable
                            && (proven_aapcs_stack
                                || outgoing_stack_cleanup(
                                    body,
                                    call_idx,
                                    stack_arg_bytes + stack_padding.map_or(0, |_| 8),
                                )
                                .is_some());
                        // Preserve the existing statement-rooted dependency
                        // policy unless the same definition also feeds stack
                        // setup that is proven removable. In that one case all
                        // dependent call arguments must move together.
                        if feeds_captured_register_argument && feeds_balanced_stack_argument {
                            for (_, argument) in found.iter_mut().flatten() {
                                let _ = substitute_exact_reg(argument, dst, src);
                            }
                        }
                        let would_dangle =
                            feeds_captured_register_argument && !feeds_balanced_stack_argument;
                        let later_slot_proves_contiguous_prefix =
                            found.iter().skip(slot + 1).any(Option::is_some);
                        if read_between[slot]
                            && (proven_aapcs_stack
                                || (arch == CallConv::Aarch64
                                    && later_slot_proves_contiguous_prefix)
                                || format_proven_arity.is_some_and(|arity| slot < arity))
                        {
                            // A locked stack layout or an already recovered
                            // higher register slot proves this slot is a call
                            // input: ABI argument registers form a contiguous
                            // prefix. An intervening read means its definition
                            // cannot be deleted, so keep the statement rooted
                            // and pass the exact reaching SSA value. Abandoning
                            // it loses x1 when x3/x5/x7 are derived from x1, or
                            // lets an older shadowed r2/r3 definition masquerade
                            // as the call argument.
                            found[slot] = Some((KEEP_ARG_SETUP, Expr::Reg(dst.clone())));
                            mark_arg_reads_in_expr(src, arch, &mut read_between);
                            continue;
                        }
                        if !would_dangle && (!read_between[slot] || feeds_balanced_stack_argument) {
                            // Keep the setup where it stands when moving it to
                            // the call would read a value written after it; the
                            // call then names the argument register instead.
                            found[slot] = if versioned_operand_is_reassigned(src, body, i, call_idx)
                            {
                                Some((KEEP_ARG_SETUP, Expr::Reg(dst.clone())))
                            } else {
                                Some((i, src.clone()))
                            };
                            if feeds_balanced_stack_argument {
                                for argument in &mut stack_args {
                                    let _ = substitute_exact_reg(argument, dst, src);
                                }
                            }
                        } else {
                            blocked_incoming[slot] = true;
                        }
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                    // An older SSA definition may feed the captured value for
                    // this same architectural slot. Clang emits this for width
                    // normalisation (`rdx#1 = 0; rdx#2 = zext rdx#1`), with flag
                    // bookkeeping sometimes between the two definitions.
                    // Follow that exact definition edge instead of treating the
                    // SSA values as unrelated clobbers and abandoning every
                    // earlier argument slot.
                    if opaque_reaching_defs.contains(dst) {
                        continue;
                    }
                    let substitutable = (is_pure_arg_normalisation(src)
                        || is_stable_frame_arg_definition(src, body, i, call_idx))
                        && !versioned_operand_is_reassigned(src, body, i, call_idx);
                    let feeds_captured_argument = resolve_captured_definition(
                        &mut found,
                        &mut stack_args,
                        dst,
                        src,
                        substitutable,
                    );
                    if feeds_captured_argument {
                        if !substitutable {
                            opaque_reaching_defs.insert(dst.clone());
                        }
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                    if found[slot]
                        .as_ref()
                        .is_some_and(|(index, _)| *index == KEEP_ARG_SETUP)
                    {
                        // The call names a later exact SSA value whose setup
                        // remains in place. Older definitions of the same
                        // architectural slot are shadowed; they cannot replace
                        // that argument and need not block the search for a
                        // still-missing lower slot (notably x0's preceding-call
                        // result behind x1#1 -> x1#2 normalisation).
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                    if proven_aapcs_stack || known_arm_core_arity.is_some() {
                        // A locked integer callee layout proves that every
                        // core slot belongs to this call. Once the nearest
                        // reaching definition of a slot is captured, an older
                        // unrelated definition of that same register is
                        // shadowed and cannot clobber it. Continue looking for
                        // the still-missing leading slots; calls, control-flow
                        // boundaries, unproved stores, and stack gaps were
                        // already rejected by the area proof above.
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                    // An unrelated second assignment to the same ABI slot is a
                    // boundary even when both writes carry SSA versions. SSA
                    // proves the definitions differ; it does not prove an older
                    // write was intended as an argument to this call. Crossing
                    // only a direct def-use edge keeps stale values out of later
                    // slots while still following compiler-generated register
                    // copies and width normalisation.
                    break;
                }
                // Register setup commonly reuses a scratch GPR between ABI
                // slots (`rax = a1; rcx = rax + 2; rax = r; rdx = rax + 1`).
                // Resolve each captured expression at its own nearest reaching
                // definition while walking backward. Leaving all of them as
                // bare `rax` reads makes later DSE bind every slot to whichever
                // scratch assignment happens to survive last.
                // SSA-versioned scratch values already have distinct
                // identities and should remain statement-rooted. This repair
                // is specifically for unversioned lifter output where several
                // reaching definitions otherwise collapse to one register.
                // A versioned scratch name already has a distinct identity, so a
                // REGISTER slot may go on naming it. A STACK argument cannot:
                // its captured expression must stand alone once the push is
                // folded away, so the definition has to be substituted in or
                // the argument is lost with it. That is how
                // `11_call_shapes:gcc:O2:call_into_spill` lost all eight of its
                // arguments once `value_number` stopped keeping the scratch
                // `%rax` bare.
                //
                // Admitted for the x86-64 conventions only, where it was
                // measured. The frame-coordinate guard still applies to both:
                // AAPCS resolves stack coordinates against a live `sp`, and
                // folding a definition into one rewrites `sp + 12` into the
                // whole frame-adjust chain.
                let versioned_stack_capture =
                    name.contains('#') && matches!(arch, CallConv::SysVAmd64 | CallConv::Win64);
                if (!name.contains('#') || versioned_stack_capture)
                    && !is_frame_coordinate_storage(arch, name)
                {
                    if opaque_reaching_defs.contains(dst) {
                        continue;
                    }
                    let substitutable = (is_pure_arg_normalisation(src)
                        || is_stable_frame_arg_definition(src, body, i, call_idx))
                        && !versioned_operand_is_reassigned(src, body, i, call_idx);
                    if resolve_captured_definition_in(
                        &mut found,
                        &mut stack_args,
                        dst,
                        src,
                        substitutable,
                        !name.contains('#'),
                    ) {
                        if !substitutable {
                            opaque_reaching_defs.insert(dst.clone());
                        }
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                }
            }
            mark_arg_reads_in_expr(src, arch, &mut read_between);
        } else {
            mark_arg_reads_in_stmt(&body[i], arch, &mut read_between);
            mark_arg_writes_in_stmt(&body[i], arch, &mut blocked_incoming);
        }
        if stop {
            // A preceding call defines the ABI return register. Captured
            // arguments may still read that value even when later setup reuses
            // the same unversioned scratch register. Give the call result its
            // own identity before deleting the register-move setup; otherwise
            // a later `rax = ...` silently becomes the argument's definition.
            // The register the arguments would actually name. A call result is
            // not always the BARE return register: once value numbering gives
            // it an ordinary SSA version (`rax#1`), captured arguments read
            // that spelling, and looking for the bare one found nothing — so
            // this branch was skipped and `call_into_spill` kept none of its
            // eight arguments. `is_return_register` tolerates the `#version`
            // suffix, which is what makes the versioned spelling recognisable.
            let return_register = match &body[i] {
                Stmt::Call {
                    dst: Some(VReg::Phys(name)),
                    ..
                } if crate::ir::abi::is_return_register(arch, name) => VReg::phys(name),
                _ => VReg::phys(return_reg(arch)),
            };
            // ABI arguments form a contiguous prefix. If the current call has
            // an explicit slot one, its unwritten slot zero is necessarily the
            // value left in the return register by this immediately preceding
            // call. A proven AAPCS stack suffix is the analogous ARM32 proof
            // even when none of the core slots needed local setup.
            let shared_result_and_slot_zero = matches!(
                arch,
                CallConv::Aarch64 | CallConv::Arm | CallConv::ArmHardFloat
            );
            let forwards_return_to_slot_zero = shared_result_and_slot_zero
                && found.first().is_some_and(Option::is_none)
                && (proven_aapcs_stack || found.get(1).is_some_and(Option::is_some));
            let consumes_return = found
                .iter()
                .flatten()
                .any(|(_, argument)| reads_reg_in_expr(argument, &return_register))
                || stack_args
                    .iter()
                    .any(|argument| reads_reg_in_expr(argument, &return_register))
                || forwards_return_to_slot_zero;
            if consumes_return {
                let existing_result = match &body[i] {
                    Stmt::Call { dst, .. } => dst.clone(),
                    _ => None,
                }
                .filter(|result| {
                    !matches!(
                        result,
                        VReg::Phys(name)
                            if crate::ir::abi::is_return_register(arch, name)
                                && !name.contains('#')
                    )
                });
                let result = existing_result
                    .unwrap_or_else(|| VReg::phys(format!("{}#call_result_{i}", return_reg(arch))));
                let replacement = Expr::Reg(result.clone());
                for (_, argument) in found.iter_mut().flatten() {
                    let _ = substitute_exact_reg(argument, &return_register, &replacement);
                }
                for argument in &mut stack_args {
                    let _ = substitute_exact_reg(argument, &return_register, &replacement);
                }
                if forwards_return_to_slot_zero {
                    // Every statement in the proven outgoing-area window is
                    // straight-line Assign/Store setup. Rewrite transitive
                    // computations as well as the final captured expressions:
                    // ARM value numbering can leave `t21 = r0; r2 = t21 + 1`
                    // with the bare architectural spelling, and renaming that
                    // later as the caller's `arg0` loses the producer result.
                    for statement in body.iter_mut().take(call_idx).skip(i + 1) {
                        match statement {
                            Stmt::Assign { src, .. } => {
                                let _ = substitute_exact_reg(src, &return_register, &replacement);
                            }
                            Stmt::Store { addr, src, .. } => {
                                let _ = substitute_exact_reg(addr, &return_register, &replacement);
                                let _ = substitute_exact_reg(src, &return_register, &replacement);
                            }
                            _ => {}
                        }
                    }
                    found[0] = Some((KEEP_ARG_SETUP, replacement));
                }
                if let Stmt::Call { dst, .. } = &mut body[i] {
                    *dst = Some(result);
                }
            }
            // ABI argument registers are caller-clobbered.  Explicit
            // assignments found after this call remain valid, but an unwritten
            // prefix can no longer be justified from this function's entry
            // value once another call has intervened.
            blocked_incoming.fill(true);
            break;
        }
    }

    // Determine the maximum contiguous prefix of filled slots. We only
    // include slot N if slots 0..N-1 were also assigned; a gap means the
    // function probably doesn't use that argument, so trimming at the first
    // gap is the safe choice.
    let mut args_out: Vec<Expr> = Vec::new();
    let mut used_stmt_indices: Vec<usize> = Vec::new();
    let Some(last_filled_slot) = found.iter().rposition(Option::is_some) else {
        // Optimized forwarding can pass this function's untouched first
        // parameter straight into its first call with no setup instruction.
        // Admit that one implicit slot only when the value-numbering analysis
        // proves slot zero is a real parameter, no earlier statement read or
        // wrote it, no prior call could clobber it, and the direct call's result
        // is consumed. The read-before-call exclusion preserves the deliberate
        // nonterminal fail-closed case where a parameter is used for unrelated
        // work before a zero-setup call.
        let contiguous_leading_parameter = param_slots.contains(&0) || param_slots.contains(&1);
        // AAPCS32/AAPCS64 have the same property this rule depends on: integer
        // parameter slots are contiguous and slot zero is a register the
        // caller already holds, so `bl callee` with no setup at all forwards
        // this function's own first parameter. Every armv7 `-O2` one-argument forward
        // (`11_call_shapes:call_result_drives_branch`, the inner `wrap_byte(a)`
        // of `call_nested`) and AArch64's loop-carried `call_chain_in_loop`
        // are that shape. Without this they rendered as `signed_step()` — a
        // call whose argument list contradicts the prototype the same run
        // recovers for the callee.
        //
        // Deliberately NOT extended to `Cdecl32` (arguments are on the stack,
        // so a zero-setup call forwards nothing) or to unmeasured `Win64`.
        let first_direct_value_call = matches!(
            arch,
            CallConv::SysVAmd64 | CallConv::Aarch64 | CallConv::Arm | CallConv::ArmHardFloat
        ) && contiguous_leading_parameter
            && !read_between[0]
            && !blocked_incoming[0]
            && enclosing.entry_value_reaches(0)
            && !body[..call_idx]
                .iter()
                .any(|statement| matches!(statement, Stmt::Call { .. }))
            && matches!(
                &body[call_idx],
                Stmt::Call {
                    target: Expr::Named { .. },
                    args,
                    dst,
                    ..
                } if args.is_empty()
                    && (dst.is_some()
                        || return_value_is_read(body, call_idx, return_reg(arch)))
            );
        if first_direct_value_call {
            // SysV integer parameter slots are contiguous. A proven slot one
            // means slot zero exists even when its only machine use was the
            // implicit call input that liveness could not see before argument
            // reconstruction made it explicit.
            param_slots.insert(0);
            // This special case exists precisely because the forwarded slot
            // has no explicit body use for value numbering to witness. The
            // proven parameter slot therefore authorizes its canonical ABI
            // spelling when `incoming_arg_expr` cannot find a versioned name.
            let incoming = incoming_overrides
                .first()
                .and_then(Clone::clone)
                .or_else(|| incoming_arg_expr(arch, 0, body))
                .or_else(|| enclosing.live_ins.first().and_then(Clone::clone))
                .unwrap_or_else(|| {
                    Expr::Reg(VReg::phys(
                        arg_slots(arch)
                            .first()
                            .and_then(|aliases| aliases.first())
                            .copied()
                            .unwrap_or("rdi"),
                    ))
                });
            if let Stmt::Call { args, .. } = &mut body[call_idx] {
                *args = vec![incoming];
            }
        }
        return;
    };
    for slot_idx in 0..=last_filled_slot {
        match &found[slot_idx] {
            Some((stmt_idx, expr)) => {
                args_out.push(expr.clone());
                if *stmt_idx != KEEP_ARG_SETUP {
                    used_stmt_indices.push(*stmt_idx);
                }
            }
            // Backfill an unwritten earlier slot from the incoming register —
            // but only when that slot really is one of THIS function's
            // parameters. Otherwise the "argument" is a register nothing defined,
            // and a void callee acquires one out of thin air
            // (`__stack_chk_fail(var24)`).
            None if args_out.is_empty()
                && !blocked_incoming[slot_idx]
                && enclosing.entry_value_reaches(slot_idx)
                && param_slots.contains(&slot_idx) =>
            {
                let Some(expr) = incoming_overrides
                    .get(slot_idx)
                    .and_then(Clone::clone)
                    .or_else(|| incoming_arg_expr(arch, slot_idx, body))
                    // A call nested in a branch arm sees only that arm. The
                    // function-wide spelling is the same live-in value, and
                    // `blocked_incoming` — seeded from the enclosing scope —
                    // is what proves it still reaches this call.
                    .or_else(|| enclosing.live_ins.get(slot_idx).and_then(Clone::clone))
                else {
                    break;
                };
                args_out.push(expr);
            }
            None => break,
        }
    }

    if args_out.is_empty() {
        return;
    }

    // SysV places every integer argument after slot five on the caller's
    // stack. Exact `rsp -= 8; [rsp] = value` pairs are encountered in source
    // order while walking backward (arg6, arg7, ...). Absorb them only when all
    // six register slots are present and an exact post-call cleanup balances
    // the complete allocation. That balance distinguishes outgoing arguments
    // from callee-save pushes and local frame storage.
    if (arch == CallConv::SysVAmd64 || proven_aapcs_stack)
        && args_out.len() == arg_slots(arch).len()
        && !stack_args.is_empty()
    {
        if preallocated_stack.is_some() || proven_aapcs_stack {
            args_out.extend(stack_args);
            used_stmt_indices.extend(stack_setup_indices);
        } else {
            let padding_bytes = stack_padding.map_or(0, |_| 8);
            let expected_cleanup = stack_arg_bytes + padding_bytes;
            if let Some(cleanup_indices) = outgoing_stack_cleanup(body, call_idx, expected_cleanup)
            {
                args_out.extend(stack_args);
                used_stmt_indices.extend(stack_setup_indices);
                if let Some(padding_index) = stack_padding {
                    used_stmt_indices.push(padding_index);
                }
                used_stmt_indices.extend(cleanup_indices);
            }
        }
    }

    // Splice the args in.
    if let Stmt::Call { args, .. } = &mut body[call_idx] {
        *args = args_out;
    }

    // Remove the folded assigns. Sort descending to keep call_idx valid.
    used_stmt_indices.sort_by(|a, b| b.cmp(a));
    for idx in used_stmt_indices {
        body.remove(idx);
    }
}

/// Prove the number of register arguments consumed by a recognized
/// `printf`-family call from a literal format string.
///
/// This is deliberately narrower than general variadic recovery. The target
/// must be named, the format slot's nearest reaching definition must be a
/// literal address in `string_pool`, and the shared parser must understand the
/// complete format. Any control-flow boundary, call, indirection, or unsupported
/// conversion declines the proof.
fn format_proven_arity(
    body: &[Stmt],
    call_idx: usize,
    arch: CallConv,
    string_pool: &std::collections::HashMap<u64, String>,
) -> Option<usize> {
    if !matches!(arch, CallConv::SysVAmd64 | CallConv::Win64) {
        return None;
    }
    let Stmt::Call {
        target: Expr::Named { name, .. },
        ..
    } = body.get(call_idx)?
    else {
        return None;
    };
    let clean = name.split('@').next().unwrap_or(name);
    let clean = clean
        .strip_prefix('_')
        .filter(|_| !clean.starts_with("__"))
        .unwrap_or(clean);
    let (format_slot, variadic_start): (usize, usize) = match clean {
        "printf" => (0, 1),
        "fprintf" => (1, 2),
        "__printf_chk" => (1, 2),
        "__fprintf_chk" => (2, 3),
        "error" => (2, 3),
        _ => return None,
    };
    for statement in body[..call_idx].iter().rev() {
        match statement {
            Stmt::Assign {
                dst: VReg::Phys(register),
                src,
            } if super::slot_of(arch, register) == Some(format_slot) => {
                let address = match src {
                    Expr::Addr(address) => *address,
                    Expr::Cast { expr, .. } => match expr.as_ref() {
                        Expr::Addr(address) => *address,
                        _ => return None,
                    },
                    _ => return None,
                };
                let conversions = crate::ir::printf_format::parse_printf_hints(
                    string_pool.get(&address)?,
                    crate::ir::abi::machine_word_bytes(arch),
                )?;
                let arity = variadic_start.checked_add(conversions.len())?;
                return (arity <= super::arg_slots(arch).len()).then_some(arity);
            }
            Stmt::Call { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Return { .. }
            | Stmt::Break => return None,
            _ => {}
        }
    }
    None
}
