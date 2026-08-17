//! The two bounded monotone analyses that fix a frame coordinate per program
//! point, before any memory expression is rewritten.
//!
//! [`collect_label_stack_deltas`] replays goto edges until every label carries a
//! known entry-stack depth or is conservatively unknown; [`collect_stack_address_defs`]
//! freezes the registers that hold a stable frame address. They are mutually
//! dependent — an epilogue can restore SP through an alias, an alias defined
//! after a textual epilogue needs the target label's depth — and the caller
//! iterates them together.

use std::collections::{HashMap, HashSet};

use super::{
    body_falls_through, entry_stack_base, is_active_stack_base, is_arm_frame_pointer,
    is_stack_pointer_reg, merge_stack_deltas, resolve_stack_address, stack_delta_after_assignment,
    stack_word_size, StackContext,
};
use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackFlow {
    Unreachable,
    Known(i64),
    Unknown,
}

fn merge_stack_flows(left: StackFlow, right: StackFlow) -> StackFlow {
    match (left, right) {
        (StackFlow::Unreachable, other) | (other, StackFlow::Unreachable) => other,
        (StackFlow::Known(a), StackFlow::Known(b)) if a == b => StackFlow::Known(a),
        (StackFlow::Known(_), StackFlow::Known(_))
        | (StackFlow::Unknown, _)
        | (_, StackFlow::Unknown) => StackFlow::Unknown,
    }
}

fn merge_stack_flow_entry(states: &mut HashMap<u64, StackFlow>, label: u64, incoming: StackFlow) {
    if incoming == StackFlow::Unreachable {
        return;
    }
    states
        .entry(label)
        .and_modify(|known| *known = merge_stack_flows(*known, incoming))
        .or_insert(incoming);
}

/// Propagate entry-stack deltas over residual goto control flow before any
/// memory expression is rewritten.
///
/// Structured AST order is usually execution order, but optimized functions
/// retain labels after one or more textual epilogues. A branch into such a
/// label still executes in the original frame. This bounded monotone analysis
/// records goto edges and replays backward edges until each label is Known or
/// conservatively Unknown; Unreachable never poisons a reachable predecessor.
pub(super) fn collect_label_stack_deltas(
    body: &[Stmt],
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> HashMap<u64, Option<i64>> {
    fn update_stack_assignment(
        flow: StackFlow,
        dst: &VReg,
        src: &Expr,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
    ) -> StackFlow {
        match flow {
            StackFlow::Known(delta) => {
                stack_delta_after_assignment(dst, src, Some(delta), ctx, address_defs)
                    .map(StackFlow::Known)
                    .unwrap_or(StackFlow::Unknown)
            }
            other => other,
        }
    }

    fn walk(
        body: &[Stmt],
        mut flow: StackFlow,
        target_states: &mut HashMap<u64, StackFlow>,
        label_states: &mut HashMap<u64, StackFlow>,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
    ) -> StackFlow {
        for statement in body {
            match statement {
                Stmt::Assign { dst, src } if is_stack_pointer_reg(dst, ctx) => {
                    flow = update_stack_assignment(flow, dst, src, ctx, address_defs);
                }
                Stmt::Push { .. } => {
                    if let StackFlow::Known(delta) = flow {
                        flow = StackFlow::Known(delta - stack_word_size(ctx));
                    }
                }
                Stmt::Pop { .. } => {
                    if let StackFlow::Known(delta) = flow {
                        flow = StackFlow::Known(delta + stack_word_size(ctx));
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    let then_flow = walk(
                        then_body,
                        flow,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    let else_flow = else_body.as_deref().map_or(flow, |else_body| {
                        walk(
                            else_body,
                            flow,
                            target_states,
                            label_states,
                            ctx,
                            address_defs,
                        )
                    });
                    flow = merge_stack_flows(then_flow, else_flow);
                }
                Stmt::While { body, .. } => {
                    let body_flow =
                        walk(body, flow, target_states, label_states, ctx, address_defs);
                    flow = merge_stack_flows(flow, body_flow);
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    flow = walk(
                        std::slice::from_ref(init.as_ref()),
                        flow,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    let loop_entry = flow;
                    let body_flow = walk(
                        body,
                        loop_entry,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    let stepped = walk(
                        std::slice::from_ref(step.as_ref()),
                        body_flow,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    flow = merge_stack_flows(loop_entry, stepped);
                }
                Stmt::DoWhile { body, .. } => {
                    let body_flow =
                        walk(body, flow, target_states, label_states, ctx, address_defs);
                    flow = merge_stack_flows(flow, body_flow);
                }
                Stmt::Switch { cases, default, .. } => {
                    let incoming = flow;
                    let mut exits = StackFlow::Unreachable;
                    for (_, case_body) in cases {
                        exits = merge_stack_flows(
                            exits,
                            walk(
                                case_body,
                                incoming,
                                target_states,
                                label_states,
                                ctx,
                                address_defs,
                            ),
                        );
                    }
                    if let Some(default_body) = default {
                        exits = merge_stack_flows(
                            exits,
                            walk(
                                default_body,
                                incoming,
                                target_states,
                                label_states,
                                ctx,
                                address_defs,
                            ),
                        );
                    } else {
                        exits = merge_stack_flows(exits, incoming);
                    }
                    flow = exits;
                }
                Stmt::Goto { target } => {
                    merge_stack_flow_entry(target_states, *target, flow);
                    flow = StackFlow::Unreachable;
                }
                Stmt::Label(label) => {
                    let targeted = target_states
                        .get(label)
                        .copied()
                        .unwrap_or(StackFlow::Unreachable);
                    flow = merge_stack_flows(flow, targeted);
                    merge_stack_flow_entry(label_states, *label, flow);
                }
                Stmt::Return { .. } | Stmt::IndirectGoto { .. } => {
                    flow = StackFlow::Unreachable;
                }
                Stmt::Store { .. }
                | Stmt::Call { .. }
                | Stmt::Assign { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
        flow
    }

    let mut target_states = HashMap::new();
    let mut label_states = HashMap::new();
    for _ in 0..64 {
        let before = target_states.clone();
        label_states.clear();
        let _ = walk(
            body,
            StackFlow::Known(0),
            &mut target_states,
            &mut label_states,
            ctx,
            address_defs,
        );
        if target_states == before {
            break;
        }
    }

    label_states
        .into_iter()
        .map(|(label, flow)| {
            let delta = match flow {
                StackFlow::Known(delta) => Some(delta),
                StackFlow::Unreachable | StackFlow::Unknown => None,
            };
            (label, delta)
        })
        .collect()
}

/// Whether `expr` would carry `register`'s frame coordinate.
///
/// This mirrors exactly the shapes [`resolve_stack_address`] resolves: a copy,
/// a displaced address, and a dereference of either. A cast, a comparison, or
/// any other arithmetic cannot produce a stack address from one, so a use in
/// those positions consumes the register's bits without inheriting its
/// coordinate.
fn expression_roots_at(expr: &Expr, register: &VReg) -> bool {
    match expr {
        Expr::Reg(reg) => reg == register,
        Expr::Lea { base, index, .. } => {
            base.as_ref() == Some(register) || index.as_ref() == Some(register)
        }
        Expr::Deref { addr, .. } => expression_roots_at(addr, register),
        Expr::Bin {
            op: crate::ir::types::BinOp::Add | crate::ir::types::BinOp::Sub,
            lhs,
            rhs,
        } => expression_roots_at(lhs, register) || expression_roots_at(rhs, register),
        _ => false,
    }
}

/// Whether `register`'s frame coordinate is dead over the rest of the body.
///
/// The value a Thumb epilogue writes back into `r7` is the restored entry-stack
/// address (`adds r7, #32; mov sp, r7`). Its consumers are the stack-pointer
/// restore and the flag and width temporaries ARM's lowering hangs off the same
/// add — machine bookkeeping that names no source storage and cannot compete
/// with the coordinate the prologue established. A memory access through the
/// register, a copy that would inherit the coordinate, an escape into a call,
/// or a returned address all keep the overwrite ambiguous.
fn frame_coordinate_is_dead_after(body: &[Stmt], register: &VReg, ctx: StackContext) -> bool {
    body.iter().all(|statement| {
        if !crate::ir::dead_stores::stmt_reads(statement, register) {
            return true;
        }
        match statement {
            // The stack-pointer restore is the teardown's whole purpose.
            Stmt::Assign { dst, .. } if is_stack_pointer_reg(dst, ctx) => true,
            Stmt::Assign { src, .. } => !expression_roots_at(src, register),
            _ => false,
        }
    })
}

/// Recover definitions that carry a constant frame/stack address into a call.
///
/// These registers are already SSA-versioned by the value model (`rax#4`,
/// `rax#8`, ...), so their identity is path-stable. Keeping this small semantic
/// map is the minimum equivalent of looking through an AIL virtual-variable or
/// a Ghidra Varnode definition; it avoids asking the general expression pass to
/// move an address computation across unrelated effects.
pub(super) fn collect_stack_address_defs(
    body: &[Stmt],
    ctx: StackContext,
    label_deltas: &HashMap<u64, Option<i64>>,
) -> HashMap<VReg, (String, i64)> {
    fn record_definition(
        dst: &VReg,
        address: Option<(String, i64)>,
        out: &mut HashMap<VReg, (String, i64)>,
        ambiguous: &mut HashSet<VReg>,
    ) {
        if ambiguous.contains(dst) {
            return;
        }
        match (out.get(dst), address) {
            (None, Some(address)) => {
                out.insert(dst.clone(), address);
            }
            (Some(existing), Some(address)) if existing == &address => {}
            (Some(_), Some(_)) | (Some(_), None) => {
                out.remove(dst);
                ambiguous.insert(dst.clone());
            }
            // A definition that carries no stack address makes the register
            // ambiguous even when it is seen FIRST. The map is keyed by
            // register, not by program point, so a single later address
            // definition would otherwise claim the whole body — including the
            // region where the register held something else entirely. GCC's
            // pre-value-folding Thumb lowering reuses one temporary for both a
            // loaded integer and the epilogue's frame address, and the frame
            // coordinate leaking backwards over the integer uses made four
            // ordinary adds look like subscripted frame accesses, seeding a
            // byte array over the whole frame. Value-numbered bodies define
            // each name once and are unaffected.
            (None, None) => {
                ambiguous.insert(dst.clone());
            }
        }
    }

    fn walk_direct(
        body: &[Stmt],
        out: &mut HashMap<VReg, (String, i64)>,
        ambiguous: &mut HashSet<VReg>,
        ctx: StackContext,
        sp_delta: &mut Option<i64>,
        label_deltas: &HashMap<u64, Option<i64>>,
    ) {
        for (statement_index, stmt) in body.iter().enumerate() {
            match stmt {
                Stmt::Assign { dst, src } => {
                    let address = resolve_stack_address(src, *sp_delta, ctx, out);
                    if is_stack_pointer_reg(dst, ctx) {
                        *sp_delta = address.and_then(|(base, disp)| {
                            (base == entry_stack_base(ctx)).then_some(disp)
                        });
                    } else if matches!(dst, VReg::Phys(name) if is_arm_frame_pointer(name, ctx)) {
                        // An epilogue overwrite of the frame register is frame
                        // teardown, not a competing reaching frame definition.
                        // A32 restores the unversioned `fp` from its saved stack
                        // word; Thumb first re-adds the prologue constant
                        // (`adds r7, #32; mov sp, r7`), which GCC lowers through
                        // register temporaries so it is not a foldable stack
                        // expression. Ignore either only when the current path
                        // terminates and every later read of the register feeds
                        // a stack-pointer restore — machine bookkeeping that
                        // addresses no source storage. A fall-through nested
                        // body or any other live use remains ambiguous.
                        let terminal_teardown = address.is_none()
                            && out.contains_key(dst)
                            && !body_falls_through(&body[statement_index + 1..])
                            && frame_coordinate_is_dead_after(
                                &body[statement_index + 1..],
                                dst,
                                ctx,
                            );
                        if terminal_teardown {
                            continue;
                        }
                        // Preserve the exact entry-SP coordinate captured
                        // by `r7#1 = sp` or `fp = sp + 4`; later direct
                        // arithmetic must resolve to the same DWARF CFA
                        // object. x86's `rbp = rsp` remains a coordinate-
                        // system establishment below.
                        record_definition(dst, address, out, ambiguous);
                        continue;
                    } else if matches!(dst, VReg::Phys(name) if is_active_stack_base(name, ctx)) {
                        // Architectural frame bases define the coordinate
                        // system used by DWARF and local naming. In particular,
                        // `rbp = rsp` is a frame establishment, not an immutable
                        // SSA address alias to rebase as `entry_rsp`.
                        out.remove(dst);
                        ambiguous.insert(dst.clone());
                    } else {
                        record_definition(dst, address, out, ambiguous);
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    let incoming = *sp_delta;
                    let mut then_delta = incoming;
                    walk_direct(
                        then_body,
                        out,
                        ambiguous,
                        ctx,
                        &mut then_delta,
                        label_deltas,
                    );
                    let mut else_delta = incoming;
                    if let Some(body) = else_body {
                        walk_direct(body, out, ambiguous, ctx, &mut else_delta, label_deltas);
                    }
                    let then_falls_through = body_falls_through(then_body);
                    let else_falls_through = else_body.as_deref().is_none_or(body_falls_through);
                    *sp_delta = match (then_falls_through, else_falls_through) {
                        (true, true) => merge_stack_deltas(then_delta, else_delta),
                        (true, false) => then_delta,
                        (false, true) => else_delta,
                        (false, false) => None,
                    };
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    let incoming = *sp_delta;
                    let mut body_delta = incoming;
                    walk_direct(body, out, ambiguous, ctx, &mut body_delta, label_deltas);
                    *sp_delta = merge_stack_deltas(incoming, body_delta);
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    walk_direct(
                        std::slice::from_ref(init.as_ref()),
                        out,
                        ambiguous,
                        ctx,
                        sp_delta,
                        label_deltas,
                    );
                    let loop_entry = *sp_delta;
                    let mut body_delta = loop_entry;
                    walk_direct(body, out, ambiguous, ctx, &mut body_delta, label_deltas);
                    walk_direct(
                        std::slice::from_ref(step.as_ref()),
                        out,
                        ambiguous,
                        ctx,
                        &mut body_delta,
                        label_deltas,
                    );
                    *sp_delta = merge_stack_deltas(loop_entry, body_delta);
                }
                Stmt::Switch { cases, default, .. } => {
                    let incoming = *sp_delta;
                    let mut merged: Option<Option<i64>> = None;
                    for (_, body) in cases {
                        let mut case_delta = incoming;
                        walk_direct(body, out, ambiguous, ctx, &mut case_delta, label_deltas);
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, case_delta),
                            None => case_delta,
                        });
                    }
                    if let Some(body) = default {
                        let mut default_delta = incoming;
                        walk_direct(body, out, ambiguous, ctx, &mut default_delta, label_deltas);
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, default_delta),
                            None => default_delta,
                        });
                    } else {
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, incoming),
                            None => incoming,
                        });
                    }
                    *sp_delta = merged.unwrap_or(incoming);
                }
                Stmt::Push { .. } => {
                    *sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
                }
                Stmt::Pop { .. } => {
                    *sp_delta = sp_delta.map(|delta| delta + stack_word_size(ctx));
                }
                Stmt::Label(label) => {
                    *sp_delta = label_deltas.get(label).copied().unwrap_or(None);
                }
                Stmt::Goto { .. } | Stmt::Return { .. } | Stmt::IndirectGoto { .. } => {
                    *sp_delta = None;
                }
                _ => {}
            }
        }
    }

    let mut ambiguous = HashSet::new();
    loop {
        let prior_ambiguities = ambiguous.len();
        let mut defs = HashMap::new();
        let mut sp_delta = Some(0);
        walk_direct(
            body,
            &mut defs,
            &mut ambiguous,
            ctx,
            &mut sp_delta,
            label_deltas,
        );
        if ambiguous.len() == prior_ambiguities {
            return defs;
        }
    }
}
