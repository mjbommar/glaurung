//! Promote stack-relative memory accesses to named locals.
//!
//! A lot of decompiled noise comes from seeing `*(u64)&[%rsp+0x158]` over
//! and over. This pass rewrites every such access whose base is a stack
//! register (rsp/ebp/sp/x29) and whose effective address is a constant
//! displacement into a named local variable. A slot is identified by its
//! `(base, disp)` alone, so a read and a write of the same slot resolve to one
//! local (keeping its def/use chain intact); the recovered access width is
//! carried alongside the name and narrowed to the true load width.
//!
//! Naming:
//! * Positive displacements from rsp/sp — likely caller-allocated scratch —
//!   become `stack_N` where N counts the slot in first-appearance order.
//! * Negative displacements from a frame pointer (rbp/x29) — classic local
//!   variables — become `local_N`.
//! * Zero-displacement `[rsp]` (stack top) becomes `stack_top`.
//!
//! Pointer arithmetic that isn't a concrete load/store (e.g. `rsp = rsp - 8`)
//! is **not** touched — those are stack-pointer updates that should keep
//! the `%rsp` form so a reader can see the prologue/epilogue shape. Address-valued
//! call arguments are different: a constant frame-relative address is promoted
//! to [`Expr::StackAddr`] so the C renderer passes `&local_N`, never arithmetic
//! on an uninitialised `rbp`/`rsp` local.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

const STACK_BASES: &[&str] = &["rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "fp"];
const FRAME_POINTER_BASES: &[&str] = &["rbp", "ebp", "bp", "x29", "w29", "fp"];

fn is_stack_base(name: &str) -> bool {
    STACK_BASES.contains(&name)
}

fn is_frame_pointer(name: &str) -> bool {
    FRAME_POINTER_BASES.contains(&name)
}

/// Opaque key for the (base_name, disp) of a stack slot. Deliberately does NOT
/// include the access size: the *same* memory slot is often read and written at
/// spellings the lowering reports with different sizes (a 4-byte load vs a store
/// whose size we don't thread through), and keying on size would then mint two
/// different local names for one variable — severing its def/use chain. The
/// recovered size is tracked in the map *value* instead (see [`SlotVal`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SlotKey {
    base: String,
    disp: i64,
}

/// Promoted local metadata. `declared_size` is the narrowest access width and
/// drives the C declaration; `span_size` is the widest access and records the
/// bytes owned by the slot so a later field read inside a wide spill can be
/// extracted from the parent instead of becoming an undefined overlapping local.
#[derive(Debug, Clone)]
struct SlotVal {
    name: String,
    declared_size: u8,
    span_size: u8,
}

#[derive(Clone, Copy)]
struct StackContext {
    cc: Option<CallConv>,
    rbp_repurposed: bool,
    /// Exact source-level arity when debug/prototype evidence locks it.
    /// Candidate stack arguments at or beyond this bound are frame storage,
    /// never additional parameters invented from a recovered displacement.
    parameter_count: Option<usize>,
}

fn is_active_stack_base(name: &str, ctx: StackContext) -> bool {
    is_stack_base(name)
        && !(ctx.rbp_repurposed && matches!(crate::ir::abi::ssa_base(name), "rbp" | "ebp" | "bp"))
}

/// Whether the function's first assignment to x86's nominal frame register
/// makes it an ordinary callee-saved value instead of establishing a frame.
fn rbp_is_repurposed(body: &[Stmt], cc: Option<CallConv>) -> bool {
    if !matches!(
        cc,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32)
    ) {
        return false;
    }
    for statement in body {
        let Stmt::Assign {
            dst: VReg::Phys(dst),
            src,
        } = statement
        else {
            continue;
        };
        if !matches!(crate::ir::abi::ssa_base(dst), "rbp" | "ebp" | "bp") {
            continue;
        }
        return !matches!(
            src,
            Expr::Reg(VReg::Phys(stack))
                if matches!(crate::ir::abi::ssa_base(stack), "rsp" | "esp" | "sp")
        );
    }
    false
}

/// Rewrite stack-relative memory accesses to named locals.
pub fn promote_stack_locals(f: &mut Function) {
    let _ = promote_stack_locals_typed(f, None);
}

/// Like [`promote_stack_locals`], but also returns the recovered byte size of
/// each promoted local (`local_0 -> 4`, `stack_1 -> 8`, ...), taken from the
/// width of the memory accesses that defined the slot. Callers thread this into
/// type recovery so a 4-byte spill slot renders as `int` rather than the
/// blanket `long`. When a name is defined at more than one width the widest is
/// kept (the safest committed size).
pub fn promote_stack_locals_typed(f: &mut Function, cc: Option<CallConv>) -> HashMap<String, u8> {
    promote_stack_locals_typed_with_parameter_count(f, cc, None)
}

/// Promote stack storage while respecting an optional authoritative parameter
/// count. This matters for optimized non-leaf functions: control-flow joins can
/// expose saved registers through a positive entry-stack displacement that has
/// the same machine shape as a genuine stack-passed argument. DWARF or another
/// locked prototype disambiguates the two without weakening stripped-binary
/// inference.
pub fn promote_stack_locals_typed_with_parameter_count(
    f: &mut Function,
    cc: Option<CallConv>,
    parameter_count: Option<usize>,
) -> HashMap<String, u8> {
    let mut map: HashMap<SlotKey, SlotVal> = HashMap::new();
    let mut stack_counter = 0usize;
    let mut local_counter = 0usize;
    let ctx = StackContext {
        cc,
        rbp_repurposed: rbp_is_repurposed(&f.body, cc),
        parameter_count,
    };
    let address_defs = collect_stack_address_defs(&f.body, ctx);
    let label_deltas = collect_label_stack_deltas(&f.body, ctx, &address_defs);
    let mut sp_delta = Some(0i64);
    rewrite_body(
        &mut f.body,
        &mut map,
        &mut stack_counter,
        &mut local_counter,
        ctx,
        &mut sp_delta,
        &address_defs,
        &label_deltas,
    );
    // Several machine SlotKeys can intentionally collapse to one source-level
    // role (notably `entry_rsp+0` and `esp+0` both render as `stack_top`).  Join
    // by that final identity explicitly. A bare `collect()` made HashMap
    // iteration order choose the declaration width, so identical inputs could
    // alternate between `char` and `long` across processes.
    let mut sizes = HashMap::new();
    for slot in map.into_values() {
        sizes
            .entry(slot.name)
            .and_modify(|size: &mut u8| *size = (*size).max(slot.declared_size))
            .or_insert(slot.declared_size);
    }
    sizes
}

/// Where a calling convention puts the arguments that do not fit in registers:
/// how many arrive in registers, and the frame-pointer offset of the first stacked
/// one in a standard frame.
///
/// SysV AMD64: six integer registers, then `[rbp+16]` upward — `[rbp]` holds the
/// saved frame pointer and `[rbp+8]` the return address. Cdecl32 has no integer
/// register arguments and starts at `[ebp+8]` in four-byte slots. AArch64 AAPCS:
/// eight registers, then `[x29+16]`, the frame record being `{fp, lr}`. Win64 and
/// ARM32 are deliberately absent: their layouts (a 32-byte shadow space; a
/// different frame record) are not exercised by any fixture here, and guessing
/// at an ABI is how a decompiler invents a parameter that does not exist.
fn stack_arg_layout(cc: CallConv) -> Option<(usize, i64, i64)> {
    match cc {
        CallConv::SysVAmd64 => Some((6, 16, 8)),
        CallConv::Cdecl32 => Some((0, 8, 4)),
        CallConv::Aarch64 => Some((8, 16, 8)),
        CallConv::Win64 | CallConv::Arm | CallConv::ArmHardFloat => None,
    }
}

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
fn collect_label_stack_deltas(
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
                | Stmt::Comment(_) => {}
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

fn rewrite_body(
    body: &mut [Stmt],
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: &mut Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
    label_deltas: &HashMap<u64, Option<i64>>,
) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => {
                rewrite_expr(
                    target,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                *sp_delta = None;
            }
            Stmt::Assign { dst, src } => {
                rewrite_expr(
                    src,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                if is_stack_pointer_reg(dst, ctx) {
                    *sp_delta =
                        stack_delta_after_assignment(dst, src, *sp_delta, ctx, address_defs);
                }
            }
            Stmt::Store { addr, src, size } => {
                // Store's addr is an Lea — we need to rewrite the Lea itself
                // into a Reg reference when the lea points to a stack slot.
                try_promote_lea_to_local(
                    addr,
                    *size,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                rewrite_expr(
                    src,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
            }
            Stmt::Call { target, args, .. } => {
                rewrite_expr(
                    target,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                for a in args {
                    rewrite_expr(
                        a,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        *sp_delta,
                        address_defs,
                    );
                    promote_address_taken_stack_object(
                        a,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        *sp_delta,
                        address_defs,
                    );
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(
                        e,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        *sp_delta,
                        address_defs,
                    );
                }
                *sp_delta = None;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(
                    cond,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                let incoming = *sp_delta;
                let mut then_delta = incoming;
                rewrite_body(
                    then_body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut then_delta,
                    address_defs,
                    label_deltas,
                );
                let mut else_delta = incoming;
                if let Some(eb) = else_body {
                    rewrite_body(
                        eb,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        &mut else_delta,
                        address_defs,
                        label_deltas,
                    );
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
            Stmt::While { cond, body } => {
                rewrite_expr(
                    cond,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rewrite_body(
                    std::slice::from_mut(init.as_mut()),
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    sp_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_expr(
                    cond,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                let loop_entry = *sp_delta;
                let mut body_delta = loop_entry;
                rewrite_body(
                    body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_body(
                    std::slice::from_mut(step.as_mut()),
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                *sp_delta = merge_stack_deltas(loop_entry, body_delta);
            }
            Stmt::DoWhile { body, cond } => {
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_expr(
                    cond,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    body_delta,
                    address_defs,
                );
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::Push { value } => {
                rewrite_expr(
                    value,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                *sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(
                    discriminant,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                    address_defs,
                );
                let incoming = *sp_delta;
                let mut merged: Option<Option<i64>> = None;
                for (_, body) in cases.iter_mut() {
                    let mut case_delta = incoming;
                    rewrite_body(
                        body,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        &mut case_delta,
                        address_defs,
                        label_deltas,
                    );
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, case_delta),
                        None => case_delta,
                    });
                }
                if let Some(b) = default {
                    let mut default_delta = incoming;
                    rewrite_body(
                        b,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        &mut default_delta,
                        address_defs,
                        label_deltas,
                    );
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
            Stmt::Pop { .. } => {
                *sp_delta = sp_delta.map(|delta| delta + stack_word_size(ctx));
            }
            // Labels have no machine effect, but textual order is not control-
            // flow order. Restore the fixed-point state collected from every
            // fallthrough and goto predecessor (including targets that appear
            // after an epilogue in the rendered body).
            Stmt::Label(label) => {
                *sp_delta = label_deltas.get(label).copied().unwrap_or(None);
            }
            Stmt::Goto { .. } => *sp_delta = None,
            Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}

fn is_stack_pointer_reg(reg: &VReg, ctx: StackContext) -> bool {
    matches!(
        (ctx.cc, reg),
        (
            Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32),
            VReg::Phys(name)
        ) if matches!(name.as_str(), "rsp" | "esp")
    ) || matches!(
        (ctx.cc, reg),
        (
            Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64),
            VReg::Phys(name),
        ) if name == "sp"
    ) || matches!(
        (ctx.cc, reg),
        (None, VReg::Phys(name)) if matches!(name.as_str(), "rsp" | "esp")
    )
}

fn entry_stack_base(ctx: StackContext) -> &'static str {
    match ctx.cc {
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64) => "entry_sp",
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32) | None => "entry_rsp",
    }
}

fn stack_word_size(ctx: StackContext) -> i64 {
    match ctx.cc {
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Cdecl32) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    }
}

fn stack_delta_after_assignment(
    dst: &VReg,
    src: &Expr,
    before: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<i64> {
    if !is_stack_pointer_reg(dst, ctx) {
        return before;
    }
    let (base, disp) = resolve_stack_address(src, before, ctx, address_defs)?;
    if base == entry_stack_base(ctx) {
        Some(disp)
    } else {
        None
    }
}

fn merge_stack_deltas(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    (a == b).then_some(a).flatten()
}

fn body_falls_through(body: &[Stmt]) -> bool {
    let Some(last) = body.last() else {
        return true;
    };
    match last {
        Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } => false,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => body_falls_through(then_body) || else_body.as_deref().is_none_or(body_falls_through),
        _ => true,
    }
}

/// Promote a `Deref { addr: Lea { base: stack_base, disp, .. } }` into a
/// `Reg(local_name)` reference. Walks sub-expressions so nested derefs fold.
fn rewrite_expr(
    e: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    match e {
        Expr::Deref { addr, size } => {
            let size_val = *size;
            rewrite_expr(
                addr,
                map,
                stack_counter,
                local_counter,
                ctx,
                sp_delta,
                address_defs,
            );
            // After recursion, see whether the addr is a bare Lea of a
            // stack slot; if so, collapse the whole deref into a Reg ref.
            if let Some((key_base, key_disp)) =
                resolved_memory_slot(addr.as_ref(), sp_delta, ctx, address_defs)
            {
                let key = SlotKey {
                    base: key_base.clone(),
                    disp: key_disp,
                };
                if let Some(entry) = map.get_mut(&key) {
                    // A load reports the true access width — let it win for
                    // the declaration while preserving the widest owned span.
                    entry.declared_size = entry.declared_size.min(size_val);
                    entry.span_size = entry.span_size.max(size_val);
                    let alias = entry.name.clone();
                    *e = Expr::Reg(VReg::phys(alias));
                    return;
                }
                if matches!(ctx.cc, Some(CallConv::SysVAmd64 | CallConv::Win64)) {
                    let child_end = key_disp.saturating_add(i64::from(size_val));
                    let parent = map
                        .iter()
                        .filter(|(candidate, slot)| {
                            candidate.base == key_base
                                && candidate.disp < key_disp
                                && slot.span_size <= 8
                                && child_end
                                    <= candidate.disp.saturating_add(i64::from(slot.span_size))
                        })
                        .max_by_key(|(candidate, _)| candidate.disp)
                        .map(|(candidate, slot)| (candidate.disp, slot.name.clone()));
                    if let Some((parent_disp, parent_name)) = parent {
                        *e = extract_little_endian_subvalue(
                            parent_name,
                            (key_disp - parent_disp) as u8,
                            size_val,
                        );
                        return;
                    }
                }
                let alias = alloc_name(&key_base, key_disp, stack_counter, local_counter, ctx);
                map.insert(
                    key,
                    SlotVal {
                        name: alias.clone(),
                        declared_size: size_val,
                        span_size: size_val,
                    },
                );
                *e = Expr::Reg(VReg::phys(alias));
                return;
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(
                lhs,
                map,
                stack_counter,
                local_counter,
                ctx,
                sp_delta,
                address_defs,
            );
            rewrite_expr(
                rhs,
                map,
                stack_counter,
                local_counter,
                ctx,
                sp_delta,
                address_defs,
            );
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(
                cond,
                map,
                stack_counter,
                local_counter,
                ctx,
                sp_delta,
                address_defs,
            );
            rewrite_expr(
                if_true,
                map,
                stack_counter,
                local_counter,
                ctx,
                sp_delta,
                address_defs,
            );
            rewrite_expr(
                if_false,
                map,
                stack_counter,
                local_counter,
                ctx,
                sp_delta,
                address_defs,
            );
        }
        Expr::Un { src, .. } => rewrite_expr(
            src,
            map,
            stack_counter,
            local_counter,
            ctx,
            sp_delta,
            address_defs,
        ),
        Expr::Cast { expr, .. } => rewrite_expr(
            expr,
            map,
            stack_counter,
            local_counter,
            ctx,
            sp_delta,
            address_defs,
        ),
        Expr::FunctionTableEntry { index, .. } => rewrite_expr(
            index,
            map,
            stack_counter,
            local_counter,
            ctx,
            sp_delta,
            address_defs,
        ),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// Recover a constant stack/frame-relative call argument as the address of a
/// real C object. angr represents the same fact with `StackBaseOffset`; Ghidra
/// gives its stack pointer a `TypeSpacebase` and resolves offsets through the
/// function's local symbol map. The important invariant is shared: a stack
/// address is storage identity, not an integer expression over a renderable
/// machine register.
fn promote_address_taken_stack_object(
    expr: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    let recovered = constant_stack_address(expr, ctx).or_else(|| match expr {
        Expr::Reg(reg) => address_defs.get(reg).cloned(),
        _ => None,
    });
    let Some((base, disp)) = recovered else {
        return;
    };
    let (key_base, key_disp) = normalized_stack_slot(&base, disp, sp_delta, ctx);
    let key = SlotKey {
        base: key_base.clone(),
        disp: key_disp,
    };
    let pointer_size = match ctx.cc {
        Some(CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    };
    let entry = map.entry(key).or_insert_with(|| SlotVal {
        name: alloc_name(&key_base, key_disp, stack_counter, local_counter, ctx),
        declared_size: pointer_size,
        span_size: pointer_size,
    });
    let object = VReg::phys(entry.name.clone());
    // A frame-local object starts at a negative offset and grows toward the
    // frame base on the supported downward-growing stacks. Reserving the whole
    // interval to the base is conservative (it may include padding or adjacent
    // machine slots), but unlike a pointer-sized scalar it cannot be overrun by
    // a constructor whose recovered source type is not yet known. Cap at the C
    // representation's bounded u16 extent so hostile displacements cannot make
    // the renderer request an unbounded object.
    let size = if key_disp < 0 {
        u16::try_from(key_disp.unsigned_abs())
            .unwrap_or(u16::MAX)
            .max(u16::from(pointer_size))
    } else {
        u16::from(pointer_size)
    };
    *expr = Expr::StackAddr { object, size };
}

/// Recover definitions that carry a constant frame/stack address into a call.
///
/// These registers are already SSA-versioned by the value model (`rax#4`,
/// `rax#8`, ...), so their identity is path-stable. Keeping this small semantic
/// map is the minimum equivalent of looking through an AIL virtual-variable or
/// a Ghidra Varnode definition; it avoids asking the general expression pass to
/// move an address computation across unrelated effects.
fn collect_stack_address_defs(body: &[Stmt], ctx: StackContext) -> HashMap<VReg, (String, i64)> {
    fn walk_direct(
        body: &[Stmt],
        out: &mut HashMap<VReg, (String, i64)>,
        ctx: StackContext,
        sp_delta: &mut Option<i64>,
    ) {
        for stmt in body {
            match stmt {
                Stmt::Assign { dst, src } => {
                    let address = resolve_stack_address(src, *sp_delta, ctx, out);
                    if is_stack_pointer_reg(dst, ctx) {
                        *sp_delta = address.and_then(|(base, disp)| {
                            (base == entry_stack_base(ctx)).then_some(disp)
                        });
                    } else if matches!(dst, VReg::Phys(name) if is_active_stack_base(name, ctx)) {
                        // Architectural frame bases define the coordinate
                        // system used by DWARF and local naming. In particular,
                        // `rbp = rsp` is a frame establishment, not an immutable
                        // SSA address alias to rebase as `entry_rsp`.
                        out.remove(dst);
                    } else if let Some(address) = address {
                        out.insert(dst.clone(), address);
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    let incoming = *sp_delta;
                    let mut then_delta = incoming;
                    walk_direct(then_body, out, ctx, &mut then_delta);
                    let mut else_delta = incoming;
                    if let Some(body) = else_body {
                        walk_direct(body, out, ctx, &mut else_delta);
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
                    walk_direct(body, out, ctx, &mut body_delta);
                    *sp_delta = merge_stack_deltas(incoming, body_delta);
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    walk_direct(std::slice::from_ref(init.as_ref()), out, ctx, sp_delta);
                    let loop_entry = *sp_delta;
                    let mut body_delta = loop_entry;
                    walk_direct(body, out, ctx, &mut body_delta);
                    walk_direct(
                        std::slice::from_ref(step.as_ref()),
                        out,
                        ctx,
                        &mut body_delta,
                    );
                    *sp_delta = merge_stack_deltas(loop_entry, body_delta);
                }
                Stmt::Switch { cases, default, .. } => {
                    let incoming = *sp_delta;
                    let mut merged: Option<Option<i64>> = None;
                    for (_, body) in cases {
                        let mut case_delta = incoming;
                        walk_direct(body, out, ctx, &mut case_delta);
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, case_delta),
                            None => case_delta,
                        });
                    }
                    if let Some(body) = default {
                        let mut default_delta = incoming;
                        walk_direct(body, out, ctx, &mut default_delta);
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
                Stmt::Label(_) => {}
                _ => {}
            }
        }
    }

    let mut defs = HashMap::new();
    let mut sp_delta = Some(0);
    walk_direct(body, &mut defs, ctx, &mut sp_delta);
    defs
}

/// Resolve an expression that carries a stable stack address. Stack-pointer
/// values are converted to an architectural-entry displacement immediately;
/// SSA aliases can then be used after later stack-pointer adjustments without
/// changing which source object they identify.
fn resolve_stack_address(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64)> {
    fn base_address(
        reg: &VReg,
        sp_delta: Option<i64>,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
    ) -> Option<(String, i64)> {
        if is_stack_pointer_reg(reg, ctx) {
            return sp_delta.map(|disp| (entry_stack_base(ctx).to_string(), disp));
        }
        if let Some(address) = address_defs.get(reg) {
            return Some(address.clone());
        }
        match reg {
            VReg::Phys(name) if is_active_stack_base(name, ctx) => Some((name.clone(), 0)),
            _ => None,
        }
    }

    match expr {
        Expr::Reg(reg) => base_address(reg, sp_delta, ctx, address_defs),
        Expr::Lea {
            base: Some(base),
            index: None,
            disp,
            segment: None,
            ..
        } => {
            let (base, base_disp) = base_address(base, sp_delta, ctx, address_defs)?;
            Some((base, base_disp.checked_add(*disp)?))
        }
        Expr::Bin { op, lhs, rhs } => {
            let (base, base_disp) = resolve_stack_address(lhs, sp_delta, ctx, address_defs)?;
            let Expr::Const(amount) = rhs.as_ref() else {
                return None;
            };
            let adjustment = match op {
                crate::ir::types::BinOp::Add => *amount,
                crate::ir::types::BinOp::Sub => amount.checked_neg()?,
                _ => return None,
            };
            Some((base, base_disp.checked_add(adjustment)?))
        }
        _ => None,
    }
}

/// Resolve only concrete load/store addresses. Direct `sp` accesses retain
/// their current-pass spelling so ARM push/pop rematerialization can still see
/// `[sp]`; an SSA alias such as `r7#1 = sp` instead uses its frozen entry-stack
/// displacement.
fn resolved_memory_slot(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64)> {
    let Expr::Lea {
        base: Some(base),
        index: None,
        disp,
        segment: None,
        ..
    } = expr
    else {
        return None;
    };
    if let VReg::Phys(name) = base {
        if is_active_stack_base(name, ctx) {
            return Some(normalized_stack_slot(name, *disp, sp_delta, ctx));
        }
    }
    let (base, base_disp) = address_defs.get(base)?.clone();
    Some((base, base_disp.checked_add(*disp)?))
}

fn constant_stack_address(expr: &Expr, ctx: StackContext) -> Option<(String, i64)> {
    match expr {
        Expr::Lea {
            base: Some(VReg::Phys(base)),
            index: None,
            disp,
            segment: None,
            ..
        } if is_active_stack_base(base, ctx) => Some((base.clone(), *disp)),
        Expr::Bin { op, lhs, rhs } => {
            let Expr::Reg(VReg::Phys(base)) = lhs.as_ref() else {
                return None;
            };
            let Expr::Const(amount) = rhs.as_ref() else {
                return None;
            };
            if !is_active_stack_base(base, ctx) {
                return None;
            }
            let disp = match op {
                crate::ir::types::BinOp::Add => *amount,
                crate::ir::types::BinOp::Sub => amount.checked_neg()?,
                _ => return None,
            };
            Some((base.clone(), disp))
        }
        _ => None,
    }
}

fn extract_little_endian_subvalue(parent: String, byte_offset: u8, size: u8) -> Expr {
    let wide_parent = Expr::Cast {
        signed: false,
        width: 8,
        expr: Box::new(Expr::Reg(VReg::phys(parent))),
    };
    let shifted = Expr::Bin {
        op: crate::ir::types::BinOp::Shr,
        lhs: Box::new(wide_parent),
        rhs: Box::new(Expr::Const(i64::from(byte_offset) * 8)),
    };
    Expr::Cast {
        signed: false,
        width: size,
        expr: Box::new(shifted),
    }
}

/// Store-address Lea: turn the full `&[base+disp]` into a `Reg(local)`.
fn try_promote_lea_to_local(
    addr: &mut Expr,
    size: u8,
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    // A later narrower read at the exact same address can narrow the declaration,
    // while `span_size` retains the bytes this store defined for overlap recovery.
    let Some((key_base, key_disp)) = resolved_memory_slot(addr, sp_delta, ctx, address_defs) else {
        return;
    };
    let key = SlotKey {
        base: key_base.clone(),
        disp: key_disp,
    };
    let entry = map.entry(key).or_insert_with(|| SlotVal {
        name: alloc_name(&key_base, key_disp, stack_counter, local_counter, ctx),
        declared_size: size,
        span_size: size,
    });
    entry.declared_size = entry.declared_size.min(size);
    entry.span_size = entry.span_size.max(size);
    let alias = entry.name.clone();
    *addr = Expr::Reg(VReg::phys(alias));
}

/// Express an rsp-relative slot against the architectural entry rsp when the
/// current delta is known. This makes `[rsp+16]` after one push the same slot as
/// `[entry_rsp+8]`, and gives naming an ABI-stable displacement.
fn normalized_stack_slot(
    base: &str,
    disp: i64,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> (String, i64) {
    if base == "rsp" || (base == "esp" && ctx.cc == Some(CallConv::Cdecl32)) {
        if let Some(delta) = sp_delta {
            return ("entry_rsp".to_string(), disp + delta);
        }
    }
    (base.to_string(), disp)
}

fn alloc_name(
    base: &str,
    disp: i64,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
) -> String {
    if disp == 0 {
        return "stack_top".to_string();
    }
    if (is_frame_pointer(base) || base == "entry_sp") && disp < 0 {
        // Name frame locals by their offset (`[rbp-0xc]` -> `local_c`), the
        // Ghidra/IDA convention. The offset is genuine recovered information and
        // lets an offset-aware consumer align our locals to the ground truth,
        // rather than an appearance-order counter that carries no such signal.
        *local_counter += 1; // keep the counter advancing for any legacy callers
        return format!("local_{:x}", disp.unsigned_abs());
    }
    // A positive frame-pointer offset at or above the ABI's first stacked-argument
    // slot IS AN INCOMING PARAMETER, not a local. Naming it `stack_N` invents a
    // local the function never assigns — which is precisely what the def-before-use
    // verifier reports for `sum_arg7`..`sum_arg10` (`stack_0 is read but never
    // defined`) — and leaves it out of the signature, so the recompiled function
    // reads uninitialised memory instead of its own argument.
    if is_frame_pointer(base) && disp > 0 {
        if let Some((reg_args, first, stride)) = ctx.cc.and_then(stack_arg_layout) {
            if disp >= first && (disp - first) % stride == 0 {
                let candidate = reg_args + ((disp - first) / stride) as usize;
                if ctx.parameter_count.is_none_or(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
        }
    }
    // A frame-pointer-omitted x86 function addresses incoming stack arguments
    // relative to the architectural entry stack pointer.  The return address
    // occupies the first machine word: SysV AMD64's stacked arguments therefore
    // start at entry_rsp+8 after six register arguments, while cdecl32 starts at
    // entry_esp+4 and has no integer register arguments.  `esp` is normalised to
    // the canonical `entry_rsp` spelling above so both modes share slot identity.
    if base == "entry_rsp" {
        match ctx.cc {
            Some(CallConv::SysVAmd64) if disp >= 8 && (disp - 8) % 8 == 0 => {
                let candidate = 6 + ((disp - 8) / 8) as usize;
                if ctx.parameter_count.is_none_or(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
            Some(CallConv::Cdecl32) if disp >= 4 && (disp - 4) % 4 == 0 => {
                let candidate = ((disp - 4) / 4) as usize;
                if ctx.parameter_count.is_none_or(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
            _ => {}
        }
    }
    // Positive offsets from rsp are outgoing-arg / scratch slots; negative
    // offsets from rsp are the function's own frame carved out by `sub
    // rsp, N`. We still use `stack_N` for both — a future pass can decide
    // to relabel based on the prologue's sub rsp amount.
    let n = *stack_counter;
    *stack_counter += 1;
    format!("stack_{}", n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }
    fn lea(base: &str, disp: i64) -> Expr {
        Expr::Lea {
            base: Some(reg(base)),
            index: None,
            scale: 0,
            disp,
            segment: None,
        }
    }
    fn deref_of(base: &str, disp: i64, size: u8) -> Expr {
        Expr::Deref {
            addr: Box::new(lea(base, disp)),
            size,
        }
    }

    fn promoted(base: &str, disp: i64, cc: Option<CallConv>) -> String {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of(base, disp, 4),
            }],
        };
        promote_stack_locals_typed(&mut f, cc);
        match &f.body[0] {
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(n)),
                ..
            } => n.clone(),
            other => panic!("expected a promoted register, got {other:?}"),
        }
    }

    #[test]
    fn a_positive_frame_offset_is_a_stack_passed_argument_not_a_local() {
        // SysV AMD64: [rbp] is the saved frame pointer, [rbp+8] the return address,
        // so [rbp+16] upward are the arguments that did not fit in the six integer
        // registers. Calling them `stack_N` invents a local the function never
        // assigns, and leaves the parameter out of the signature.
        let cc = Some(CallConv::SysVAmd64);
        assert_eq!(promoted("rbp", 16, cc), "arg6");
        assert_eq!(promoted("rbp", 24, cc), "arg7");
        assert_eq!(promoted("rbp", 32, cc), "arg8");
        assert_eq!(promoted("rbp", 40, cc), "arg9");
    }

    #[test]
    fn a_locked_two_parameter_prototype_rejects_spurious_stack_arguments() {
        let mut f = Function {
            name: "ackermann".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", 40, 8),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rsp", 8, 8),
                },
            ],
        };

        let sizes = promote_stack_locals_typed_with_parameter_count(
            &mut f,
            Some(CallConv::SysVAmd64),
            Some(2),
        );

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_1"
        ));
        assert!(!sizes.keys().any(|name| name.starts_with("arg")));
    }

    #[test]
    fn cdecl32_arguments_start_at_ebp_plus_eight_in_four_byte_slots() {
        let cc = Some(CallConv::Cdecl32);
        assert_eq!(promoted("ebp", 8, cc), "arg0");
        assert_eq!(promoted("ebp", 12, cc), "arg1");
        assert_eq!(promoted("ebp", 16, cc), "arg2");
        assert_eq!(promoted("ebp", -4, cc), "local_4");
    }

    #[test]
    fn an_unchanged_entry_stack_pointer_exposes_optimized_sysv_stack_arguments() {
        // GCC/Clang -O2 omit the frame pointer for leaf functions such as
        // `sum_arg10`. With no prologue adjustment, [rsp] is the return address
        // and [rsp+8], [rsp+16], ... are the arguments after r9. Treating those
        // reads as `stack_N` locals truncates the C signature at six arguments
        // and makes the rebuilt function consume uninitialised locals.
        let mut f = Function {
            name: "sum_arg8".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 8, 4),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rsp", 16, 8),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg6"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg7"
        ));
        assert_eq!(sizes.get("arg6"), Some(&4));
        assert_eq!(sizes.get("arg7"), Some(&8));
    }

    #[test]
    fn an_unchanged_entry_esp_exposes_optimized_cdecl32_arguments() {
        let mut f = Function {
            name: "cdecl_pair".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("esp", 4, 4),
                },
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("esp", 8, 4),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg0"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg1"
        ));
        assert_eq!(sizes.get("arg0"), Some(&4));
        assert_eq!(sizes.get("arg1"), Some(&4));
    }

    #[test]
    fn cdecl32_callee_saved_pushes_are_normalized_before_mapping_arguments() {
        fn subtract_esp() -> Stmt {
            Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(4)),
                },
            }
        }

        let mut f = Function {
            name: "rand_str".into(),
            entry_va: 0,
            body: vec![
                subtract_esp(),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("edi")),
                    size: 4,
                },
                subtract_esp(),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("esi")),
                    size: 4,
                },
                subtract_esp(),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("ebx")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("esi"),
                    src: deref_of("esp", 20, 4),
                },
                Stmt::Assign {
                    dst: reg("ebx"),
                    src: deref_of("esp", 16, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert!(matches!(
            &f.body[6],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg1"
        ));
        assert!(matches!(
            &f.body[7],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg0"
        ));
    }

    #[test]
    fn an_adjusted_stack_pointer_does_not_invent_incoming_arguments() {
        // Once a function carves out a frame, a positive displacement from the
        // new rsp can be a local or outgoing-call slot. It is not safe to map it
        // to an incoming parameter without normalising the stack delta.
        let mut f = Function {
            name: "has_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 16, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
    }

    #[test]
    fn a_loop_label_preserves_a_consistent_stack_slot_identity() {
        let mut f = Function {
            name: "loop_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Store {
                    addr: lea("rsp", 8),
                    src: Expr::Reg(reg("rdi")),
                    size: 4,
                },
                Stmt::Label(0x1010),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rsp", 8, 4),
                },
                Stmt::Goto { target: 0x1010 },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
        assert!(matches!(
            &f.body[3],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
    }

    #[test]
    fn a_goto_after_an_epilogue_keeps_the_target_frame_depth() {
        let adjust = |op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(40)),
            },
        };
        let mut f = Function {
            name: "optimized_recursive_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Push {
                    value: Expr::Reg(reg("rbx")),
                },
                adjust(crate::ir::types::BinOp::Sub),
                Stmt::Store {
                    addr: lea("rsp", 24),
                    src: Expr::Reg(reg("rax")),
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![Stmt::Goto { target: 0x1680 }],
                    else_body: None,
                },
                adjust(crate::ir::types::BinOp::Add),
                Stmt::Pop { target: reg("rbx") },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
                Stmt::Label(0x1680),
                Stmt::Store {
                    addr: lea("rsp", 24),
                    src: Expr::Reg(reg("rdi")),
                    size: 8,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count(&mut f, Some(CallConv::SysVAmd64), Some(2));

        let first = match &f.body[2] {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } => name,
            other => panic!("expected promoted first store, got {other:?}"),
        };
        let target = match &f.body[8] {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } => name,
            other => panic!("expected promoted target store, got {other:?}"),
        };
        assert_eq!(first, target);
    }

    #[test]
    fn a_returning_if_arm_does_not_poison_the_fallthrough_stack_state() {
        let adjust = |op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(32)),
            },
        };
        let mut f = Function {
            name: "early_return_frame".into(),
            entry_va: 0,
            body: vec![
                adjust(crate::ir::types::BinOp::Sub),
                Stmt::Store {
                    addr: lea("rsp", 8),
                    src: Expr::Reg(reg("rdi")),
                    size: 4,
                },
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![
                        adjust(crate::ir::types::BinOp::Add),
                        Stmt::Return {
                            value: Some(Expr::Const(0)),
                        },
                    ],
                    else_body: None,
                },
                Stmt::Label(0x1010),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rsp", 8, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[4],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
    }

    #[test]
    fn callee_saved_pushes_are_normalized_before_mapping_stack_arguments() {
        // Clang -O2 `sum_arg8` pushes rbx, then reads a6 from [rsp+16] and a7
        // from [rsp+24]. GCC `sum_arg10` has the same shape with rbp. The
        // current rsp is entry_rsp-8, so those addresses are entry_rsp+8 and
        // entry_rsp+16 respectively.
        let mut f = Function {
            name: "sum_arg8".into(),
            entry_va: 0,
            body: vec![
                Stmt::Push {
                    value: Expr::Reg(reg("rbx")),
                },
                Stmt::Assign {
                    dst: reg("r10"),
                    src: deref_of("rsp", 16, 4),
                },
                Stmt::Assign {
                    dst: reg("r11"),
                    src: deref_of("rsp", 24, 4),
                },
                Stmt::Pop { target: reg("rbx") },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg6"
        ));
        assert!(matches!(
            &f.body[2],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg7"
        ));
    }

    #[test]
    fn aarch64_stacked_arguments_start_after_eight_registers() {
        let cc = Some(CallConv::Aarch64);
        assert_eq!(promoted("x29", 16, cc), "arg8");
        assert_eq!(promoted("x29", 24, cc), "arg9");
    }

    #[test]
    fn arm_frame_pointer_snapshot_promotes_sp_relative_locals() {
        use crate::ir::types::BinOp;

        // GCC Cortex-M -O0 frame from DecBench's real `console_getc`:
        //
        //   push {r7}; sub sp, #20; mov r7, sp
        //   str r0, [r7, #4]; strb ..., [r7, #15]
        //
        // r7 is an SSA snapshot of the adjusted stack pointer, not a general
        // address. The two accesses are entry_sp-20 and entry_sp-9 and must
        // retain that stable source-storage identity throughout the function.
        let mut f = Function {
            name: "console_getc".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: lea("sp", 0),
                    src: Expr::Reg(reg("r7")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(20)),
                    },
                },
                Stmt::Assign {
                    dst: reg("r7#1"),
                    src: Expr::Reg(reg("sp")),
                },
                Stmt::Store {
                    addr: lea("r7#1", 4),
                    src: Expr::Reg(reg("r0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("r7#1", 15),
                    src: Expr::Const(0),
                    size: 1,
                },
                Stmt::Assign {
                    dst: reg("r3#1"),
                    src: deref_of("r7#1", 15, 1),
                },
                Stmt::Return { value: None },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::Arm));

        assert!(matches!(
            &f.body[4],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_14"
        ));
        assert!(matches!(
            &f.body[5],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_9"
        ));
        assert!(matches!(
            &f.body[6],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_9"
        ));
        assert_eq!(sizes.get("local_14"), Some(&4));
        assert_eq!(sizes.get("local_9"), Some(&1));
    }

    #[test]
    fn frame_locals_and_return_address_slots_are_unaffected() {
        let cc = Some(CallConv::SysVAmd64);
        // Negative frame offsets are the function's own locals.
        assert_eq!(promoted("rbp", -0xc, cc), "local_c");
        // Below the first stacked-argument slot ([rbp+8] is the return address).
        assert_eq!(promoted("rbp", 8, cc), "stack_0");
    }

    #[test]
    fn an_abi_we_do_not_model_keeps_the_conservative_name() {
        // Win64 (32-byte shadow space) and ARM32 have different layouts and no
        // fixture coverage here. Guessing at an ABI would invent a parameter that
        // does not exist, so those keep `stack_N`.
        assert_eq!(promoted("rbp", 16, Some(CallConv::Win64)), "stack_0");
        assert_eq!(promoted("rbp", 16, Some(CallConv::Arm)), "stack_0");
        assert_eq!(promoted("rbp", 16, None), "stack_0");
    }

    #[test]
    fn a_misaligned_positive_offset_is_not_an_argument_slot() {
        // Stacked arguments are 8-aligned from the first slot; anything else is not
        // an argument (it could be a field of a by-value struct).
        assert_eq!(promoted("rbp", 20, Some(CallConv::SysVAmd64)), "stack_0");
    }

    #[test]
    fn load_of_stack_slot_becomes_named_local() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rsp", 0x158, 8),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("stack_0")));
        }
    }

    #[test]
    fn store_to_stack_slot_becomes_named_local_on_lhs() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: lea("rsp", 0x10),
                src: Expr::Reg(reg("rax")),
                size: 8,
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Store { addr, src, .. } = &f.body[0] {
            assert_eq!(*addr, Expr::Reg(reg("stack_0")));
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn same_slot_reused_gets_same_name() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", 0x10),
                    src: Expr::Const(1),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 0x10, 8),
                },
            ],
        };
        promote_stack_locals(&mut f);
        let names: Vec<_> = f
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Store { addr, .. } => Some(addr.clone()),
                Stmt::Assign { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names[0], Expr::Reg(reg("stack_0")));
        assert_eq!(names[1], Expr::Reg(reg("stack_0")));
    }

    #[test]
    fn different_slots_get_distinct_names() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", 0x10),
                    src: Expr::Const(1),
                    size: 8,
                },
                Stmt::Store {
                    addr: lea("rsp", 0x18),
                    src: Expr::Const(2),
                    size: 8,
                },
            ],
        };
        promote_stack_locals(&mut f);
        let addrs: Vec<_> = f
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Store { addr, .. } => Some(addr.clone()),
                _ => None,
            })
            .collect();
        assert_ne!(addrs[0], addrs[1]);
    }

    #[test]
    fn frame_pointer_negative_offsets_get_local_prefix() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rbp", -0x8, 4),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            // Named by frame offset (Ghidra/IDA convention): `[rbp-0x8]` -> `local_8`.
            assert_eq!(*src, Expr::Reg(reg("local_8")));
        }
    }

    #[test]
    fn same_slot_read_and_write_share_one_local_name() {
        // A store to and a load from the same frame slot must resolve to a
        // single local (its def/use chain stays intact), even though the store
        // path can't see the access width.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0xc),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", -0xc, 4),
                },
            ],
        };
        promote_stack_locals(&mut f);
        let store_name = match &f.body[0] {
            Stmt::Store { addr, .. } => addr.clone(),
            _ => panic!("expected store"),
        };
        let load_name = match &f.body[1] {
            Stmt::Assign { src, .. } => src.clone(),
            _ => panic!("expected assign"),
        };
        assert_eq!(store_name, Expr::Reg(reg("local_c")));
        assert_eq!(load_name, Expr::Reg(reg("local_c")));
    }

    #[test]
    fn lea_call_argument_becomes_address_of_the_same_recovered_object() {
        let mut f = Function {
            name: "construct".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "Widget::Widget".into(),
                    },
                    args: vec![lea("rbp", -0x20)],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rbp", -0x20, 4),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_20"
        ));
        assert_eq!(sizes.get("local_20"), Some(&4));
    }

    #[test]
    fn reconstructed_frame_arithmetic_call_argument_becomes_stack_object_address() {
        let mut f = Function {
            name: "construct_after_expression_reconstruction".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Addr(0x1000),
                args: vec![Expr::Bin {
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rbp"))),
                    rhs: Box::new(Expr::Const(32)),
                }],
                dst: None,
                call_spec: None,
            }],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
        assert_eq!(sizes.get("local_20"), Some(&8));
    }

    #[test]
    fn repurposed_rbp_value_is_not_promoted_as_a_stack_object_address() {
        let value = Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("rbp"))),
            rhs: Box::new(Expr::Const(2)),
        };
        let mut f = Function {
            name: "optimized_caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("rsi"))),
                    },
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "callee".into(),
                    },
                    args: vec![value.clone()],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call: {f:#?}");
        };
        assert_eq!(args, &[value]);
        assert!(
            sizes.is_empty(),
            "repurposed rbp invented locals: {sizes:?}"
        );
    }

    #[test]
    fn stack_address_definition_reaching_a_call_is_materialised() {
        // GCC -O0 computes `rax#4 = rbp - 32`, then argument reconstruction
        // passes `rax#4` to the constructor. The address-producing definition
        // is not adjacent to the call, so ordinary expression reconstruction
        // deliberately leaves it statement-rooted.
        let address = reg("rax#4");
        let mut f = Function {
            name: "construct_via_value".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: address.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Reg(address)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
    }

    #[test]
    fn architectural_frame_pointer_is_not_rebased_as_an_ssa_alias() {
        // `rbp = rsp` establishes the x86 frame coordinate system. It is not
        // an ordinary immutable address value: DWARF and every later frame-slot
        // pass intentionally keep `rbp-N` as `local_N`. Rebasing it to entry_rsp
        // turns address-taken frame objects into unrelated `stack_N` storage.
        let address = reg("rax#4");
        let mut f = Function {
            name: "construct_with_frame_prologue".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                Stmt::Assign {
                    dst: address.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Reg(address)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[2] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
    }

    #[test]
    fn a_narrow_read_inside_a_wide_spill_extracts_the_parent_value() {
        // GCC -O0 `dist2(struct pt a, struct pt b)` spills the packed 8-byte
        // argument with `mov [rbp-0x18], rdi`, then reads `a.y` with
        // `mov edx, [rbp-0x14]`. The latter is the upper half of local_18, not
        // a new local_14 that nothing defines.
        let mut f = Function {
            name: "dist2".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0x18),
                    src: Expr::Reg(reg("rdi")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rbp", -0x14, 4),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Assign { src, .. } = &f.body[1] else {
            panic!("expected the upper-half load");
        };
        assert!(
            matches!(
                src,
                Expr::Cast {
                    signed: false,
                    width: 4,
                    expr,
                } if matches!(
                    expr.as_ref(),
                    Expr::Bin {
                        op: crate::ir::types::BinOp::Shr,
                        lhs,
                        rhs,
                    } if matches!(
                        lhs.as_ref(),
                        Expr::Cast {
                            signed: false,
                            width: 8,
                            expr,
                        } if matches!(expr.as_ref(), Expr::Reg(VReg::Phys(name)) if name == "local_18")
                    ) && matches!(rhs.as_ref(), Expr::Const(32))
                )
            ),
            "the high field must be extracted from the defined parent spill: {src:#?}"
        );
        assert!(
            !sizes.contains_key("local_14"),
            "an overlapping field must not become an undefined standalone local"
        );
    }

    #[test]
    fn stack_top_zero_offset_gets_special_name() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rsp", 0, 8),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("stack_top")));
        }
    }

    #[test]
    fn colliding_stack_top_views_have_one_deterministic_wide_declaration() {
        // A mixed-width stack function can address the same rendered
        // `stack_top` role through distinct machine views. Those are distinct
        // SlotKeys (`entry_rsp` and `esp`) but ONE C identifier. Collecting the
        // HashMap values directly let whichever key iterated last choose the
        // declaration, so identical decompilations alternated between `char`
        // and `long` (observed on blinded bin_209.elf).
        for _ in 0..64 {
            let mut f = Function {
                name: "mixed_stack_top".into(),
                entry_va: 0,
                body: vec![
                    Stmt::Assign {
                        dst: reg("rax"),
                        src: deref_of("rsp", 0, 8),
                    },
                    Stmt::Assign {
                        dst: reg("al"),
                        src: deref_of("esp", 0, 1),
                    },
                ],
            };

            let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));
            assert_eq!(
                sizes.get("stack_top"),
                Some(&8),
                "one rendered identifier must use the widest compatible storage view"
            );
        }
    }

    #[test]
    fn non_stack_base_is_unchanged() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rdi", 8, 8),
            }],
        };
        let orig = f.clone();
        promote_stack_locals(&mut f);
        assert_eq!(f, orig, "rdi-based deref must not be promoted");
    }

    #[test]
    fn stack_pointer_update_is_not_touched() {
        // `%rsp = %rsp - 8;` must stay — it's a stack-pointer adjustment,
        // not a slot access.
        use crate::ir::types::BinOp;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }],
        };
        let orig = f.clone();
        promote_stack_locals(&mut f);
        assert_eq!(f, orig);
    }
}
