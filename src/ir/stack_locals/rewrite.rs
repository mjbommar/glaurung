//! Rewrite statements and expressions against the recovered slot map.
//!
//! This is the mutating half of the pass. `rewrite_body` walks the statement
//! tree once, tracking the stack-pointer delta, and hands every expression to
//! `rewrite_expr`, which folds a frame access into a `Reg(local)`. Slots that
//! only later turn out to be address-taken are repaired by a second walk in
//! `reconcile_late_address_taken_objects`. Nothing here decides which frame
//! coordinate an expression denotes (`address_recovery`) or what a slot is
//! called (`alloc_name` in the parent); it decides what the statement becomes.

use std::collections::HashMap;

use super::slot_views::{compose_little_endian_slots, extract_little_endian_subvalue};
use super::{
    alloc_name, body_falls_through, bounded_overlap, bounded_scalar_slot, escaped_stack_address,
    is_active_stack_base, is_arm_frame_pointer, is_stack_pointer_reg, merge_stack_deltas,
    normalized_stack_slot, resolve_stack_address, resolved_memory_address, resolved_memory_slot,
    stack_arg_layout, stack_assignment_object_address, stack_delta_after_assignment,
    stack_object_address, stack_object_constant_address, stack_word_size, SlotKey, SlotNames,
    SlotVal, StackContext,
};
use crate::ir::ast::{Expr, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

pub(super) fn rewrite_body(
    body: &mut [Stmt],
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: &mut Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
    label_deltas: &HashMap<u64, Option<i64>>,
) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => {
                rewrite_expr(target, map, names, ctx, *sp_delta, address_defs);
                *sp_delta = None;
            }
            Stmt::Assign { dst, src } => {
                rewrite_expr(src, map, names, ctx, *sp_delta, address_defs);
                // `mov %rsp,%rbp` DEFINES a coordinate system; it does not
                // compute a loop bound. `collect_stack_address_defs` already
                // treats a write to an architectural frame base that way, and
                // the frame base is one past the end of whatever object ends at
                // it — so without the same rule here, `-O0`'s prologue rendered
                // as a dead `stack_0 = &local_c[0] + 12` and stopped being
                // recognised as a prologue at all. Only the END-POINTER reading
                // is withheld: an address INSIDE a known object is still that
                // object's address whatever the destination register is.
                let establishes_a_frame_base = matches!(
                    dst, VReg::Phys(name) if is_active_stack_base(name, ctx)
                );
                if !is_stack_pointer_reg(dst, ctx) {
                    if let Some(object_addr) = stack_assignment_object_address(
                        src,
                        map,
                        *sp_delta,
                        ctx,
                        address_defs,
                        !establishes_a_frame_base,
                    ) {
                        *src = object_addr;
                    }
                }
                if is_stack_pointer_reg(dst, ctx) {
                    *sp_delta =
                        stack_delta_after_assignment(dst, src, *sp_delta, ctx, address_defs);
                }
            }
            Stmt::Store { addr, src, size } => {
                // Whether this store addressed MEMORY before promotion. A store
                // whose address is already a bare register is a pointer write
                // (`*p = v`) and must never be mistaken for a slot assignment —
                // see `argument_slot_assignment`.
                let addressed_memory = matches!(addr, Expr::Lea { .. });
                // Store's addr is an Lea — we need to rewrite the Lea itself
                // into a Reg reference when the lea points to a stack slot.
                try_promote_lea_to_local(addr, *size, map, names, ctx, *sp_delta, address_defs);
                rewrite_expr(src, map, names, ctx, *sp_delta, address_defs);
                // A by-reference closure capture stores a frame address into a
                // field before the closure is called. This escape is every bit
                // as strong as passing the address directly to a callee: the
                // pointee must retain storage identity instead of rendering as
                // arithmetic on an uninitialised frame register.
                promote_address_taken_stack_object(src, map, names, ctx, *sp_delta, address_defs);
                if addressed_memory {
                    if let Some(parameter) = argument_slot_assignment(addr, *size, ctx) {
                        *s = Stmt::Assign {
                            dst: parameter,
                            src: src.clone(),
                        };
                    }
                }
            }
            Stmt::Call { target, args, .. } => {
                rewrite_expr(target, map, names, ctx, *sp_delta, address_defs);
                for a in args {
                    rewrite_expr(a, map, names, ctx, *sp_delta, address_defs);
                    promote_address_taken_stack_object(a, map, names, ctx, *sp_delta, address_defs);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e, map, names, ctx, *sp_delta, address_defs);
                }
                *sp_delta = None;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, map, names, ctx, *sp_delta, address_defs);
                let incoming = *sp_delta;
                let mut then_delta = incoming;
                rewrite_body(
                    then_body,
                    map,
                    names,
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
                        names,
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
                rewrite_expr(cond, map, names, ctx, *sp_delta, address_defs);
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    names,
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
                    names,
                    ctx,
                    sp_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_expr(cond, map, names, ctx, *sp_delta, address_defs);
                let loop_entry = *sp_delta;
                let mut body_delta = loop_entry;
                rewrite_body(
                    body,
                    map,
                    names,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_body(
                    std::slice::from_mut(step.as_mut()),
                    map,
                    names,
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
                    names,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_expr(cond, map, names, ctx, body_delta, address_defs);
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::Push { value } => {
                rewrite_expr(value, map, names, ctx, *sp_delta, address_defs);
                *sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(discriminant, map, names, ctx, *sp_delta, address_defs);
                let incoming = *sp_delta;
                let mut merged: Option<Option<i64>> = None;
                for (_, body) in cases.iter_mut() {
                    let mut case_delta = incoming;
                    rewrite_body(
                        body,
                        map,
                        names,
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
                        names,
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
            Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

/// Promote a `Deref { addr: Lea { base: stack_base, disp, .. } }` into a
/// `Reg(local_name)` reference. Walks sub-expressions so nested derefs fold.
fn rewrite_expr(
    e: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    match e {
        Expr::Deref { addr, size } => {
            let size_val = *size;
            rewrite_expr(addr, map, names, ctx, sp_delta, address_defs);
            if let Some(source_value) = bounded_overlap::aapcs_top_padding_scalar_value(
                addr.as_ref(),
                size_val,
                map,
                sp_delta,
                ctx,
                address_defs,
            ) {
                *e = source_value;
                return;
            }
            if let Some(object_addr) =
                stack_object_address(addr.as_ref(), size_val, map, sp_delta, ctx, address_defs)
            {
                **addr = object_addr;
                return;
            }
            // After recursion, see whether the addr is a bare Lea of a
            // stack slot; if so, collapse the whole deref into a Reg ref.
            if let Some((key_base, key_disp)) =
                resolved_memory_slot(addr.as_ref(), sp_delta, ctx, address_defs)
            {
                let ordinary_key = SlotKey {
                    base: key_base.clone(),
                    disp: key_disp,
                };
                let key = bounded_scalar_slot(map, &key_base, key_disp, size_val, sp_delta, ctx)
                    .map(|(key, _)| key)
                    .unwrap_or(ordinary_key);
                if let Some(entry) = map.get_mut(&key) {
                    // A narrower load at the same starting address is a view
                    // into a previously wider scalar spill, not evidence that
                    // the parent object itself is narrow.  Preserve the full
                    // declaration and materialise the little-endian view
                    // explicitly; otherwise a dword call result followed by a
                    // byte union-field read becomes a one-byte C local and its
                    // upper bytes are irretrievably lost.
                    if size_val < entry.span_size && entry.span_size <= 8 {
                        entry.declared_size = entry.declared_size.max(entry.span_size);
                        let alias = entry.name.clone();
                        *e = extract_little_endian_subvalue(alias, 0, size_val);
                        return;
                    }
                    // A load WIDER than the slot it starts in reads the slots
                    // next to it too. Rewriting it to that one slot's name
                    // silently drops the rest, which is how GCC's
                    // `mov [rsp-0x14],eax; mov [rsp-0x10],eax; mov rax,[rsp-0x14]`
                    // returned only the first member of `agr198_make_trio`, and
                    // how the byte at `[rsp-0x2]` vanished from
                    // `agr198_make_bytes3`'s `movzx eax,WORD PTR [rsp-0x3]`.
                    // Where the neighbours tile the access exactly, the load's
                    // value IS their little-endian concatenation.
                    let spans_neighbours = size_val > entry.span_size;
                    if spans_neighbours {
                        if let Some(composed) = compose_little_endian_slots(
                            map,
                            &key_base,
                            key_disp,
                            size_val,
                            stack_word_size(ctx).try_into().unwrap_or(8),
                        ) {
                            *e = composed;
                            return;
                        }
                    }
                    let Some(entry) = map.get_mut(&key) else {
                        return;
                    };
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
                let alias = alloc_name(&key_base, key_disp, names, ctx);
                map.insert(
                    key,
                    SlotVal {
                        name: alias.clone(),
                        declared_size: size_val,
                        span_size: size_val,
                        object_size: None,
                        bounded_object: false,
                        source_type: None,
                        source_name: None,
                        debug_proven: false,
                    },
                );
                *e = Expr::Reg(VReg::phys(alias));
                return;
            }
        }
        Expr::Call { target, args, .. } => {
            rewrite_expr(target, map, names, ctx, sp_delta, address_defs);
            for argument in args {
                rewrite_expr(argument, map, names, ctx, sp_delta, address_defs);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, map, names, ctx, sp_delta, address_defs);
            rewrite_expr(rhs, map, names, ctx, sp_delta, address_defs);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond, map, names, ctx, sp_delta, address_defs);
            rewrite_expr(if_true, map, names, ctx, sp_delta, address_defs);
            rewrite_expr(if_false, map, names, ctx, sp_delta, address_defs);
        }
        Expr::Un { src, .. } => rewrite_expr(src, map, names, ctx, sp_delta, address_defs),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            rewrite_expr(expr, map, names, ctx, sp_delta, address_defs)
        }
        Expr::FunctionTableEntry { index, .. } => {
            rewrite_expr(index, map, names, ctx, sp_delta, address_defs)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                rewrite_expr(argument, map, names, ctx, sp_delta, address_defs);
            }
        }
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

/// Revisit promoted scalar accesses when an address escape was discovered
/// later in statement order.
///
/// A closure commonly initializes its captured scalar before storing
/// ``&scalar`` into the closure object. The first access has already become a
/// bare promoted local by the time the later store proves that the slot is an
/// addressable object. Reconcile those earlier and later scalar spellings with
/// the final slot map so the renderer declares and accesses one byte object.
pub(super) fn reconcile_late_address_taken_objects(
    body: &mut [Stmt],
    map: &HashMap<SlotKey, SlotVal>,
) {
    #[derive(Clone)]
    struct ObjectView {
        object: VReg,
        size: u16,
        offset: i64,
        width: u8,
    }

    let roots = map
        .iter()
        .filter_map(|(key, slot)| {
            slot.object_size
                .map(|size| (key, VReg::phys(slot.name.clone()), size))
        })
        .collect::<Vec<_>>();
    let mut objects: HashMap<VReg, ObjectView> = HashMap::new();
    for (key, slot) in map {
        if slot.bounded_object && slot.object_size.is_none() {
            continue;
        }
        let Some((root, object, size)) = roots
            .iter()
            .filter(|(root, _, size)| {
                root.base == key.base
                    && root.disp <= key.disp
                    && key.disp < root.disp.saturating_add(i64::from(*size))
            })
            .max_by_key(|(root, _, _)| root.disp)
        else {
            continue;
        };
        objects.insert(
            VReg::phys(slot.name.clone()),
            ObjectView {
                object: object.clone(),
                size: *size,
                offset: key.disp.saturating_sub(root.disp),
                width: slot.declared_size,
            },
        );
    }
    if objects.is_empty() {
        return;
    }

    fn object_address(reg: &VReg, objects: &HashMap<VReg, ObjectView>) -> Option<Expr> {
        objects.get(reg).map(|view| {
            let object = Expr::StackAddr {
                object: view.object.clone(),
                size: view.size,
            };
            if view.offset == 0 {
                object
            } else {
                Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(object),
                    rhs: Box::new(Expr::Const(view.offset)),
                }
            }
        })
    }

    fn rewrite_value(expr: &mut Expr, objects: &HashMap<VReg, ObjectView>) {
        if let Expr::Reg(reg) = expr {
            if let Some(view) = objects.get(reg) {
                *expr = Expr::Deref {
                    addr: Box::new(object_address(reg, objects).expect("known object view")),
                    size: view.width,
                };
            }
            return;
        }
        match expr {
            Expr::Deref { addr, .. } => {
                if let Expr::Reg(reg) = addr.as_ref() {
                    if let Some(address) = object_address(reg, objects) {
                        **addr = address;
                        return;
                    }
                }
                rewrite_value(addr, objects);
            }
            Expr::Call { target, args, .. } => {
                rewrite_value(target, objects);
                for argument in args {
                    rewrite_value(argument, objects);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                rewrite_value(lhs, objects);
                rewrite_value(rhs, objects);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                rewrite_value(cond, objects);
                rewrite_value(if_true, objects);
                rewrite_value(if_false, objects);
            }
            Expr::Un { src, .. } => rewrite_value(src, objects),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                rewrite_value(expr, objects)
            }
            Expr::FunctionTableEntry { index, .. } => rewrite_value(index, objects),
            Expr::WideArithmetic { args, .. } => {
                for arg in args {
                    rewrite_value(arg, objects);
                }
            }
            Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
            Expr::Reg(_) => unreachable!(),
        }
    }

    fn walk(body: &mut [Stmt], objects: &HashMap<VReg, ObjectView>) {
        for statement in body {
            match statement {
                Stmt::Assign { src, .. } => rewrite_value(src, objects),
                Stmt::Store { addr, src, .. } => {
                    if let Expr::Reg(reg) = addr {
                        if let Some(address) = object_address(reg, objects) {
                            *addr = address;
                        }
                    }
                    rewrite_value(src, objects);
                }
                Stmt::Call {
                    target,
                    args,
                    dst: _,
                    call_spec: _,
                } => {
                    rewrite_value(target, objects);
                    for arg in args {
                        rewrite_value(arg, objects);
                    }
                }
                Stmt::Return { value } => {
                    if let Some(value) = value {
                        rewrite_value(value, objects);
                    }
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    rewrite_value(cond, objects);
                    walk(then_body, objects);
                    if let Some(else_body) = else_body {
                        walk(else_body, objects);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                    rewrite_value(cond, objects);
                    walk(body, objects);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    walk(std::slice::from_mut(init.as_mut()), objects);
                    rewrite_value(cond, objects);
                    walk(std::slice::from_mut(step.as_mut()), objects);
                    walk(body, objects);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    rewrite_value(discriminant, objects);
                    for (_, case) in cases {
                        walk(case, objects);
                    }
                    if let Some(default) = default {
                        walk(default, objects);
                    }
                }
                Stmt::IndirectGoto { target } => rewrite_value(target, objects),
                Stmt::Push { value } => rewrite_value(value, objects),
                Stmt::Pop { .. }
                | Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
    }

    walk(body, &objects);
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
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    // A debug scalar is seeded in CFA/entry-SP coordinates before the body is
    // walked. If its address escapes through the post-prologue SP spelling,
    // promote that exact seeded slot into an addressable object instead of
    // creating a second, uninitialised current-SP object beside it.
    let scalar_address = resolved_memory_address(expr, sp_delta, ctx, address_defs).or_else(|| {
        resolve_stack_address(expr, sp_delta, ctx, address_defs)
            .map(|(base, disp)| (base, disp, None, 1))
    });
    if let Some((base, disp, index, _scale)) = scalar_address {
        if index.is_none() {
            if let Some((key, relative)) = bounded_scalar_slot(map, &base, disp, 0, sp_delta, ctx) {
                let entry = map
                    .get_mut(&key)
                    .expect("bounded scalar key came from this map");
                let size = u16::from(entry.span_size);
                entry.object_size = Some(size);
                let object = Expr::StackAddr {
                    object: VReg::phys(entry.name.clone()),
                    size,
                };
                *expr = if relative == 0 {
                    object
                } else {
                    Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(object),
                        rhs: Box::new(Expr::Const(relative)),
                    }
                };
                return;
            }
        }
    }
    // A call can receive a slice whose start is computed dynamically, e.g.
    // `memcpy(rsp + index*4 + 48, src, n)`.  This is the same address shape as
    // an indexed load/store, but there is no dereference node for
    // `rewrite_expr` to promote.  Root it in an already-seeded object before
    // falling back to the constant-address path below.
    if let Some(object_addr) = stack_object_address(expr, 0, map, sp_delta, ctx, address_defs) {
        *expr = object_addr;
        return;
    }
    // An address definition may point inside an object that an earlier call,
    // store, or debug hint already seeded. Preserve that interior byte offset:
    // collapsing `&local[0] + 1` to `&local[0]` changes the stored value even
    // though both addresses identify the same underlying stack object.
    if let Some(object_addr) =
        stack_object_constant_address(expr, map, sp_delta, ctx, address_defs, false)
    {
        *expr = object_addr;
        return;
    }
    // `push {r7, lr}` saves the CALLER's frame register, and the alias map is
    // keyed by register rather than by program point, so that store's source
    // resolves to THIS frame's anchor coordinate. The anchor is by construction
    // the base of the whole frame, so the "grow conservatively to the frame
    // base" extent below measures the frame, not an object: A32's `fp` sits one
    // word below the CFA and produced a harmless four-byte slot, while Thumb's
    // `r7` sits at the bottom and produced a forty-byte array that swallowed
    // `seed`'s argument home. A bare anchor is evidence of a machine word at
    // that coordinate and of nothing wider. Every path that joins an ALREADY
    // proven object — a DWARF aggregate, a seeded partition, an observed run of
    // slots — has run above, so a genuine escape into a known object still
    // resolves at its real extent.
    let bare_frame_anchor =
        matches!(expr, Expr::Reg(VReg::Phys(name)) if is_arm_frame_pointer(name, ctx));
    let recovered = escaped_stack_address(expr, sp_delta, ctx, address_defs, false);
    let Some((base, disp)) = recovered else {
        return;
    };
    let (key_base, key_disp) = normalized_stack_slot(&base, disp, sp_delta, ctx);
    let key = SlotKey {
        base: key_base.clone(),
        disp: key_disp,
    };
    // AAPCS own-frame memory can remain in current-SP coordinates until an
    // address escapes. Address SSA and DWARF CFA facts use the entry-SP
    // coordinate, however. If the scalar was initialized before its address
    // was copied, move that existing slot metadata to the now-proven object
    // coordinate so the already-rendered scalar name can be reconciled with
    // the object rather than leaving an initialized scalar beside an
    // uninitialized byte array.
    if matches!(
        ctx.cc,
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64)
    ) && key_base == "entry_sp"
        && !map.contains_key(&key)
    {
        if let Some(current_disp) = sp_delta.and_then(|delta| key_disp.checked_sub(delta)) {
            let current_key = SlotKey {
                base: "sp".to_string(),
                disp: current_disp,
            };
            if let Some(existing) = map.remove(&current_key) {
                map.insert(key.clone(), existing);
            }
        }
    }
    let next_slot_extent = map
        .keys()
        .filter(|candidate| candidate.base == key_base && candidate.disp > key_disp)
        .map(|candidate| candidate.disp - key_disp)
        .min()
        .and_then(|extent| u16::try_from(extent).ok())
        .filter(|extent| *extent > 0);
    let pointer_size = match ctx.cc {
        Some(CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    };
    let entry = map.entry(key).or_insert_with(|| SlotVal {
        name: alloc_name(&key_base, key_disp, names, ctx),
        declared_size: pointer_size,
        span_size: pointer_size,
        object_size: None,
        bounded_object: false,
        source_type: None,
        source_name: None,
        debug_proven: false,
    });
    let object = VReg::phys(entry.name.clone());
    // A frame-local object starts at a negative offset and grows toward the
    // frame base on the supported downward-growing stacks. Reserving the whole
    // interval to the base is conservative (it may include padding or adjacent
    // machine slots), but unlike a pointer-sized scalar it cannot be overrun by
    // a constructor whose recovered source type is not yet known. Cap at the C
    // representation's bounded u16 extent so hostile displacements cannot make
    // the renderer request an unbounded object.
    let conservative_size = if key_disp < 0 {
        u16::try_from(key_disp.unsigned_abs())
            .unwrap_or(u16::MAX)
            .max(u16::from(pointer_size))
    } else {
        u16::from(pointer_size)
    };
    // A separately observed slot closer to the frame base is a hard object
    // boundary.  Without it, an address-taken struct at rbp-0x20 absorbs an
    // independent argument at rbp-0x14 merely because its source type is not
    // yet known.
    let size = if bare_frame_anchor {
        u16::from(pointer_size)
    } else {
        next_slot_extent.unwrap_or(conservative_size)
    };
    // Persist the storage identity in the slot map, not only in this call
    // argument.  Later loads/stores must remain dereferences of the same byte
    // array; rewriting them as scalar `Reg(local)` values would make C decay
    // the array to its address and use pointer bits as object contents.
    entry.object_size = Some(entry.object_size.unwrap_or(0).max(size));
    entry.bounded_object |= next_slot_extent.is_some() || key_disp >= 0;
    *expr = Expr::StackAddr { object, size };
}

/// Store-address Lea: turn the full `&[base+disp]` into a `Reg(local)`.
/// The parameter a just-promoted store address names, when the store writes an
/// incoming argument's HOME SLOT.
///
/// A write to that slot is an assignment to the parameter, not a store through
/// it. On SysV AMD64 and AArch64 the first several arguments arrive in
/// registers, so the shape barely occurs; cdecl32 passes EVERY argument on the
/// stack, so a plain `x = f(x);` on a parameter compiles to exactly this store.
/// Left as a store it rendered `*(int *)(arg2) = v` — a dereference of the
/// parameter's VALUE, which faults on a scalar parameter and silently corrupts
/// memory through a pointer one.
///
/// Two guards keep this exact rather than approximate:
///
/// * the caller only asks when the address was an `Expr::Lea` before promotion,
///   so a genuine `*p = v` (whose address is already a register) can never
///   arrive here;
/// * the write must cover the WHOLE slot. A narrower write is a byte-level
///   effect on the argument's memory that a scalar assignment cannot express,
///   and keeps its store form.
fn argument_slot_assignment(addr: &Expr, size: u8, ctx: StackContext) -> Option<VReg> {
    let Expr::Reg(register @ VReg::Phys(name)) = addr else {
        return None;
    };
    crate::ir::ast::parse_arg_index(name)?;
    let (_reg_args, _first, stride) = ctx.cc.and_then(stack_arg_layout)?;
    (i64::from(size) == stride).then(|| register.clone())
}

fn try_promote_lea_to_local(
    addr: &mut Expr,
    size: u8,
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    if let Some(object_addr) = stack_object_address(addr, size, map, sp_delta, ctx, address_defs) {
        *addr = object_addr;
        return;
    }
    // A later narrower read at the exact same address can narrow the declaration,
    // while `span_size` retains the bytes this store defined for overlap recovery.
    let Some((key_base, key_disp)) = resolved_memory_slot(addr, sp_delta, ctx, address_defs) else {
        return;
    };
    let ordinary_key = SlotKey {
        base: key_base.clone(),
        disp: key_disp,
    };
    let key = bounded_scalar_slot(map, &key_base, key_disp, size, sp_delta, ctx)
        .map(|(key, _)| key)
        .unwrap_or(ordinary_key);
    let entry = map.entry(key).or_insert_with(|| SlotVal {
        name: alloc_name(&key_base, key_disp, names, ctx),
        declared_size: size,
        span_size: size,
        object_size: None,
        bounded_object: false,
        source_type: None,
        source_name: None,
        debug_proven: false,
    });
    entry.declared_size = entry.declared_size.min(size);
    entry.span_size = entry.span_size.max(size);
    let alias = entry.name.clone();
    *addr = Expr::Reg(VReg::phys(alias));
}
