//! Seed the bounded indexed frame regions that later rewriting must respect.
//!
//! This recovers STORAGE, not an element type: byte-array identity is enough
//! for C pointer arithmetic to preserve the alias between a wide zeroing store
//! and a later byte or int indexing of the same region.

use std::collections::HashMap;

use super::{
    alloc_name, body_falls_through, is_arm_frame_pointer, is_stack_pointer_reg, merge_stack_deltas,
    resolved_memory_address, stack_delta_after_assignment, stack_word_size, SlotKey, SlotNames,
    SlotVal, StackContext,
};
use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

/// Discover the starts of bounded indexed frame regions before rewriting any
/// statement.  Adjacent starts normally partition the compiler frame and the
/// frame base closes the final region.  Compilers also spell one array through
/// adjacent, same-stride views (for example, `base - 36 + 4 * (i + 1)` and
/// `base - 32 + 4 * i`); those views must share storage rather than becoming
/// separate C arrays.  This intentionally recovers storage, not an element
/// type: byte-array identity is enough for C pointer arithmetic to preserve
/// aliases between wide zeroing stores and later byte/int indexing.
pub(super) fn seed_indexed_stack_objects(
    body: &[Stmt],
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    label_deltas: &HashMap<u64, Option<i64>>,
) {
    fn collect_expr(
        expr: &Expr,
        sp_delta: Option<i64>,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
        starts: &mut Vec<(String, i64, u8)>,
    ) {
        if let Some((base, disp, Some(_), scale)) =
            resolved_memory_address(expr, sp_delta, ctx, address_defs)
        {
            if scale != 0 && disp < 0 {
                starts.push((base, disp, scale));
            }
        }
        match expr {
            Expr::Deref { addr, .. } => collect_expr(addr, sp_delta, ctx, address_defs, starts),
            Expr::Call { target, args, .. } => {
                collect_expr(target, sp_delta, ctx, address_defs, starts);
                for argument in args {
                    collect_expr(argument, sp_delta, ctx, address_defs, starts);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                collect_expr(lhs, sp_delta, ctx, address_defs, starts);
                collect_expr(rhs, sp_delta, ctx, address_defs, starts);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                collect_expr(cond, sp_delta, ctx, address_defs, starts);
                collect_expr(if_true, sp_delta, ctx, address_defs, starts);
                collect_expr(if_false, sp_delta, ctx, address_defs, starts);
            }
            Expr::Un { src, .. } => collect_expr(src, sp_delta, ctx, address_defs, starts),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                collect_expr(expr, sp_delta, ctx, address_defs, starts)
            }
            Expr::FunctionTableEntry { index, .. } => {
                collect_expr(index, sp_delta, ctx, address_defs, starts)
            }
            Expr::WideArithmetic { args, .. } => {
                for arg in args {
                    collect_expr(arg, sp_delta, ctx, address_defs, starts);
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

    fn walk(
        body: &[Stmt],
        ctx: StackContext,
        mut sp_delta: Option<i64>,
        address_defs: &HashMap<VReg, (String, i64)>,
        label_deltas: &HashMap<u64, Option<i64>>,
        starts: &mut Vec<(String, i64, u8)>,
    ) -> Option<i64> {
        for stmt in body {
            match stmt {
                Stmt::Assign { dst, src } => {
                    // AAPCS uses r7/r11/fp arithmetic to restore SP in the
                    // epilogue. At this pre-value-folding stage the constant
                    // adjustment can still be a temporary register, which has
                    // the same syntax as a dynamic array index. It is machine
                    // frame bookkeeping, not an indexed memory access and
                    // must not seed a byte object spanning the entire frame.
                    let arm_epilogue_frame_arithmetic = matches!(
                        (dst, src),
                        (
                            VReg::Phys(name),
                            Expr::Bin { lhs, rhs, .. }
                        ) if is_arm_frame_pointer(name, ctx)
                            && matches!(lhs.as_ref(), Expr::Reg(_))
                            && matches!(rhs.as_ref(), Expr::Reg(_))
                    );
                    if !arm_epilogue_frame_arithmetic {
                        collect_expr(src, sp_delta, ctx, address_defs, starts);
                    }
                    if is_stack_pointer_reg(dst, ctx) {
                        sp_delta =
                            stack_delta_after_assignment(dst, src, sp_delta, ctx, address_defs);
                    }
                }
                Stmt::Store { addr, src, .. } => {
                    collect_expr(addr, sp_delta, ctx, address_defs, starts);
                    collect_expr(src, sp_delta, ctx, address_defs, starts);
                }
                Stmt::Call { target, args, .. } => {
                    collect_expr(target, sp_delta, ctx, address_defs, starts);
                    for arg in args {
                        collect_expr(arg, sp_delta, ctx, address_defs, starts);
                    }
                }
                Stmt::Return { value } => {
                    if let Some(value) = value {
                        collect_expr(value, sp_delta, ctx, address_defs, starts);
                    }
                    sp_delta = None;
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    collect_expr(cond, sp_delta, ctx, address_defs, starts);
                    let then_delta =
                        walk(then_body, ctx, sp_delta, address_defs, label_deltas, starts);
                    let else_delta = else_body.as_deref().map_or(sp_delta, |branch| {
                        walk(branch, ctx, sp_delta, address_defs, label_deltas, starts)
                    });
                    let then_falls = body_falls_through(then_body);
                    let else_falls = else_body.as_deref().is_none_or(body_falls_through);
                    sp_delta = match (then_falls, else_falls) {
                        (true, true) => merge_stack_deltas(then_delta, else_delta),
                        (true, false) => then_delta,
                        (false, true) => else_delta,
                        (false, false) => None,
                    };
                }
                Stmt::While { cond, body } => {
                    collect_expr(cond, sp_delta, ctx, address_defs, starts);
                    let body_delta = walk(body, ctx, sp_delta, address_defs, label_deltas, starts);
                    sp_delta = merge_stack_deltas(sp_delta, body_delta);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    sp_delta = walk(
                        std::slice::from_ref(init.as_ref()),
                        ctx,
                        sp_delta,
                        address_defs,
                        label_deltas,
                        starts,
                    );
                    collect_expr(cond, sp_delta, ctx, address_defs, starts);
                    let loop_entry = sp_delta;
                    let mut body_delta =
                        walk(body, ctx, loop_entry, address_defs, label_deltas, starts);
                    body_delta = walk(
                        std::slice::from_ref(step.as_ref()),
                        ctx,
                        body_delta,
                        address_defs,
                        label_deltas,
                        starts,
                    );
                    sp_delta = merge_stack_deltas(loop_entry, body_delta);
                }
                Stmt::DoWhile { body, cond } => {
                    let body_delta = walk(body, ctx, sp_delta, address_defs, label_deltas, starts);
                    collect_expr(cond, body_delta, ctx, address_defs, starts);
                    sp_delta = merge_stack_deltas(sp_delta, body_delta);
                }
                Stmt::Push { value } => {
                    collect_expr(value, sp_delta, ctx, address_defs, starts);
                    sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
                }
                Stmt::Pop { .. } => {
                    sp_delta = sp_delta.map(|delta| delta + stack_word_size(ctx));
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    collect_expr(discriminant, sp_delta, ctx, address_defs, starts);
                    let incoming = sp_delta;
                    let mut exits = Vec::new();
                    for (_, branch) in cases {
                        exits.push(walk(
                            branch,
                            ctx,
                            incoming,
                            address_defs,
                            label_deltas,
                            starts,
                        ));
                    }
                    if let Some(branch) = default {
                        exits.push(walk(
                            branch,
                            ctx,
                            incoming,
                            address_defs,
                            label_deltas,
                            starts,
                        ));
                    } else {
                        exits.push(incoming);
                    }
                    sp_delta = exits
                        .into_iter()
                        .reduce(merge_stack_deltas)
                        .unwrap_or(incoming);
                }
                Stmt::IndirectGoto { target } => {
                    collect_expr(target, sp_delta, ctx, address_defs, starts);
                    sp_delta = None;
                }
                Stmt::Label(label) => {
                    sp_delta = label_deltas.get(label).copied().unwrap_or(None);
                }
                Stmt::Goto { .. } => sp_delta = None,
                Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
        sp_delta
    }

    let mut starts = Vec::new();
    let _ = walk(body, ctx, Some(0), address_defs, label_deltas, &mut starts);
    starts.sort();
    starts.dedup();

    let mut grouped_starts: Vec<(String, i64, Vec<u8>)> = Vec::new();
    for (base, start, scale) in starts {
        let joined_existing =
            if let Some((last_base, last_start, scales)) = grouped_starts.last_mut() {
                if *last_base == base && *last_start == start {
                    if !scales.contains(&scale) {
                        scales.push(scale);
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };
        if !joined_existing {
            grouped_starts.push((base, start, vec![scale]));
        }
    }

    // An indexed view displaced by at most one of its own elements from the
    // preceding same-stride view is an aliasing bias, not a new allocation.
    // Compare consecutive displacement groups so chains such as -40/-36/-32
    // coalesce even when another access width also starts at one boundary.
    let mut partitions = Vec::new();
    for (index, (base, start, scales)) in grouped_starts.iter().enumerate() {
        let aliases_previous = index
            .checked_sub(1)
            .and_then(|previous| grouped_starts.get(previous))
            .is_some_and(|(previous_base, previous_start, previous_scales)| {
                previous_base == base
                    && start.checked_sub(*previous_start).is_some_and(|gap| {
                        gap > 0
                            && scales.iter().any(|scale| {
                                previous_scales.contains(scale) && gap <= i64::from(*scale)
                            })
                    })
            });
        if !aliases_previous {
            partitions.push((base.clone(), *start));
        }
    }

    // A partition that OVERLAPS a debug-proven object is not a second
    // allocation, and seeding it makes the recompiled C allocate two arrays
    // where the machine had one. Two ways this arises, both measured:
    //
    // * the partition starts inside the object — `nodes[i].next` is an indexed
    //   access eight bytes into `struct Node nodes[8]`
    //   (`111_self_referential_struct:gcc:O2`, which put the list terminator in
    //   the wrong object);
    // * the partition starts BELOW it and runs through it — gcc addresses
    //   `int32_t temp[16]` at `rsp+0x30` as `0x2c(%rsp) + (out+1)*4`, so the
    //   recovered start is one element low and the conservative extent then
    //   covers the whole proven array plus the scalar in front of it
    //   (`24_merge_sort:gcc:O2:merge_sort_i32`).
    //
    // The existing rule ("never replace an exact extent with the heuristic's
    // conservative partition") covered only an exact START match.
    let proven: Vec<(String, i64, i64)> = map
        .iter()
        .filter(|(_, slot)| slot.debug_proven)
        .filter_map(|(key, slot)| {
            let end = key.disp.checked_add(i64::from(slot.object_size?))?;
            Some((key.base.clone(), key.disp, end))
        })
        .collect();
    for index in 0..partitions.len() {
        let (base, start) = &partitions[index];
        let end = partitions
            .get(index + 1)
            .filter(|(next_base, _)| next_base == base)
            .map_or(0, |(_, next_start)| *next_start);
        if proven
            .iter()
            .any(|(proven_base, proven_start, proven_end)| {
                proven_base == base && *start < *proven_end && end > *proven_start
            })
        {
            continue;
        }
        let Some(extent) = end.checked_sub(*start) else {
            continue;
        };
        let Ok(size) = u16::try_from(extent) else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let key = SlotKey {
            base: base.clone(),
            disp: *start,
        };
        let name = alloc_name(base, *start, names, ctx);
        // Debug-proven aggregate bounds are seeded before this heuristic and
        // are authoritative. Never replace an exact `temp[16]` extent with the
        // heuristic's conservative "to the frame base" partition merely
        // because both observe the same indexed start.
        map.entry(key).or_insert_with(|| SlotVal {
            name,
            declared_size: 1,
            span_size: 1,
            object_size: Some(size),
            bounded_object: partitions.get(index + 1).is_some(),
            source_type: None,
            source_name: None,
            debug_proven: false,
        });
    }
}
