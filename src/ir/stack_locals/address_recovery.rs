//! Resolve a machine address expression to the frame storage it names.
//!
//! Everything here answers one question in two steps: which `(base, disp)`
//! frame coordinate does this expression denote, and which promoted object owns
//! that coordinate. The rewriter, the indexed-object seeder and the frame-flow
//! analyses all sit on top of this layer; none of it decides what a slot is
//! called or mutates a statement.

use std::collections::HashMap;

use super::{
    entry_stack_base, is_active_stack_base, is_stack_pointer_reg, SlotKey, SlotVal, StackContext,
};
use crate::ir::ast::Expr;
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

/// Resolve an expression that carries a stable stack address. Stack-pointer
/// values are converted to an architectural-entry displacement immediately;
/// SSA aliases can then be used after later stack-pointer adjustments without
/// changing which source object they identify.
pub(super) fn resolve_stack_address(
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
pub(super) fn resolved_memory_slot(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64)> {
    let (base, disp, index, _) = resolved_memory_address(expr, sp_delta, ctx, address_defs)?;
    index.is_none().then_some((base, disp))
}

/// Resolve a stack memory operand while retaining its optional dynamic index.
/// The constant part is normalized to entry-SP coordinates exactly like scalar
/// slots, so frame-pointer omission does not create a second storage identity.
pub(super) fn resolved_memory_address(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64, Option<VReg>, u8)> {
    fn scaled_index(expr: &Expr) -> Option<(VReg, u8, i64)> {
        match expr {
            Expr::Reg(index) => Some((index.clone(), 1, 0)),
            Expr::Bin {
                op: crate::ir::types::BinOp::Mul,
                lhs,
                rhs,
            } => {
                let (Expr::Reg(index), Expr::Const(scale)) = (lhs.as_ref(), rhs.as_ref()) else {
                    let (Expr::Const(scale), Expr::Reg(index)) = (lhs.as_ref(), rhs.as_ref())
                    else {
                        return None;
                    };
                    return u8::try_from(*scale)
                        .ok()
                        .filter(|scale| *scale > 0)
                        .map(|scale| (index.clone(), scale, 0));
                };
                u8::try_from(*scale)
                    .ok()
                    .filter(|scale| *scale > 0)
                    .map(|scale| (index.clone(), scale, 0))
            }
            Expr::Bin {
                op: crate::ir::types::BinOp::Shl,
                lhs,
                rhs,
            } => {
                let (Expr::Reg(index), Expr::Const(shift)) = (lhs.as_ref(), rhs.as_ref()) else {
                    return None;
                };
                u32::try_from(*shift)
                    .ok()
                    .and_then(|shift| 1u8.checked_shl(shift))
                    .filter(|scale| *scale > 0)
                    .map(|scale| (index.clone(), scale, 0))
            }
            Expr::Bin { op, lhs, rhs }
                if matches!(
                    op,
                    crate::ir::types::BinOp::Add | crate::ir::types::BinOp::Sub
                ) =>
            {
                if let Expr::Const(amount) = rhs.as_ref() {
                    let (index, scale, offset) = scaled_index(lhs)?;
                    let adjustment = match op {
                        crate::ir::types::BinOp::Add => *amount,
                        crate::ir::types::BinOp::Sub => amount.checked_neg()?,
                        _ => unreachable!(),
                    };
                    return Some((index, scale, offset.checked_add(adjustment)?));
                }
                if matches!(op, crate::ir::types::BinOp::Add) {
                    if let Expr::Const(amount) = lhs.as_ref() {
                        let (index, scale, offset) = scaled_index(rhs)?;
                        return Some((index, scale, offset.checked_add(*amount)?));
                    }
                }
                None
            }
            _ => None,
        }
    }

    // Alias expansion represents a constant stack address as ordinary
    // arithmetic (`sp + 68`) instead of a low-level Lea. Resolve that exact
    // non-indexed form before looking for dynamic address components; otherwise
    // the address-valued definition promotes while a store through the same
    // alias remains rooted at an uninitialised synthetic `sp` C local.
    if matches!(ctx.cc, Some(CallConv::Arm | CallConv::ArmHardFloat)) {
        if let Some((base, disp)) = resolve_stack_address(expr, sp_delta, ctx, address_defs) {
            return Some((base, disp, None, 1));
        }
    }

    // Argument reconstruction represents effective addresses as ordinary AST
    // arithmetic rather than `Lea`: `((stack_base + index*scale) + disp)`.
    // Recover that form before handling the lower-level memory operand below.
    if let Expr::Bin { op, lhs, rhs } = expr {
        if let Expr::Const(amount) = rhs.as_ref() {
            let adjustment = match op {
                crate::ir::types::BinOp::Add => Some(*amount),
                crate::ir::types::BinOp::Sub => amount.checked_neg(),
                _ => None,
            };
            if let Some(adjustment) = adjustment {
                if let Some((base, disp, index, scale)) =
                    resolved_memory_address(lhs, sp_delta, ctx, address_defs)
                {
                    return Some((base, disp.checked_add(adjustment)?, index, scale));
                }
            }
        }
        if matches!(op, crate::ir::types::BinOp::Add) {
            for (base_expr, index_expr) in
                [(lhs.as_ref(), rhs.as_ref()), (rhs.as_ref(), lhs.as_ref())]
            {
                if let (Some((base, disp)), Some((index, scale, index_offset))) = (
                    resolve_stack_address(base_expr, sp_delta, ctx, address_defs),
                    scaled_index(index_expr),
                ) {
                    return Some((base, disp.checked_add(index_offset)?, Some(index), scale));
                }
            }
        }
    }

    let Expr::Lea {
        base: Some(base),
        index,
        scale,
        disp,
        segment: None,
    } = expr
    else {
        return None;
    };
    if let Some((resolved_base, base_disp)) = address_defs.get(base) {
        return Some((
            resolved_base.clone(),
            base_disp.checked_add(*disp)?,
            index.clone(),
            *scale,
        ));
    }
    if let VReg::Phys(name) = base {
        if is_active_stack_base(name, ctx) {
            let (base, disp) = normalized_stack_slot(name, *disp, sp_delta, ctx);
            return Some((base, disp, index.clone(), *scale));
        }
    }

    // Addition is commutative when the SIB scale is one. Encoders freely put
    // the stack-derived alias in the index field (`[rax+r8]`) and the logical
    // subscript in the base field. Recover the same object while retaining the
    // non-stack base as the dynamic byte offset.
    let stack_index = index.as_ref()?;
    if *scale != 1 {
        return None;
    }
    let (resolved_base, resolved_disp) =
        if let Some((resolved_base, base_disp)) = address_defs.get(stack_index) {
            (resolved_base.clone(), base_disp.checked_add(*disp)?)
        } else if let VReg::Phys(name) = stack_index {
            if is_active_stack_base(name, ctx) {
                normalized_stack_slot(name, *disp, sp_delta, ctx)
            } else {
                return None;
            }
        } else {
            return None;
        };
    Some((resolved_base, resolved_disp, Some(base.clone()), 1))
}

/// Re-express an AAPCS current-SP coordinate in DWARF's CFA coordinate.
///
/// Ordinary own-frame slots may retain their current-SP spelling. Debug-proven
/// aggregate objects are different: their locations are relative to the
/// call-frame address (the entry SP), so look through that second coordinate
/// only when an authoritative object actually contains the access.
pub(super) fn aapcs_entry_stack_coordinate(
    base: &str,
    disp: i64,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> Option<(&'static str, i64)> {
    (matches!(
        ctx.cc,
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64)
    ) && base == "sp")
        .then(|| disp.checked_add(sp_delta?))?
        .map(|disp| ("entry_sp", disp))
}

/// The promoted object an access at `(base, disp)` falls inside.
///
/// `allow_end_pointer` admits an address that lands exactly ONE PAST the end of
/// a debug-proven object. `lea 0x20(%rsp),%rdx` is the bound `&a[8]` of the loop
/// that fills the `int32_t a[8]` at `rsp`, and C says that address exists; while
/// a heuristic object ran to the frame base it was swallowed by accident, and
/// with the exact DWARF extent, refusing it left the bound as arithmetic on an
/// undefined `rsp` (`196_disjoint_frame_slots:gcc:O2:dfs196_indexed_control`).
///
/// Three conditions keep it from absorbing the NEXT object, which occupies the
/// very same coordinate and is what makes this dangerous:
///
/// * a DEREFERENCE there is still refused — only `access_size == 0` qualifies;
/// * the extent must be debug-proven. A recovered extent's last byte is a
///   guess: allowing this for every bounded object added 275 undefined reads to
///   `rustc:O0` and 165 to `rustc:O2`, whose iterator code is built out of end
///   pointers, while moving no cell;
/// * only a value-producing ASSIGNMENT asks for it. An address handed to a
///   CALLEE that lands one past an object is far more likely to be the
///   neighbouring object — at `-O0`, `Movable b` sitting directly above
///   `Movable a` became `&a + 8` and the recompiled C wrote past `a`'s end
///   (`10_cpp_runtime_shapes:gcc:O0:cpp_move`).
///
/// A slot that really starts at that coordinate and is already an object still
/// wins, because the selection below keeps the greatest start.
fn containing_stack_object<'a>(
    map: &'a HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    access_size: u8,
    indexed: bool,
    require_bounded: bool,
    allow_end_pointer: bool,
) -> Option<(i64, &'a SlotVal, u16)> {
    let access_end = disp.checked_add(i64::from(access_size))?;
    map.iter()
        .filter_map(|(key, slot)| {
            let size = slot.object_size?;
            let end = key.disp.checked_add(i64::from(size))?;
            let end_pointer =
                allow_end_pointer && access_size == 0 && disp == end && slot.debug_proven;
            (key.base == base
                && (!require_bounded || slot.bounded_object)
                && key.disp <= disp
                && (disp < end || end_pointer)
                && (indexed || access_end <= end || end_pointer))
                .then_some((key.disp, slot, size))
        })
        .max_by_key(|(start, _, _)| *start)
}

fn bounded_scalar_at_coordinate(
    map: &HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    access_size: u8,
) -> Option<(SlotKey, i64)> {
    let Some(access_end) = disp.checked_add(i64::from(access_size)) else {
        return None;
    };
    map.iter()
        .filter_map(|(key, slot)| {
            let slot_end = key.disp.checked_add(i64::from(slot.span_size))?;
            (key.base == base
                && slot.bounded_object
                && slot.object_size.is_none()
                // A scalar hint can become a C lvalue only for a whole-value
                // access at its exact base. Partial/interior machine-word
                // transports need byte-object semantics that this path does
                // not yet model; collapsing them loses untouched bytes.
                && key.disp == disp
                && (access_size == 0 || access_size == slot.span_size)
                && if access_size == 0 {
                    disp < slot_end
                } else {
                    access_end <= slot_end
                })
            .then_some((key.clone(), disp - key.disp))
        })
        .max_by_key(|(key, _)| key.disp)
}

pub(super) fn bounded_scalar_slot(
    map: &HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    access_size: u8,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> Option<(SlotKey, i64)> {
    aapcs_entry_stack_coordinate(base, disp, sp_delta, ctx)
        .and_then(|(alternate_base, alternate_disp)| {
            bounded_scalar_at_coordinate(map, alternate_base, alternate_disp, access_size)
        })
        .or_else(|| bounded_scalar_at_coordinate(map, base, disp, access_size))
}

/// A debug-proven object an INDEXED access addresses from one element BELOW it.
///
/// Compilers routinely bias a subscript rather than the base: gcc reaches
/// `int32_t temp[16]` at `rsp+0x30` as `0x2c(%rsp) + (out+1)*4`, so the
/// recovered constant part sits one element under the proven array while the
/// effective address is inside it. `seed_indexed_stack_objects` already treats
/// that shape as an aliasing bias when comparing two heuristic partitions; this
/// is the same rule against an authoritative extent, and it is what lets the
/// proven object own the access instead of a second array being invented under
/// it. The relative offset comes out NEGATIVE, which is exactly the bias the
/// machine applied: `&temp[0] + (out + 1)*4 - 4`.
///
/// Bounded by one element deliberately. A larger gap is a different allocation,
/// not a bias, and the caller has already asked every containment rule first.
fn biased_indexed_object<'a>(
    map: &'a HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    index: Option<&VReg>,
    scale: u8,
) -> Option<(i64, &'a SlotVal, u16)> {
    index?;
    if scale == 0 {
        return None;
    }
    let reach = disp.checked_add(i64::from(scale))?;
    map.iter()
        .filter_map(|(key, slot)| {
            let size = slot.object_size?;
            (key.base == base && slot.debug_proven && disp < key.disp && key.disp <= reach)
                .then_some((key.disp, slot, size))
        })
        .min_by_key(|(start, _, _)| *start)
}

/// Materialise an access inside a seeded stack region as byte-pointer
/// arithmetic rooted at one [`Expr::StackAddr`].
pub(super) fn stack_object_address(
    expr: &Expr,
    access_size: u8,
    map: &HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<Expr> {
    let (base, disp, index, scale) = resolved_memory_address(expr, sp_delta, ctx, address_defs)?;
    if index.is_some() && scale == 0 {
        return None;
    }
    let alternate = aapcs_entry_stack_coordinate(&base, disp, sp_delta, ctx);
    if bounded_scalar_slot(map, &base, disp, access_size, sp_delta, ctx).is_some() {
        return None;
    }
    let contained = alternate
        .and_then(|(alternate_base, alternate_disp)| {
            containing_stack_object(
                map,
                alternate_base,
                alternate_disp,
                access_size,
                index.is_some(),
                true,
                false,
            )
            .map(|(start, slot, size)| (alternate_disp, start, slot, size))
        })
        .or_else(|| {
            containing_stack_object(map, &base, disp, access_size, index.is_some(), false, false)
                .map(|(start, slot, size)| (disp, start, slot, size))
        });
    let biased = alternate
        .and_then(|(alternate_base, alternate_disp)| {
            biased_indexed_object(map, alternate_base, alternate_disp, index.as_ref(), scale)
                .map(|(start, slot, size)| (alternate_disp, start, slot, size))
        })
        .or_else(|| {
            biased_indexed_object(map, &base, disp, index.as_ref(), scale)
                .map(|(start, slot, size)| (disp, start, slot, size))
        });
    // An object that contains only the FIRST address of an indexed sequence is
    // not the array that sequence walks. `queue[head++]` at
    // `23_topological_sort:i386:O2` is addressed `0x58(%esp,%edi,4)` with `%edi`
    // starting at one — a base one element low, exactly the merge_sort bias —
    // and there the element below `queue` is the LAST element of the adjacent
    // `indegree[16]`. Containment therefore matched, and matched the wrong
    // array: every dynamic address the sequence produces is in `queue`, and only
    // the base byte is in `indegree`. Before the CFA repair neither array was
    // proven and the heuristic partitioned from the biased base, which is why
    // this shape has no host-lane analogue and survived two `@o0`/`@o2` sweeps.
    //
    // Two conditions, both needed. The sequence must leave the containing
    // object by its SECOND element, and the base must not be that object's own
    // start — a bias displaces the base from the array it walks, so a base
    // sitting exactly on an object is that object being addressed directly.
    // Without the second condition a one-element proven object indexed at its
    // own start would hand itself to whatever follows it.
    let escapes_immediately = |start: i64, size: u16| {
        disp > start
            && start
                .checked_add(i64::from(size))
                .is_some_and(|end| end <= disp.saturating_add(i64::from(scale)))
    };
    let (object_disp, start, slot, object_size) = match (contained, biased) {
        (Some((_, start, _, size)), Some(biased)) if escapes_immediately(start, size) => biased,
        (Some(contained), _) => contained,
        (None, biased) => biased?,
    };

    let mut offset = index.map(|index| {
        let index = Expr::Reg(index);
        if scale == 1 {
            index
        } else {
            Expr::Bin {
                op: crate::ir::types::BinOp::Mul,
                lhs: Box::new(index),
                rhs: Box::new(Expr::Const(i64::from(scale))),
            }
        }
    });
    let relative = object_disp.checked_sub(start)?;
    if relative != 0 {
        offset = Some(match offset {
            Some(index) => Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(index),
                rhs: Box::new(Expr::Const(relative)),
            },
            None => Expr::Const(relative),
        });
    }
    let object = Expr::StackAddr {
        object: VReg::phys(slot.name.clone()),
        size: object_size,
    };
    Some(match offset {
        Some(offset) => Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(object),
            rhs: Box::new(offset),
        },
        None => object,
    })
}

/// Recover a value-producing copy of the current frame/stack address. This is
/// distinct from a memory operand: optimized code often moves `rsp` into a
/// callee-saved register and then advances that register as an array cursor.
pub(super) fn stack_object_constant_address(
    expr: &Expr,
    map: &HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    allow_end_pointer: bool,
) -> Option<Expr> {
    let recovered = escaped_stack_address(expr, sp_delta, ctx, address_defs, true)?;
    let (base, disp) = normalized_stack_slot(&recovered.0, recovered.1, sp_delta, ctx);
    let alternate = aapcs_entry_stack_coordinate(&base, disp, sp_delta, ctx);
    let (object_disp, start, slot, size) = alternate
        .and_then(|(alternate_base, alternate_disp)| {
            containing_stack_object(
                map,
                alternate_base,
                alternate_disp,
                0,
                true,
                true,
                allow_end_pointer,
            )
            .map(|(start, slot, size)| (alternate_disp, start, slot, size))
        })
        .or_else(|| {
            containing_stack_object(map, &base, disp, 0, true, false, allow_end_pointer)
                .map(|(start, slot, size)| (disp, start, slot, size))
        })?;
    let object = Expr::StackAddr {
        object: VReg::phys(slot.name.clone()),
        size,
    };
    let relative = object_disp.checked_sub(start)?;
    Some(if relative != 0 {
        Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(object),
            rhs: Box::new(Expr::Const(relative)),
        }
    } else {
        object
    })
}

/// Materialise a copied frame address even when the object was first observed
/// as contiguous scalar initialisers. Optimised GCC commonly zeroes a small
/// array with lane stores, then copies `rsp` into a cursor for the scalar
/// fallback. A separately recovered indexed object at the next displacement is
/// a hard boundary; otherwise only a gap-free run of promoted slots is joined.
pub(super) fn stack_assignment_object_address(
    expr: &Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    allow_end_pointer: bool,
) -> Option<Expr> {
    if let Some(existing) =
        stack_object_constant_address(expr, map, sp_delta, ctx, address_defs, allow_end_pointer)
    {
        return Some(existing);
    }
    let recovered = escaped_stack_address(expr, sp_delta, ctx, address_defs, true)?;
    let (base, disp) = normalized_stack_slot(&recovered.0, recovered.1, sp_delta, ctx);
    let key = SlotKey {
        base: base.clone(),
        disp,
    };
    let first = map.get(&key)?;
    if first.object_size.is_some() {
        return stack_object_constant_address(
            expr,
            map,
            sp_delta,
            ctx,
            address_defs,
            allow_end_pointer,
        );
    }

    let boundary = map
        .iter()
        .filter(|(candidate, slot)| {
            candidate.base == base && candidate.disp > disp && slot.object_size.is_some()
        })
        .map(|(candidate, _)| candidate.disp)
        .min();
    let mut candidates = map
        .iter()
        .filter(|(candidate, slot)| {
            candidate.base == base
                && candidate.disp >= disp
                && candidate.disp < boundary.unwrap_or(i64::MAX)
                && slot.object_size.is_none()
        })
        .map(|(candidate, slot)| (candidate.disp, slot.span_size))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(candidate_disp, _)| *candidate_disp);
    let mut end = disp.checked_add(i64::from(first.span_size))?;
    let mut extends_first_slot = false;
    for (candidate_disp, span) in candidates {
        if candidate_disp > end {
            break;
        }
        let candidate_end = candidate_disp.checked_add(i64::from(span))?;
        if candidate_disp > disp && candidate_end > end {
            extends_first_slot = true;
        }
        end = end.max(candidate_end);
    }
    // A lone saved frame pointer is also an eight-byte slot followed by
    // `rbp = rsp`. It is frame establishment, not evidence that the slot is an
    // address-taken array. Require a second contiguous scalar initializer to
    // extend the candidate object before joining the run.
    if !extends_first_slot {
        return None;
    }
    if boundary == Some(end) {
        end = boundary?;
    }
    let minimum_size = match ctx.cc {
        Some(CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    };
    let size = u16::try_from(end.checked_sub(disp)?)
        .ok()
        .filter(|size| *size > 0)?
        .max(minimum_size);
    let slot = map.get_mut(&key)?;
    slot.object_size = Some(size);
    slot.bounded_object = true;
    stack_object_constant_address(expr, map, sp_delta, ctx, address_defs, allow_end_pointer)
}

/// Resolve an escaping stack address without broadening the established x86
/// frame model. AAPCS needs the SSA frame-pointer definition (`r7#1 = sp`) to
/// reach the entry-SP coordinate; x86 frame registers deliberately retain
/// their architectural coordinate and use the narrower legacy spelling.
pub(super) fn escaped_stack_address(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    prefer_active_base: bool,
) -> Option<(String, i64)> {
    if matches!(ctx.cc, Some(CallConv::Arm | CallConv::ArmHardFloat)) {
        return resolve_stack_address(expr, sp_delta, ctx, address_defs);
    }
    if prefer_active_base {
        return match expr {
            Expr::Reg(VReg::Phys(name)) if is_active_stack_base(name, ctx) => {
                Some((name.clone(), 0))
            }
            Expr::Reg(reg) => address_defs.get(reg).cloned(),
            _ => constant_stack_address(expr, ctx),
        };
    }
    constant_stack_address(expr, ctx).or_else(|| match expr {
        Expr::Reg(reg) => address_defs.get(reg).cloned(),
        _ => None,
    })
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
            let (Expr::Reg(VReg::Phys(base)), Expr::Const(amount)) = (lhs.as_ref(), rhs.as_ref())
            else {
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

/// Express an rsp-relative slot against the architectural entry rsp when the
/// current delta is known. This makes `[rsp+16]` after one push the same slot as
/// `[entry_rsp+8]`, and gives naming an ABI-stable displacement.
pub(super) fn normalized_stack_slot(
    base: &str,
    disp: i64,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> (String, i64) {
    // `sp` is normalised unconditionally for ARM32, whose whole frame model this
    // already describes. AArch64 was deliberately excluded: `resolve_stack_address`
    // gives it an `entry_sp` identity through a different path, and unifying them
    // here moves a lane that is already 82% correct.
    //
    // That exclusion is kept for the callee's OWN frame and lifted only at or
    // above the entry stack pointer, which is the caller's territory and the only
    // place an AAPCS64 stacked argument can live. A frame-pointer-omitted
    // `ldr w9, [sp]` is exactly how `sum_arg9`/`sum_arg10` read their ninth and
    // tenth arguments, and without the entry-relative spelling those promoted to
    // an undefined `stack_top`.
    //
    // The `disp + delta >= 0` bound is not cosmetic and was not reasoned into
    // existence: normalising AArch64's negative (own-frame) offsets too renamed
    // `24_merge_sort:aarch64:O2:merge_sort_i32`'s locals, split its scratch buffer,
    // and turned a passing execution differential into a failing one. See
    // `tools/arch_roundtrip.py --check`.
    let architectural_sp = base == "rsp" || (base == "esp" && ctx.cc == Some(CallConv::Cdecl32));
    let aapcs_sp = base == "sp"
        && matches!(
            ctx.cc,
            Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64)
        );
    if architectural_sp || aapcs_sp {
        if let Some(delta) = sp_delta {
            let normalized = disp + delta;
            let own_frame_of_aarch64 = ctx.cc == Some(CallConv::Aarch64) && normalized < 0;
            if !own_frame_of_aarch64 {
                return (entry_stack_base(ctx).to_string(), normalized);
            }
        }
    }
    (base.to_string(), disp)
}
