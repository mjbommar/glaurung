//! Exact source-value recovery for bounded frame-object overlap.

use std::collections::HashMap;

use super::{
    aapcs_entry_stack_coordinate, entry_stack_base, resolved_memory_address, SlotKey, SlotVal,
    StackAddressDefs, StackContext,
};
use crate::ir::ast::Expr;
use crate::ir::types::VReg;

/// Recover the source scalar from a machine-word load that extends only into
/// the padding at the top of an AAPCS frame.
///
/// GCC commonly stores a one-byte bitfield temporary at `entry_sp - word` and
/// reloads a whole word before extracting its low nibble. DWARF proves the
/// source object is the byte, while the remaining bytes end exactly at the
/// caller's entry SP and own no source object. Treating the wide access as a
/// second scalar invents an uninitialised local; dereferencing the one-byte C
/// array as a word would instead be out of bounds. Project the authoritative
/// scalar value directly, which is the defined source semantics of that load.
///
/// This deliberately rejects interior frame padding, indexed accesses, loads
/// that cross the entry-SP boundary, unbounded inferred objects, and aggregates
/// larger than a scalar. Those shapes need a real overlap/use oracle rather
/// than this exact top-padding proof.
pub(super) fn aapcs_top_padding_scalar_value(
    expr: &Expr,
    access_size: u8,
    map: &HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &StackAddressDefs,
) -> Option<Expr> {
    let (base, disp, index, _scale) = resolved_memory_address(expr, sp_delta, ctx, address_defs)?;
    if index.is_some() {
        return None;
    }
    let (entry_base, entry_disp) = if base == entry_stack_base(ctx) {
        (base.as_str(), disp)
    } else {
        aapcs_entry_stack_coordinate(&base, disp, sp_delta, ctx)?
    };
    if entry_disp.checked_add(i64::from(access_size))? != 0 {
        return None;
    }
    let slot = map.iter().find_map(|(key, slot)| {
        (key.base == entry_base && key.disp == entry_disp && slot.bounded_object).then_some(slot)
    })?;
    let object_size = slot.object_size?;
    let scalar_size = u8::try_from(object_size).ok()?;
    if !matches!(scalar_size, 1 | 2 | 4 | 8) || scalar_size >= access_size {
        return None;
    }
    Some(Expr::Deref {
        addr: Box::new(Expr::StackAddr {
            object: VReg::phys(slot.name.clone()),
            size: object_size,
        }),
        size: scalar_size,
    })
}
