//! Machine accesses that do not coincide with one promoted slot.
//!
//! Promotion mints a C VARIABLE per frame coordinate, and a C variable is read
//! and written whole. The machine has no such rule: it reloads two bytes of a
//! four-byte spill, and it reloads eight bytes across two four-byte stores.
//! Neither access names a variable, so neither can be spelled as one — a
//! narrower read has to EXTRACT from its slot, and a wider read has to
//! CONCATENATE the slots it covers.
//!
//! Both directions are little-endian by construction: every architecture this
//! decompiler lifts stores the low-order byte first, so byte offset `k` inside
//! an access is bit offset `8k` of its value.
//!
//! Split out of [`super::rewrite`] on 2026-08-18, when adding the concatenation
//! took that file past 1,000 LOC. The two halves are the same question asked in
//! opposite directions and belong together; the surrounding pass is about
//! WHICH slot an address names, which is a different one.

use std::collections::HashMap;

use super::{SlotKey, SlotVal};
use crate::ir::ast::Expr;
use crate::ir::types::{BinOp, VReg};

/// The value of a load that spans SEVERAL promoted scalar slots, or `None`
/// when the slots do not tile the access exactly.
///
/// The inverse of [`extract_little_endian_subvalue`]. GCC -O2 returns a
/// twelve-byte aggregate by writing two dwords into the red zone and reloading
/// eight bytes across both; promoted to the first slot's name alone, the second
/// member was computed into a C local that nothing read
/// (`198_aggregate_return_edges:gcc:O2:agr198_make_trio`, and the byte at
/// `[rsp-0x2]` in `agr198_make_bytes3`).
///
/// Deliberately exact rather than best-effort. Every condition below is a
/// property the concatenation depends on, and a shape that fails any of them
/// keeps the existing single-slot behaviour instead of acquiring a value this
/// model cannot prove:
///
/// * the parts must tile `[disp, disp + size)` with no gap and no overlap — an
///   unobserved byte inside the run has no C variable to name;
/// * each part must be a plain scalar whose declared and spanned widths agree,
///   so masking it to its own width is lossless (a slot whose declaration was
///   already narrowed by a sub-word view is not one storage unit);
/// * a bounded frame object is refused outright: its bytes are an array, and
///   an element of it is not a scalar to concatenate;
/// * an incoming PARAMETER slot is refused outright. Its width is the recovered
///   prototype's, not the observed accesses': the signature already declares
///   the whole object, so masking it to one tile would drop bytes the
///   declaration says are there;
/// * the whole access must fit THIS TARGET's machine word, because the
///   concatenation is built out of machine-word shifts. An `fild QWORD` on
///   i386 reads eight bytes across two four-byte slots and really is their
///   concatenation — but on that path the high slot is a copy of the SECOND
///   HALF of a stacked `int64_t` parameter, which promotion names as a local of
///   its own (`parameter_count` says there is one argument, so the second slot
///   is not `arg1`) and which nothing ever defines. Composing made that
///   undefined read LIVE, where the single-slot form had left it dead and
///   copy propagation had folded the surviving half back to `arg0`:
///   `173_float_int_conversions:i386:O0:widen_long_to_double` went from pass to
///   fail. The parameter naming is the defect; this bound keeps the rewrite
///   from depending on it.
///
/// Each part is masked to its OWN width before being widened. Without that a
/// `signed char` part sign-fills every higher byte of the result, which is
/// exactly the bytes the neighbouring parts occupy.
pub(super) fn compose_little_endian_slots(
    map: &HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    size: u8,
    machine_word: u8,
) -> Option<Expr> {
    if size > machine_word {
        return None;
    }
    let end = disp.checked_add(i64::from(size))?;
    let mut parts = map
        .iter()
        .filter(|(key, _)| key.base == base && key.disp >= disp && key.disp < end)
        .map(|(key, slot)| (key.disp, slot))
        .collect::<Vec<_>>();
    parts.sort_by_key(|(part_disp, _)| *part_disp);
    if parts.len() < 2 {
        return None;
    }
    let mut cursor = disp;
    let mut composed: Option<Expr> = None;
    for (part_disp, slot) in parts {
        if part_disp != cursor
            || slot.object_size.is_some()
            || slot.bounded_object
            || crate::ir::ast::parse_arg_index(&slot.name).is_some()
            || slot.declared_size != slot.span_size
            || !matches!(slot.span_size, 1 | 2 | 4 | 8)
        {
            return None;
        }
        let offset = u8::try_from(part_disp - disp).ok()?;
        let masked = Expr::Cast {
            signed: false,
            width: slot.span_size,
            expr: Box::new(Expr::Reg(VReg::phys(slot.name.clone()))),
        };
        let widened = Expr::Cast {
            signed: false,
            width: size,
            expr: Box::new(masked),
        };
        let positioned = if offset == 0 {
            widened
        } else {
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(widened),
                rhs: Box::new(Expr::Const(i64::from(offset) * 8)),
            }
        };
        composed = Some(match composed {
            None => positioned,
            Some(previous) => Expr::Bin {
                op: BinOp::Or,
                lhs: Box::new(previous),
                rhs: Box::new(positioned),
            },
        });
        cursor = cursor.checked_add(i64::from(slot.span_size))?;
    }
    (cursor == end).then_some(composed?)
}

/// The `size` bytes at `byte_offset` inside one promoted slot, as an
/// expression over that slot's whole value.
pub(super) fn extract_little_endian_subvalue(parent: String, byte_offset: u8, size: u8) -> Expr {
    let wide_parent = Expr::Cast {
        signed: false,
        width: 8,
        expr: Box::new(Expr::Reg(VReg::phys(parent))),
    };
    let shifted = Expr::Bin {
        op: BinOp::Shr,
        lhs: Box::new(wide_parent),
        rhs: Box::new(Expr::Const(i64::from(byte_offset) * 8)),
    };
    Expr::Cast {
        signed: false,
        width: size,
        expr: Box::new(shifted),
    }
}
