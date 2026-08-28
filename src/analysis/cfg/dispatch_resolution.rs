//! Answering one indirect transfer: which targets does this dispatch reach?
//!
//! Split out of `analysis::cfg` on 2026-08-27, when the ARM word-table form
//! arrived and made this the third encoding the resolver has to know about.
//! It is a self-contained question with a self-contained answer -- given a
//! decoded instruction, a tracker that has walked the block, and the tables the
//! section scan found, produce a [`Resolution`] -- and the parent file is the
//! largest product file in the tree, so it does not need to also be the place
//! this lives.
//!
//! Two of the three forms are answered HERE rather than by
//! `DispatchTracker::resolve_with`, and for the same reason in both cases:
//! `resolve_with` resolves a REGISTER that holds a table-relative target, and
//! neither of these is that shape.
//!
//! * Thumb-2 `tbb`/`tbh` name their table in the instruction (`pc` is the
//!   base) and store it inline in `.text` as unsigned offsets, so the table
//!   address is a decode-time constant and only the entry COUNT is a dataflow
//!   fact.
//! * ARM `ldr pc, [rBase, rIdx, lsl #2]` reads a table of ABSOLUTE addresses
//!   off a base the tracker materialised from `adr`. The base is a tracked
//!   register, but the entries are whole addresses rather than offsets from the
//!   table, so the relative decoder cannot read them.
//!
//! Both report through the same [`Resolution`] as the register form, so every
//! caller -- including the post-CFG revalidation, which replays a block and
//! must reach the identical verdict -- treats all three identically.

use super::*;

pub(super) fn resolve_dispatch(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    regions: &[ExecRegion],
    tracker: &crate::analysis::dispatch::DispatchTracker,
    instruction: &Instruction,
    tables: &std::collections::BTreeMap<u64, Vec<u64>>,
) -> Option<crate::analysis::dispatch::Resolution> {
    // Thumb-2 `tbb`/`tbh` name their table in the instruction (`pc` is the base)
    // and store it inline in `.text` as unsigned halfword counts. Nothing about
    // that shape reaches `resolve_with`, which resolves a REGISTER to a
    // rodata-relative table, so it is answered here and reported through the
    // same `Resolution` so every caller — including the post-CFG revalidation —
    // treats it identically.
    if let Some(branch) = tracker.thumb_table_branch(instruction) {
        let Some(entry_count) = branch.entry_count else {
            return Some(crate::analysis::dispatch::Resolution::Unresolved(
                crate::analysis::dispatch::Unresolved::NoBound(branch.table_va),
            ));
        };
        return Some(
            match decode_thumb_table_branch(
                image,
                data,
                branch.table_va,
                branch.entry_size,
                entry_count,
                |target| in_exec_regions(regions, target).is_some(),
            ) {
                Ok(table) => crate::analysis::dispatch::Resolution::Table {
                    table_va: table.table_va,
                    targets: table.targets,
                },
                Err(decline) => crate::analysis::dispatch::Resolution::Unresolved(
                    crate::analysis::dispatch::Unresolved::NoTableAt {
                        table: branch.table_va,
                        decline,
                    },
                ),
            },
        );
    }
    // ARM `ldr pc, [rBase, rIdx, lsl #2]` reads a table of ABSOLUTE addresses
    // off a base the tracker materialised from `adr`. Like `tbb`/`tbh` nothing
    // about that shape reaches `resolve_with`, which resolves a register
    // holding a table-RELATIVE target; it is answered here and reported through
    // the same `Resolution` so the post-CFG revalidation treats it identically.
    if let Some(branch) = tracker.arm_word_table_branch(instruction) {
        let Some(entry_count) = branch.entry_count else {
            return Some(crate::analysis::dispatch::Resolution::Unresolved(
                crate::analysis::dispatch::Unresolved::NoBound(branch.table_va),
            ));
        };
        return Some(
            match crate::analysis::jump_table::decode_absolute_word_table(
                image,
                data,
                branch.table_va,
                entry_count,
                |target| in_exec_regions(regions, target).is_some(),
            ) {
                Ok(table) => crate::analysis::dispatch::Resolution::Table {
                    table_va: table.table_va,
                    targets: table.targets,
                },
                Err(decline) => crate::analysis::dispatch::Resolution::Unresolved(
                    crate::analysis::dispatch::Unresolved::NoTableAt {
                        table: branch.table_va,
                        decline,
                    },
                ),
            },
        );
    }
    tracker.resolve_with(instruction, tables, |table_va, entry_count| {
        decode_bounded_relative_jump_table(image, data, table_va, entry_count, |target| {
            in_exec_regions(regions, target).is_some()
        })
        .map(|table| table.targets)
    })
}
