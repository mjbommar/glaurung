//! ARM-specific dispatch facts: how `pc` reads, and the absolute word table.
//!
//! Split out of `analysis::dispatch` on 2026-08-27, when adding the ARM
//! word-table recogniser took that file past 1,000 lines. These two types are a
//! self-contained ARM concern -- neither is referenced by the x86 rules -- and
//! keeping them here means the shared tracker file stays about the tracker.

/// How `pc` reads as a *source operand* on 32-bit ARM.
///
/// ARM's `pc` is not the address of the instruction that names it; it is two
/// instruction slots ahead, and the two execution states disagree on both the
/// offset and the alignment. Getting this wrong does not fail loudly — it names
/// a table four or eight bytes off, decodes whatever is there, and reports a
/// confident answer, which is why the value is never guessed from the
/// instruction alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmPcMode {
    /// A32: `pc` reads as the instruction's address plus 8.
    A32,
    /// T32: `pc` reads as the instruction's address plus 4, rounded DOWN to a
    /// 4-byte boundary — so a 2-byte `add rD, pc, #imm` at an odd halfword and
    /// one at an even halfword read different values.
    Thumb,
}

impl ArmPcMode {
    /// The value `pc` reads when named as a source by the instruction at `va`.
    pub(super) fn pc_value(self, va: u64) -> Option<u64> {
        match self {
            ArmPcMode::A32 => va.checked_add(8),
            ArmPcMode::Thumb => va.checked_add(4).map(|value| value & !3),
        }
    }
}

/// An ARM table dispatch that loads `pc` from an absolute word table.
///
/// The corpus form, uniformly, is
///
/// ```text
/// cmp   rIdx, #N            ; the extent
/// bhi   default             ; in-range on the fall-through edge
/// add   rBase, pc, #imm     ; = adr rBase, <table>
/// ldr   pc, [rBase, rIdx, lsl #2]
/// ```
///
/// Unlike `tbb`/`tbh` the table is NOT named by the instruction — the base is a
/// tracked register — and unlike the x86 relative form the entries are absolute
/// addresses rather than offsets from the table. It therefore needs both halves:
/// a value for `rBase` and an extent for `rIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmWordTableBranch {
    /// VA of the first table entry — the resolved value of the base register.
    pub table_va: u64,
    /// Entries the range check proves, or `None` when the index arrived
    /// unbounded. Fail-closed for the same reason as [`ThumbTableBranch`]: past
    /// the last entry lie the case bodies, whose bytes read as plausible
    /// addresses.
    pub entry_count: Option<usize>,
}
