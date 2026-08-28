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

// ---------------------------------------------------------------------------
// The ARM recognisers, as methods on the shared tracker.
//
// Moved here from `analysis::dispatch` on 2026-08-28: that file had grown back
// past 1,000 product lines, and these three are the same self-contained ARM
// concern the types above are -- none is referenced by the x86 rules. Rust
// allows an inherent `impl` in any module of the defining crate, so the tracker
// stays one type while its ARM knowledge lives beside the ARM types it reads.
// ---------------------------------------------------------------------------

use super::{canon, DispatchTracker, ThumbTableBranch, Val};
use crate::core::instruction::{Instruction, OperandKind};

impl DispatchTracker {
    /// The address an ARM `add rD, pc, #imm` (the assembler's `adr`)
    /// materialises, or `None` when this is not that instruction or the
    /// execution state was never declared.
    /// `pub(super)` because the x86 rules in the parent call it to recognise a
    /// pc-relative materialisation; it is not part of the crate-wide surface.
    pub(super) fn arm_adr_target(&self, ins: &Instruction) -> Option<u64> {
        let mode = self.arm_pc_mode?;
        let mnemonic = ins.mnemonic.to_ascii_lowercase();
        let stem = mnemonic
            .strip_suffix(".w")
            .or_else(|| mnemonic.strip_suffix(".n"))
            .unwrap_or(&mnemonic);
        // Two spellings of one operation, and which one arrives depends on the
        // encoding, not on the source:
        //
        //   `adr rD, #imm`      — 2 operands. What Capstone reports for the
        //                         16-bit Thumb encoding, which is every one of
        //                         the ARM table dispatches in the DecBench
        //                         corpus.
        //   `add rD, pc, #imm`  — 3 operands, `pc` named explicitly. The A32
        //                         spelling.
        //
        // Matching only the second is why this rule originally recognised a
        // hand-written A32 reproduction and none of the real firmware.
        let immediate = match stem {
            "adr" if ins.operands.len() == 2 => ins.operands.get(1)?.immediate?,
            "add" if ins.operands.len() == 3 => {
                // Operand 1 must be `pc` itself. A tracked register that merely
                // HOLDS a code address is a different fact and must not take
                // this path.
                if !ins
                    .operands
                    .get(1)
                    .and_then(|operand| operand.register.as_deref())
                    .is_some_and(|register| register.eq_ignore_ascii_case("pc"))
                {
                    return None;
                }
                ins.operands.get(2)?.immediate?
            }
            _ => return None,
        };
        // A negative `adr` (`sub rD, pc, #imm`) reaches this arm as a different
        // mnemonic; a negative immediate here is a decode this rule does not
        // model, and inventing a table start for it would be worse than
        // declining.
        let immediate = u64::try_from(immediate).ok()?;
        mode.pc_value(ins.address.value)?.checked_add(immediate)
    }

    /// Recognise an ARM `ldr pc, [rBase, rIdx, lsl #2]` and report its table.
    ///
    /// `None` when this is not that instruction. `Some` with `entry_count:
    /// None` when it is, but the index arrived without a proven extent — the
    /// caller reports that as [`Unresolved::NoBound`] rather than reading an
    /// unbounded run of words.
    pub fn arm_word_table_branch(&self, ins: &Instruction) -> Option<ArmWordTableBranch> {
        if !ins.mnemonic.to_ascii_lowercase().starts_with("ldr") {
            return None;
        }
        // The destination must be `pc` — that is what makes this a branch
        // rather than an ordinary indexed load.
        if !ins
            .operands
            .first()
            .and_then(|operand| operand.register.as_deref())
            .is_some_and(|register| register.eq_ignore_ascii_case("pc"))
        {
            return None;
        }
        let memory = ins
            .operands
            .iter()
            .find(|operand| matches!(operand.kind, OperandKind::Memory))?;
        // Word entries only. A different stride is a table this decoder does not
        // know how to read, and guessing four would fabricate targets.
        if memory.scale != Some(4) || memory.displacement.unwrap_or(0) != 0 {
            return None;
        }
        let base = memory.base.as_deref()?;
        let index = memory.index.as_deref()?;
        // `[pc, rIdx, lsl #2]` names its table by position rather than through a
        // tracked register. It is a real encoding, but it is not the corpus
        // shape and it is not what this rule proves, so it declines.
        let Some(Val::Addr(table_va)) = self.get(base) else {
            return None;
        };
        let entry_count = self
            .bounded
            .get(&canon(index))
            .and_then(|bound| usize::try_from(*bound).ok())
            .and_then(|bound| bound.checked_add(1));
        Some(ArmWordTableBranch {
            table_va,
            entry_count,
        })
    }

    /// Recognise a Thumb-2 `tbb`/`tbh` and report its inline table.
    ///
    /// `None` when this is not a table branch. The entry count comes from the
    /// index register's proven bound, which the walker carried across the range
    /// check's in-range edge — see [`Self::inherit_bound`].
    pub fn thumb_table_branch(&self, ins: &Instruction) -> Option<ThumbTableBranch> {
        let entry_size = match ins.mnemonic.to_ascii_lowercase().as_str() {
            "tbb" => 1u8,
            "tbh" => 2,
            _ => return None,
        };
        // Both encodings are 32-bit Thumb-2. Anything else is a decode this
        // module does not understand, and inventing a table start for it would
        // be worse than declining.
        if ins.length != 4 {
            return None;
        }
        // Compilers only ever emit the `pc`-based form; a non-`pc` base names a
        // table this pass cannot locate.
        let operand = ins
            .operands
            .iter()
            .find(|operand| operand.base.as_deref() == Some("pc"))?;
        let index = operand.index.as_deref()?;
        let entry_count = self
            .bounded
            .get(&canon(index))
            .and_then(|bound| usize::try_from(*bound).ok())
            .and_then(|bound| bound.checked_add(1));
        Some(ThumbTableBranch {
            table_va: ins.address.value.checked_add(4)?,
            entry_size,
            entry_count,
        })
    }
}
