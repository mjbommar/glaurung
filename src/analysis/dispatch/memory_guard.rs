//! Range checks made against a memory location rather than a register.
//!
//! # Why this exists
//!
//! [`DispatchTracker`](super::DispatchTracker) tracks boundedness as a fact
//! about *values*, carried through registers and stack slots. That covers every
//! shape where the compared value ever sits in a register. GCC -O2 has one where
//! it never does:
//!
//! ```text
//! lea    0xf15(%rip),%rax        ; a byte permutation table
//! and    $0x7,%edi
//! cmpb   $0x6,(%rax,%rdi,1)      ; the range check, on an INDEXED MEMORY operand
//! ja     default                 ; ---- block boundary ----
//! movzbl (%rax,%rdi,1),%eax      ; the index, read from the SAME address
//! lea    0xe81(%rip),%rdx ; movslq (%rdx,%rax,4),%rax ; add %rdx,%rax ; jmp *%rax
//! ```
//!
//! There is no register holding the compared value on either side of the branch,
//! so a rule keyed on a register name proves nothing. The only thing the guard
//! and the load share is the *effective address*, so that is what the proof is
//! attached to here.
//!
//! # What makes it sound
//!
//! A bound wrongly attributed to a jump-table index does not fail loudly: it
//! silently attaches arms belonging to the next table in `.rodata`, or deletes
//! real ones. Everything here therefore fails closed.
//!
//! * The identity is the WHOLE address expression plus the access width
//!   ([`MemKey`]). Same segment, same base, same index, same scale, same
//!   displacement, same width, or it is a different location.
//! * A definition of the base or of the index drops the fact
//!   ([`MemoryBounds::forget_through`]).
//! * Anything that could have written memory drops every fact
//!   ([`may_write_memory`]), decided from an allowlist so that unmodelled
//!   instructions refuse rather than survive.
//! * A comparison in the dispatch's own block proves nothing, because the branch
//!   that acts on its flags has not been taken. Only a fact that crossed a
//!   guard's in-range edge may bind a load — which is why [`MemoryBounds`] keeps
//!   the inherited facts and this block's comparison in separate fields.

use std::collections::HashMap;

use crate::core::instruction::{Access, Instruction, Operand, OperandKind};

/// The complete effective-address expression of a memory operand — the identity
/// of the *location* a comparison bounded.
///
/// Every field is part of the identity, and that is the point. A bound proved
/// about `[rax + rdi*1 + 0]` may only be handed to a load whose address is
/// `[rax + rdi*1 + 0]`. Anything less than component-for-component equality is a
/// bound attributed to a location it was not proved about.
///
/// Registers are canonicalised (`eax` and `rax` are one register) so that
/// invalidation catches a write through *any* view of a base or index.
/// Canonicalising in the direction of more collisions is the safe direction for
/// invalidation, and costs at most a declined recovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemKey {
    /// Segment override, if the encoding carries one: an `fs`/`gs`-relative
    /// operand names a different address space than the same base/index pair
    /// without one.
    pub segment: Option<String>,
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u8,
    pub displacement: i64,
    /// Access width in bits. A `cmp` of the low byte proves nothing about the
    /// dword at the same address.
    pub size: u8,
}

/// The memory range checks in force, split by how much they have proved.
#[derive(Debug, Default, Clone)]
pub(super) struct MemoryBounds {
    /// Locations a PREDECESSOR's guard proved in range. Inherited across the
    /// in-range edge, and the only facts a load may consume.
    proved: HashMap<MemKey, u64>,
    /// The most recent `cmp <memory>, imm` in this block. A fact only on the
    /// in-range edge, so it is exported but never consumed here.
    pending: Option<(MemKey, u64)>,
}

impl MemoryBounds {
    /// Nothing to track — the common case, since only x86 encodes a comparison
    /// against a memory operand at all.
    pub(super) fn is_idle(&self) -> bool {
        self.proved.is_empty() && self.pending.is_none()
    }

    pub(super) fn clear(&mut self) {
        self.proved.clear();
        self.pending = None;
    }

    /// Forget this block's comparison without touching the inherited facts —
    /// what a `sub`, which writes its destination, leaves behind.
    pub(super) fn clear_comparison(&mut self) {
        self.pending = None;
    }

    pub(super) fn inherit(&mut self, mems: HashMap<MemKey, u64>) {
        self.proved.extend(mems);
    }

    /// Facts that survived this block, WITHOUT this block's own comparison.
    pub(super) fn proved(&self) -> HashMap<MemKey, u64> {
        self.proved.clone()
    }

    /// Facts for the in-range successor: what survived, plus what the guard just
    /// established, whichever bound is tighter on overlap.
    pub(super) fn export(&self) -> HashMap<MemKey, u64> {
        let mut mems = self.proved.clone();
        if let Some((key, limit)) = &self.pending {
            mems.entry(key.clone())
                .and_modify(|existing| *existing = (*existing).min(*limit))
                .or_insert(*limit);
        }
        mems
    }

    pub(super) fn export_pending_with_maximum(&self, maximum: u64) -> HashMap<MemKey, u64> {
        self.pending
            .as_ref()
            .map(|(key, _)| HashMap::from([(key.clone(), maximum)]))
            .unwrap_or_default()
    }

    /// The limit this block's comparison established, for the walker to decide
    /// whether the guard's in-range edge carries anything at all.
    pub(super) fn pending_limit(&self) -> Option<u64> {
        self.pending.as_ref().map(|(_, limit)| *limit)
    }

    /// Record `cmp <memory>, imm`, replacing any earlier comparison.
    ///
    /// A negative immediate is refused: the bound is an unsigned inclusive
    /// maximum, which is what an unsigned-above branch proves.
    pub(super) fn record_comparison(&mut self, ins: &Instruction, immediate: Option<i64>) {
        self.pending = match (
            ins.operands.first().and_then(mem_key),
            immediate.filter(|limit| *limit >= 0),
        ) {
            (Some(key), Some(limit)) => Some((key, limit as u64)),
            _ => None,
        };
    }

    /// Drop everything if this instruction could have written memory.
    pub(super) fn forget_stores(&mut self, ins: &Instruction) {
        if !self.is_idle() && may_write_memory(ins) {
            self.clear();
        }
    }

    /// Drop every fact whose address mentions `register`.
    ///
    /// Called for every register definition the tracker sees, so a base or index
    /// overwritten between the comparison and the load can never carry a bound
    /// across.
    pub(super) fn forget_through(&mut self, register: &str) {
        let mentions = |key: &MemKey| {
            key.base.as_deref() == Some(register) || key.index.as_deref() == Some(register)
        };
        self.proved.retain(|key, _| !mentions(key));
        if self.pending.as_ref().is_some_and(|(key, _)| mentions(key)) {
            self.pending = None;
        }
    }

    /// The bound a load inherits from the memory location it reads.
    ///
    /// Fires only when a predecessor's guard proved that exact location in range
    /// and this instruction's destination value IS that location's value:
    ///
    /// * a zero-extending move, whose destination equals the loaded bytes read
    ///   as an unsigned integer — the same reading the unsigned guard proved; or
    /// * an exact-width move, where no extension happens at all.
    ///
    /// Sign-extending loads are declined even though `[0, N]` with `N < 0x80`
    /// would survive one: the immediate's width is not the access width in
    /// general, and this recovery is not worth a case analysis that has to be
    /// right every time.
    pub(super) fn load_bound(&self, ins: &Instruction) -> Option<u64> {
        if self.proved.is_empty() || ins.operands.len() != 2 {
            return None;
        }
        let destination = ins.operands.first()?;
        if destination.kind != OperandKind::Register
            || destination.access != Access::Write
            || destination.register.is_none()
        {
            return None;
        }
        let source = ins.operands.get(1)?;
        if source.access != Access::Read {
            return None;
        }
        let carries_the_value = match ins.mnemonic.to_ascii_lowercase().as_str() {
            "movzx" | "movzbl" | "movzwl" | "movzbq" | "movzwq" => true,
            "mov" | "movb" | "movw" | "movl" | "movq" => source.size == destination.size,
            _ => false,
        };
        if !carries_the_value {
            return None;
        }
        self.proved.get(&mem_key(source)?).copied()
    }
}

/// The full effective-address identity of a memory operand, or `None` when this
/// operand is not one this module is willing to name.
///
/// Declines `rip`/`pc`-relative operands: the decoder has already folded those
/// into an absolute displacement, so their "base" is not a register whose later
/// definition would invalidate anything.
fn mem_key(operand: &Operand) -> Option<MemKey> {
    if operand.kind != OperandKind::Memory || operand.size == 0 {
        return None;
    }
    let base = operand.base.as_deref().map(super::canon);
    let index = operand.index.as_deref().map(super::canon);
    if matches!(base.as_deref(), Some("rip") | Some("pc") | Some("eip")) {
        return None;
    }
    if base.is_none() && index.is_none() {
        return None;
    }
    let scale = operand.scale.unwrap_or(1);
    if index.is_some() && !matches!(scale, 1 | 2 | 4 | 8) {
        return None;
    }
    Some(MemKey {
        segment: operand.segment.clone(),
        base,
        index,
        scale,
        displacement: operand.displacement?,
        size: operand.size,
    })
}

/// Mnemonics that provably do not write memory.
///
/// An ALLOWLIST, so every unmodelled form — string operations, stack pushes,
/// calls, atomics, and every ARM store, whose operands Capstone reports as
/// `Read` — clears the memory facts instead of silently surviving them. A
/// refusal costs one declined recovery; a survival attributes a bound to a
/// location something else may have overwritten.
const NO_MEMORY_WRITE: &[&str] = &[
    "mov", "movb", "movw", "movl", "movq", "movabs", "movzx", "movzbl", "movzwl", "movzbq",
    "movzwq", "movsx", "movsxd", "movslq", "movsbl", "movswl", "lea", "nop", "nopl", "nopw",
    "endbr32", "endbr64", "cmp", "test", "add", "sub", "adc", "sbb", "and", "or", "xor", "not",
    "neg", "shl", "sal", "shr", "sar", "rol", "ror", "shld", "shrd", "imul", "mul", "inc", "dec",
    "bswap", "cdq", "cdqe", "cqo", "cwde", "cwd", "cbw", "bt", "bsf", "bsr", "popcnt", "tzcnt",
    "lzcnt",
];

/// Mnemonics whose operand 0 is a memory location they only READ.
const MEMORY_SOURCE_ONLY: &[&str] = &[
    "cmp", "test", "push", "jmp", "call", "bt", "nop", "nopl", "nopw",
];

/// Could this instruction have written memory?
pub(super) fn may_write_memory(ins: &Instruction) -> bool {
    let is_memory = |operand: &Operand| operand.kind == OperandKind::Memory;
    if ins.operands.iter().any(|operand| {
        is_memory(operand) && matches!(operand.access, Access::Write | Access::ReadWrite)
    }) {
        return true;
    }
    let lower = ins.mnemonic.to_ascii_lowercase();
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower);
    // A memory operand in the DESTINATION position is a store for every form but
    // the handful that only read it. Decided from the operand position rather
    // than the decoder's access flags, because the ARM backend reports every
    // operand as `Read` — see `DispatchTracker::kill_register`.
    if ins.operands.first().is_some_and(is_memory) && !MEMORY_SOURCE_ONLY.contains(&m) {
        return true;
    }
    if m.starts_with("set") || m.starts_with("cmov") || m.starts_with('j') {
        return false;
    }
    !NO_MEMORY_WRITE.contains(&m)
}
