//! The active copy environment: what may be recorded, and when a record dies.
//!
//! Copy propagation is a substitution driven by a table. This module owns the
//! table -- [`Copies`] -- together with the two questions that decide what goes
//! into it ([`is_pure_copyable`], [`is_repeatable_versioned_flag_expr`]) and the
//! three that take entries back out ([`Copies::invalidate`],
//! [`Copies::invalidate_all`], [`copies_stable_across_loop`]). The walkers in
//! the parent decide *where* an entry is consulted; nothing here knows about
//! statement order, and nothing here edits the AST.
//!
//! # Invalidation is the hot path, and it is 85% "no"
//!
//! Every write asks the whole environment "does any recorded source read this
//! name?", and almost every recorded source does not. That is the one answer a
//! tree walk cannot reach early: proving a name *absent* means visiting every
//! node of every recorded expression. So each record carries a 64-bit Bloom
//! summary of the names its source reads ([`reg_bit`], [`read_summary`]), and a
//! single `AND` retires the common case before any walk starts. False positives
//! are free to be wrong -- they cost one exact [`super::alias::contains_reg`]
//! call; false negatives would be a soundness bug, which is why [`reg_bit`] is a
//! pure function of the register's value and nothing else.
//!
//! [`Copies::invalidate_all`] exists for the same reason at loop scale: a body
//! that assigns 128 locals used to re-scan the environment 128 times, walking
//! every recorded source in full each time.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::alias::contains_reg;
use super::hash::{RegMap, RegSet};
use super::reads::visit_expr_reads;

/// Is `e` safe to record as a copy source and duplicate into use sites? Only
/// pure, stable values: a register/local reference, a constant, or a resolved
/// address/name. Memory loads (`Deref`) and arithmetic are excluded — their
/// value can change or their operands be clobbered before the use.
pub(super) fn is_pure_copyable(e: &Expr) -> bool {
    match e {
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. } => true,
        // Integer view changes are pure, cheap, and retain the source register
        // in the expression, so the ordinary invalidation rule still removes
        // the alias if that source is overwritten. Treating the view as a copy
        // prevents a machine-width SSA value from becoming a fake mutable C
        // variable merely because it has more than one use.
        Expr::Cast { expr, .. } => is_pure_copyable(expr),
        _ => false,
    }
}

/// Whether a value-numbered predicate definition is safe to repeat at each use.
///
/// Arithmetic expressions are not general-purpose copies: carrying one after an
/// operand write would use a new value. The propagation environment already
/// invalidates aliases on every operand write and clears them at control-flow
/// boundaries, so a side-effect-free *SSA predicate* can be repeated safely.
/// This narrow exception exposes flag algebra such as
/// `SF ^ (signed_less ^ SF)` even when a CMOV sequence consumes it twice.
pub(super) fn is_repeatable_versioned_flag_expr(dst: &VReg, expression: &Expr) -> bool {
    if !matches!(dst, VReg::FlagValue { version, .. } if *version > 0) {
        return false;
    }
    fn pure(expression: &Expr) -> bool {
        match expression {
            Expr::Reg(_) | Expr::Const(_) => true,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => pure(lhs) && pure(rhs),
            Expr::Un { src, .. }
            | Expr::Cast { expr: src, .. }
            | Expr::NumericConvert { expr: src, .. } => pure(src),
            Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Deref { .. }
            | Expr::Call { .. }
            | Expr::Select { .. }
            | Expr::Unknown(_)
            | Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::FunctionTableEntry { .. }
            | Expr::WideArithmetic { .. } => false,
        }
    }
    pure(expression)
}

/// One recorded copy: its source expression plus a summary of the register
/// names that expression reads.
#[derive(Clone, Debug)]
struct Recorded {
    src: Expr,
    /// Bloom filter over the source's read set, one bit per [`reg_bit`] class.
    ///
    /// `invalidate` asks "does this source read the name just written?" once
    /// per recorded copy per write, and the answer is almost always no — which
    /// is the one answer a tree walk cannot reach early, because proving a name
    /// absent means visiting every node. The summary answers "certainly not"
    /// with a single `AND`; only a set bit pays for the exact walk.
    reads: u64,
}

/// A name's bit in [`Recorded::reads`].
///
/// Any deterministic function of the *value* of a `VReg` works: the filter is
/// allowed false positives (they cost one exact walk) and must have no false
/// negatives, which holds as long as equal registers map to equal bits. FNV-1a
/// over the discriminant and payload, folded to one of 64 buckets.
fn reg_bit(register: &VReg) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    fn mix(hash: u64, byte: u8) -> u64 {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    }
    fn mix_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
        for byte in bytes {
            hash = mix(hash, *byte);
        }
        hash
    }
    let hash = match register {
        VReg::Phys(name) => mix_bytes(mix(OFFSET, 1), name.as_bytes()),
        VReg::Temp(index) => mix_bytes(mix(OFFSET, 2), &index.to_le_bytes()),
        VReg::Flag(flag) => mix_bytes(mix(OFFSET, 3), flag.ident().as_bytes()),
        VReg::FlagValue { flag, version } => mix_bytes(
            mix_bytes(mix(OFFSET, 4), flag.ident().as_bytes()),
            &version.to_le_bytes(),
        ),
    };
    1u64 << (hash >> 58)
}

/// Union of [`reg_bit`] over every register `e` reads.
fn read_summary(e: &Expr) -> u64 {
    let mut summary = 0;
    visit_expr_reads(e, &mut |register| {
        summary |= reg_bit(register);
        true
    });
    summary
}

/// The active copy environment: destination name -> recorded source value.
#[derive(Clone, Debug, Default)]
pub(super) struct Copies {
    map: RegMap<Recorded>,
}

impl Copies {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// The one-entry environment the narrow adjacent-value folders substitute
    /// with.
    pub(super) fn single(dst: VReg, src: Expr) -> Self {
        let mut copies = Self::new();
        copies.insert(dst, src);
        copies
    }

    pub(super) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.map.clear();
    }

    pub(super) fn get(&self, register: &VReg) -> Option<&Expr> {
        self.map.get(register).map(|recorded| &recorded.src)
    }

    pub(super) fn insert(&mut self, dst: VReg, src: Expr) {
        let reads = read_summary(&src);
        self.map.insert(dst, Recorded { src, reads });
    }

    /// Drop every recorded copy the predicate rejects, by destination and
    /// source expression.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&VReg, &Expr) -> bool) {
        self.map.retain(|dst, recorded| keep(dst, &recorded.src));
    }

    /// Invalidate every copy whose destination *is* `written`, or whose source
    /// *reads* `written` (its recorded value is now stale).
    fn invalidate(&mut self, written: &VReg) {
        if self.map.is_empty() {
            return;
        }
        // Removing the destination up front is what lets the scan below skip
        // the per-entry name comparison entirely.
        self.map.remove(written);
        let bit = reg_bit(written);
        self.map.retain(|_, recorded| {
            recorded.reads & bit == 0 || !contains_reg(&recorded.src, written)
        });
    }

    /// [`Copies::invalidate`] for a whole write set at once.
    ///
    /// One scan, not one per name: a loop body that assigns 128 locals used to
    /// re-scan the entire environment 128 times, and every one of those scans
    /// walked every recorded source expression in full.
    fn invalidate_all(&mut self, written: &RegSet) {
        if self.map.is_empty() || written.is_empty() {
            return;
        }
        let bits = written
            .iter()
            .fold(0u64, |bits, register| bits | reg_bit(register));
        self.map.retain(|dst, recorded| {
            if written.contains(dst) {
                return false;
            }
            if recorded.reads & bits == 0 {
                return true;
            }
            let mut reads_written = false;
            visit_expr_reads(&recorded.src, &mut |register| {
                if written.contains(register) {
                    reads_written = true;
                }
                !reads_written
            });
            !reads_written
        });
    }
}

pub(super) fn invalidate(copies: &mut Copies, written: &VReg) {
    copies.invalidate(written);
}

/// Every register/local a structured statement may redefine.
///
/// A pre-loop copy is valid in a loop condition only when neither its
/// destination nor any source register can change in the body.  The condition
/// is evaluated again after every backedge, so substituting an entry snapshot
/// for a loop-carried cursor freezes it after the first iteration.
fn collect_written_regs(body: &[Stmt], written: &mut RegSet) {
    for statement in body {
        match statement {
            Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
                written.insert(dst.clone());
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                ..
            } => {
                written.insert(dst.clone());
            }
            Stmt::Call { dst: Some(dst), .. } => {
                written.insert(dst.clone());
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_written_regs(then_body, written);
                if let Some(else_body) = else_body {
                    collect_written_regs(else_body, written);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_written_regs(body, written);
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_written_regs(std::slice::from_ref(init.as_ref()), written);
                collect_written_regs(body, written);
                collect_written_regs(std::slice::from_ref(step.as_ref()), written);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collect_written_regs(case_body, written);
                }
                if let Some(default_body) = default {
                    collect_written_regs(default_body, written);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_written_regs(try_body, written);
                for catch in catches {
                    collect_written_regs(&catch.body, written);
                }
            }
            Stmt::Store { .. }
            | Stmt::Call { dst: None, .. }
            | Stmt::Return { .. }
            | Stmt::Push { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. } => {}
        }
    }
}

pub(super) fn copies_stable_across_loop(copies: &Copies, body: &[Stmt]) -> Copies {
    let mut stable = copies.clone();
    let mut written = RegSet::default();
    collect_written_regs(body, &mut written);
    stable.invalidate_all(&written);
    stable
}

pub(super) fn is_self_ref(dst: &VReg, src: &Expr) -> bool {
    matches!(src, Expr::Reg(r) if r == dst)
}
