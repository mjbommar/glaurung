//! Static Single Assignment form over [`LlirFunction`].
//!
//! Rather than duplicate every LLIR op into an SSA variant, this module
//! produces a side-car [`SsaInfo`] that records:
//!
//! * the dominator tree of the function,
//! * dominance frontiers per block,
//! * phi-placement (where and for which VRegs),
//! * a version number for every def site, and
//! * a version number for every use site.
//!
//! Consumers keep the original `LlirFunction` and cross-reference it with
//! `SsaInfo` by [`InstrAddr`]. This keeps the LLIR types stable and avoids
//! a second parallel type hierarchy.
//!
//! Scope (v1):
//! * Operates on register and predicate VRegs (`VReg::Phys`, `VReg::Temp`, and
//!   `VReg::Flag`) — memory is not versioned.
//! * Dominance is computed with the iterative algorithm of Cooper, Harvey &
//!   Kennedy (2001) — simple and well within our budgets for the function
//!   sizes we see today.
//! * Entry-block uses without a preceding def stay at version 0.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use crate::ir::regview;
use crate::ir::types::{CallTarget, LlirFunction, MemOp, Op, VReg, Value};
use crate::ir::use_def::{for_each_def, for_each_use, use_count, InstrAddr};
use crate::target::{TargetId, TargetSpec};

/// The identity of one machine value in SSA form.
///
/// `base` names the canonical storage location (for example both `edi` and
/// `rdi` map to `rdi` on x86-64); `version` identifies the particular write.
/// Version zero is the implicit live-in definition at function entry.  This is
/// the stable key downstream value/type/storage analyses consume instead of
/// collapsing every lifetime of an architectural register into one fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaValue {
    pub base: VReg,
    pub version: u32,
}

/// A phi node placed by SSA construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phi {
    pub block_idx: usize,
    /// The original VReg being renamed at this merge point.
    pub base: VReg,
    /// Version assigned to this phi's *result*.
    pub dst_version: u32,
    /// One (predecessor block, incoming version) entry per predecessor.
    pub incoming: Vec<(usize, u32)>,
}

/// SSA side-car information about an [`LlirFunction`].
#[derive(Debug, Default, Clone)]
pub struct SsaInfo {
    /// Immediate dominator of each block, by block index. The entry block
    /// has no idom and maps to `None`.
    pub idom: Vec<Option<usize>>,
    /// Dominance frontier sets, by block index.
    pub frontier: Vec<BTreeSet<usize>>,
    /// All placed phi nodes, grouped by their block.
    pub phis: Vec<Phi>,
    /// Version of the def written at this instruction (register-VReg defs only).
    pub def_versions: HashMap<InstrAddr, u32>,
    /// Version read at this `(instruction, use_index)` pair. The use_index
    /// corresponds to the source-order uses enumerated by [`def_uses`].
    pub use_versions: HashMap<(InstrAddr, usize), u32>,
    /// Complete output identities, including every output of a multi-output
    /// intrinsic. The legacy `def_versions` map remains the output-zero view.
    def_values_all: OperandTable,
    /// Complete use identities with canonical storage captured at analysis
    /// time. This prevents queries from re-canonicalizing under a different
    /// architecture later.
    use_values_all: OperandTable,
}

/// Per-`(block, instruction, operand)` storage, indexed rather than hashed.
///
/// The key of these two tables is a dense coordinate — block index,
/// instruction index, operand position — so a `HashMap` was hashing 24 bytes of
/// integers on every query and every insert to reach a slot arithmetic can
/// address directly. On `07_packet_parser::parse_packet` that was the single
/// largest cost in the dataflow phase: SipHash accounted for 16.6% of it, and
/// `hash_one::<&(InstrAddr, usize)>` for another 4.9%, because the bit-demand
/// fixed point asks for the definition and every use of every instruction on
/// every sweep.
///
/// Indexing is also why the tables cannot reorder anything: there is no
/// iteration order to depend on, and a slot's address is a function of the
/// coordinate alone.
#[derive(Debug, Default, Clone)]
pub(crate) struct OperandGrid<T> {
    /// Flat index of each block's first instruction, with a final terminator,
    /// so `block_base[b + 1] - block_base[b]` is block `b`'s length.
    block_base: Vec<u32>,
    /// Start offset into `slots` for each flat instruction, with a terminator.
    instr_base: Vec<u32>,
    slots: Vec<T>,
}

/// The SSA identity tables: one optional value per operand position.
type OperandTable = OperandGrid<Option<SsaValue>>;

impl<T: Clone + Default> OperandGrid<T> {
    /// Reserve exactly `width(op)` operand slots for each instruction of `lf`.
    pub(crate) fn with_widths(lf: &LlirFunction, width: impl Fn(&Op) -> usize) -> Self {
        let mut block_base: Vec<u32> = Vec::with_capacity(lf.blocks.len() + 1);
        let mut instr_base: Vec<u32> = Vec::new();
        let mut flat = 0u32;
        let mut total = 0u32;
        for block in &lf.blocks {
            block_base.push(flat);
            for instruction in &block.instrs {
                instr_base.push(total);
                total = total.saturating_add(width(&instruction.op) as u32);
                flat += 1;
            }
        }
        block_base.push(flat);
        instr_base.push(total);
        Self {
            block_base,
            instr_base,
            slots: vec![T::default(); total as usize],
        }
    }

    /// Total operand slots, which is also an exact capacity for any map keyed
    /// by the same coordinates.
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    fn slot(&self, addr: InstrAddr, index: usize) -> Option<usize> {
        let start = *self.block_base.get(addr.block_idx)? as usize;
        let end = *self.block_base.get(addr.block_idx + 1)? as usize;
        let flat = start.checked_add(addr.instr_idx)?;
        if flat >= end {
            return None;
        }
        let operand_start = self.instr_base[flat] as usize;
        let operand_end = self.instr_base[flat + 1] as usize;
        let slot = operand_start.checked_add(index)?;
        (slot < operand_end).then_some(slot)
    }

    pub(crate) fn cell(&self, addr: InstrAddr, index: usize) -> Option<&T> {
        Some(&self.slots[self.slot(addr, index)?])
    }

    pub(crate) fn cell_mut(&mut self, addr: InstrAddr, index: usize) -> Option<&mut T> {
        let slot = self.slot(addr, index)?;
        Some(&mut self.slots[slot])
    }
}

impl OperandTable {
    fn get(&self, addr: InstrAddr, index: usize) -> Option<&SsaValue> {
        self.cell(addr, index)?.as_ref()
    }

    fn set(&mut self, addr: InstrAddr, index: usize, value: SsaValue) {
        if let Some(cell) = self.cell_mut(addr, index) {
            *cell = Some(value);
        }
    }
}

/// How many SSA-eligible registers an operation defines.
pub(crate) fn ssa_def_width(op: &Op) -> usize {
    let mut width = 0;
    for_each_def(op, |register| {
        if is_ssa_reg(register) {
            width += 1;
        }
    });
    width
}

impl SsaInfo {
    /// Return the SSA value defined by the instruction at `addr`.
    pub fn def_value(&self, lf: &LlirFunction, addr: InstrAddr) -> Option<SsaValue> {
        self.def_value_ref(lf, addr).cloned()
    }

    /// Borrow the SSA value defined by the instruction at `addr`.
    ///
    /// An `SsaValue` owns the physical-register spelling, so the cloning form
    /// allocates a `String` per call. The bit-demand fixed point asks this once
    /// per instruction per sweep, which is the only reason this exists.
    pub fn def_value_ref(&self, lf: &LlirFunction, addr: InstrAddr) -> Option<&SsaValue> {
        lf.blocks.get(addr.block_idx)?.instrs.get(addr.instr_idx)?;
        self.def_values_all.get(addr, 0)
    }

    /// Borrow the SSA value read at source-order use `use_index`. See
    /// [`SsaInfo::def_value_ref`].
    pub fn use_value_ref(
        &self,
        lf: &LlirFunction,
        addr: InstrAddr,
        use_index: usize,
    ) -> Option<&SsaValue> {
        lf.blocks.get(addr.block_idx)?.instrs.get(addr.instr_idx)?;
        self.use_values_all.get(addr, use_index)
    }

    /// Return every SSA value defined by one instruction, in output order.
    pub fn def_values(&self, lf: &LlirFunction, addr: InstrAddr) -> Vec<SsaValue> {
        if lf
            .blocks
            .get(addr.block_idx)
            .and_then(|block| block.instrs.get(addr.instr_idx))
            .is_none()
        {
            return Vec::new();
        }
        (0..)
            .map_while(|index| self.def_values_all.get(addr, index).cloned())
            .collect()
    }

    /// The version of the definition at `addr`, or 0 when there is none.
    ///
    /// The same answer as `def_versions[addr]`, read out of the indexed table
    /// rather than by hashing the address: renaming writes both from one
    /// `new_version`, so they agree by construction.
    pub fn def_version(&self, lf: &LlirFunction, addr: InstrAddr) -> u32 {
        self.def_value_ref(lf, addr).map_or(0, |value| value.version)
    }

    /// The version read at source-order use `use_index`, or 0. See
    /// [`SsaInfo::def_version`].
    pub fn use_version(&self, lf: &LlirFunction, addr: InstrAddr, use_index: usize) -> u32 {
        self.use_value_ref(lf, addr, use_index)
            .map_or(0, |value| value.version)
    }

    /// Return the SSA value read at the source-order use `use_index` of the
    /// instruction at `addr`. The index is exactly the one returned by
    /// [`def_uses`], so consumers do not need to reproduce the renamer's order.
    pub fn use_value(
        &self,
        lf: &LlirFunction,
        addr: InstrAddr,
        use_index: usize,
    ) -> Option<SsaValue> {
        self.use_value_ref(lf, addr, use_index).cloned()
    }
}

/// Registers and flag predicates are SSA values. Memory remains outside SSA.
fn is_ssa_reg(v: &VReg) -> bool {
    matches!(v, VReg::Phys(_) | VReg::Temp(_) | VReg::Flag(_))
}

/// The 64-bit parent of a general-purpose x86-64 register name, for the 32-bit
/// (and 64-bit identity) views. A 32-bit write ZERO-EXTENDS into the 64-bit
/// register, and a 32-bit read is the low half — so `eax` and `rax` are ONE SSA
/// value: versioning them together lets a `%rax` write shadow a later `%eax`
/// read (and vice versa), fixing the "64-bit value read via a 32-bit view reads
/// a stale sub-register" corruption. 8/16-bit views (`al`/`ax`) are partial
/// (they preserve the high bits) so they are intentionally NOT merged here.
///
/// The layout and the merge rule both come from [`crate::ir::regview`], the one
/// register-view descriptor shared with the lifter and the execution engine — this
/// is deliberately not a third private register table.
/// AArch64 is consulted after x86-64 because the two name spaces are disjoint
/// except for `sp`, which x86-64 spells as a 16-bit bit-preserving view (so
/// [`regview::ssa_parent`] declines it) and AArch64 spells as its own 64-bit
/// parent (so the fallback maps it to itself — an identity, not a merge).
///
/// Leaving AArch64 out was not a missing nicety: `wN` is the zero-extending low
/// half of `xN`, so without it `ldr w0,[sp,#12]` followed by `lsl x1,x0,#32`
/// were two unrelated SSA values and the shift read an undefined live-in.
/// `reconstruct_64` decompiled to `return 0;`.
pub fn parent64(n: &str) -> Option<&'static str> {
    if ARM32_AMBIGUOUS.contains(&n) {
        return None;
    }
    regview::ssa_parent(regview::Arch::X86_64, n)
        .or_else(|| regview::ssa_parent(regview::Arch::AArch64, n))
}

/// Register names that AArch64 and ARM32 spell alike but size differently.
///
/// This lookup is architecture-blind, so it must decline ambiguous aliases.
/// ARM32 has no sub-register views and loses nothing by retaining these names.
const ARM32_AMBIGUOUS: [&str; 2] = ["lr", "fp"];

/// Canonicalize a GP sub-register VReg to its 64-bit parent (identity otherwise).
pub fn canon_gpr(v: &VReg) -> VReg {
    if let VReg::Phys(n) = v {
        if let Some(p) = parent64(n) {
            return VReg::Phys(p.to_string());
        }
    }
    v.clone()
}

/// Canonicalized SSA-eligible definitions of `op`, appended to `out`.
///
/// Written against [`for_each_def`] rather than [`defs_uses`]: the collecting
/// form allocates a `Vec<VReg>` and clones the physical-register `String` of
/// every definition, only for this to clone each survivor a second time under
/// `canonicalize`. The renamer asks this per instruction.
fn write_regs_into(op: &Op, canonicalize: &impl Fn(&VReg) -> VReg, out: &mut Vec<VReg>) {
    out.clear();
    for_each_def(op, |register| {
        if is_ssa_reg(register) {
            out.push(canonicalize(register));
        }
    });
}

fn write_regs(op: &Op, canonicalize: &impl Fn(&VReg) -> VReg) -> Vec<VReg> {
    let mut out = Vec::new();
    write_regs_into(op, canonicalize, &mut out);
    out
}

/// Canonicalized reads of `op`, appended to `out`. See [`write_regs_into`] for
/// why this borrows instead of collecting twice.
fn uses_of_op_canonical_into(
    op: &Op,
    canonicalize: &impl Fn(&VReg) -> VReg,
    out: &mut Vec<VReg>,
) {
    out.clear();
    for_each_use(op, |register| out.push(canonicalize(register)));
}

/// Canonicalize one register under the function's actual target.
pub fn canon_gpr_for_target(target: TargetSpec, value: &VReg) -> VReg {
    let VReg::Phys(name) = value else {
        return value.clone();
    };
    // IA-32 still shares downstream ABI/naming consumers with the historical
    // architecture-blind model, which spells its `e*` values as `r*`. Changing
    // that identity independently regresses most of the i386 fixture corpus.
    // Preserve it until the x86-32 lifter and consumers migrate together.
    if target.id() == TargetId::X86_32 {
        return canon_gpr(value);
    }
    let parent = match target.id() {
        TargetId::X86_64 => regview::ssa_parent(regview::Arch::X86_64, name),
        TargetId::AArch64 => regview::ssa_parent(regview::Arch::AArch64, name),
        TargetId::Arm32 => match name.as_str() {
            "a1" => Some("r0"),
            "a2" => Some("r1"),
            "a3" => Some("r2"),
            "a4" => Some("r3"),
            "v1" => Some("r4"),
            "v2" => Some("r5"),
            "v3" => Some("r6"),
            "v4" => Some("r7"),
            "v5" => Some("r8"),
            "v6" | "sb" => Some("r9"),
            "v7" | "sl" => Some("r10"),
            "v8" | "fp" => Some("r11"),
            "ip" => Some("r12"),
            "r13" | "sp" => Some("sp"),
            "r14" | "lr" => Some("lr"),
            "r15" | "pc" => Some("pc"),
            _ => None,
        },
        TargetId::X86_32 => unreachable!("handled by compatibility branch above"),
        TargetId::Unsupported(_) => None,
    };
    VReg::Phys(parent.unwrap_or(name).to_string())
}

/// Canonicalize a register READ under the function's actual target.
///
/// Definitions use [`regview::ssa_parent`]: only a whole-parent or
/// zero-extending write defines the complete parent value. Reads have the
/// opposite rule. Reading `ax`, `al`, or `ah` observes a window of the current
/// `rax` value, so it must use that parent's reaching SSA version. Partial x86
/// writes are already lifted as explicit parent read-modify-writes; this does
/// not invent a parent definition.
fn canon_read_for_target(target: TargetSpec, value: &VReg) -> VReg {
    let VReg::Phys(name) = value else {
        return value.clone();
    };
    if target.id() == TargetId::X86_32 {
        return canon_gpr(value);
    }
    let parent = match target.id() {
        TargetId::X86_64 => regview::view(regview::Arch::X86_64, name)
            .filter(|view| view.bank == regview::RegBank::Gp)
            .map(|view| view.parent),
        TargetId::AArch64 => regview::view(regview::Arch::AArch64, name)
            .filter(|view| view.bank == regview::RegBank::Gp)
            .map(|view| view.parent),
        TargetId::X86_32 => unreachable!("handled by compatibility branch above"),
        TargetId::Arm32 | TargetId::Unsupported(_) => {
            return canon_gpr_for_target(target, value);
        }
    };
    VReg::Phys(parent.unwrap_or(name).to_string())
}

/// Compute predecessor lists derived from each block's `succs`.
fn build_preds(lf: &LlirFunction) -> Vec<Vec<usize>> {
    let n = lf.blocks.len();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    // Map VA → block index for successor resolution.
    let va_to_idx: HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    for (i, b) in lf.blocks.iter().enumerate() {
        for s in &b.succs {
            if let Some(&j) = va_to_idx.get(s) {
                preds[j].push(i);
            }
        }
    }
    for p in &mut preds {
        p.sort_unstable();
        p.dedup();
    }
    preds
}

/// Iterative dominators via Cooper/Harvey/Kennedy, using a reverse-postorder
/// traversal of the CFG rooted at block 0.
///
/// Returns `(idom, rpo)` where `idom[i]` is the immediate dominator of block
/// `i` (None for the entry), and `rpo` is the reverse-post-order.
fn compute_dominators(lf: &LlirFunction, preds: &[Vec<usize>]) -> (Vec<Option<usize>>, Vec<usize>) {
    let n = lf.blocks.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }

    // --- Reverse postorder via iterative DFS on successors -------------------
    let rpo: Vec<usize>;
    {
        let mut visited = vec![false; n];
        let mut order: Vec<usize> = Vec::with_capacity(n);
        let mut stack: Vec<(usize, usize)> = Vec::new(); // (node, next_succ_cursor)
        stack.push((0, 0));
        visited[0] = true;

        // One VA->index map for the whole walk. Rebuilding it inside the
        // closure made every stack visit pay an O(blocks) hash-map build, so
        // the depth-first walk itself cost O(blocks * (blocks + edges)).
        let va_to_idx: HashMap<u64, usize> = lf
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start_va, i))
            .collect();
        let succ_of = |bi: usize, out: &mut Vec<usize>| {
            out.clear();
            for s in &lf.blocks[bi].succs {
                if let Some(&j) = va_to_idx.get(s) {
                    out.push(j);
                }
            }
        };

        let mut succs: Vec<usize> = Vec::new();
        while let Some(&(node, cursor)) = stack.last() {
            succ_of(node, &mut succs);
            if cursor < succs.len() {
                let next = succs[cursor];
                // advance cursor
                let top = stack.last_mut().unwrap();
                top.1 += 1;
                if !visited[next] {
                    visited[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
        // post-order is `order`; reverse-post-order is its reverse.
        order.reverse();
        // Any unreachable blocks get appended at the end (keeps them indexed
        // but they stay with no idom).
        for i in 0..n {
            if !visited[i] {
                order.push(i);
            }
        }
        rpo = order;
    }

    // `rpo_pos[block]` = index within rpo (smaller = earlier).
    let mut rpo_pos = vec![usize::MAX; n];
    for (i, &b) in rpo.iter().enumerate() {
        rpo_pos[b] = i;
    }

    // --- Dominator fixed-point ----------------------------------------------
    let mut idom: Vec<Option<usize>> = vec![None; n];
    idom[0] = Some(0); // self-dominate sentinel during the loop

    let intersect = |mut b1: usize, mut b2: usize, idom: &[Option<usize>]| -> usize {
        while b1 != b2 {
            while rpo_pos[b1] > rpo_pos[b2] {
                b1 = idom[b1].expect("idom must be set on finger in intersect");
            }
            while rpo_pos[b2] > rpo_pos[b1] {
                b2 = idom[b2].expect("idom must be set on finger in intersect");
            }
        }
        b1
    };

    let mut changed = true;
    while changed {
        changed = false;
        // Process blocks in reverse-postorder, skipping the entry.
        for &b in &rpo {
            if b == 0 {
                continue;
            }
            // Pick a processed predecessor as starting point.
            let mut new_idom: Option<usize> = None;
            for &p in &preds[b] {
                if idom[p].is_some() {
                    new_idom = Some(p);
                    break;
                }
            }
            let Some(mut new_idom) = new_idom else {
                continue; // unreachable
            };
            for &p in &preds[b] {
                if p == new_idom {
                    continue;
                }
                if idom[p].is_some() {
                    new_idom = intersect(p, new_idom, &idom);
                }
            }
            if idom[b] != Some(new_idom) {
                idom[b] = Some(new_idom);
                changed = true;
            }
        }
    }

    // Entry dominates itself; surface as None per our convention.
    idom[0] = None;
    (idom, rpo)
}

/// Compute dominance frontier for each block, given immediate dominators and
/// predecessor lists.
fn compute_frontiers(idom: &[Option<usize>], preds: &[Vec<usize>]) -> Vec<BTreeSet<usize>> {
    let n = idom.len();
    let mut df: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for b in 0..n {
        if preds[b].len() < 2 {
            continue;
        }
        let Some(b_idom) = idom[b] else { continue };
        for &p in &preds[b] {
            let mut runner = p;
            while runner != b_idom {
                df[runner].insert(b);
                let Some(next) = idom[runner] else { break };
                if next == runner {
                    break;
                }
                runner = next;
            }
        }
    }
    df
}

/// Compute which blocks define each SSA-eligible VReg.
/// The blocks are visited in ascending order, so each variable's list is built
/// already sorted and deduplicated — which is what a `BTreeSet<usize>` was
/// providing at the cost of a tree node per element.
fn def_blocks(
    lf: &LlirFunction,
    canonicalize: &impl Fn(&VReg) -> VReg,
) -> BTreeMap<VReg, Vec<usize>> {
    let mut out: BTreeMap<VReg, Vec<usize>> = BTreeMap::new();
    let mut defs: Vec<VReg> = Vec::new();
    for (bi, b) in lf.blocks.iter().enumerate() {
        for ins in &b.instrs {
            write_regs_into(&ins.op, canonicalize, &mut defs);
            for d in defs.drain(..) {
                let blocks = out.entry(d).or_default();
                if blocks.last() != Some(&bi) {
                    blocks.push(bi);
                }
            }
        }
    }
    out
}

/// Place phi nodes at the iterated dominance frontier of the def-blocks of
/// each variable. Returns a parallel vector indexed by block number of phi
/// records (one per VReg requiring a phi at that block).
fn place_phis(
    def_blocks: &BTreeMap<VReg, Vec<usize>>,
    frontier: &[BTreeSet<usize>],
    preds: &[Vec<usize>],
) -> Vec<Vec<(VReg, Vec<usize>)>> {
    let n = frontier.len();
    let mut phi_blocks: Vec<Vec<(VReg, Vec<usize>)>> = vec![Vec::new(); n];
    // Membership over block indices, which are dense: two reused bit vectors
    // rather than two fresh `HashSet`s per variable. `stamp` avoids clearing
    // them between variables — a block belongs to the current variable's set
    // only if its stamp matches.
    let mut has_phi: Vec<u32> = vec![0; n];
    let mut in_work: Vec<u32> = vec![0; n];
    let mut work: VecDeque<usize> = VecDeque::new();
    let mut stamp = 0u32;
    for (v, defs) in def_blocks {
        stamp += 1;
        work.clear();
        work.extend(defs.iter().copied());
        for &b in defs {
            in_work[b] = stamp;
        }
        while let Some(b) = work.pop_front() {
            in_work[b] = 0;
            for &y in &frontier[b] {
                if has_phi[y] == stamp {
                    continue;
                }
                has_phi[y] = stamp;
                phi_blocks[y].push((v.clone(), preds[y].clone()));
                if defs.binary_search(&y).is_err() && in_work[y] != stamp {
                    work.push_back(y);
                    in_work[y] = stamp;
                }
            }
        }
    }
    phi_blocks
}

/// Build child lists from the idom array (for dom-tree DFS).
fn dom_children(idom: &[Option<usize>]) -> Vec<Vec<usize>> {
    let n = idom.len();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (b, i) in idom.iter().enumerate() {
        if let Some(p) = i {
            if *p != b {
                children[*p].push(b);
            }
        }
    }
    children
}

/// Classic Cytron-style renaming.
fn rename(
    lf: &LlirFunction,
    idom: &[Option<usize>],
    phi_blocks: &[Vec<(VReg, Vec<usize>)>],
    canonicalize_def: &impl Fn(&VReg) -> VReg,
    canonicalize_use: &impl Fn(&VReg) -> VReg,
) -> (SsaInfo, Vec<Vec<Phi>>) {
    let n = lf.blocks.len();
    let children = dom_children(idom);

    // Counter and version stack per VReg.
    let mut counter: HashMap<VReg, u32> = HashMap::new();
    let mut stack: HashMap<VReg, Vec<u32>> = HashMap::new();

    let mut def_values_all = OperandTable::with_widths(lf, ssa_def_width);
    let mut use_values_all = OperandTable::with_widths(lf, use_count);
    // Exact capacities from the operand counts already computed above. Growing
    // these incrementally made `reserve_rehash` 3.9% of the dataflow phase on
    // `07_packet_parser::parse_packet`.
    let mut def_versions: HashMap<InstrAddr, u32> =
        HashMap::with_capacity(def_values_all.len());
    let mut use_versions: HashMap<(InstrAddr, usize), u32> =
        HashMap::with_capacity(use_values_all.len());
    // Phi results and incoming version slots, filled in as we rename.
    let mut phi_dst: Vec<HashMap<VReg, u32>> = vec![HashMap::new(); n];
    let mut phi_inputs: Vec<HashMap<VReg, HashMap<usize, u32>>> = vec![HashMap::new(); n];

    // Explicit definitions are numbered from 1. Version 0 is reserved as the
    // implicit *entry-def* of every register — the value that is live-in at the
    // function entry (a parameter for an ABI argument register). A use with no
    // reaching in-function def reads version 0 (see `top_version`), so a live-in
    // parameter and the first scratch redefinition of the same physical register
    // no longer collide at version 0 — which is what lets later passes tell a
    // parameter apart from a reused-as-scratch argument register.
    fn new_version(
        counter: &mut HashMap<VReg, u32>,
        stack: &mut HashMap<VReg, Vec<u32>>,
        v: &VReg,
    ) -> u32 {
        // `entry` takes the key by value, so the plain form allocated a `String`
        // for the physical-register spelling on every definition even when the
        // register was already known. Look up first; clone only to insert.
        let ver = match counter.get_mut(v) {
            Some(c) => {
                let ver = *c;
                *c += 1;
                ver
            }
            None => {
                counter.insert(v.clone(), 2);
                1
            }
        };
        match stack.get_mut(v) {
            Some(s) => s.push(ver),
            None => {
                stack.insert(v.clone(), vec![ver]);
            }
        }
        ver
    }

    fn top_version(stack: &HashMap<VReg, Vec<u32>>, v: &VReg) -> u32 {
        stack.get(v).and_then(|s| s.last().copied()).unwrap_or(0)
    }

    let va_to_idx: HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();

    // Reused across every instruction so the canonicalized def/use walks do not
    // allocate a fresh `Vec<VReg>` per instruction.
    let mut use_scratch: Vec<VReg> = Vec::new();
    let mut def_scratch: Vec<VReg> = Vec::new();

    // Iterative DFS of the dominator tree so we don't blow the stack on deep
    // CFGs. Each stack entry is (block, child_cursor, pushed_vregs).
    let mut dfs: Vec<(usize, usize, Vec<VReg>)> = idom
        .iter()
        .enumerate()
        .rev()
        .filter_map(|(block, immediate)| immediate.is_none().then_some((block, 0, Vec::new())))
        .collect();

    while let Some(&mut (block, cursor, _)) = dfs.last_mut() {
        if cursor == 0 {
            // --- Entering `block`: rename all defs and uses here ------------
            let mut pushed_here: Vec<VReg> = Vec::new();

            // 1. Phis defined at this block get fresh versions.
            for (v, _preds) in &phi_blocks[block] {
                let ver = new_version(&mut counter, &mut stack, v);
                phi_dst[block].insert(v.clone(), ver);
                pushed_here.push(v.clone());
            }

            // 2. Rename each LLIR op's uses, then its def.
            for (ii, ins) in lf.blocks[block].instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx: block,
                    instr_idx: ii,
                };
                uses_of_op_canonical_into(&ins.op, canonicalize_use, &mut use_scratch);
                // Drained, so the canonicalized register moves into the SSA
                // value instead of being cloned into it — one `String`
                // allocation per use rather than two.
                for (ui, u) in use_scratch.drain(..).enumerate() {
                    if is_ssa_reg(&u) {
                        let version = top_version(&stack, &u);
                        use_versions.insert((addr, ui), version);
                        use_values_all.set(addr, ui, SsaValue { base: u, version });
                    }
                }
                write_regs_into(&ins.op, canonicalize_def, &mut def_scratch);
                for (output_index, d) in def_scratch.drain(..).enumerate() {
                    let ver = new_version(&mut counter, &mut stack, &d);
                    if output_index == 0 {
                        def_versions.insert(addr, ver);
                    }
                    def_values_all.set(
                        addr,
                        output_index,
                        SsaValue {
                            base: d.clone(),
                            version: ver,
                        },
                    );
                    pushed_here.push(d);
                }
            }

            // 3. Fill successor phi's incoming-version slots for this predecessor.
            // `va_to_idx` is hoisted out of the dominator-tree walk: building it
            // here rebuilt an O(blocks) hash map once per block.
            for succ in lf.blocks[block]
                .succs
                .iter()
                .filter_map(|s| va_to_idx.get(s))
            {
                for (v, _preds) in &phi_blocks[*succ] {
                    let ver = top_version(&stack, v);
                    phi_inputs[*succ]
                        .entry(v.clone())
                        .or_default()
                        .insert(block, ver);
                }
            }

            dfs.last_mut().unwrap().2 = pushed_here;
        }

        // --- Descend into next child, if any -----------------------------------
        let (block, cursor) = {
            let top = dfs.last().unwrap();
            (top.0, top.1)
        };
        let children_of_block = &children[block];
        if cursor < children_of_block.len() {
            let next = children_of_block[cursor];
            dfs.last_mut().unwrap().1 = cursor + 1;
            dfs.push((next, 0, Vec::new()));
            continue;
        }

        // --- Leaving `block`: pop versions we pushed --------------------------
        let (_, _, pushed_here) = dfs.pop().unwrap();
        for v in pushed_here {
            if let Some(s) = stack.get_mut(&v) {
                s.pop();
            }
        }
    }

    // Materialise `Phi` records from the per-block maps.
    let mut phis: Vec<Phi> = Vec::new();
    let mut per_block_phis: Vec<Vec<Phi>> = vec![Vec::new(); n];
    for bi in 0..n {
        for (v, _preds) in &phi_blocks[bi] {
            let dst_version = *phi_dst[bi]
                .get(v)
                .expect("phi dst not assigned during renaming");
            let incoming_map = phi_inputs[bi].get(v).cloned().unwrap_or_default();
            let mut incoming: Vec<(usize, u32)> = incoming_map.into_iter().collect();
            incoming.sort_by_key(|(p, _)| *p);
            let phi = Phi {
                block_idx: bi,
                base: v.clone(),
                dst_version,
                incoming,
            };
            per_block_phis[bi].push(phi.clone());
            phis.push(phi);
        }
    }

    let info = SsaInfo {
        idom: idom.to_vec(),
        frontier: Vec::new(), // filled in by caller
        phis,
        def_versions,
        use_versions,
        def_values_all,
        use_values_all,
    };
    (info, per_block_phis)
}

/// Compute SSA information for `lf`.
pub fn compute_ssa(lf: &LlirFunction) -> SsaInfo {
    compute_ssa_canonicalized(lf, &canon_gpr, &canon_gpr)
}

/// Compute SSA using the canonical register identity of `target`.
pub fn compute_ssa_for_target(lf: &LlirFunction, target: TargetSpec) -> SsaInfo {
    compute_ssa_canonicalized(lf, &|value| canon_gpr_for_target(target, value), &|value| {
        canon_read_for_target(target, value)
    })
}

fn compute_ssa_canonicalized(
    lf: &LlirFunction,
    canonicalize_def: &impl Fn(&VReg) -> VReg,
    canonicalize_use: &impl Fn(&VReg) -> VReg,
) -> SsaInfo {
    let preds = build_preds(lf);
    let (idom, _rpo) = compute_dominators(lf, &preds);
    let frontier = compute_frontiers(&idom, &preds);
    let def_blocks = def_blocks(lf, canonicalize_def);
    let phi_blocks = place_phis(&def_blocks, &frontier, &preds);
    let (mut info, _per_block) = rename(lf, &idom, &phi_blocks, canonicalize_def, canonicalize_use);
    info.frontier = frontier;
    info
}

// -- suppress unused-import lints when no consumer uses MemOp/Value pattern --
#[allow(dead_code)]
fn _keep_imports(_m: &MemOp, _v: &Value, _c: &CallTarget) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, LlirBlock, LlirInstr, Op, VReg};

    /// Build an LLIR function with given (va_start, ops, succs_vas) per block.
    fn mk_cfg(spec: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        let entry_va = spec.first().map(|(s, _, _)| *s).unwrap_or(0);
        let blocks = spec
            .into_iter()
            .map(|(start_va, ops, succs)| LlirBlock {
                start_va,
                end_va: start_va + 0x100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: start_va + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs,
            })
            .collect();
        LlirFunction { entry_va, blocks }
    }

    fn assign(reg: &str, c: i64) -> Op {
        Op::Assign {
            dst: VReg::phys(reg),
            src: Value::Const(c),
        }
    }

    #[test]
    fn predicate_flags_receive_ssa_versions() {
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Cmp {
                    dst: VReg::Flag(crate::ir::types::Flag::Z),
                    op: crate::ir::types::CmpOp::Eq,
                    lhs: Value::Reg(VReg::phys("rdi")),
                    rhs: Value::Const(0),
                },
                Op::CondJump {
                    cond: VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1100,
                    inverted: true,
                },
            ],
            vec![0x1100],
        )]);

        let info = compute_ssa(&lf);
        let def = InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        };
        let use_at = InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        };
        assert_eq!(info.def_versions.get(&def), Some(&1));
        assert_eq!(info.use_versions.get(&(use_at, 0)), Some(&1));
    }

    fn add(reg: &str, a: &str, b: &str) -> Op {
        Op::Bin {
            dst: VReg::phys(reg),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys(a)),
            rhs: Value::Reg(VReg::phys(b)),
        }
    }

    #[test]
    fn single_block_no_phis_versions_increase_per_def() {
        // B0: %rax = 1 ; %rax = 2 ; %rbx = rax
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                assign("rax", 1),
                assign("rax", 2),
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("rax")),
                },
            ],
            vec![],
        )]);
        let info = compute_ssa(&lf);
        assert!(info.phis.is_empty(), "single block has no phis");
        let defs_a = info.def_versions[&InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        }];
        let defs_b = info.def_versions[&InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        }];
        assert_ne!(
            defs_a, defs_b,
            "two defs of rax must have distinct versions"
        );
        // rbx read uses rax at its second version.
        let read_ver = info.use_versions[&(
            InstrAddr {
                block_idx: 0,
                instr_idx: 2,
            },
            0,
        )];
        assert_eq!(read_ver, defs_b);
    }

    #[test]
    fn live_in_use_reads_entry_def_version_zero() {
        // B0: %rbx = rdi ; %rdi = 5 ; %rcx = rdi
        // The first read of rdi is a live-in parameter -> version 0 (entry-def).
        // The reassignment is version 1, and the later read sees version 1.
        // A parameter and a scratch redefinition of the same register must not
        // collide at version 0.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("rdi")),
                },
                assign("rdi", 5),
                Op::Assign {
                    dst: VReg::phys("rcx"),
                    src: Value::Reg(VReg::phys("rdi")),
                },
            ],
            vec![],
        )]);
        let info = compute_ssa(&lf);
        // Live-in read of rdi (in `rbx = rdi`) is the entry-def, version 0.
        let param_read = info.use_versions[&(
            InstrAddr {
                block_idx: 0,
                instr_idx: 0,
            },
            0,
        )];
        assert_eq!(param_read, 0, "live-in parameter read must be version 0");
        // The reassignment `rdi = 5` is a distinct (non-zero) version.
        let redef = info.def_versions[&InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        }];
        assert_ne!(redef, 0, "an explicit redefinition must not be version 0");
        // The read after the redef sees the redef's version, not the param.
        let scratch_read = info.use_versions[&(
            InstrAddr {
                block_idx: 0,
                instr_idx: 2,
            },
            0,
        )];
        assert_eq!(scratch_read, redef);
    }

    #[test]
    fn explicit_value_queries_preserve_storage_identity_and_version() {
        // The public value identity consumed by type recovery must expose the
        // canonical storage (`edi` and `rdi` are one x86-64 storage location)
        // without collapsing distinct definitions back together.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Assign {
                    dst: VReg::phys("rax"),
                    src: Value::Reg(VReg::phys("edi")),
                },
                assign("edi", 7),
                Op::Assign {
                    dst: VReg::phys("rcx"),
                    src: Value::Reg(VReg::phys("rdi")),
                },
            ],
            vec![],
        )]);
        let info = compute_ssa(&lf);
        let first = InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        };
        let redef = InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        };
        let last = InstrAddr {
            block_idx: 0,
            instr_idx: 2,
        };

        assert_eq!(
            info.use_value(&lf, first, 0),
            Some(SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            })
        );
        let redefined_value = info
            .def_value(&lf, redef)
            .expect("explicit definition value");
        assert_eq!(redefined_value.base, VReg::phys("rdi"));
        assert_ne!(redefined_value.version, 0);
        assert_eq!(info.use_value(&lf, last, 0), Some(redefined_value));
    }

    #[test]
    fn diamond_cfg_inserts_phi_at_merge() {
        //        B0: cond
        //       /     \
        //      B1      B2        (each defines %rax)
        //       \     /
        //        B3: use rax     ← must phi
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![assign("rax", 1)], vec![0x1300]),
            (0x1200, vec![assign("rax", 2)], vec![0x1300]),
            (
                0x1300,
                vec![Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("rax")),
                }],
                vec![],
            ),
        ]);
        let info = compute_ssa(&lf);
        // Exactly one phi, at block 3, for rax.
        assert_eq!(info.phis.len(), 1, "expected one phi: {:#?}", info.phis);
        let p = &info.phis[0];
        assert_eq!(p.block_idx, 3);
        assert_eq!(p.base, VReg::phys("rax"));
        assert_eq!(p.incoming.len(), 2);
        // The two incoming versions must differ and come from the two
        // predecessor blocks 1 and 2.
        let pred_blocks: Vec<usize> = p.incoming.iter().map(|(b, _)| *b).collect();
        assert_eq!(pred_blocks, vec![1, 2]);
        let versions: Vec<u32> = p.incoming.iter().map(|(_, v)| *v).collect();
        assert_ne!(versions[0], versions[1]);
    }

    #[test]
    fn loop_with_counter_gets_phi_at_header() {
        //    B0: %i = 0
        //       |
        //       v
        //    B1 (header): use i, cmp i, 10
        //      /       \
        //    B2: i = i+1      B3 (exit)
        //      \______________/
        // Back-edge from B2 → B1 forces a phi for i at B1.
        let lf = mk_cfg(vec![
            (0x1000, vec![assign("i", 0)], vec![0x1100]),
            (
                0x1100,
                vec![Op::Assign {
                    dst: VReg::phys("tmp"),
                    src: Value::Reg(VReg::phys("i")),
                }],
                vec![0x1200, 0x1300],
            ),
            (0x1200, vec![add("i", "i", "one")], vec![0x1100]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let info = compute_ssa(&lf);
        // Find the phi for %i.
        let phi_for_i: Vec<&Phi> = info
            .phis
            .iter()
            .filter(|p| p.base == VReg::phys("i"))
            .collect();
        assert_eq!(phi_for_i.len(), 1, "expected phi for i: {:#?}", info.phis);
        assert_eq!(phi_for_i[0].block_idx, 1, "phi must sit at loop header");
    }

    #[test]
    fn works_on_real_lifted_function() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
                total_timeout_ms: 0,
            },
        );
        for f in &funcs {
            if let Ok(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let info = compute_ssa(&lf);
                // No assertions about exact counts — just that SSA completes
                // on real input without panics and produces internally-
                // consistent version numbers.
                for (_addr, ver) in &info.def_versions {
                    assert!(*ver < u32::MAX);
                }
                for ((_addr, _ui), ver) in &info.use_versions {
                    assert!(*ver < u32::MAX);
                }
                // Every phi's incoming list must only reference this
                // function's predecessor blocks.
                let preds = build_preds(&lf);
                for p in &info.phis {
                    for (pred_b, _) in &p.incoming {
                        assert!(
                            preds[p.block_idx].contains(pred_b),
                            "phi at block {} lists non-predecessor {}",
                            p.block_idx,
                            pred_b,
                        );
                    }
                }
            }
        }
    }

    /// AArch64 `wN` must share one SSA identity with `xN`, exactly as `eax`
    /// shares one with `rax`. Without this a value stored through the 32-bit
    /// view and read at full width binds to a stale definition.
    #[test]
    fn aarch64_w_views_share_the_x_parent_ssa_identity() {
        assert_eq!(parent64("w0"), Some("x0"));
        assert_eq!(parent64("w19"), Some("x19"));
        assert_eq!(parent64("x0"), Some("x0"));
        assert_eq!(canon_gpr(&VReg::phys("w8")), VReg::phys("x8"));
        // x86-64 is unchanged, and its bit-PRESERVING views still keep their
        // own identity — merging those would claim a def that does not exist.
        assert_eq!(parent64("eax"), Some("rax"));
        assert_eq!(parent64("al"), None);
        assert_eq!(parent64("ax"), None);
        // `sp` is the one name both tables spell. x86-64 declines it (16-bit,
        // bit-preserving); the AArch64 fallback maps it to itself.
        assert_eq!(parent64("sp"), Some("sp"));
    }

    #[test]
    fn x86_partial_view_reads_use_the_current_parent_definition() {
        use crate::core::binary::{Arch, Endianness, Format};

        // The x86 lifter expands partial WRITES into an explicit parent
        // read-modify-write, but an instruction may still READ `ax` directly
        // (for example `movsx eax, ax`). That read observes the low 16 bits of
        // the current rax value; treating it as an unrelated `ax#0` live-in is
        // how a loop accumulator became `ret = (short)ret` in
        // cpp_template_int16.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                assign("rax", 7),
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("ax")),
                },
            ],
            vec![],
        )]);
        let target =
            TargetSpec::from_image_metadata(Arch::X86_64, Endianness::Little, Format::ELF, false);
        let info = compute_ssa_for_target(&lf, target);
        let definition = info
            .def_value(
                &lf,
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 0,
                },
            )
            .expect("rax definition");
        let read = info
            .use_value(
                &lf,
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
                0,
            )
            .expect("ax read");

        assert_eq!(read.base, VReg::phys("rax"));
        assert_eq!(read.version, definition.version);
    }

    #[test]
    fn x86_32_keeps_legacy_identity_until_its_machine_model_migrates_as_one_unit() {
        use crate::core::binary::{Arch, Endianness, Format};

        let target =
            TargetSpec::from_image_metadata(Arch::X86, Endianness::Little, Format::PE, false);
        assert_eq!(
            canon_gpr_for_target(target, &VReg::phys("eax")),
            VReg::phys("rax")
        );
        assert_eq!(
            canon_read_for_target(target, &VReg::phys("eax")),
            VReg::phys("rax")
        );
        assert_eq!(
            canon_read_for_target(target, &VReg::phys("ax")),
            VReg::phys("ax")
        );
    }

    #[test]
    fn arch_blind_parent_lookup_does_not_rewrite_arm32_aliases() {
        assert_eq!(parent64("lr"), None);
        assert_eq!(parent64("fp"), None);
        assert_eq!(canon_gpr(&VReg::phys("lr")), VReg::phys("lr"));
        assert_eq!(canon_gpr(&VReg::phys("fp")), VReg::phys("fp"));
        assert_eq!(parent64("x29"), Some("x29"));
        assert_eq!(parent64("x30"), Some("x30"));
    }
}
