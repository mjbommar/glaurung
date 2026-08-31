//! Chaitin coalescing of the copies inserted to leave SSA.
//!
//! `insert_phi_copies` materialises a copy per phi per predecessor, which is
//! correct and standardly verbose. This module removes the ones liveness and
//! width evidence prove removable, by giving the two sides one name. Its one
//! reason to change is what may be proved safe to merge -- interference,
//! declaration width, or an authoritative source lifetime.

use std::collections::{HashMap, HashSet};

use crate::ir::types::{LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_ref, def_uses, for_each_use, InstrAddr};

use super::architectural_reads::architecturally_read_names;
use super::vreg_walk::for_each_vreg_mut;

/// A source variable's authoritative residence in one machine register.
///
/// Value numbering uses these ranges only to keep distinct source lifetimes
/// from being coalesced back into one C identity after SSA destruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRegisterLifetime {
    pub register: String,
    pub ranges: Vec<(u64, u64)>,
}

/// Exact machine width of the definition at one raw LLIR instruction site.
///
/// A kept-bare ABI register can have several definitions which deliberately
/// share one [`VReg`] spelling. The public name-keyed width map cannot represent
/// those definitions independently, so phi coalescing consumes this companion
/// map before deciding whether a shared name supplies consistent width evidence.
pub(crate) type DefinitionWidthsBySite = HashMap<InstrAddr, u8>;

/// A value-numbered name eligible for coalescing: `reg#version`.
///
/// Only tagged names qualify. A bare name is one of three things the rest of the
/// pipeline binds by spelling — a live-in parameter (version 0), a structural
/// frame register, or a return value [`KeepBare`] deliberately did not version —
/// and renaming any of them would move a source-level identity, not a temporary.
fn coalescable(v: &VReg) -> Option<(&str, u32)> {
    let VReg::Phys(name) = v else { return None };
    let (base, version) = name.rsplit_once('#')?;
    Some((base, version.parse().ok()?))
}

/// Successor block indices, resolved from each block's successor VAs.
fn successor_indices(lf: &LlirFunction) -> Vec<Vec<usize>> {
    let va_to_idx: HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    lf.blocks
        .iter()
        .map(|b| {
            let mut s: Vec<usize> = b
                .succs
                .iter()
                .filter_map(|va| va_to_idx.get(va).copied())
                .collect();
            s.sort_unstable();
            s.dedup();
            s
        })
        .collect()
}

/// What one coalescing class claims about the machine width of its values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassWidth {
    /// Every member with an opinion says this many bytes.
    Known(u8),
    /// No member has an opinion, so any width may still be adopted.
    Open,
    /// The value is a merge of definitions whose widths disagree. One name
    /// cannot describe it, so it is not merged with anything.
    Ambiguous,
}

impl ClassWidth {
    fn join(self, other: ClassWidth) -> ClassWidth {
        match (self, other) {
            (ClassWidth::Ambiguous, _) | (_, ClassWidth::Ambiguous) => ClassWidth::Ambiguous,
            (ClassWidth::Open, other) | (other, ClassWidth::Open) => other,
            (ClassWidth::Known(a), ClassWidth::Known(b)) if a == b => self,
            _ => ClassWidth::Ambiguous,
        }
    }

    fn merge(self, other: ClassWidth) -> Option<ClassWidth> {
        match (self, other) {
            (ClassWidth::Ambiguous, _) | (_, ClassWidth::Ambiguous) => None,
            (ClassWidth::Known(a), ClassWidth::Known(b)) => (a == b).then_some(self),
            (ClassWidth::Known(_), ClassWidth::Open) => Some(self),
            (ClassWidth::Open, ClassWidth::Known(_)) => Some(other),
            (ClassWidth::Open, ClassWidth::Open) => Some(ClassWidth::Open),
        }
    }
}

/// Width constraints that must survive even when several SSA values receive one
/// source-level name.
///
/// A plain assignment, load, comparison or truncation already carries
/// its value semantics in the expression that lowering emits. The destination's
/// physical register spelling is only storage, so an eight-byte `mov` of a
/// four-byte value must not conflict with that value's four-byte arithmetic.
/// Arithmetic, widening conversions and width-parameterized intrinsics are
/// different: their result requires the recorded destination width, and a
/// shared C declaration has to preserve it. In particular, rendering an 8-byte
/// `sext` through an `int` declaration silently truncates the widened value.
/// Join every definition of a name up front so kept-bare names are no longer
/// attributed by whichever definition happened to be visited last.
fn coalescing_definition_claims(
    out: &LlirFunction,
    definition_widths: &HashMap<VReg, u8>,
    definition_widths_by_site: &DefinitionWidthsBySite,
) -> HashMap<VReg, ClassWidth> {
    let mut claims = HashMap::new();
    for (block_idx, block) in out.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let Some(destination) = def_ref(&instruction.op).cloned() else {
                continue;
            };
            let site = InstrAddr {
                block_idx,
                instr_idx,
            };
            let claim = match &instruction.op {
                Op::Bin { .. }
                | Op::Un { .. }
                | Op::Ite { .. }
                | Op::ZExt { .. }
                | Op::SExt { .. }
                | Op::Intrinsic { .. } => definition_widths_by_site
                    .get(&site)
                    // Direct primitive tests construct already-numbered LLIR and
                    // historically provide only the compatibility map. The real
                    // value-numbering path always supplies the per-site entry.
                    .or_else(|| definition_widths.get(&destination))
                    .copied()
                    .map_or(ClassWidth::Open, ClassWidth::Known),
                _ => ClassWidth::Open,
            };
            claims
                .entry(destination)
                .and_modify(|existing: &mut ClassWidth| *existing = existing.join(claim))
                .or_insert(claim);
        }
    }
    // Lowering often materialises a widening into a temporary and then moves
    // that temporary into the architectural SSA value consumed by a phi. The
    // move is width-neutral, but its destination still needs a declaration wide
    // enough to hold the already-widened result. Propagate only when source and
    // destination storage widths agree: a 4-byte result moved through an 8-byte
    // register does not require a narrow declaration, and an 8-to-4 move already
    // carries truncation semantics.
    loop {
        let mut changed = false;
        for (block_idx, block) in out.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let Op::Assign {
                    dst,
                    src: Value::Reg(src),
                } = &instruction.op
                else {
                    continue;
                };
                let Some(ClassWidth::Known(source_width)) = claims.get(src).copied() else {
                    continue;
                };
                let site = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let destination_width = definition_widths_by_site
                    .get(&site)
                    .or_else(|| definition_widths.get(dst))
                    .copied();
                if destination_width != Some(source_width) {
                    continue;
                }
                let current = claims.get(dst).copied().unwrap_or(ClassWidth::Open);
                let next = current.join(ClassWidth::Known(source_width));
                if next != current {
                    claims.insert(dst.clone(), next);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    claims
}

/// The starting width claim of every candidate, decided before any merging so
/// the outcome cannot depend on which copy is visited first.
///
/// A value the lifter defined has its recorded width. A phi destination has
/// none — nothing lifted it — so it inherits the width its incoming values
/// agree on, and is [`ClassWidth::Ambiguous`] when they do not.
///
/// The inheritance is a fixed point over the lattice
/// `Open < Known(w) < Ambiguous`, because a phi's incoming value is routinely
/// another phi's result: nested loops copy each carried value through one phi
/// per level, so a single pass would call every level after the first ambiguous
/// and coalesce nothing. The lattice is three-deep and every step is monotone,
/// so the iteration terminates; a loop-carried phi whose own result is its input
/// starts at `Open` and simply takes whatever its other edges prove.
///
/// This reads **every** copy, not only the ones whose operands are coalescable.
/// A phi edge from a kept-bare name is still evidence about the phi's width even
/// though that name will never be renamed, and dropping it is what let
/// `factorial_while` at `clang -O2` see only its `mov eax,1` initialiser: the
/// 8-byte `imul` result reaches the same phi through the bare return register,
/// so the phi is ambiguous, and without that edge it looked like a 4-byte value.
#[cfg(test)]
fn class_widths(
    names: &[VReg],
    index: &HashMap<VReg, usize>,
    copies: &[(VReg, VReg)],
    definition_claims: &HashMap<VReg, ClassWidth>,
    consumed_live_ins: &HashSet<VReg>,
) -> Vec<ClassWidth> {
    class_widths_with_incoming_values(
        names,
        index,
        copies,
        definition_claims,
        consumed_live_ins,
        &[],
    )
}

/// Decide class widths while retaining the exact width of each phi incoming
/// SSA value, including values whose kept-bare ABI spelling is shared by
/// several definitions.
fn class_widths_with_incoming_values(
    names: &[VReg],
    index: &HashMap<VReg, usize>,
    copies: &[(VReg, VReg)],
    definition_claims: &HashMap<VReg, ClassWidth>,
    consumed_live_ins: &HashSet<VReg>,
    incoming_widths: &[Option<u8>],
) -> Vec<ClassWidth> {
    let mut widths: Vec<ClassWidth> = names
        .iter()
        .map(|value| {
            definition_claims
                .get(value)
                .copied()
                .unwrap_or(ClassWidth::Open)
        })
        .collect();
    // Each copy, reduced to (destination candidate, source candidate or a fixed
    // claim for a source that is not a candidate).
    //
    // The compatibility `definition_claims` map is keyed by rendered NAME. That
    // is sufficient for versioned values but cannot distinguish several
    // definitions deliberately kept under one ABI spelling. Prefer the exact
    // SSA incoming-edge width collected before tagging; only fall back to the
    // name claim when no edge identity is available. A missing live-in width is
    // not positive evidence: `consumed_live_ins` keeps the existing fail-closed
    // rule for architectural values that cannot safely seed a phi class.
    let edges: Vec<(usize, Option<usize>, ClassWidth)> = copies
        .iter()
        .enumerate()
        .filter_map(|(copy_index, (dst, src))| {
            let d = *index.get(dst)?;
            if let Some(&s) = index.get(src) {
                return Some((d, Some(s), ClassWidth::Open));
            }
            let claim = incoming_widths
                .get(copy_index)
                .copied()
                .flatten()
                .map(ClassWidth::Known)
                .or_else(|| definition_claims.get(src).copied())
                .unwrap_or_else(|| {
                    if consumed_live_ins.contains(src) {
                        ClassWidth::Ambiguous
                    } else {
                        ClassWidth::Open
                    }
                });
            Some((d, None, claim))
        })
        .collect();
    // Three lattice levels x |candidates| bounds the fixed point; the extra
    // rounds are cheap and the loop exits as soon as nothing moves.
    for _ in 0..(names.len().saturating_mul(3).max(4)) {
        let mut changed = false;
        for &(d, source, fixed) in &edges {
            let contribution = source.map_or(fixed, |s| widths[s]);
            let next = widths[d].join(contribution);
            if next != widths[d] {
                widths[d] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    widths
}

/// Live-in architectural values that are not proven safe phi inputs.
///
/// Such a copy is usually a compiler scratch-register snapshot, not the start
/// of one source variable. Joining its phi class to later scratch definitions
/// creates artificial long-lived cycles: otherwise single-use address
/// calculations stop inlining and shared guards can no longer be structured.
/// A phi destination consumed by a real architectural operand proves that its
/// bare incoming value participates in the same source-level carrier, even when
/// an entry guard consumed that value before the loop. Such a value remains
/// open; loop-form recovery retains the guard proof after coalescing.
/// A destination retained only by call may-uses or otherwise unread supplies no
/// parameter proof; its bare edge is refused, as is a late snapshot whose phi
/// result is not genuinely consumed.
fn consumed_live_ins_before_phi_copy(
    out: &LlirFunction,
    names: &HashSet<VReg>,
    copies: &[(VReg, VReg)],
) -> HashSet<VReg> {
    let copy_pairs: HashSet<(VReg, VReg)> = copies.iter().cloned().collect();
    let architecturally_read = architecturally_read_names(out);
    let definitions: HashSet<VReg> = out
        .blocks
        .iter()
        .flat_map(|block| block.instrs.iter())
        .filter_map(|instruction| def_ref(&instruction.op).cloned())
        .collect();
    let mut first_copy = HashMap::<VReg, u64>::new();
    let mut read_through_phi = HashSet::<VReg>::new();
    for block in &out.blocks {
        for instruction in &block.instrs {
            let Op::Assign {
                dst,
                src: Value::Reg(src),
            } = &instruction.op
            else {
                continue;
            };
            if copy_pairs.contains(&(dst.clone(), src.clone()))
                && names.contains(dst)
                && !names.contains(src)
                && !definitions.contains(src)
            {
                if matches!(dst, VReg::Phys(name) if architecturally_read.contains(name)) {
                    read_through_phi.insert(src.clone());
                }
                first_copy
                    .entry(src.clone())
                    .and_modify(|va| *va = (*va).min(instruction.va))
                    .or_insert(instruction.va);
            }
        }
    }

    let mut first_semantic_use = HashMap::<VReg, u64>::new();
    for block in &out.blocks {
        for instruction in &block.instrs {
            for_each_use(&instruction.op, |source| {
                if !first_copy.contains_key(source) {
                    return;
                }
                let is_phi_copy = matches!(
                    &instruction.op,
                    Op::Assign { dst, src: Value::Reg(src) }
                        if copy_pairs.contains(&(dst.clone(), src.clone()))
                );
                if !is_phi_copy {
                    first_semantic_use
                        .entry(source.clone())
                        .and_modify(|va| *va = (*va).min(instruction.va))
                        .or_insert(instruction.va);
                }
            });
        }
    }
    first_copy
        .into_iter()
        .filter_map(|(source, copy_va)| {
            let consumed_before = first_semantic_use
                .get(&source)
                .is_some_and(|use_va| *use_va < copy_va);
            let unread = !first_semantic_use.contains_key(&source);
            (!read_through_phi.contains(&source) && (consumed_before || unread)).then_some(source)
        })
        .collect()
}

/// Coalescing is bounded work: past this many distinct phi-copy operands the
/// interference build is abandoned and the copies stand exactly as inserted.
/// Nothing about the result changes except its verbosity, so failing open here
/// costs output quality on a pathological function and never correctness.
const MAX_COALESCE_CANDIDATES: usize = 4096;

/// Give the two sides of an out-of-SSA phi copy one name whenever liveness
/// proves they never hold different values at the same program point.
///
/// `insert_phi_copies` is the standard, and standardly *verbose*, way to leave
/// SSA: every merged value gets a copy in every predecessor. On real code that
/// dominates the emitted artifact — on the extbench Tier B corpus **20% of all
/// rendered lines were a bare `name = name` copy, 9,180 of them between two
/// value-numbered registers** — and each surviving name also costs a local
/// declaration. Adjacent copy propagation cannot remove them because a phi copy
/// sits precisely at a control-flow join, which is where that pass stops.
///
/// This is Chaitin's coalescing, run once over the copies the previous step
/// created:
///
/// * Build the live range of every phi-copy operand by ordinary backward
///   liveness. The program is no longer in SSA at this point — the copies made
///   it executable — so this is plain liveness with no phi semantics to model.
/// * Two names **interfere** when one is live immediately after a definition of
///   the other. At a copy `d = s` the source is exempt at that one point: both
///   names hold the same value there, which is exactly the condition that makes
///   the copy removable. A later, genuinely different definition of either name
///   still records the interference and blocks the merge.
/// * A copy whose two names do not interfere is coalesced. Merging is
///   transitive, so the check is between whole classes, not just the pair.
///
/// Two extra conditions beyond interference, neither of which is about
/// correctness of the dataflow:
///
/// * **Only tagged names.** See [`coalescable`] — bare names carry ABI identity.
/// * **One semantic arithmetic width per class.** Plain moves and loads carry
///   storage width but preserve their expression's value semantics, so they do
///   not constrain a source-level declaration. Arithmetic, selects and
///   width-parameterized intrinsics do: two such definitions that genuinely
///   wrap at different widths cannot share one declaration. A phi destination
///   inherits those constraints from all incoming values at a fixed point; a
///   disagreement is decided before merging so copy order cannot change the
///   result.
///
/// Liveness restricted to candidates is exact rather than approximate: whether a
/// value is live at a point does not depend on which other values are.
#[cfg(test)]
pub(crate) fn coalesce_phi_copies(
    out: &mut LlirFunction,
    copies: &[(VReg, VReg)],
    definition_widths: &mut HashMap<VReg, u8>,
) {
    coalesce_phi_copies_with_definition_sites(
        out,
        copies,
        definition_widths,
        &DefinitionWidthsBySite::new(),
        &[],
        &[],
    );
}

#[cfg(test)]
pub(crate) fn coalesce_phi_copies_with_lifetimes(
    out: &mut LlirFunction,
    copies: &[(VReg, VReg)],
    definition_widths: &mut HashMap<VReg, u8>,
    lifetimes: &[SourceRegisterLifetime],
) {
    coalesce_phi_copies_with_definition_sites(
        out,
        copies,
        definition_widths,
        &DefinitionWidthsBySite::new(),
        &[],
        lifetimes,
    );
}

/// Coalesce out-of-SSA phi copies using exact definition-site widths.
///
/// Phi copies are inserted immediately before a trailing terminator (which has
/// no value definition) or appended to a fallthrough block. Consequently every
/// original value-defining instruction retains its [`InstrAddr`] between width
/// collection and this query; synthetic copies have no entry and remain
/// width-neutral.
pub(crate) fn coalesce_phi_copies_with_definition_sites(
    out: &mut LlirFunction,
    copies: &[(VReg, VReg)],
    definition_widths: &mut HashMap<VReg, u8>,
    definition_widths_by_site: &DefinitionWidthsBySite,
    incoming_widths: &[Option<u8>],
    source_lifetimes: &[SourceRegisterLifetime],
) {
    if copies.is_empty() {
        return;
    }

    // --- Candidate set: the operands of the copies we are trying to remove ---
    let mut index: HashMap<VReg, usize> = HashMap::new();
    let mut names: Vec<VReg> = Vec::new();
    let intern = |v: &VReg, index: &mut HashMap<VReg, usize>, names: &mut Vec<VReg>| {
        coalescable(v)?;
        Some(*index.entry(v.clone()).or_insert_with(|| {
            names.push(v.clone());
            names.len() - 1
        }))
    };
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for (dst, src) in copies {
        let (Some(d), Some(s)) = (
            intern(dst, &mut index, &mut names),
            intern(src, &mut index, &mut names),
        ) else {
            continue;
        };
        if d != s {
            pairs.push((d, s));
        }
        if names.len() > MAX_COALESCE_CANDIDATES {
            return;
        }
    }
    if pairs.is_empty() {
        return;
    }
    let n = names.len();

    // One machine register may hold unrelated source variables in disjoint
    // lexical ranges. Record, for each SSA value, whether each occurrence is
    // inside or outside an authoritative source lifetime. Exact signatures may
    // coalesce; crossing a boundary may not, even when machine liveness says
    // the storage reuse itself is safe.
    let mut lifetime_signatures = vec![std::collections::BTreeSet::new(); n];
    for block in &out.blocks {
        for instruction in &block.instrs {
            let (definition, uses) = def_uses(&instruction.op);
            for value in definition.into_iter().chain(uses) {
                let Some(&value_index) = index.get(&value) else {
                    continue;
                };
                let Some((base, _version)) = coalescable(&value) else {
                    continue;
                };
                for (lifetime_index, lifetime) in source_lifetimes.iter().enumerate() {
                    if lifetime.register != base {
                        continue;
                    }
                    let inside = lifetime
                        .ranges
                        .iter()
                        .any(|&(start, end)| instruction.va >= start && instruction.va < end);
                    lifetime_signatures[value_index].insert((lifetime_index, inside));
                }
            }
        }
    }

    // --- Backward liveness over the candidate values -------------------------
    let succs = successor_indices(out);
    let blocks = out.blocks.len();
    let mut live_in: Vec<HashSet<usize>> = vec![HashSet::new(); blocks];
    let mut live_out: Vec<HashSet<usize>> = vec![HashSet::new(); blocks];
    // Monotone and bounded by |candidates| x |blocks|; the cap is a guard against
    // a pathological CFG, not an expected exit.
    for _ in 0..(blocks.saturating_mul(2).max(8)) {
        let mut changed = false;
        for bi in (0..blocks).rev() {
            let mut out_set: HashSet<usize> = HashSet::new();
            for &s in &succs[bi] {
                out_set.extend(live_in[s].iter().copied());
            }
            if out_set != live_out[bi] {
                live_out[bi] = out_set;
                changed = true;
            }
            let mut cur = live_out[bi].clone();
            for ins in out.blocks[bi].instrs.iter().rev() {
                let (def, uses) = def_uses(&ins.op);
                if let Some(d) = def.as_ref().and_then(|d| index.get(d)) {
                    cur.remove(d);
                }
                for u in &uses {
                    if let Some(u) = index.get(u) {
                        cur.insert(*u);
                    }
                }
            }
            if cur != live_in[bi] {
                live_in[bi] = cur;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // --- Interference: a name is live immediately after another's definition --
    let mut interferes: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for (bi, block_live_out) in live_out.iter().enumerate() {
        let mut live = block_live_out.clone();
        for ins in out.blocks[bi].instrs.iter().rev() {
            let (def, uses) = def_uses(&ins.op);
            if let Some(d) = def.as_ref().and_then(|d| index.get(d)).copied() {
                // At `d = s` both names hold one value, so this point alone does
                // not separate them.
                let exempt = match &ins.op {
                    Op::Assign {
                        src: Value::Reg(s), ..
                    } => index.get(s).copied(),
                    _ => None,
                };
                for &l in live.iter() {
                    if l != d && Some(l) != exempt {
                        interferes[d].insert(l);
                        interferes[l].insert(d);
                    }
                }
                live.remove(&d);
            }
            for u in &uses {
                if let Some(u) = index.get(u) {
                    live.insert(*u);
                }
            }
        }
    }

    // --- Union-find over the copy pairs, checked class against class ----------
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    let mut members: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
    let definition_claims =
        coalescing_definition_claims(out, definition_widths, definition_widths_by_site);
    let candidate_names: HashSet<VReg> = names.iter().cloned().collect();
    let consumed_live_ins = consumed_live_ins_before_phi_copy(out, &candidate_names, copies);
    let mut width: Vec<ClassWidth> = class_widths_with_incoming_values(
        &names,
        &index,
        copies,
        &definition_claims,
        &consumed_live_ins,
        incoming_widths,
    );
    let mut attempted = 0usize;
    let mut already_joined = 0usize;
    let mut refused_interference = 0usize;
    let mut refused_width = 0usize;
    let mut refused_lifetime = 0usize;
    let mut merged = 0usize;
    for (d, s) in pairs.iter().copied() {
        attempted += 1;
        let (a, b) = (find(&mut parent, d), find(&mut parent, s));
        if a == b {
            already_joined += 1;
            continue;
        }
        if members[b].iter().any(|m| interferes[a].contains(m)) {
            refused_interference += 1;
            continue;
        }
        if lifetime_signatures[a] != lifetime_signatures[b] {
            refused_lifetime += 1;
            continue;
        }
        let Some(merged_width) = width[a].merge(width[b]) else {
            refused_width += 1;
            continue;
        };
        let moved = std::mem::take(&mut members[b]);
        let taken = std::mem::take(&mut interferes[b]);
        members[a].extend(moved);
        interferes[a].extend(taken);
        width[a] = merged_width;
        parent[b] = a;
        merged += 1;
    }

    // --- Rename to one representative per class ------------------------------
    // The lowest version in the class: stable, and it keeps the name closest to
    // the value's first definition rather than to an arbitrary merge order.
    let mut representative: HashMap<usize, usize> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        let version = |k: usize| coalescable(&names[k]).map(|(_, v)| v).unwrap_or(0);
        representative
            .entry(root)
            .and_modify(|best| {
                if version(i) < version(*best) {
                    *best = i;
                }
            })
            .or_insert(i);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "phi-coalesce-stats attempted={attempted} merged={merged} \
             interference={refused_interference} width={refused_width} \
             lifetime={refused_lifetime} joined={already_joined}"
        );
        for (&root, &rep) in &representative {
            let class: Vec<&VReg> = members[root].iter().map(|&member| &names[member]).collect();
            eprintln!(
                "phi-coalesce {:?} width={:?} -> {:?}",
                class, width[root], names[rep]
            );
        }
    }
    let mut rename: HashMap<VReg, VReg> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        let rep = representative[&root];
        if rep != i {
            rename.insert(names[i].clone(), names[rep].clone());
        }
    }
    if rename.is_empty() {
        return;
    }

    for block in out.blocks.iter_mut() {
        for ins in block.instrs.iter_mut() {
            for_each_vreg_mut(&mut ins.op, &mut |r| {
                if let Some(target) = rename.get(r) {
                    *r = target.clone();
                }
            });
        }
        // A copy whose two sides became one name is the copy this pass exists to
        // delete. Removing it cannot orphan a read: the name is unchanged on both
        // sides, so whatever defined it still does.
        block
            .instrs
            .retain(|ins| !matches!(&ins.op, Op::Assign { dst, src: Value::Reg(s) } if dst == s));
    }

    let mut merged_widths: HashMap<VReg, u8> = HashMap::new();
    for (value, w) in definition_widths.iter() {
        let key = rename.get(value).cloned().unwrap_or_else(|| value.clone());
        merged_widths
            .entry(key)
            .and_modify(|existing| *existing = (*existing).max(*w))
            .or_insert(*w);
    }
    // A width-sensitive definition is the semantic constraint for the merged
    // name. Width-neutral moves may have contributed a wider storage spelling,
    // but choosing that spelling would silently change 32-bit arithmetic. Open
    // classes have no such constraint and keep the widest observed storage.
    for root in 0..n {
        if find(&mut parent, root) != root {
            continue;
        }
        let ClassWidth::Known(exact_width) = width[root] else {
            continue;
        };
        let representative_index = representative[&root];
        merged_widths.insert(names[representative_index].clone(), exact_width);
    }
    *definition_widths = merged_widths;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{LlirBlock, LlirInstr};

    #[test]
    fn an_explicit_widening_result_constrains_the_merged_declaration_width() {
        let widened = VReg::Temp(0);
        let value = VReg::phys("rax#1");
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::SExt {
                            dst: widened.clone(),
                            src: Value::Reg(VReg::phys("eax")),
                            from: crate::ir::types::Width::W32,
                            to: crate::ir::types::Width::W64,
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: value.clone(),
                            src: Value::Reg(widened.clone()),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let claims = coalescing_definition_claims(
            &lf,
            &HashMap::from([(widened, 8), (value.clone(), 8)]),
            &DefinitionWidthsBySite::from([
                (
                    InstrAddr {
                        block_idx: 0,
                        instr_idx: 0,
                    },
                    8,
                ),
                (
                    InstrAddr {
                        block_idx: 0,
                        instr_idx: 1,
                    },
                    8,
                ),
            ]),
        );

        assert_eq!(
            claims.get(&value),
            Some(&ClassWidth::Known(8)),
            "assigning a sign-extended long through an int declaration would truncate it"
        );
    }

    /// A phi destination has no width of its own; it takes the one its incoming
    /// values agree on. When they disagree it is width-ambiguous, and the answer
    /// must not depend on which incoming edge is visited first — otherwise
    /// `factorial_while` (`mov eax,1` into the accumulator, `imul rax` out of it)
    /// stamps 4 bytes on a 64-bit product and returns 1.
    #[test]
    fn a_phi_width_is_decided_before_merging_not_by_visit_order() {
        let names = vec![
            VReg::phys("rax#3"), // the phi result — no recorded width
            VReg::phys("rax#1"), // `mov eax,1`
            VReg::phys("rax#2"), // `imul rax`
        ];
        let index: HashMap<VReg, usize> = names
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, v)| (v, i))
            .collect();
        let mut claims = HashMap::new();
        claims.insert(VReg::phys("rax#1"), ClassWidth::Known(4));
        claims.insert(VReg::phys("rax#2"), ClassWidth::Known(8));
        let edge = |d: usize, s: usize| (names[d].clone(), names[s].clone());
        for copies in [vec![edge(0, 1), edge(0, 2)], vec![edge(0, 2), edge(0, 1)]] {
            let decided = class_widths(&names, &index, &copies, &claims, &HashSet::new());
            assert_eq!(
                decided[0],
                ClassWidth::Ambiguous,
                "a 4-byte and an 8-byte incoming value leave the phi ambiguous \
                 regardless of edge order: {copies:?}"
            );
            assert_eq!(decided[0].merge(decided[1]), None);
            assert_eq!(decided[0].merge(decided[2]), None);
        }

        // Kept-bare names can have several definitions. Their constraints are
        // joined while the defining operations are still visible, rather than
        // trusting whichever name-keyed width happened to be recorded last.
        let both = vec![edge(0, 1), (names[0].clone(), VReg::phys("rax"))];
        let mut with_bare = HashMap::new();
        with_bare.insert(VReg::phys("rax#1"), ClassWidth::Known(4));
        with_bare.insert(VReg::phys("rax"), ClassWidth::Ambiguous);
        let decided = class_widths(&names, &index, &both, &with_bare, &HashSet::new());
        assert_eq!(
            decided[0],
            ClassWidth::Ambiguous,
            "conflicting definitions of a kept-bare source must remain ambiguous"
        );
        let decided = class_widths_with_incoming_values(
            &names,
            &index,
            &both,
            &with_bare,
            &HashSet::new(),
            &[None, Some(4)],
        );
        assert_eq!(
            decided[0],
            ClassWidth::Known(4),
            "the exact definition reaching this bare phi edge must override the \
             ambiguity of unrelated definitions sharing its register spelling"
        );
        with_bare.insert(VReg::phys("rax"), ClassWidth::Known(4));
        let decided = class_widths(&names, &index, &both, &with_bare, &HashSet::new());
        assert_eq!(decided[0], ClassWidth::Known(4));
        // A live-in has no definition here at all, so this map says nothing
        // about it. Missing evidence is Open, not a contradiction: the phi may
        // take the width proved by its other incoming values. Interference is
        // responsible for keeping genuinely distinct loop-carried values apart;
        // using width ambiguity as that guard couples two unrelated proofs and
        // is what refuses ordinary parameter-fed phi webs at scale.
        with_bare.remove(&VReg::phys("rax"));
        let decided = class_widths(&names, &index, &both, &with_bare, &HashSet::new());
        assert_eq!(decided[0], ClassWidth::Known(4));

        // Agreement is what permits a merge, and it propagates through a chain of
        // phis — the nested-loop shape, where one carried value is copied once per
        // loop level.
        let chain = vec![
            VReg::phys("rax#4"), // outer phi
            VReg::phys("rax#5"), // inner phi, fed by the outer one
            VReg::phys("rax#1"),
        ];
        let chain_index: HashMap<VReg, usize> = chain
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, v)| (v, i))
            .collect();
        let mut agreed = HashMap::new();
        agreed.insert(VReg::phys("rax#1"), ClassWidth::Known(4));
        let decided = class_widths(
            &chain,
            &chain_index,
            &[
                (chain[0].clone(), chain[2].clone()),
                (chain[1].clone(), chain[0].clone()),
            ],
            &agreed,
            &HashSet::new(),
        );
        assert_eq!(decided[0], ClassWidth::Known(4));
        assert_eq!(
            decided[1],
            ClassWidth::Known(4),
            "a phi fed only by another phi must inherit its width, or nested \
             loops coalesce nothing"
        );
    }

    /// Kept-bare ABI names can have several machine definitions. Width evidence
    /// belongs to each definition site, not to the shared spelling: otherwise
    /// whichever definition was visited last is replayed for every operation and
    /// a genuinely mixed-width phi input looks safe to coalesce.
    #[test]
    fn kept_bare_definition_widths_are_not_collapsed_by_name() {
        let kept_bare = VReg::phys("rax");
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::ZExt {
                            dst: kept_bare.clone(),
                            src: Value::Const(1),
                            from: crate::ir::types::Width::W8,
                            to: crate::ir::types::Width::W32,
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::SExt {
                            dst: kept_bare.clone(),
                            src: Value::Const(-1),
                            from: crate::ir::types::Width::W32,
                            to: crate::ir::types::Width::W64,
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        // This is the lossy public compatibility map: the second insertion for
        // `rax` replaced the first. The claim collector must not use that one
        // entry as the width of both definitions.
        let name_widths = HashMap::from([(kept_bare.clone(), 8)]);
        let site_widths = DefinitionWidthsBySite::from([
            (
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 0,
                },
                4,
            ),
            (
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
                8,
            ),
        ]);

        let claims = coalescing_definition_claims(&lf, &name_widths, &site_widths);

        assert_eq!(
            claims.get(&kept_bare),
            Some(&ClassWidth::Ambiguous),
            "32- and 64-bit definitions sharing one bare name must remain distinct"
        );
    }
}
