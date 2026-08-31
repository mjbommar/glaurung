//! How one dispatch fact is carried, joined, replayed and withdrawn.
//!
//! Resolving a jump table is not a decision made at the dispatch instruction.
//! It is made from facts that reached it -- a range check in some predecessor,
//! a table base materialised in a loop preheader -- and those facts have to
//! survive a join with every other path, then survive a second look once the
//! graph is finished. The primitives for all of that are here, and nothing here
//! walks a graph or owns a fixed point: `merge_dispatch_addresses` and
//! [`join_dispatch_bounds`] are the lattice joins, [`combine_dispatch_bounds`]
//! is the union of two independent proofs on one path, [`replay_dispatch_block`]
//! re-derives a block's facts from its recorded instruction stream, and
//! [`trim_unproven_dispatch_edges`] is how an over-scanned table's arms leave
//! the graph again.
//!
//! [`must_dataflow`](super::must_dataflow) is the module that drives them.
//!
//! The two things most easily got wrong are both recorded in the item docs
//! below: the replay must model ARM's `pc` exactly as the walker did or it
//! deletes arms the walker correctly proved, and the trim must be keyed on how
//! many times a target occurs in the proven prefix rather than on set
//! membership, because a `switch` with shared case labels names the same VA in
//! both halves.

use super::*;

/// Merge one predecessor's concrete address facts into a block input.
///
/// The first predecessor establishes the candidate map; later predecessors can
/// only remove facts. A register survives a join precisely when every incoming
/// path agrees on the same address.
pub(super) fn merge_dispatch_addresses(
    inputs: &mut std::collections::HashMap<u64, std::collections::HashMap<String, u64>>,
    target: u64,
    incoming: std::collections::HashMap<String, u64>,
) -> bool {
    use std::collections::hash_map::Entry;
    match inputs.entry(target) {
        Entry::Vacant(entry) => {
            entry.insert(incoming);
            true
        }
        Entry::Occupied(mut entry) => {
            let before = entry.get().len();
            entry
                .get_mut()
                .retain(|register, address| incoming.get(register) == Some(address));
            entry.get().len() != before
        }
    }
}

/// Join upper-bound facts from reachable predecessors.
///
/// A register remains bounded only when every currently reachable predecessor
/// proves a bound for it; the joined maximum covers every incoming value.
/// Predecessors without an output are still unreachable in the fixed-point and
/// therefore do not weaken the result yet.
pub(super) fn join_dispatch_bounds<'a>(
    incoming: impl Iterator<Item = &'a crate::analysis::dispatch::Bounds>,
) -> crate::analysis::dispatch::Bounds {
    let mut incoming = incoming;
    let Some(first) = incoming.next() else {
        return crate::analysis::dispatch::Bounds::default();
    };
    let mut joined = first.clone();
    for next in incoming {
        joined.regs.retain(|register, bound| {
            let Some(next_bound) = next.regs.get(register) else {
                return false;
            };
            *bound = (*bound).max(*next_bound);
            true
        });
        joined.slots.retain(|slot, bound| {
            let Some(next_bound) = next.slots.get(slot) else {
                return false;
            };
            *bound = (*bound).max(*next_bound);
            true
        });
        joined.mems.retain(|location, bound| {
            let Some(next_bound) = next.mems.get(location) else {
                return false;
            };
            *bound = (*bound).max(*next_bound);
            true
        });
    }
    joined
}

/// Combine independent proofs that hold on the same path.  Either proof is
/// sufficient, so retain their union and choose the tighter bound on overlap.
pub(super) fn combine_dispatch_bounds(
    mut left: crate::analysis::dispatch::Bounds,
    right: Option<&crate::analysis::dispatch::Bounds>,
) -> crate::analysis::dispatch::Bounds {
    let Some(right) = right else {
        return left;
    };
    for (register, bound) in &right.regs {
        left.regs
            .entry(register.clone())
            .and_modify(|old| *old = (*old).min(*bound))
            .or_insert(*bound);
    }
    for (slot, bound) in &right.slots {
        left.slots
            .entry(slot.clone())
            .and_modify(|old| *old = (*old).min(*bound))
            .or_insert(*bound);
    }
    for (location, bound) in &right.mems {
        left.mems
            .entry(location.clone())
            .and_modify(|old| *old = (*old).min(*bound))
            .or_insert(*bound);
    }
    left
}

/// Drop the dispatch edges an over-scanned table extent contributed, and report
/// how many arms the block is left with.
///
/// `attached` is the sequence of targets the speculative walk attached to
/// `block_start`, one entry per table slot and in table order; `retained` is how
/// many leading slots the whole-CFG range proof stands behind. Everything past
/// that is scanner over-read — `discover_jump_tables` builds the LONGEST run of
/// section words that decode to executable addresses, so it runs straight
/// through the end of one table into whatever follows.
///
/// The removal is keyed on how many times each target occurs in the PROVEN
/// prefix, never on set membership. Duplicate targets are the ordinary shape of
/// a `switch` whose case labels are shared across indices, so the trimmed suffix
/// routinely names a VA the proven prefix names too. Deleting every edge
/// `block_start -> T` whose target appeared anywhere in the suffix therefore
/// deleted the PROVEN arm as well, and nothing downstream could put it back:
/// `cfg::repair::rebuild_block_relationships` de-duplicates successor lists, but
/// de-duplication cannot restore a successor that was never added. Meanwhile the
/// arm count went on claiming the prefix length, so `stats.resolved_dispatches`
/// and the edge set disagreed about the same switch.
///
/// The count returned is read off the surviving edges rather than assumed, so
/// the caller records an arm count the graph can actually be checked against.
pub(super) fn trim_unproven_dispatch_edges(
    edges: &mut Vec<(u64, u64, ControlFlowEdgeKind)>,
    block_start: u64,
    attached: &[u64],
    retained: usize,
) -> usize {
    let mut quota: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for target in attached.iter().take(retained) {
        *quota.entry(*target).or_default() += 1;
    }
    let mut kept = 0usize;
    edges.retain(|(source, target, _)| {
        if *source != block_start {
            return true;
        }
        match quota.get_mut(target) {
            Some(remaining) if *remaining > 0 => {
                *remaining -= 1;
                kept += 1;
                true
            }
            _ => false,
        }
    });
    kept
}

#[derive(Debug)]
pub(super) struct TentativeDispatchEdges {
    pub(super) site: u64,
    pub(super) block_start: u64,
    pub(super) attached: Vec<u64>,
    /// True when the section scan supplied candidate arms before range
    /// dataflow proved the dispatch extent.  Such edges must be trimmed or
    /// rejected during final validation; they are never accepted as-is.
    pub(super) needs_bound_proof: bool,
}

/// Replay one decoded block through the dispatch abstract interpreter.
///
/// The first CFG walk must speculate with the predecessors known at that point
/// in order to discover table arms. Once the graph is complete, this replay is
/// used by a proper must-dataflow fixed point and validates every speculative
/// resolution. That second check is what makes a late conflicting back-edge
/// fail closed instead of leaving already-added, unsound successors behind.
#[allow(clippy::too_many_arguments)]
pub(super) fn replay_dispatch_block(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
    endianness: Endianness,
    thumb: Option<bool>,
    start_va: u64,
    end_va: u64,
    bounds: Option<crate::analysis::dispatch::Bounds>,
    addresses: Option<&std::collections::HashMap<String, u64>>,
    stop_at: Option<u64>,
    decoded: Option<&[Instruction]>,
) -> Option<(
    crate::analysis::dispatch::DispatchTracker,
    Option<Instruction>,
)> {
    let darch: crate::core::disassembler::Architecture = arch.into();
    let bits = darch.address_bits();
    let mut tracker = crate::analysis::dispatch::DispatchTracker::new();
    // The replay must model `pc` exactly as the walker did. Without this the
    // revalidation cannot materialise an ARM table base, reports the dispatch
    // unresolved, and DELETES the edges the walker correctly proved — so the
    // arms are lost after being found. The walker's mode comes from
    // `arm32_mode`; here the same fact arrives as the `thumb` flag.
    tracker.set_arm_pc_mode(match (arch, thumb) {
        (BArch::ARM, Some(true)) => Some(crate::analysis::dispatch::ArmPcMode::Thumb),
        (BArch::ARM, Some(false)) => Some(crate::analysis::dispatch::ArmPcMode::A32),
        _ => None,
    });
    tracker.inherit_bound(bounds);
    tracker.inherit_addresses(addresses);

    // The walk that built this block already decoded every instruction in it.
    // Replaying from that stream is the same sequence of `observe` calls
    // against the same instructions -- see `discover_function`, which records
    // exactly `[start, block_end)` and only ever shortens a block afterwards,
    // so the recorded stream is a superset of what this replay reads.
    if let Some(decoded) = decoded {
        let mut cur_va = start_va;
        for instruction in decoded {
            if cur_va >= end_va {
                break;
            }
            let next_va = cur_va.saturating_add(instruction.length as u64);
            if matches!(arch, BArch::ARM) {
                if let Some(defined) = arm_defined_register(instruction) {
                    tracker.kill_register(defined);
                }
            }
            tracker.observe(instruction);
            if stop_at == Some(cur_va) {
                return Some((tracker, Some(instruction.clone())));
            }
            if next_va <= cur_va {
                return None;
            }
            cur_va = next_va;
        }
        return Some((tracker, None));
    }

    let mut backend = registry::for_arch(darch, endianness)?;
    if let Some(thumb) = thumb {
        let _ = backend.set_thumb_mode(thumb);
    }
    let mut cur_va = start_va;
    while cur_va < end_va {
        let file_offset = indexed_code_offset(image, data, cur_va)?;
        let bytes = data.get(file_offset..)?;
        let address = Address::new(AddressKind::VA, cur_va, bits, None, None).ok()?;
        let instruction = backend.disassemble_instruction(&address, bytes).ok()?;
        let next_va = cur_va.saturating_add(instruction.length as u64);
        // Mirrors the streaming walk in `discover_function`: the ARM decoder
        // reports no writes, so definitions are named from the mnemonic. A
        // replay that skipped this would prove a bound the first pass refused
        // and re-validate a dispatch into existence.
        if matches!(arch, BArch::ARM) {
            if let Some(defined) = arm_defined_register(&instruction) {
                tracker.kill_register(defined);
            }
        }
        tracker.observe(&instruction);
        if stop_at == Some(cur_va) {
            return Some((tracker, Some(instruction)));
        }
        if next_va <= cur_va {
            return None;
        }
        cur_va = next_va;
    }
    Some((tracker, None))
}

/// Every block's decoded instruction stream, keyed by block start.
///
/// The streaming walk decodes each block once; the two must-dataflow fixed
/// points and the dispatch revalidation then read the same blocks again, three
/// more times on average. Decoding is by far the most expensive thing this
/// module does -- on `win10-webservices.dll` the walk decodes 281k
/// instructions and the replays 840k -- so the stream is kept rather than
/// recovered. Bounded by `budgets.max_instructions` per function and dropped
/// when the function is built.
pub(super) type BlockStreams = std::collections::HashMap<u64, Vec<Instruction>>;

#[cfg(test)]
mod dispatch_trim_tests {
    use super::*;

    fn branch(source: u64, target: u64) -> (u64, u64, ControlFlowEdgeKind) {
        (source, target, ControlFlowEdgeKind::Branch)
    }

    fn targets_from(edges: &[(u64, u64, ControlFlowEdgeKind)], source: u64) -> Vec<u64> {
        edges
            .iter()
            .filter(|(edge_source, _, _)| *edge_source == source)
            .map(|(_, target, _)| *target)
            .collect()
    }

    /// A `switch` whose case labels are shared across indices attaches the same
    /// target more than once, and `discover_jump_tables` scans the LONGEST run
    /// of executable-looking words rather than the table's real end — so the
    /// unproven suffix routinely names a VA the proven prefix names too.
    ///
    /// Removing edges by target VALUE (`extras.contains(target)`) deleted every
    /// edge to such a target, proven arm included. Nothing downstream could
    /// repair it: `cfg::repair` de-duplicates successor lists, and de-duplication
    /// cannot restore a successor that was never added. The proven arm simply
    /// left the graph while the recorded arm count still claimed it.
    #[test]
    fn a_proven_arm_survives_the_unproven_suffix_naming_it_again() {
        let block = 0x1000;
        // Table order: cases 0..5 share three bodies; slots 4 and 5 are scanner
        // over-read past the proven extent and repeat 0x2010 and 0x2020.
        let attached = [0x2010, 0x2020, 0x2010, 0x2030, 0x2010, 0x2020];
        let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();
        // An unrelated block reaching the same case body must not be disturbed.
        edges.push(branch(0x1800, 0x2010));

        let kept = trim_unproven_dispatch_edges(&mut edges, block, &attached, 4);

        assert_eq!(
            targets_from(&edges, block),
            vec![0x2010, 0x2020, 0x2010, 0x2030],
            "the four proven slots survive in table order"
        );
        assert_eq!(kept, 4, "the arm count is the surviving edge count");
        assert_eq!(
            targets_from(&edges, 0x1800),
            vec![0x2010],
            "trimming one block's dispatch must not touch another block's edges"
        );
    }

    /// The negative control: with all-distinct targets the value-keyed retain and
    /// the multiplicity-keyed one agree exactly, so the previous behaviour is
    /// preserved wherever the defect could not fire.
    #[test]
    fn an_all_distinct_table_is_trimmed_exactly_as_before() {
        let block = 0x1000;
        let attached = [0x2010, 0x2020, 0x2030, 0x2040, 0x2050];
        let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();

        let kept = trim_unproven_dispatch_edges(&mut edges, block, &attached, 3);

        assert_eq!(targets_from(&edges, block), vec![0x2010, 0x2020, 0x2030]);
        assert_eq!(kept, 3);
    }

    /// A repeat entirely inside the proven prefix keeps BOTH of its edges: the
    /// lifted block's successor list is positional, so collapsing shared case
    /// labels here would lose which indices reach the shared body.
    #[test]
    fn a_repeat_inside_the_proven_prefix_keeps_every_edge() {
        let block = 0x1000;
        let attached = [0x2010, 0x2010, 0x2020, 0x2030];
        let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();

        let kept = trim_unproven_dispatch_edges(&mut edges, block, &attached, 3);

        assert_eq!(targets_from(&edges, block), vec![0x2010, 0x2010, 0x2020]);
        assert_eq!(kept, 3);
    }

    /// Nothing proven means nothing kept, and a fully proven table is untouched.
    #[test]
    fn the_degenerate_extents_behave() {
        let block = 0x1000;
        let attached = [0x2010, 0x2020, 0x2010];

        let mut none: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();
        assert_eq!(
            trim_unproven_dispatch_edges(&mut none, block, &attached, 0),
            0
        );
        assert!(targets_from(&none, block).is_empty());

        let mut all: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();
        assert_eq!(
            trim_unproven_dispatch_edges(&mut all, block, &attached, attached.len()),
            3
        );
        assert_eq!(targets_from(&all, block), attached.to_vec());
    }
}
