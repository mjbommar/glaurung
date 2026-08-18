//! Turning a finished block graph into a [`Function`].
//!
//! This is the last phase of `discover_function` and the only one that touches
//! a `Function` at all. Everything before it works in the walk's own currency
//! -- a `HashMap<u64, (u64, u32)>` of block extents, a `Vec` of `(from, to,
//! kind)` edges, a `Vec<FunctionXref>` of call sites -- and none of that
//! survives past this file. The split is therefore a real boundary rather than
//! a size cut: upstream is graph discovery, downstream is the data model.
//!
//! Every input is read-only here. The graph has already been pruned to what is
//! reachable through validated edges, so this phase never decides what belongs
//! to the function; it only renders the decision. The one thing it does decide
//! is `relationships_known`, and only in the negative direction -- see the
//! comment on `declined_dispatch_blocks`.
//!
//! `?` propagates the same way it did inline: an `Address::new` or
//! `Function::new` failure aborts the whole discovery of this seed, which is
//! why the return type is `Option<Function>` and not `Function`.

use super::*;

use std::collections::HashMap;

/// Build the `Function` object for a completed, validated block graph.
///
/// `blocks`, `edges` and `call_edges` are the walk's final state; `stats` is
/// the walk's own truncation record, which travels onto the function it
/// describes and nowhere else.
pub(super) fn build_function(
    entry: &Address,
    bits: u8,
    arm32_mode: Option<crate::analysis::arm32_mode::Arm32Mode>,
    blocks: &HashMap<u64, (u64, u32)>,
    edges: &[(u64, u64, ControlFlowEdgeKind)],
    call_edges: &[FunctionXref],
    stats: &SingleFunctionDiscoveryStats,
) -> Option<Function> {
    let fname = format!("sub_{:x}", entry.value);
    let mut func = Function::new(fname, entry.clone(), FunctionKind::Normal).ok()?;
    if matches!(
        arm32_mode,
        Some(crate::analysis::arm32_mode::Arm32Mode::Thumb)
    ) {
        func.add_flag(FunctionFlags::IS_THUMB);
    }

    // Build BasicBlocks with successor/predecessor IDs
    let mut bb_ids: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    for (&start, &(end, instrs)) in blocks {
        let id = format!("bb_{:x}", start);
        bb_ids.insert(start, id.clone());
        let bb = BasicBlock::new(
            id,
            Address::new(AddressKind::VA, start, bits, None, None).ok()?,
            Address::new(AddressKind::VA, end, bits, None, None).ok()?,
            instrs,
            None,
            None,
        );
        func.add_basic_block(bb);
    }

    // Populate successors/predecessors and function edges
    let mut succs: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut preds: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (src_va, dst_va, kind) in edges {
        // Only add CFG edges when both endpoints are block starts
        if let (Some(sid), Some(did)) = (bb_ids.get(src_va), bb_ids.get(dst_va)) {
            succs.entry(sid.clone()).or_default().push(did.clone());
            preds.entry(did.clone()).or_default().push(sid.clone());
            // Also track as function-level edge from start of block -> start of dest
            let saddr = Address::new(AddressKind::VA, *src_va, bits, None, None).ok()?;
            let daddr = Address::new(AddressKind::VA, *dst_va, bits, None, None).ok()?;
            // We encode only control flow transitions; calls already tagged with Call in `edges`, but we emit CFG fallthrough/branch here.
            if matches!(
                kind,
                ControlFlowEdgeKind::Fallthrough | ControlFlowEdgeKind::Branch
            ) {
                func.add_edge(saddr, daddr);
            }
        }
    }
    // Blocks whose terminator is an indirect transfer this pass declined.
    //
    // Their successor list is empty because the targets were never recovered,
    // not because the block has no successors — and `relationships_known` was
    // set true for them along with everyone else, which made
    // `BasicBlock::is_exit_block()` (`relationships_known && successors.empty()`)
    // answer TRUE for a `jmp *%rax` with forty arms. Measured over the 758
    // fixture objects: 2909 of the 28169 blocks claiming to be exits, 10.3%.
    //
    // The flag is one bit covering both directions, so the honest single-bit
    // answer for these blocks is `false`. That also withdraws
    // `is_entry_block()` from 45 of them, which is the correct direction:
    // both predicates are knowledge-shaped (`false` means "not known to be",
    // not "known not to be"), so clearing the flag turns a claim into an
    // absence of one, while leaving it set turned an absence into a claim.
    let declined_dispatch_blocks: std::collections::BTreeSet<&str> = stats
        .unresolved_indirect
        .iter()
        .filter_map(|(site, _)| {
            blocks
                .iter()
                .find(|(start, (end, _))| *site >= **start && *site < *end)
                .and_then(|(start, _)| bb_ids.get(start))
                .map(String::as_str)
        })
        .collect();

    // Patch blocks with relationships (best-effort): replace blocks with enriched copies
    for bb in &mut func.basic_blocks {
        let id = bb.id.clone();
        if let Some(s) = succs.get(&id) {
            bb.successor_ids = s.clone();
        }
        if let Some(p) = preds.get(&id) {
            bb.predecessor_ids = p.clone();
        }
        bb.relationships_known = !declined_dispatch_blocks.contains(id.as_str());
    }

    // Seed the function's primary chunk from the basic-block extents so
    // every discovered function has at least one entry in `chunks`. The
    // chunk-merge pass relies on this — without it, parents that haven't
    // had `range` set explicitly silently swallow their cold splits but
    // expose `chunks=[<cold only>]` to consumers.
    if !func.basic_blocks.is_empty() {
        let entry_va = func.entry_point.value;
        let max_end = func
            .basic_blocks
            .iter()
            .map(|bb| bb.end_address.value)
            .max()
            .unwrap_or(entry_va);
        if max_end > entry_va {
            if let Ok(start) = Address::new(AddressKind::VA, entry_va, bits, None, None) {
                if let Ok(range) = AddressRange::new(start, max_end - entry_va, None) {
                    func.add_chunk(range);
                }
            }
        }
    }

    // Retain exact interprocedural targets on the function object.  Address-scoped
    // decompilation intentionally stops discovery once all requested entries are
    // found, but its name map still needs these xrefs in order to render an
    // anonymous terminal jump as `sub_<va>(...)` rather than a dangling local goto.
    for xref in call_edges {
        if let Ok(callee) = Address::new(AddressKind::VA, xref.target_va, bits, None, None) {
            func.add_callee(callee);
        }
    }

    // The truncation record travels on the body it describes. This is the ONLY
    // place it is written, and it is written from the stats of the single walk
    // that just produced `func` -- which is what makes it impossible for one
    // function's budget hit to mark a different function incomplete.
    record_cfg_incompleteness(&mut func, &stats);
    Some(func)
}
