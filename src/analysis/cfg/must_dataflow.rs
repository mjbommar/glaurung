//! Must-dataflow fixed points over the completed block graph.
//!
//! Both passes here run *after* `discover_function`'s streaming BFS has stopped
//! adding blocks and edges, and *before* the tentative jump-table arms are
//! validated. That ordering is the whole point: the streaming walk sees each
//! block once, in queue order, so a fact it derived from the only predecessor
//! it had seen so far can be falsified by a back-edge decoded later. These two
//! passes re-derive the same facts to a fixed point over the finished graph,
//! and [`validate_dispatch_edges`] -- the third item here -- trusts only what
//! survives them.
//!
//! Each is a pure function of `(blocks, edges, index_bounds)` plus the decoder
//! inputs: they read the graph, they never mutate it, and neither reads the
//! other's output. That is why they could be lifted at all -- everything
//! between the BFS and the `Function` build shares mutable state with its
//! neighbours, and these do not. The maps they return are read exactly once
//! each, by the dispatch revalidation below.
//!
//! What stays in the walk: `thumb`. It is derived from `arm32_mode` under the
//! comment that now documents [`bound_fixed_point`], so it arrives here as a
//! parameter rather than a local.

use super::*;

use std::collections::{HashMap, VecDeque};

/// Prove loop-carried value ranges over the completed speculative graph.
/// This is deliberately separate from the one-edge `index_bounds` map: a
/// compiler may remove a switch guard after proving that an enum/state
/// register is always in range.  Candidate table arms make those state
/// transitions reachable for analysis, but final validation below keeps
/// only the exact prefix justified by this fixed point.
pub(super) fn bound_fixed_point(
    facts: &DiscoveryFacts<'_>,
    data: &[u8],
    arch: BArch,
    end: Endianness,
    thumb: Option<bool>,
    entry: &Address,
    blocks: &HashMap<u64, (u64, u32)>,
    edges: &[(u64, u64, ControlFlowEdgeKind)],
    block_streams: &BlockStreams,
) -> HashMap<u64, crate::analysis::dispatch::Bounds> {
    let mut final_bound_inputs: HashMap<u64, crate::analysis::dispatch::Bounds> = HashMap::new();
    let mut final_bound_outputs: HashMap<u64, crate::analysis::dispatch::Bounds> = HashMap::new();
    let mut bound_queue: VecDeque<u64> = VecDeque::from([entry.value]);
    let mut bound_queued = std::collections::HashSet::from([entry.value]);
    let bound_step_limit = blocks.len().saturating_mul(256).max(256);
    let mut bound_steps = 0usize;
    while let Some(block_start) = bound_queue.pop_front() {
        bound_queued.remove(&block_start);
        bound_steps += 1;
        if bound_steps > bound_step_limit {
            // Failure to converge means no range proof is trustworthy.  The
            // speculative dispatches will consequently be rejected below.
            final_bound_inputs.clear();
            final_bound_outputs.clear();
            break;
        }
        let Some(&(block_end, _)) = blocks.get(&block_start) else {
            continue;
        };
        let predecessors: Vec<u64> = edges
            .iter()
            .filter_map(|(source, target, _)| (*target == block_start).then_some(*source))
            .collect();
        let input = if block_start == entry.value {
            crate::analysis::dispatch::Bounds::default()
        } else {
            let reachable: Vec<_> = predecessors
                .iter()
                .filter_map(|predecessor| final_bound_outputs.get(predecessor))
                .collect();
            if reachable.is_empty() {
                continue;
            }
            join_dispatch_bounds(reachable.into_iter())
        };
        // A block whose joined input is the one it was last replayed with
        // produces the output it produced then, and the convergence check
        // below would `continue` on it -- so recognising it here skips a
        // replay instead of repeating one. The queue re-reaches a block 2.1
        // times on average on `win10-webservices.dll` (106,613 steps over
        // 49,917 blocks), and the replay is the expensive half of a step.
        if final_bound_outputs.contains_key(&block_start)
            && final_bound_inputs.get(&block_start) == Some(&input)
        {
            continue;
        }
        final_bound_inputs.insert(block_start, input.clone());
        let Some((tracker, _)) = replay_dispatch_block(
            facts.image,
            data,
            arch,
            end,
            thumb,
            block_start,
            block_end,
            Some(input),
            None,
            None,
            block_streams.get(&block_start).map(Vec::as_slice),
        ) else {
            continue;
        };
        let output = tracker.export_stable_bounds();
        if final_bound_outputs.get(&block_start) == Some(&output) {
            continue;
        }
        final_bound_outputs.insert(block_start, output);
        for successor in edges
            .iter()
            .filter_map(|(source, target, _)| (*source == block_start).then_some(*target))
        {
            if bound_queued.insert(successor) {
                bound_queue.push_back(successor);
            }
        }
    }
    final_bound_inputs
}

/// Recompute concrete-address facts to a fixed point over the now-complete
/// graph. The streaming walk above sees predecessors incrementally; a loop
/// back-edge discovered after its header can invalidate a table-base fact
/// that looked unique on the first visit. Must-dataflow makes that loss
/// propagate through every downstream block before tentative table edges are
/// accepted.
pub(super) fn address_fixed_point(
    facts: &DiscoveryFacts<'_>,
    data: &[u8],
    arch: BArch,
    end: Endianness,
    thumb: Option<bool>,
    entry: &Address,
    blocks: &HashMap<u64, (u64, u32)>,
    edges: &[(u64, u64, ControlFlowEdgeKind)],
    index_bounds: &HashMap<u64, crate::analysis::dispatch::Bounds>,
    block_streams: &BlockStreams,
) -> HashMap<u64, HashMap<String, u64>> {
    let mut final_address_inputs: HashMap<u64, HashMap<String, u64>> = HashMap::new();
    final_address_inputs.insert(entry.value, HashMap::new());
    let mut address_queue: VecDeque<u64> = VecDeque::from([entry.value]);
    let mut address_steps = 0usize;
    let address_step_limit = blocks.len().saturating_mul(64).max(64);
    while let Some(block_start) = address_queue.pop_front() {
        address_steps += 1;
        if address_steps > address_step_limit {
            // The domain is finite and only shrinks after first arrival; hitting
            // this limit indicates malformed graph churn. Clear inherited facts
            // so validation fails closed rather than trusting an incomplete run.
            final_address_inputs.clear();
            final_address_inputs.insert(entry.value, HashMap::new());
            break;
        }
        let Some(&(block_end, _)) = blocks.get(&block_start) else {
            continue;
        };
        let input = final_address_inputs
            .get(&block_start)
            .cloned()
            .unwrap_or_default();
        let Some((tracker, _)) = replay_dispatch_block(
            facts.image,
            data,
            arch,
            end,
            thumb,
            block_start,
            block_end,
            index_bounds.get(&block_start).cloned(),
            Some(&input),
            None,
            block_streams.get(&block_start).map(Vec::as_slice),
        ) else {
            continue;
        };
        let output = tracker.export_addresses();
        let successors: Vec<u64> = edges
            .iter()
            .filter_map(|(source, target, _)| (*source == block_start).then_some(*target))
            .collect();
        for successor in successors {
            if merge_dispatch_addresses(&mut final_address_inputs, successor, output.clone()) {
                address_queue.push_back(successor);
            }
        }
    }
    final_address_inputs
}

/// Re-derive both fixed points over the finished graph, and keep only the
/// dispatch arms that survive them.
///
/// This is where a speculative resolution becomes a real one or leaves the
/// graph. The streaming walk attached table arms from the predecessors it
/// happened to have seen; the two passes above re-derive the same facts to a
/// fixed point over the completed CFG, and every tentative dispatch is then
/// replayed against them. Three outcomes:
///
/// * the replay proves exactly what was attached -- the edges stand;
/// * it proves a strict prefix of a `needs_bound_proof` dispatch -- the
///   unproven suffix is trimmed and the recorded arm count is read back off the
///   surviving edges, not asserted;
/// * it proves something else, or nothing -- every edge the site contributed is
///   removed and the site is recorded in `unresolved_indirect`, because a
///   dropped arm is a CFG missing real edges and every verifier downstream
///   would otherwise report clean on the truncated graph.
///
/// It lives beside the fixed points rather than in the walk because it is their
/// only consumer, and because it is the second half of one idea: the first walk
/// speculates, this closes the graph.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_dispatch_edges(
    facts: &DiscoveryFacts<'_>,
    data: &[u8],
    arch: BArch,
    end: Endianness,
    thumb: Option<bool>,
    regions: &[ExecRegion],
    entry: &Address,
    blocks: &HashMap<u64, (u64, u32)>,
    edges: &mut Vec<(u64, u64, ControlFlowEdgeKind)>,
    index_bounds: &HashMap<u64, crate::analysis::dispatch::Bounds>,
    block_streams: &BlockStreams,
    resolved_dispatch_edges: &[TentativeDispatchEdges],
    stats: &mut SingleFunctionDiscoveryStats,
) {
    let final_bound_inputs = bound_fixed_point(
        facts,
        data,
        arch,
        end,
        thumb,
        entry,
        blocks,
        edges,
        block_streams,
    );
    let final_address_inputs = address_fixed_point(
        facts,
        data,
        arch,
        end,
        thumb,
        entry,
        blocks,
        edges,
        index_bounds,
        block_streams,
    );

    let mut invalid_dispatches: Vec<(u64, u64, Vec<u64>, crate::analysis::dispatch::Unresolved)> =
        Vec::new();
    let mut trimmed_dispatches: Vec<(u64, u64, Vec<u64>, usize)> = Vec::new();
    for dispatch_edge in resolved_dispatch_edges {
        let inherited_bounds = combine_dispatch_bounds(
            final_bound_inputs
                .get(&dispatch_edge.block_start)
                .cloned()
                .unwrap_or_default(),
            index_bounds.get(&dispatch_edge.block_start),
        );
        let resolution = blocks
            .get(&dispatch_edge.block_start)
            .and_then(|(block_end, _)| {
                replay_dispatch_block(
                    facts.image,
                    data,
                    arch,
                    end,
                    thumb,
                    dispatch_edge.block_start,
                    *block_end,
                    Some(inherited_bounds),
                    final_address_inputs.get(&dispatch_edge.block_start),
                    Some(dispatch_edge.site),
                    block_streams
                        .get(&dispatch_edge.block_start)
                        .map(Vec::as_slice),
                )
                .and_then(|(tracker, instruction)| {
                    instruction.and_then(|instruction| {
                        resolve_dispatch(
                            facts.image,
                            data,
                            regions,
                            &tracker,
                            &instruction,
                            facts.tables,
                        )
                    })
                })
            });
        let resolved_targets = match &resolution {
            Some(crate::analysis::dispatch::Resolution::Table { targets, .. }) => Some(
                targets
                    .iter()
                    .copied()
                    .filter(|target| in_exec_regions(regions, *target).is_some())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };
        let still_exact = resolved_targets.as_ref().is_some_and(|targets| {
            if dispatch_edge.needs_bound_proof {
                !targets.is_empty() && dispatch_edge.attached.starts_with(targets)
            } else {
                targets == &dispatch_edge.attached
            }
        });
        if still_exact {
            if dispatch_edge.needs_bound_proof {
                let targets = resolved_targets.expect("checked above");
                if targets.len() < dispatch_edge.attached.len() {
                    trimmed_dispatches.push((
                        dispatch_edge.site,
                        dispatch_edge.block_start,
                        dispatch_edge.attached.clone(),
                        targets.len(),
                    ));
                }
            }
        } else {
            let why = match resolution {
                Some(crate::analysis::dispatch::Resolution::Unresolved(why)) => why,
                Some(crate::analysis::dispatch::Resolution::Table { .. }) | None => {
                    crate::analysis::dispatch::Unresolved::UnknownBase
                }
            };
            invalid_dispatches.push((
                dispatch_edge.site,
                dispatch_edge.block_start,
                dispatch_edge.attached.clone(),
                why,
            ));
        }
    }
    for (site, block_start, attached, retained) in trimmed_dispatches {
        let kept = trim_unproven_dispatch_edges(edges, block_start, &attached, retained);
        if let Some((_, arms)) = stats
            .resolved_dispatches
            .iter_mut()
            .find(|(resolved, _)| *resolved == site)
        {
            // `kept`, not `retained`: the arm count is read off the surviving
            // edges instead of being asserted next to them.
            *arms = kept;
        }
    }
    for (site, block_start, attached, why) in invalid_dispatches {
        edges.retain(|(source, target, _)| !(*source == block_start && attached.contains(target)));
        stats
            .resolved_dispatches
            .retain(|(resolved, _)| *resolved != site);
        if !stats
            .unresolved_indirect
            .iter()
            .any(|(unresolved, _)| *unresolved == site)
        {
            stats.unresolved_indirect.push((site, why));
        }
    }
}
