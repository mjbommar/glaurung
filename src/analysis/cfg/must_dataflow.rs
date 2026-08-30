//! Must-dataflow fixed points over the completed block graph.
//!
//! Both passes here run *after* `discover_function`'s streaming BFS has stopped
//! adding blocks and edges, and *before* the tentative jump-table arms are
//! validated. That ordering is the whole point: the streaming walk sees each
//! block once, in queue order, so a fact it derived from the only predecessor
//! it had seen so far can be falsified by a back-edge decoded later. These two
//! passes re-derive the same facts to a fixed point over the finished graph,
//! and the dispatch validation downstream trusts only what survives them.
//!
//! Each is a pure function of `(blocks, edges, index_bounds)` plus the decoder
//! inputs: they read the graph, they never mutate it, and neither reads the
//! other's output. That is why they could be lifted at all -- everything
//! between the BFS and the `Function` build shares mutable state with its
//! neighbours, and these do not. The maps they return are read exactly once
//! each, by the dispatch-revalidation loop in the parent.
//!
//! What stays in the parent: `thumb`. It is derived from `arm32_mode` under the
//! comment that now documents [`bound_fixed_point`], but the dispatch
//! revalidation reads it again after both calls return, so it is a parameter
//! here rather than a local.

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
