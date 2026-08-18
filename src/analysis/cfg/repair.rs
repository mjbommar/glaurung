//! Post-discovery repairs to the function set.
//!
//! Every pass here runs *after* the entry-rooted walk in the parent has
//! produced a `Vec<Function>`, and each one fixes something the walk cannot
//! see for itself:
//!
//! - [`merge_compiler_split_chunks`] folds `main.cold` / `foo.part.0` back
//!   into the parent symbol they were split out of.
//! - [`apply_dwarf_overrides`] replaces heuristic names and ranges with DWARF's
//!   authoritative ones where a `-g` build supplies them.
//! - [`attach_exception_landing_pads`] discovers the handler blocks the
//!   unwinder reaches through LSDA metadata, which have no ordinary
//!   predecessor and so are unreachable from an entry-rooted walk.
//!
//! The parent calls exactly those three, in that order, from
//! `analyze_functions_bytes_within`; everything else in here is private to the
//! cluster. The block-surgery helpers `split_parent_block_at`,
//! `split_parent_blocks_at_handler_leaders`, `count_machine_instructions` and
//! `rebuild_block_relationships` exist only because merging an independently
//! discovered handler subgraph invalidates the parent's block boundaries and
//! predecessor lists. `chunk_tests` (below) tests the split-chunk merge and
//! moved here with it.
//!
//! What stays in the parent, because the call graph says it is shared and not
//! repair-private: `DiscoveryFacts` is the discovery context that
//! `discover_function_image_at` and `analyze_functions_bytes_within` also
//! build and read, and `discover_function` — which landing-pad recovery
//! re-enters with a narrowed `DiscoveryFacts` — is the walk itself.

use super::*;

/// Apply DWARF subprogram entries on top of heuristically-discovered
/// functions. When a DWARF entry matches an existing Function by entry
/// VA, we override the name and chunk list (DWARF wins) and bump the
/// parameter count into the signature field. Functions with no DWARF
/// match are left alone.
///
/// We do NOT yet add brand-new Functions for DWARF entries that the
/// heuristic discovery missed — that's a v1.5 follow-up. v1's measurable
/// win is: every -g function gets its real name and authoritative
/// chunk list, so the chunk-merge band-aid stops being load-bearing.
pub(super) fn apply_dwarf_overrides(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    functions: &mut [Function],
) -> usize {
    let entries = image.map_or_else(
        || extract_dwarf_functions(data).into(),
        crate::program::image::ProgramImage::dwarf_functions,
    );
    if entries.is_empty() {
        return 0;
    }
    use std::collections::HashMap;
    let mut by_va: HashMap<u64, &DwarfFunction> = HashMap::new();
    for e in entries.iter() {
        by_va.entry(e.entry_va).or_insert(e);
    }

    let mut applied = 0usize;
    for f in functions.iter_mut() {
        let bits = if f.entry_point.bits == 64 { 64 } else { 32 };
        let dw = match by_va.get(&f.entry_point.value) {
            Some(d) => *d,
            None => continue,
        };
        if let Some(name) = &dw.name {
            f.name = name.clone();
        }
        // Replace chunks with the DWARF set — they're authoritative.
        let mut new_chunks: Vec<AddressRange> = Vec::new();
        for r in &dw.chunks {
            if let Ok(start) = Address::new(AddressKind::VA, r.start, bits, None, None) {
                if let Ok(rng) = AddressRange::new(start, r.size, None) {
                    new_chunks.push(rng);
                }
            }
        }
        if !new_chunks.is_empty() {
            f.chunks = new_chunks.clone();
            f.range = Some(new_chunks[0].clone());
            f.size = Some(new_chunks[0].size);
        }
        if dw.param_count > 0 && f.signature.is_none() {
            f.signature = Some(format!("fn({} args)", dw.param_count));
        }
        applied += 1;
    }
    applied
}

/// Attach LSDA-only landing-pad blocks to their authoritative parent function.
///
/// These blocks have no ordinary predecessor: the unwinder transfers to them
/// after a protected call throws. They therefore cannot be found by the normal
/// entry-rooted CFG walk. We discover from each metadata-proven landing pad,
/// retain only blocks inside the parent's authoritative ranges, and merge their
/// ordinary handler-internal edges. The exceptional edge itself intentionally
/// remains typed metadata in [`crate::analysis::exception`]; presenting it as a
/// normal branch would confuse dominance and structuring.
pub(super) fn attach_exception_landing_pads(
    data: &[u8],
    arch: BArch,
    end: Endianness,
    regions: &[ExecRegion],
    budgets: &Budgets,
    facts: &DiscoveryFacts<'_>,
    functions: &mut [Function],
    eh_frame_extent: &std::collections::HashMap<u64, u64>,
    deadline: Deadline<'_>,
) -> Vec<(u64, FunctionXref)> {
    let sites = facts.image.map_or_else(
        || crate::analysis::exception::extract_exception_call_sites(data).into(),
        crate::program::image::ProgramImage::exception_call_sites,
    );
    if sites.is_empty() {
        return Vec::new();
    }
    // An LSDA FDE is rooted at the compiler's original function fragment.
    // Split-function merging removes the cold fragment's standalone Function,
    // but deliberately retains its authoritative range on the hot parent.
    // Preserve exact entry ownership first, then teach the lookup about those
    // merged chunk starts so landing-pad discovery still reaches the parent.
    let mut parent_by_fde_start: std::collections::HashMap<u64, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.entry_point.value, index))
        .collect();
    for (index, function) in functions.iter().enumerate() {
        for range in function.all_ranges() {
            parent_by_fde_start
                .entry(range.start.value)
                .or_insert(index);
        }
    }
    let mut call_edges = Vec::new();
    let mut touched = std::collections::BTreeSet::new();

    // Every interval any function already owns, sorted by start, so claiming a
    // proven tail can never take bytes from a neighbour. Maintained as tails
    // are added rather than rebuilt per site.
    let mut occupied: Vec<(u64, u64)> = functions
        .iter()
        .flat_map(|function| {
            function.all_ranges().into_iter().map(|range| {
                (
                    range.start.value,
                    range.start.value.saturating_add(range.size),
                )
            })
        })
        .collect();
    occupied.sort_unstable();

    for site in sites.iter() {
        let Some(&parent_index) = parent_by_fde_start.get(&site.function_start) else {
            continue;
        };
        // The walk that produced `all_ranges` stops where NORMAL flow stops,
        // and this pass exists precisely because a landing pad has no normal
        // predecessor. GCC and Clang park the landing-pad trampoline after the
        // epilogue and inside the same FDE, so testing ownership against the
        // walked extent rejects exactly the bytes being recovered. The FDE is
        // the authoritative bound; take the tail the walk never reached.
        if let Some(&proven_end) = eh_frame_extent.get(&site.function_start) {
            if !functions[parent_index].contains_va(site.landing_pad) {
                claim_proven_tail(
                    functions,
                    parent_index,
                    site.function_start,
                    proven_end,
                    &mut occupied,
                );
            }
        }
        let ranges = functions[parent_index].all_ranges();
        let owns = |start: u64, end: u64| {
            ranges.iter().any(|range| {
                let range_start = range.start.value;
                range_start
                    .checked_add(range.size)
                    .is_some_and(|range_end| start >= range_start && end <= range_end)
            })
        };
        if !owns(site.landing_pad, site.landing_pad.saturating_add(1)) {
            continue;
        }
        // Normal discovery does not split at calls. Exceptional dataflow does:
        // the protected call must terminate its own block so its normal and
        // landing-pad successors describe the two possible continuations.
        if split_parent_block_at(
            facts.image,
            data,
            arch,
            end,
            &mut functions[parent_index],
            site.protected_end,
        ) {
            touched.insert(parent_index);
        }
        if functions[parent_index]
            .basic_blocks
            .iter()
            .any(|block| block.start_address.value == site.landing_pad)
        {
            functions[parent_index].add_flag(FunctionFlags::HAS_EH);
            touched.insert(parent_index);
            continue;
        }
        let bits = functions[parent_index].entry_point.bits;
        let leaders: Vec<u64> = functions[parent_index]
            .basic_blocks
            .iter()
            .map(|block| block.start_address.value)
            .collect();
        let Ok(entry) = Address::new(AddressKind::VA, site.landing_pad, bits, None, None) else {
            continue;
        };
        let Some((mut handler, handler_calls, _stats)) = discover_function(
            data,
            arch,
            end,
            entry,
            regions,
            budgets,
            &DiscoveryFacts {
                image: facts.image,
                tables: facts.tables,
                noreturn_targets: facts.noreturn_targets,
                plt_stub_ranges: facts.plt_stub_ranges,
                owned_ranges: Some(&ranges),
                owned_leaders: Some(&leaders),
                proven_end: None,
            },
            deadline,
        ) else {
            continue;
        };
        handler
            .basic_blocks
            .retain(|block| owns(block.start_address.value, block.end_address.value));
        let retained_starts: std::collections::HashSet<u64> = handler
            .basic_blocks
            .iter()
            .map(|block| block.start_address.value)
            .collect();
        handler.edges.retain(|(source, target)| {
            retained_starts.contains(&source.value) && retained_starts.contains(&target.value)
        });
        if handler.basic_blocks.is_empty() {
            continue;
        }

        let parent = &mut functions[parent_index];
        split_parent_blocks_at_handler_leaders(
            facts.image,
            data,
            arch,
            end,
            parent,
            &handler.basic_blocks,
        );
        for block in handler.basic_blocks {
            if !parent
                .basic_blocks
                .iter()
                .any(|existing| existing.start_address.value == block.start_address.value)
            {
                parent.basic_blocks.push(block);
            }
        }
        for edge in handler.edges {
            if !parent.edges.contains(&edge) {
                parent.edges.push(edge);
            }
        }
        parent.callees.extend(handler.callees);
        parent.add_flag(FunctionFlags::HAS_EH);
        touched.insert(parent_index);
        call_edges.extend(
            handler_calls
                .into_iter()
                .filter(|xref| {
                    parent.basic_blocks.iter().any(|block| {
                        xref.callsite_va >= block.start_address.value
                            && xref.callsite_va < block.end_address.value
                    })
                })
                .map(|xref| (parent.entry_point.value, xref)),
        );
    }

    for index in touched {
        rebuild_block_relationships(&mut functions[index]);
    }
    call_edges
}

/// Grow the fragment starting at `fragment_start` to the end its `.eh_frame`
/// FDE proves, when the entry-rooted walk stopped short of it.
///
/// Returns whether the fragment grew. The existing chunk is *widened* rather
/// than a second chunk appended: [`Function::total_size`] sums chunks, and two
/// abutting chunks also make an otherwise contiguous fragment look
/// non-contiguous to every consumer that reasons about locality. A `-g` build
/// of the same source already gets the single wide range from DWARF, so
/// widening is what makes the two builds agree.
///
/// Never claims bytes another function already owns: an FDE describes one
/// function, so an overlap means one of the two extents is wrong and silently
/// double-owning the bytes is the worse of the two failures.
fn claim_proven_tail(
    functions: &mut [Function],
    parent_index: usize,
    fragment_start: u64,
    proven_end: u64,
    occupied: &mut Vec<(u64, u64)>,
) -> bool {
    let Some(walked_end) = functions[parent_index]
        .all_ranges()
        .iter()
        .find(|range| range.start.value == fragment_start)
        .map(|range| range.start.value.saturating_add(range.size))
    else {
        return false;
    };
    if walked_end >= proven_end {
        return false;
    }
    // `occupied` is sorted by start, so nothing at or beyond `proven_end` can
    // overlap; the prefix below it still has to be checked in full because the
    // intervals are not sorted by end.
    let first_after = occupied.partition_point(|(start, _)| *start < proven_end);
    if occupied[..first_after]
        .iter()
        .any(|(start, end)| *start < proven_end && *end > walked_end)
    {
        return false;
    }
    let parent = &mut functions[parent_index];
    let Some(anchor) = parent
        .all_ranges()
        .into_iter()
        .find(|range| range.start.value == fragment_start)
    else {
        return false;
    };
    let Ok(widened) = AddressRange::new(
        anchor.start.clone(),
        proven_end - fragment_start,
        anchor.alignment,
    ) else {
        return false;
    };
    if parent.chunks.is_empty() {
        parent.chunks.push(anchor.clone());
    }
    for chunk in &mut parent.chunks {
        if chunk.start.value == fragment_start {
            *chunk = widened.clone();
        }
    }
    if parent
        .range
        .as_ref()
        .is_some_and(|range| range.start.value == fragment_start)
    {
        parent.range = Some(widened.clone());
        parent.size = Some(widened.size);
    }
    let insert_at = occupied.partition_point(|(start, _)| *start < walked_end);
    occupied.insert(insert_at, (walked_end, proven_end));
    true
}

/// Split an existing normal-flow block when an EH subgraph branches into its
/// interior. GCC commonly rejoins a catch path at the final `mov` immediately
/// before the normal epilogue jump, which is a new leader even though normal
/// entry-rooted discovery originally swept across it.
fn split_parent_blocks_at_handler_leaders(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
    endianness: Endianness,
    parent: &mut Function,
    handler: &[BasicBlock],
) {
    let mut leaders: Vec<u64> = handler
        .iter()
        .map(|block| block.start_address.value)
        .collect();
    leaders.sort_unstable();
    leaders.dedup();
    for leader in leaders {
        split_parent_block_at(image, data, arch, endianness, parent, leader);
    }
}

fn split_parent_block_at(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
    endianness: Endianness,
    parent: &mut Function,
    leader: u64,
) -> bool {
    let Some(index) = parent
        .basic_blocks
        .iter()
        .position(|block| block.start_address.value < leader && leader < block.end_address.value)
    else {
        return false;
    };
    let source_start = parent.basic_blocks[index].start_address.clone();
    let old_end = parent.basic_blocks[index].end_address.clone();
    let old_successors = parent.basic_blocks[index].successor_ids.clone();
    let Some(head_count) =
        count_machine_instructions(image, data, arch, endianness, source_start.value, leader)
    else {
        return false;
    };
    let Some(tail_count) =
        count_machine_instructions(image, data, arch, endianness, leader, old_end.value)
    else {
        return false;
    };
    let Ok(new_start) = Address::new(
        AddressKind::VA,
        leader,
        source_start.bits,
        source_start.space.clone(),
        None,
    ) else {
        return false;
    };
    let source_id = parent.basic_blocks[index].id.clone();
    let new_id = format!("bb_{leader:x}");
    let tail = BasicBlock::new(
        new_id.clone(),
        new_start.clone(),
        old_end,
        tail_count,
        Some(old_successors),
        Some(vec![source_id]),
    );
    let block = &mut parent.basic_blocks[index];
    block.end_address = new_start.clone();
    block.instruction_count = head_count;
    block.successor_ids = vec![new_id];

    let mut moved_targets = Vec::new();
    parent.edges.retain(|(source, target)| {
        if source.value == source_start.value {
            moved_targets.push(target.clone());
            false
        } else {
            true
        }
    });
    parent.add_edge(source_start, new_start.clone());
    for target in moved_targets {
        parent.add_edge(new_start.clone(), target);
    }
    parent.basic_blocks.push(tail);
    true
}

fn count_machine_instructions(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
    endianness: Endianness,
    start: u64,
    end: u64,
) -> Option<u32> {
    if end <= start {
        return None;
    }
    let darch: crate::core::disassembler::Architecture = arch.into();
    let mut backend = registry::for_arch(darch, endianness)?;
    if matches!(arch, BArch::ARM) {
        let mode = crate::analysis::arm32_mode::mode_at(data, start, endianness);
        let _ = backend.set_thumb_mode(matches!(
            mode,
            crate::analysis::arm32_mode::Arm32Mode::Thumb
        ));
    }
    let bits = darch.address_bits();
    let mut cursor = start;
    let mut count = 0_u32;
    while cursor < end {
        let offset = indexed_code_offset(image, data, cursor)?;
        let bytes = data.get(offset..)?;
        let address = Address::new(AddressKind::VA, cursor, bits, None, None).ok()?;
        let instruction = backend.disassemble_instruction(&address, bytes).ok()?;
        let next = cursor.checked_add(u64::from(instruction.length))?;
        if next <= cursor || next > end {
            return None;
        }
        cursor = next;
        count = count.checked_add(1)?;
    }
    (cursor == end).then_some(count)
}

/// Recompute predecessor lists after merging an independently discovered
/// landing-pad subgraph. Successors are the authoritative direction.
fn rebuild_block_relationships(function: &mut Function) {
    let ids: std::collections::HashSet<String> = function
        .basic_blocks
        .iter()
        .map(|block| block.id.clone())
        .collect();
    for block in &mut function.basic_blocks {
        block
            .successor_ids
            .retain(|successor| ids.contains(successor));
        block.successor_ids.sort();
        block.successor_ids.dedup();
        block.predecessor_ids.clear();
        // `relationships_known` is deliberately NOT re-asserted here. This pass
        // recomputes the PREDECESSOR direction only; a block that arrived with
        // the flag cleared did so because its successors were never recovered
        // (a declined indirect dispatch), and rebuilding predecessors does not
        // recover them. Forcing it true put the false `is_exit_block()` claim
        // back on every function that had a landing pad merged into it.
    }
    let mut predecessors: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for block in &function.basic_blocks {
        for successor in &block.successor_ids {
            predecessors
                .entry(successor.clone())
                .or_default()
                .push(block.id.clone());
        }
    }
    for block in &mut function.basic_blocks {
        block.predecessor_ids = predecessors.remove(&block.id).unwrap_or_default();
        block.predecessor_ids.sort();
        block.predecessor_ids.dedup();
    }
    function.basic_blocks.sort_by_key(|block| {
        (
            block.start_address.value != function.entry_point.value,
            block.start_address.value,
        )
    });
}

/// Compiler-emitted suffixes that mark a separate symbol as belonging to
/// the same logical function as `<base>`. The first match wins per child;
/// `<base>` is everything before the suffix in the raw symbol name.
const COMPILER_SPLIT_SUFFIXES: &[&str] = &[
    ".cold",   // GCC -O2: cold-path split (single)
    ".cold.0", // GCC: numbered cold splits when multiple cold paths
    ".cold.1", ".cold.2", ".cold.3", ".part.0", // GCC: partial-inlining splits (.part.<n>)
    ".part.1", ".part.2",
];

/// Strip a known split suffix from `raw_name` and return the parent name,
/// or `None` if `raw_name` carries no recognised split suffix.
fn split_parent_name(raw_name: &str) -> Option<&str> {
    for suf in COMPILER_SPLIT_SUFFIXES {
        if let Some(parent) = raw_name.strip_suffix(suf) {
            if !parent.is_empty() {
                return Some(parent);
            }
        }
    }
    None
}

/// The surviving function a split child must fold into.
///
/// A split can nest, and the shape is not hypothetical: on Ubuntu 25.10,
/// `/usr/lib/x86_64-linux-gnu/libwebsockets.a` carries all three of
/// `lws_context_destroy`, `lws_context_destroy.part.0` and
/// `lws_context_destroy.part.0.cold` at once (`libmbedtls.a` and
/// `libboost_url.a` have their own). Folding a child into its *immediate* parent is
/// only correct when that parent survives the pass. When the parent is itself a
/// child it is removed from the list at the end, and everything merged into it
/// goes with it — so the leaf fragment's blocks and range are lost. Which of
/// the two merges runs first is decided by the order the two symbols sit in the
/// function list, which is discovery order, which for symbol-seeded functions
/// is symbol-table order and so link order. That made the loss intermittent
/// rather than absent, which is the worst of the two.
///
/// Walks only through links that exist: a `foo.part.0.cold` whose `foo.part.0`
/// was never discovered stays an orphan exactly as it did before, because the
/// evidence tying it to `foo` is the middle symbol.
fn split_root_index(
    by_name: &std::collections::HashMap<String, usize>,
    child_index: usize,
    child_name: &str,
) -> Option<usize> {
    let mut current = child_name;
    let mut root = None;
    // Every step strips a non-empty suffix, so `current` strictly shortens and
    // the walk terminates on its own; the bound only guards a symbol table that
    // spells two different functions the same way.
    for _ in 0..child_name.len() {
        let Some(parent_name) = split_parent_name(current) else {
            break;
        };
        match by_name.get(parent_name) {
            Some(&index) if index != child_index && Some(index) != root => {
                root = Some(index);
                current = parent_name;
            }
            _ => break,
        }
    }
    root
}

/// Merge compiler-emitted split children (`main.cold`, `foo.part.0`, ...)
/// into their parent function's `chunks` list and drop them from the
/// flat function list. Returns the number of children folded in.
///
/// Pass this *after* symbol renaming so child names are already canonical.
pub(super) fn merge_compiler_split_chunks(functions: &mut Vec<Function>) -> usize {
    use std::collections::HashMap;

    // entry_va → index into `functions` for fast parent lookup.
    let by_name: HashMap<String, usize> = functions
        .iter()
        .enumerate()
        .map(|(i, f)| (f.name.clone(), i))
        .collect();

    let mut to_remove: Vec<usize> = Vec::new();
    let mut merges: Vec<(usize, usize)> = Vec::new(); // (root_idx, child_idx)

    for (child_idx, child) in functions.iter().enumerate() {
        let Some(parent_idx) = split_root_index(&by_name, child_idx, &child.name) else {
            continue;
        };
        merges.push((parent_idx, child_idx));
        to_remove.push(child_idx);
    }

    for (parent_idx, child_idx) in &merges {
        // Take every child-owned graph component without removing the child
        // yet — the post-loop removal pass uses indices, so we can't shift the
        // list in place here. Chunks without blocks are metadata, not a merged
        // function: address-scoped lifting would otherwise clip or call out to
        // the executable cold fragment instead of structuring it locally.
        let (child_ranges, child_blocks, child_edges, child_callers, child_callees, child_flags) = {
            let child = &functions[*child_idx];
            let ranges = if !child.chunks.is_empty() {
                child.chunks.clone()
            } else {
                child.range.clone().map(|r| vec![r]).unwrap_or_default()
            };
            (
                ranges,
                child.basic_blocks.clone(),
                child.edges.clone(),
                child.callers.clone(),
                child.callees.clone(),
                child.flags,
            )
        };
        let parent = &mut functions[*parent_idx];
        // Ensure the parent's primary range is in chunks before appending.
        if parent.chunks.is_empty() {
            if let Some(r) = parent.range.clone() {
                parent.chunks.push(r);
            }
        }
        for r in child_ranges {
            parent.add_chunk(r);
        }
        for block in child_blocks {
            if !parent
                .basic_blocks
                .iter()
                .any(|existing| existing.start_address.value == block.start_address.value)
            {
                parent.basic_blocks.push(block);
            }
        }
        for edge in child_edges {
            if !parent.edges.contains(&edge) {
                parent.edges.push(edge);
            }
        }
        let parent_entry = parent.entry_point.clone();
        parent.callers.extend(
            child_callers
                .into_iter()
                .filter(|caller| caller != &parent_entry),
        );
        parent.callees.extend(child_callees);
        // The merged entry stops being an interprocedural target here, but the
        // removal is deferred to a pass over the finished merge set below: in a
        // nested split the middle fragment's own callee list names the leaf, so
        // removing at this point would only hold when the leaf happened to be
        // merged second.
        if !parent.has_flag(FunctionFlags::HAS_EH) {
            parent.add_flag(FunctionFlags::HAS_EH);
        }
        // The merged body now contains the child's blocks, so it also inherits
        // whatever the child's walk failed to reach. Dropping this here would
        // reintroduce exactly the silent incompleteness the flags exist for,
        // one level up: the child object disappears from the function list.
        for flag in [
            FunctionFlags::CFG_BLOCK_LIMIT,
            FunctionFlags::CFG_INSTRUCTION_LIMIT,
            FunctionFlags::CFG_WALK_TIMEOUT,
            FunctionFlags::CFG_ANALYSIS_DEADLINE,
        ] {
            if child_flags & flag {
                parent.add_flag(flag);
            }
        }
    }

    // Every merged entry is now local control flow inside its root, whichever
    // merge contributed the reference. Done once over the finished set so the
    // result does not depend on the order the children were visited.
    let merged_entries: Vec<(usize, Address)> = merges
        .iter()
        .map(|(root_idx, child_idx)| (*root_idx, functions[*child_idx].entry_point.clone()))
        .collect();
    for (root_idx, child_entry) in merged_entries {
        functions[root_idx].callees.remove(&child_entry);
    }

    // Remove children in descending index order so earlier indices stay valid.
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.iter().rev() {
        functions.remove(*idx);
    }

    merges.len()
}

#[cfg(test)]
mod chunk_tests {
    use super::*;

    fn _va_range(start: u64, size: u64) -> AddressRange {
        let s = Address::new(AddressKind::VA, start, 64, None, None).unwrap();
        AddressRange::new(s, size, None).unwrap()
    }

    fn _func(name: &str, va: u64, size: u64) -> Function {
        let entry = Address::new(AddressKind::VA, va, 64, None, None).unwrap();
        Function::new_full(
            name.to_string(),
            entry,
            FunctionKind::Normal,
            Some(_va_range(va, size)),
            FunctionFlags::NONE,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn split_parent_name_recognises_known_suffixes() {
        assert_eq!(split_parent_name("main.cold"), Some("main"));
        assert_eq!(split_parent_name("foo.cold.0"), Some("foo"));
        assert_eq!(split_parent_name("bar.part.0"), Some("bar"));
        assert_eq!(split_parent_name("plain"), None);
        assert_eq!(split_parent_name(".cold"), None); // empty parent rejected
    }

    #[test]
    fn merge_folds_cold_into_parent() {
        let mut funcs = vec![
            _func("main", 0x1000, 0x80),
            _func("main.cold", 0x2000, 0x20),
            _func("other", 0x3000, 0x40),
        ];
        let primary_block = BasicBlock::new(
            "primary".to_string(),
            Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x1080, 64, None, None).unwrap(),
            4,
            Some(Vec::new()),
            Some(Vec::new()),
        );
        let cold_block = BasicBlock::new(
            "cold".to_string(),
            Address::new(AddressKind::VA, 0x2000, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x2020, 64, None, None).unwrap(),
            2,
            Some(Vec::new()),
            Some(Vec::new()),
        );
        funcs[0].add_basic_block(primary_block);
        funcs[1].add_basic_block(cold_block);
        funcs[0].add_callee(Address::new(AddressKind::VA, 0x2000, 64, None, None).unwrap());
        funcs[1].add_callee(Address::new(AddressKind::VA, 0x5000, 64, None, None).unwrap());
        let merged = merge_compiler_split_chunks(&mut funcs);
        assert_eq!(merged, 1);
        assert_eq!(funcs.len(), 2, "child symbol should be dropped");
        let main = funcs.iter().find(|f| f.name == "main").unwrap();
        assert_eq!(main.chunks.len(), 2);
        assert_eq!(main.total_size(), 0x80 + 0x20);
        assert!(main.has_flag(FunctionFlags::HAS_EH));
        assert!(main.contains_va(0x2010));
        assert_eq!(
            main.basic_blocks
                .iter()
                .map(|block| block.start_address.value)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x2000],
            "merging a split function must retain the child's executable CFG"
        );
        assert!(
            !main.callees.iter().any(|callee| callee.value == 0x2000),
            "the merged child entry is local control flow, not a callee"
        );
        assert!(main.callees.iter().any(|callee| callee.value == 0x5000));
    }

    /// The numbers are measured, not invented: `g++ -O2` (no `-g`) on
    /// `tests/decompiler_fixtures/src/136_cpp_exception_unwinding.cpp` puts
    /// `cpp_catch_by_type` at 0x14c0, ends normal flow at the `ret` on 0x14d4,
    /// and parks the landing-pad trampoline (`endbr64; mov %rax,%rdi;
    /// jmp <cold>`) at 0x14d5. `readelf --debug-dump=frames` gives that
    /// function's FDE as `pc=0x14c0..0x14e1`, so the pad is inside the extent
    /// the FDE proves and outside the extent the entry-rooted walk found.
    ///
    /// Testing ownership against the walked extent therefore rejected the one
    /// thing landing-pad recovery exists to recover — and only on builds
    /// without `-g`, because DWARF hands the same function the wide range.
    /// Every fixture in `tests/decompiler_fixtures/` is compiled `-g`
    /// (`tools/fixture_harness.py`), which is why no lane could see this.
    #[test]
    fn a_landing_pad_past_the_walked_end_is_owned_by_its_fde() {
        let mut funcs = vec![_func("cpp_catch_by_type", 0x14c0, 0x15)];
        let mut occupied = vec![(0x14c0, 0x14d5)];
        assert!(
            !funcs[0].contains_va(0x14d5),
            "precondition: the walked extent stops at the epilogue"
        );
        assert!(claim_proven_tail(
            &mut funcs,
            0,
            0x14c0,
            0x14e1,
            &mut occupied
        ));
        assert!(funcs[0].contains_va(0x14d5));
        assert!(funcs[0].contains_va(0x14e0));
        assert!(!funcs[0].contains_va(0x14e1), "the FDE end is exclusive");
        assert_eq!(
            funcs[0].all_ranges().len(),
            1,
            "abutting proven bytes widen the fragment; a second chunk would \
             make a contiguous function look split"
        );
        assert_eq!(funcs[0].total_size(), 0x21);
    }

    #[test]
    fn a_proven_tail_never_takes_bytes_from_a_neighbour() {
        let mut funcs = vec![_func("hot", 0x1000, 0x10), _func("neighbour", 0x1010, 0x10)];
        let mut occupied = vec![(0x1000, 0x1010), (0x1010, 0x1020)];
        assert!(!claim_proven_tail(
            &mut funcs,
            0,
            0x1000,
            0x1020,
            &mut occupied
        ));
        assert_eq!(funcs[0].total_size(), 0x10);
    }

    #[test]
    fn a_walk_that_reached_the_proven_end_is_left_alone() {
        let mut funcs = vec![_func("hot", 0x1000, 0x20)];
        let mut occupied = vec![(0x1000, 0x1020)];
        assert!(!claim_proven_tail(
            &mut funcs,
            0,
            0x1000,
            0x1020,
            &mut occupied
        ));
        assert_eq!(
            funcs[0].total_size(),
            0x20,
            "nothing claimed, nothing grown"
        );
        assert_eq!(occupied.len(), 1, "and no interval recorded");
    }

    fn _block(name: &str, start: u64, end: u64) -> BasicBlock {
        BasicBlock::new(
            name.to_string(),
            Address::new(AddressKind::VA, start, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, end, 64, None, None).unwrap(),
            2,
            Some(Vec::new()),
            Some(Vec::new()),
        )
    }

    /// `foo` <- `foo.part.0` <- `foo.part.0.cold` is a chain, not a star, and
    /// GCC really emits it: `/usr/bin/perf` on Ubuntu 25.10 ships
    /// `comm_str__put.part.0.cold` alongside `comm_str__put.part.0`.
    ///
    /// The chain is the whole point of the test. Folding the middle link into
    /// the root first leaves the leaf merging into a `Function` that is about
    /// to be removed from the list, so its blocks and its range go with it —
    /// and which of the two merges runs first is decided by the order the two
    /// symbols happen to sit in, which is symbol-table order, which is link
    /// order. Both orders must produce the same function.
    fn nested_split_chain(cold_first: bool) -> Vec<Function> {
        let mut root = _func("foo", 0x1000, 0x40);
        root.add_basic_block(_block("root", 0x1000, 0x1040));
        let mut part = _func("foo.part.0", 0x2000, 0x40);
        part.add_basic_block(_block("part", 0x2000, 0x2040));
        let mut cold = _func("foo.part.0.cold", 0x3000, 0x20);
        cold.add_basic_block(_block("cold", 0x3000, 0x3020));
        if cold_first {
            vec![root, cold, part]
        } else {
            vec![root, part, cold]
        }
    }

    #[test]
    fn nested_split_keeps_the_cold_fragment_in_either_symbol_order() {
        for cold_first in [true, false] {
            let mut funcs = nested_split_chain(cold_first);
            let merged = merge_compiler_split_chunks(&mut funcs);
            assert_eq!(merged, 2, "cold_first={cold_first}");
            assert_eq!(funcs.len(), 1, "cold_first={cold_first}");
            let foo = &funcs[0];
            assert_eq!(foo.name, "foo");
            assert!(
                foo.contains_va(0x3010),
                "cold_first={cold_first}: the nested cold fragment's RANGE was lost"
            );
            assert!(
                foo.basic_blocks
                    .iter()
                    .any(|block| block.start_address.value == 0x3000),
                "cold_first={cold_first}: the nested cold fragment's BLOCKS were lost"
            );
            assert_eq!(
                foo.total_size(),
                0x40 + 0x40 + 0x20,
                "cold_first={cold_first}"
            );
        }
    }

    #[test]
    fn merge_skips_orphan_cold_with_no_parent() {
        // `mystery.cold` exists but `mystery` does not — leave the orphan
        // alone rather than silently dropping data we can't account for.
        let mut funcs = vec![_func("mystery.cold", 0x4000, 0x20)];
        let merged = merge_compiler_split_chunks(&mut funcs);
        assert_eq!(merged, 0);
        assert_eq!(funcs.len(), 1);
    }
}
