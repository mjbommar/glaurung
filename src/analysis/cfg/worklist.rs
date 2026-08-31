//! The whole-binary discovery run: which seeds, in which order, and who owns
//! what when two of them overlap.
//!
//! [`analyze_functions_unpacked`] is the only place the pieces meet. It collects
//! every seed source ([`seeds`](super::seeds)), walks them one at a time
//! ([`walk`](super::walk)), feeds each function's call and jump targets back
//! onto the worklist, and finishes by handing the result to the repair chain and
//! building the callgraph.
//!
//! **Seed ORDER is the design.** [`DiscoverySeedKind`] is not a label: it decides
//! both budget priority and body ownership. The trusted sources -- a requested
//! VA, the entry point, a symbol, an unwind-table start -- run first and are
//! never refused. Everything after them is `is_body_overlap_gated`, meaning a
//! candidate that lands strictly inside a function already discovered is
//! rejected and *recorded* as rejected, because a scanner finding the middle of
//! a known body has found a false start, not a function. `.pdata` inverts that:
//! an unwind table is more authoritative than a walk, so the earlier function is
//! capped at the seed instead.
//!
//! The three questions that gate every seed -- does a body already cover this
//! VA, is it already a block leader, does a declared extent contain it -- are
//! answered by [`BodyIndex`](super::BodyIndex) and
//! [`extents`](super::extents) rather than re-scanned here, which is what keeps
//! the loop linear in the number of seeds instead of quadratic in the result.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiscoverySeedKind {
    Requested,
    EntryPoint,
    Symbol,
    Flirt,
    Vtable,
    JumpTable,
    Export,
    Pdata,
    /// An `.eh_frame` FDE start — the ELF counterpart of `Pdata`.
    EhFrame,
    Prologue,
    Thunk,
    TinyStub,
    DirectCall,
    DirectCallBodySplit,
    IndirectCall,
    TailCall,
    DataRef,
}

impl DiscoverySeedKind {
    pub(super) fn is_body_overlap_gated(self) -> bool {
        matches!(
            self,
            Self::Vtable
                | Self::JumpTable
                | Self::Prologue
                | Self::Thunk
                | Self::TinyStub
                | Self::DirectCall
                | Self::IndirectCall
                | Self::TailCall
                | Self::DataRef
        )
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::EntryPoint => "entrypoint",
            Self::Symbol => "symbol",
            Self::Flirt => "flirt",
            Self::Vtable => "vtable",
            Self::JumpTable => "jump_table",
            Self::Export => "export",
            Self::Pdata => "trusted_pdata",
            Self::EhFrame => "trusted_eh_frame",
            Self::Prologue => "prologue",
            Self::Thunk => "thunk",
            Self::TinyStub => "tiny_stub",
            Self::DirectCall => "direct_call",
            Self::DirectCallBodySplit => "direct_call_body_split",
            Self::IndirectCall => "indirect_call",
            Self::TailCall => "tail_call",
            Self::DataRef => "data_ref",
        }
    }
}

pub(super) fn analyze_functions_unpacked(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
    deadline: Deadline<'_>,
    image: Option<&crate::program::image::ProgramImage>,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    let (regions, arch, end, entry) =
        image.map_or_else(|| parse_exec_regions(data), parse_exec_regions_in);
    let mut functions: Vec<Function> = Vec::new();
    // Answers the two body-ownership questions the worklist asks per seed
    // without rescanning `functions`. See `body_index` for the identity it
    // preserves and for the measurement that motivated it.
    let mut body_index = BodyIndex::new(&regions);
    let mut cg = CallGraph::new();
    let mut stats = FunctionDiscoveryStats {
        max_functions: budgets.max_functions,
        max_blocks: budgets.max_blocks,
        max_instructions: budgets.max_instructions,
        timeout_ms: budgets.timeout_ms,
        total_timeout_ms: budgets.total_timeout_ms,
        ..FunctionDiscoveryStats::default()
    };
    if regions.is_empty() {
        stats.elapsed_ms = deadline.elapsed_ms();
        return (functions, cg, stats);
    }
    // One import-table read per image, shared with every other consumer of it.
    // The byte-only compatibility path still recovers its own copy.
    let noreturn_targets: std::sync::Arc<std::collections::HashSet<u64>> = image.map_or_else(
        || {
            std::sync::Arc::new(crate::analysis::call_semantics::imported_noreturn_targets(
                data,
            ))
        },
        crate::program::image::ProgramImage::noreturn_import_targets,
    );
    let plt_stub_ranges = plt::elf_plt_stub_ranges(image, data, arch);

    let bits = if arch.is_64_bit() { 64 } else { 32 };
    // Every seed source, in the order that decides both budget priority and
    // body ownership. See `seeds` for what each phase contributes.
    let Seeds {
        seeds,
        mut known,
        mut seed_kind_by_va,
        flirt_library,
        flirt_name_by_va,
        jump_table_index,
        eh_frame_extent,
        is_pe_image,
    } = collect_seeds(
        data,
        image,
        &regions,
        arch,
        bits,
        entry,
        requested_vas,
        &functions,
        deadline,
        &mut stats,
    );

    // Recursive multi-pass discovery. Each discovered function's
    // direct-call targets feed back as new seeds; without this the
    // discovery pass terminates as soon as the initial seed list is
    // exhausted, missing every internal function not reached by any
    // other seed source. Worklist-based to keep the iteration bounded
    // by a positive `max_functions` while still propagating xrefs to a
    // fixed point. `max_functions == 0` means no function-count cap.
    let discovery_facts = DiscoveryFacts {
        image,
        tables: &jump_table_index,
        noreturn_targets: &noreturn_targets,
        plt_stub_ranges: &plt_stub_ranges,
        owned_ranges: None,
        owned_leaders: None,
        proven_end: None,
    };
    // What some authority has *declared* to be a function's extent, as opposed
    // to what a walk has reached. The two differ exactly where a landing pad
    // sits: unreachable in the CFG, and squarely inside its parent's FDE.
    let declared_extents = extents::DeclaredExtents::from_eh_frame(
        &eh_frame_extent,
        &plt::stub_ranges_including_unsectioned(image, data, arch),
    );
    stats.declared_extents = declared_extents.len();
    let mut calls_all: Vec<(u64, FunctionXref)> = Vec::new(); // (caller_entry_va, xref)
    let mut worklist: std::collections::VecDeque<(Address, DiscoverySeedKind)> =
        seeds.into_iter().collect();
    stats.seeds_initial = worklist.len();
    while let Some((seed, seed_kind)) = worklist.pop_front() {
        if budgets.max_functions > 0 && functions.len() >= budgets.max_functions {
            stats.hit_function_limit = true;
            worklist.push_front((seed, seed_kind));
            break;
        }
        // The one loop that was genuinely unbounded: `timeout_ms` restarts inside
        // `discover_function`, so a binary with tens of thousands of seeds could
        // run for hours entirely inside budget. The seed goes back on the front
        // so `seeds_remaining` counts what was NOT analysed.
        if deadline.expired() {
            stats.hit_total_timeout = true;
            worklist.push_front((seed, seed_kind));
            break;
        }
        stats.seeds_processed = stats.seeds_processed.saturating_add(1);
        let seed_overlaps_body = body_index.contains_body(&functions, seed.value);
        let seed_is_owned_block_leader =
            seed_kind.is_body_overlap_gated() && body_index.is_block_leader(&functions, seed.value);
        if seed_kind == DiscoverySeedKind::Pdata && seed_overlaps_body {
            stats.pdata_body_overlap_starts = stats.pdata_body_overlap_starts.saturating_add(1);
            cap_discovered_functions_at_va(&mut functions, seed.value, &mut body_index);
        } else if seed_kind.is_body_overlap_gated()
            && (seed_overlaps_body || seed_is_owned_block_leader)
        {
            record_scan_rejection(
                &mut stats,
                seed.value,
                None,
                format!("body_overlap:{}", seed_kind.label()),
                "candidate lies inside an already discovered function body",
            );
            continue;
        } else if let Some(owner) = seed_kind
            .is_body_overlap_gated()
            .then(|| declared_extents.containing_start(seed.value))
            .flatten()
        {
            // Reachability is the wrong question for a landing pad: the
            // unwinder arrives by indirect jump, so no walk of the parent
            // covers it and the gate above sees nothing. Its FDE does. See
            // `extents` for the worked example and for why this costs no
            // recall on binaries without unwind tables.
            record_scan_rejection(
                &mut stats,
                seed.value,
                Some(owner),
                format!("declared_extent:{}", seed_kind.label()),
                "candidate lies strictly inside another function's declared extent",
            );
            continue;
        }
        // Bound this function by its own FDE when one covers the seed. Looked
        // up per seed rather than stored on the shared facts because the bound
        // is a property of the function being walked, not of the binary.
        let seed_facts = DiscoveryFacts {
            proven_end: eh_frame_extent.get(&seed.value).copied(),
            ..discovery_facts
        };
        if let Some((f, calls, func_stats)) = discover_function(
            data,
            arch,
            end,
            seed.clone(),
            &regions,
            budgets,
            &seed_facts,
            deadline,
        ) {
            stats.function_seed_kinds.push((
                f.entry_point.value,
                seed_kind_by_va
                    .get(&f.entry_point.value)
                    .copied()
                    .unwrap_or(seed_kind)
                    .label()
                    .to_string(),
            ));
            merge_single_function_stats(&mut stats, func_stats);
            for xref in &calls {
                calls_all.push((f.entry_point.value, *xref));
                match xref.call_type {
                    CallType::Direct => {
                        stats.direct_call_targets = stats.direct_call_targets.saturating_add(1);
                    }
                    CallType::Indirect => {
                        stats.indirect_call_targets = stats.indirect_call_targets.saturating_add(1);
                    }
                    CallType::Tail => {
                        stats.tail_call_targets = stats.tail_call_targets.saturating_add(1);
                    }
                    CallType::Virtual => {}
                }
                // Xref-backtracking seed: any direct call/jump target
                // landing in an exec region that we haven't already
                // queued becomes a new candidate function entry.
                if !known.contains(&xref.target_va)
                    && in_exec_regions(&regions, xref.target_va).is_some()
                    && !va_in_function_body(&f, xref.target_va)
                    && !body_index.contains_body(&functions, xref.target_va)
                    && (!is_pe_image
                        || pe_xref_seed_looks_like_function_start(data, xref.target_va))
                {
                    if let Ok(addr) =
                        Address::new(AddressKind::VA, xref.target_va, bits, None, None)
                    {
                        let seed_kind = match xref.call_type {
                            CallType::Direct => DiscoverySeedKind::DirectCall,
                            CallType::Indirect => DiscoverySeedKind::IndirectCall,
                            CallType::Tail => DiscoverySeedKind::TailCall,
                            CallType::Virtual => DiscoverySeedKind::IndirectCall,
                        };
                        worklist.push_back((addr, seed_kind));
                        known.insert(xref.target_va);
                        seed_kind_by_va.insert(xref.target_va, seed_kind);
                        record_seed_provenance(
                            &mut stats,
                            xref.target_va,
                            Some(xref.callsite_va),
                            seed_kind,
                            "worklist_xref",
                        );
                        stats.xref_seeds_added = stats.xref_seeds_added.saturating_add(1);
                        match xref.call_type {
                            CallType::Direct => {
                                stats.direct_call_seeds_added =
                                    stats.direct_call_seeds_added.saturating_add(1);
                            }
                            CallType::Indirect => {
                                stats.indirect_call_seeds_added =
                                    stats.indirect_call_seeds_added.saturating_add(1);
                            }
                            CallType::Tail => {
                                stats.tail_call_seeds_added =
                                    stats.tail_call_seeds_added.saturating_add(1);
                            }
                            CallType::Virtual => {}
                        }
                    }
                }
            }
            cg.add_node(f.name.clone());
            body_index.insert(functions.len(), &f);
            functions.push(f);
        }
    }
    stats.seeds_remaining = worklist.len();

    // Post-process: rename functions by matching defined symbol names at their
    // entry VAs, then let the repair chain build on those names.
    apply_symbol_and_export_names(data, arch, &regions, &mut functions);

    // Fold compiler-emitted split chunks while the symbol-table suffixes are
    // still intact. A DWARF subprogram covers every range of the logical
    // function, so applying it first renames both `dispatch` and
    // `dispatch.cold` to `dispatch`; the suffix then disappears and the child
    // survives as a duplicate function. After this merge, DWARF can safely
    // replace the surviving parent's chunk list with its authoritative ranges.
    merge_compiler_split_chunks(&mut functions);

    // Apply DWARF authoritative ground truth where available. DWARF
    // gives us the canonical function name, multi-chunk address ranges
    // (DW_AT_ranges), parameter count, and source language — all of
    // which beat the heuristic discovery output on -g builds. We only
    // *override* fields that DWARF has hard answers for; heuristic
    // basic-block CFG and edges remain.
    apply_dwarf_overrides(image, data, &mut functions);

    // C++/Itanium handlers are reached through LSDA metadata rather than a
    // branch instruction. Merge their blocks only after DWARF establishes the
    // authoritative function ranges used to reject cross-function walks.
    calls_all.extend(attach_exception_landing_pads(
        data,
        arch,
        end,
        &regions,
        budgets,
        &discovery_facts,
        &mut functions,
        &eh_frame_extent,
        deadline,
    ));

    // FLIRT-style signature matching. Runs *after* DWARF / symbol-rename
    // so it only touches functions still named `sub_*` — we never
    // overwrite a name we already trust. Also lifts names from the seed
    // map computed during the discovery pass (covers FLIRT-discovered
    // entries that didn't survive symbol-rename for any reason).
    if !flirt_name_by_va.is_empty() {
        for f in &mut functions {
            if !f.name.starts_with("sub_") {
                continue;
            }
            if let Some(name) = flirt_name_by_va.get(&f.entry_point.value) {
                f.name = name.clone();
            }
        }
    }
    if let Some(ref lib) = flirt_library {
        apply_flirt_overrides(data, &mut functions, lib);
    }

    let shape_stats = classify_function_shapes(data, arch, &mut functions);
    stats.thunk_functions = shape_stats.thunk_functions;
    stats.import_thunk_functions = shape_stats.import_thunk_functions;
    stats.tail_thunk_functions = shape_stats.tail_thunk_functions;
    stats.tiny_functions_le8 = shape_stats.tiny_functions_le8;
    stats.tiny_functions_le32 = shape_stats.tiny_functions_le32;

    // Build callgraph using discovered functions where possible
    let name_by_va: std::collections::HashMap<u64, String> = functions
        .iter()
        .map(|f| (f.entry_point.value, f.name.clone()))
        .collect();

    for (caller_entry_va, xref) in calls_all {
        let caller = name_by_va
            .get(&caller_entry_va)
            .cloned()
            .unwrap_or_else(|| format!("sub_{:x}", caller_entry_va));
        let callee = name_by_va
            .get(&xref.target_va)
            .cloned()
            .unwrap_or_else(|| format!("sub_{:x}", xref.target_va));
        cg.add_node(callee.clone());
        let edge = Address::new(AddressKind::VA, xref.callsite_va, bits, None, None)
            .map(|site| {
                CallGraphEdge::with_call_sites(
                    caller.clone(),
                    callee.clone(),
                    xref.call_type,
                    vec![site],
                )
            })
            .unwrap_or_else(|_| CallGraphEdge::new(caller.clone(), callee, xref.call_type));
        cg.add_edge(edge);
    }

    stats.code_labels = collect_code_labels(data, &functions);
    stats.code_label_count = stats.code_labels.len();
    stats.functions_discovered = functions.len();
    stats.callgraph_functions = cg.function_count();
    stats.callgraph_edges = cg.edge_count();
    stats.elapsed_ms = deadline.elapsed_ms();

    (functions, cg, stats)
}
