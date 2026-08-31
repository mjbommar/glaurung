//! One function's bounded block walk.
//!
//! [`discover_function`] is handed an entry address and a set of facts about the
//! binary, and returns the blocks, edges and call sites reachable from it.
//! Everything it does is bounded -- block count, instruction count, a per-walk
//! clock and the whole-run [`Deadline`](super::Deadline) -- and any of them
//! firing is recorded rather than absorbed; see
//! [`SingleFunctionDiscoveryStats`](super::SingleFunctionDiscoveryStats).
//!
//! [`DiscoveryFacts`] is the other half of the contract: what the *rest* of the
//! program already knows, gathered once per run instead of per seed. Two of its
//! fields decide where a walk stops. `proven_end` is an `.eh_frame` extent, and
//! without it a function whose last instruction calls a `noreturn` helper has no
//! terminator, so the sweep runs into whatever follows -- `main` in a stripped
//! musl `getent` is 97 bytes and was discovered as 154, swallowing `_start` and
//! reporting its calls as its own. `owned_ranges` is the continuation /
//! landing-pad case, where a jump that looks like a tail call is really
//! intra-function.
//!
//! What the walk deliberately does NOT do is decide whether a speculative jump
//! table was right. It attaches the arms it can see and records them as
//! tentative; `must_dataflow::validate_dispatch_edges` closes the graph
//! afterwards, and only then are the blocks pruned to what is reachable through
//! validated edges.

use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct FunctionXref {
    pub(super) callsite_va: u64,
    pub(super) target_va: u64,
    pub(super) call_type: CallType,
}

pub(super) struct DiscoveryFacts<'a> {
    // Program-scoped address index. Legacy byte-only analysis leaves this empty;
    // session-backed entry points always supply it.
    pub(super) image: Option<&'a crate::program::image::ProgramImage>,
    // Jump tables discovered once for the whole binary, indexed by table VA.
    //
    // These used to be consumed only as function-discovery seeds. Keeping the
    // table-to-dispatch binding here lets the dispatching CFG acquire its arms.
    pub(super) tables: &'a std::collections::BTreeMap<u64, Vec<u64>>,
    // Resolved import/thunk addresses whose contracts prohibit fallthrough.
    pub(super) noreturn_targets: &'a std::collections::HashSet<u64>,
    // PLT stub extents proven once for this run by `elf_plt_stub_ranges`.
    pub(super) plt_stub_ranges: &'a [std::ops::Range<u64>],
    // Optional authoritative ranges for a continuation/landing-pad walk. A
    // direct jump that stays inside these ranges is intra-function even when
    // its target bytes resemble a standalone prologue.
    pub(super) owned_ranges: Option<&'a [AddressRange]>,
    // Existing basic-block starts in the owning function. A landing-pad walk
    // must treat these as leaders even when it reaches one by linear flow.
    pub(super) owned_leaders: Option<&'a [u64]>,
    // Exclusive upper bound on this function's bytes, when `.eh_frame` proves
    // one. Without it a function whose last instruction is a call to a
    // `noreturn` helper has no terminator, so the walk falls through into
    // whatever follows and keeps going: `main` in a stripped musl `getent` is
    // 97 bytes but was discovered as 154, swallowing `_start` and `_start_c`
    // and reporting their calls — including `__libc_start_main` — as its own.
    pub(super) proven_end: Option<u64>,
}

impl DiscoveryFacts<'_> {
    /// True when `va` lies at or past this function's proven end.
    ///
    /// Only ever consulted when `.eh_frame` supplied an exact extent, so this
    /// cannot truncate a function whose length is merely guessed.
    pub(super) fn beyond_proven_end(&self, va: u64) -> bool {
        self.proven_end.is_some_and(|end| va >= end)
    }

    /// True when `va` lands inside linker-generated import glue.
    pub(super) fn target_is_plt_stub(&self, va: u64) -> bool {
        self.plt_stub_ranges.iter().any(|range| range.contains(&va))
    }

    pub(super) fn owns(&self, va: u64) -> bool {
        self.owned_ranges.is_some_and(|ranges| {
            ranges.iter().any(|range| {
                let start = range.start.value;
                start
                    .checked_add(range.size)
                    .is_some_and(|end| va >= start && va < end)
            })
        })
    }
}

/// Discover a single function starting at `entry` within executable regions.
pub(super) fn discover_function(
    data: &[u8],
    arch: BArch,
    end: Endianness,
    entry: Address,
    regions: &[ExecRegion],
    budgets: &Budgets,
    facts: &DiscoveryFacts<'_>,
    deadline: Deadline<'_>,
) -> Option<(Function, Vec<FunctionXref>, SingleFunctionDiscoveryStats)> {
    let darch: crate::core::disassembler::Architecture = arch.into();
    let mut backend = registry::for_arch(darch, end)?;
    let arm32_mode = matches!(arch, BArch::ARM)
        .then(|| crate::analysis::arm32_mode::mode_at(data, entry.value, end));
    if let Some(mode) = arm32_mode {
        let _ = backend.set_thumb_mode(matches!(
            mode,
            crate::analysis::arm32_mode::Arm32Mode::Thumb
        ));
    }
    let bits = darch.address_bits();
    let t0 = std::time::Instant::now();
    let mut stats = SingleFunctionDiscoveryStats::default();

    // BFS over basic block starts
    use std::collections::{HashMap, VecDeque};
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut blocks: HashMap<u64, (u64, u32)> = HashMap::new(); // start_va -> (end_va, instr_count)
                                                               // start_va -> the instructions the walk decoded for that block, so the
                                                               // must-dataflow fixed points and the dispatch revalidation below can replay
                                                               // a block without decoding it again. See `BlockStreams`.
    let mut block_streams: BlockStreams = HashMap::new();
    // block start -> inclusive max switch index its guard admits. Written when a
    // block ends in a range check, read when its in-range successor is walked.
    // BFS reaches the guard before the dispatch, so the fact is always available.
    let mut index_bounds: HashMap<u64, crate::analysis::dispatch::Bounds> = HashMap::new();
    // Concrete register addresses that reach a block on every predecessor seen
    // so far. Unlike range bounds, these flow across ordinary branches too: a
    // loop preheader commonly materialises the jump-table base once and a later
    // dispatch block reads it. Values are merged by intersection at joins and
    // killed by DispatchTracker on any write.
    let mut dispatch_addresses: HashMap<u64, HashMap<String, u64>> = HashMap::new();
    let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = Vec::new();
    let mut call_edges: Vec<FunctionXref> = Vec::new();
    // (dispatch instruction, containing block, tentatively attached targets).
    // Revalidated against the completed CFG's address-dataflow fixed point
    // before the Function is built.
    let mut resolved_dispatch_edges: Vec<TentativeDispatchEdges> = Vec::new();

    if let Some(r) = in_exec_regions(regions, entry.value) {
        let _ = r;
    } else {
        return None;
    }
    queue.push_back(entry.value);
    seen.insert(entry.value);
    if let Some(leaders) = facts.owned_leaders {
        for leader in leaders {
            if *leader != entry.value
                && in_exec_regions(regions, *leader).is_some()
                && seen.insert(*leader)
            {
                queue.push_back(*leader);
            }
        }
    }

    let mut decoded_instructions = 0usize;

    while let Some(start_va) = queue.pop_front() {
        if blocks.len() >= budgets.max_blocks {
            stats.hit_block_limit = true;
            break;
        }
        if t0.elapsed().as_millis() as u64 > budgets.timeout_ms {
            stats.hit_timeout = true;
            break;
        }
        // Whichever ceiling fires first wins: the per-function clock restarts on
        // every seed, so without this check the whole-analysis budget could be
        // exceeded by an arbitrary multiple and nothing would notice.
        if deadline.expired() {
            stats.hit_total_timeout = true;
            break;
        }
        // A block start at or past the proven end belongs to the next function,
        // not this one. Guarding here rather than at each of the four enqueue
        // sites keeps the rule in one place and covers branch, dispatch and
        // fallthrough targets alike.
        if facts.beyond_proven_end(start_va) {
            continue;
        }
        // Decode sequentially until a terminating control flow or budget hit
        let mut cur_va = start_va;
        let mut instrs = 0u32;
        // Register tracking for indirect-dispatch resolution, per block. Reset
        // here because a value set up in one block is not guaranteed to reach
        // this one — there may be several predecessors.
        let mut dispatch = crate::analysis::dispatch::DispatchTracker::new();
        // `add rD, pc, #imm` materialises a jump table's base on ARM, and what
        // `pc` reads depends on the execution state. Declared, never guessed:
        // an A32 reading of a Thumb `adr` names a table four bytes off and
        // decodes whatever is there without complaining.
        dispatch.set_arm_pc_mode(arm32_mode.map(|mode| match mode {
            crate::analysis::arm32_mode::Arm32Mode::Thumb => {
                crate::analysis::dispatch::ArmPcMode::Thumb
            }
            _ => crate::analysis::dispatch::ArmPcMode::A32,
        }));
        // A switch's range check sits in the block BEFORE the dispatch, and it
        // is the only thing that knows how many entries the table has. Carry it
        // across the in-range edge; see `DispatchTracker::inherit_bound`.
        dispatch.inherit_bound(index_bounds.get(&start_va).cloned());
        dispatch.inherit_addresses(dispatch_addresses.get(&start_va));
        let mut stream: Vec<Instruction> = Vec::new();
        'block: loop {
            if decoded_instructions >= budgets.max_instructions {
                stats.hit_instruction_limit = true;
                break 'block;
            }
            if t0.elapsed().as_millis() as u64 > budgets.timeout_ms {
                stats.hit_timeout = true;
                break 'block;
            }
            if deadline.expired() {
                stats.hit_total_timeout = true;
                break 'block;
            }
            // Basic-block leader rule: if the linear sweep has reached the start
            // of another already-discovered block (a branch/fallthrough target
            // in `seen`), the current block ends here and falls through to it.
            // Without this a block that falls into a jump-target (e.g. a rotated
            // `-O0` loop's body falling into its condition block) would swallow
            // the successor's instructions and inherit its edges, destroying the
            // back-edge so no natural loop is recovered.
            // Linear flow has reached the end `.eh_frame` proved for this
            // function. The bytes from here belong to the next one, so the
            // block ends without a fallthrough edge — inventing one would
            // reintroduce exactly the overrun this bound exists to stop.
            if cur_va != start_va && facts.beyond_proven_end(cur_va) {
                blocks.insert(start_va, (cur_va, instrs));
                break 'block;
            }
            if cur_va != start_va && seen.contains(&cur_va) {
                edges.push((start_va, cur_va, ControlFlowEdgeKind::Fallthrough));
                merge_dispatch_addresses(
                    &mut dispatch_addresses,
                    cur_va,
                    dispatch.export_addresses(),
                );
                blocks.insert(start_va, (cur_va, instrs));
                break 'block;
            }
            // Map VA -> file offset using shared helper for robustness. The CODE
            // resolver: in a relocatable object every section shares address 0, and
            // the general one would hand back whichever section is listed first.
            let fo = match indexed_code_offset(facts.image, data, cur_va) {
                Some(v) => v,
                None => break 'block,
            };
            if fo >= data.len() {
                break 'block;
            }
            let slice = &data[fo..];
            let addr = Address::new(AddressKind::VA, cur_va, bits, None, None).ok()?;
            match backend.disassemble_instruction(&addr, slice) {
                Ok(i) => stream.push(i),
                Err(_) => break 'block,
            };
            // Borrowed from the recorded stream rather than owned: the walk
            // needs the instruction here and the replays need it later, and
            // cloning one costs about as much as decoding it.
            let ins = stream.last().expect("just pushed");
            decoded_instructions += 1;
            instrs = instrs.saturating_add(1);
            // Streaming, so the block is neither buffered nor decoded twice.
            // On ARM the decoder reports no writes at all, so the definition
            // has to be named here or a stale bound would size the next table.
            if matches!(arch, BArch::ARM) {
                if let Some(defined) = arm_defined_register(&ins) {
                    dispatch.kill_register(defined);
                }
            }
            dispatch.observe(&ins);
            let end_va = cur_va.saturating_add(ins.length as u64);
            if is_code_padding_terminator(&ins.mnemonic, arch) {
                blocks.insert(start_va, (end_va, instrs));
                break 'block;
            }
            let (mut is_branch, is_call, mut is_ret) = classify_ctrl_flow(&ins.mnemonic, arch);
            // ARM `pop {…, pc}` / `ldm …, pc` is a return; the mnemonic alone
            // can't say so, so resolve it on the operands here.
            if matches!(arch, BArch::ARM) && arm_pop_writes_pc(&ins) {
                is_ret = true;
            }
            // `ldr pc, [rBase, rIdx, lsl #2]` is an unconditional indirect
            // branch, and the mnemonic alone cannot say so either. Without this
            // the sweep decodes the table it reads as instructions.
            let arm_table_dispatch =
                matches!(arch, BArch::ARM) && !is_ret && arm_ldr_pc_table_dispatch(&ins);
            if arm_table_dispatch {
                is_branch = true;
            }
            if is_call {
                // Preserve the exact instruction VA so downstream xref tables
                // report callsites, not just caller-function granularity.  A
                // resolved noreturn import ends the block and the function:
                // decoding its lexical successor would cross into padding or a
                // neighbouring function on optimized stripped binaries.
                let resolved_target = immediate_target(&ins)
                    .or_else(|| indirect_memory_target(facts.image, data, &ins, bits));
                if let Some(tgt) = resolved_target {
                    call_edges.push(FunctionXref {
                        callsite_va: cur_va,
                        target_va: tgt,
                        call_type: if immediate_target(&ins).is_some() {
                            CallType::Direct
                        } else {
                            CallType::Indirect
                        },
                    });
                }
                if resolved_target.is_some_and(|target| facts.noreturn_targets.contains(&target)) {
                    blocks.insert(start_va, (end_va, instrs));
                    break 'block;
                }
                // continue to fallthrough
            } else if is_branch {
                // Determine conditional vs unconditional by mnemonic content
                // A table dispatch never falls through: the byte after it is
                // either padding or the table itself.
                let unconditional =
                    is_unconditional_branch_mnemonic(&ins.mnemonic, arch) || arm_table_dispatch;
                if let Some(tgt) = immediate_target(&ins) {
                    let is_exec_target = in_exec_regions(regions, tgt).is_some();
                    let is_pe_tail_target = unconditional
                        && !facts.owns(tgt)
                        && data.len() >= 2
                        && &data[..2] == b"MZ"
                        && is_exec_target
                        && pe_tail_target_looks_like_function_start(data, tgt, arch.is_64_bit());
                    let is_elf_x86_tail_target = unconditional
                        && !facts.owns(tgt)
                        && tgt != entry.value
                        && is_exec_target
                        && elf_x86_tail_target_looks_like_function_start(
                            facts.image,
                            data,
                            tgt,
                            arch,
                        );
                    let is_elf_plt_tail_target = unconditional
                        && !facts.owns(tgt)
                        && tgt != entry.value
                        && is_exec_target
                        && facts.target_is_plt_stub(tgt);
                    if is_pe_tail_target || is_elf_x86_tail_target || is_elf_plt_tail_target {
                        call_edges.push(FunctionXref {
                            callsite_va: cur_va,
                            target_va: tgt,
                            call_type: CallType::Tail,
                        });
                    } else {
                        // Queue target if new and in region
                        if is_exec_target && seen.insert(tgt) {
                            queue.push_back(tgt);
                        }
                        // Use block start as source for CFG edges
                        edges.push((start_va, tgt, ControlFlowEdgeKind::Branch));
                        merge_dispatch_addresses(
                            &mut dispatch_addresses,
                            tgt,
                            dispatch.export_addresses(),
                        );
                    }
                } else if unconditional {
                    if let Some(tgt) = indirect_memory_target(facts.image, data, &ins, bits) {
                        call_edges.push(FunctionXref {
                            callsite_va: cur_va,
                            target_va: tgt,
                            call_type: CallType::Tail,
                        });
                    } else {
                        // A register-indirect unconditional jump: either a
                        // dispatch whose arms belong in THIS function, or a
                        // transfer we cannot follow. Before this, both produced
                        // the same thing — no edges — so a switch lost every arm
                        // and nothing recorded that the graph was incomplete.
                        match resolve_dispatch(
                            facts.image,
                            data,
                            regions,
                            &dispatch,
                            &ins,
                            facts.tables,
                        ) {
                            Some(crate::analysis::dispatch::Resolution::Table {
                                targets, ..
                            }) => {
                                let mut arms = 0usize;
                                let mut attached = Vec::new();
                                for tgt in targets {
                                    if in_exec_regions(regions, tgt).is_none() {
                                        continue;
                                    }
                                    if seen.insert(tgt) {
                                        queue.push_back(tgt);
                                    }
                                    edges.push((start_va, tgt, ControlFlowEdgeKind::Branch));
                                    merge_dispatch_addresses(
                                        &mut dispatch_addresses,
                                        tgt,
                                        dispatch.export_addresses(),
                                    );
                                    attached.push(tgt);
                                    arms += 1;
                                }
                                stats.resolved_dispatches.push((cur_va, arms));
                                resolved_dispatch_edges.push(TentativeDispatchEdges {
                                    site: cur_va,
                                    block_start: start_va,
                                    attached,
                                    needs_bound_proof: false,
                                });
                            }
                            Some(crate::analysis::dispatch::Resolution::Unresolved(
                                crate::analysis::dispatch::Unresolved::NoBound(table),
                            )) if facts
                                .tables
                                .get(&table)
                                .is_some_and(|targets| (2..=256).contains(&targets.len())) =>
                            {
                                // Some optimized state machines have no explicit
                                // range check: the compiler proves the enum
                                // invariant and emits a bare table dispatch. Use
                                // the scanned targets only as speculative CFG
                                // reachability. A later whole-CFG range analysis
                                // must prove an exact prefix before any edge is
                                // retained.
                                let targets = facts.tables[&table].clone();
                                let mut attached = Vec::new();
                                for tgt in targets {
                                    if in_exec_regions(regions, tgt).is_none() {
                                        continue;
                                    }
                                    if seen.insert(tgt) {
                                        queue.push_back(tgt);
                                    }
                                    edges.push((start_va, tgt, ControlFlowEdgeKind::Branch));
                                    merge_dispatch_addresses(
                                        &mut dispatch_addresses,
                                        tgt,
                                        dispatch.export_addresses(),
                                    );
                                    attached.push(tgt);
                                }
                                stats.resolved_dispatches.push((cur_va, attached.len()));
                                resolved_dispatch_edges.push(TentativeDispatchEdges {
                                    site: cur_va,
                                    block_start: start_va,
                                    attached,
                                    needs_bound_proof: true,
                                });
                            }
                            Some(crate::analysis::dispatch::Resolution::Unresolved(why)) => {
                                stats.unresolved_indirect.push((cur_va, why));
                            }
                            // Not a register-indirect transfer at all.
                            None => {}
                        }
                    }
                }
                if !unconditional {
                    // Fallthrough edge
                    if in_exec_regions(regions, end_va).is_some() && seen.insert(end_va) {
                        queue.push_back(end_va);
                    }
                    edges.push((start_va, end_va, ControlFlowEdgeKind::Fallthrough));
                    merge_dispatch_addresses(
                        &mut dispatch_addresses,
                        end_va,
                        dispatch.export_addresses(),
                    );
                    // An unsigned-above branch to the default arm makes the
                    // FALLTHROUGH the in-range path, so the compare's immediate
                    // is that successor's inclusive index bound — and therefore
                    // the jump table's entry count. Restricted to the unsigned
                    // forms because a switch index is unsigned after the
                    // compiler's rebase; a signed test is a different construct.
                    if guard_bound_reaches_fallthrough(&ins.mnemonic, arch)
                        && dispatch.pending_bound().is_some()
                    {
                        // Carry the register bounds AND the slot bounds: clang -O0
                        // spills the switch value before the check and reloads it
                        // into a different register in the dispatch block.
                        index_bounds.insert(end_va, dispatch.export_bounds());
                    }
                }
                // Block ends after branch
                cur_va = end_va;
                blocks.insert(start_va, (end_va, instrs));
                break 'block;
            } else if is_ret {
                blocks.insert(start_va, (end_va, instrs));
                break 'block;
            }

            cur_va = end_va;
            // Continue linear sweep in this block
        }
        // For blocks that didn't terminate with explicit CF change, ensure end recorded
        blocks.entry(start_va).or_insert((cur_va, instrs));
        block_streams.insert(start_va, stream);
    }

    // Split blocks that overlap a later leader. The linear sweep can run past a
    // block start `t` that only becomes a leader when a *backward* branch to it
    // is decoded later — the classic `-O0` do-while: the body block is entered
    // by fall-through, but its own trailing `jne <body-top>` makes the body top
    // a leader only after the sweep already ran through it. That block `[s, e)`
    // then swallows the real `[t, e)` block and inherits its out-edges (so the
    // setup block ends up with the loop's branch/exit edges, mis-structuring the
    // loop). Truncate `[s, e)` to `[s, t)` with a single fall-through to `t`; the
    // real `[t, e)` block was decoded separately from the queue.
    {
        use std::ops::Bound::Excluded;
        let leaders: std::collections::BTreeSet<u64> = blocks.keys().copied().collect();
        let truncations: Vec<(u64, u64)> = blocks
            .iter()
            .filter_map(|(&s, &(e, _))| {
                // A leader whose first byte does not decode produces an EMPTY
                // block (`e == s`): the sweep breaks before consuming an
                // instruction. It has no interior to search, and asking a
                // BTreeSet for `(Excluded(s), Excluded(s))` is a panic, not an
                // empty range — which crashed the whole decompile of any binary
                // with an undecodable branch target (a jump table read as code,
                // padding, or data).
                if s >= e {
                    return None;
                }
                leaders
                    .range((Excluded(s), Excluded(e)))
                    .next()
                    .map(|&t| (s, t))
            })
            .collect();
        for (s, t) in truncations {
            if let Some(slot) = blocks.get_mut(&s) {
                slot.0 = t;
            }
            // The out-edges recorded for `s` belonged to the swallowed `[t, e)`
            // block; a block ending in a fall-through has exactly one successor.
            edges.retain(|(src, _, _)| *src != s);
            edges.push((s, t, ControlFlowEdgeKind::Fallthrough));
        }
    }

    let thumb =
        arm32_mode.map(|mode| matches!(mode, crate::analysis::arm32_mode::Arm32Mode::Thumb));

    validate_dispatch_edges(
        facts,
        data,
        arch,
        end,
        thumb,
        regions,
        &entry,
        &blocks,
        &mut edges,
        &index_bounds,
        &block_streams,
        &resolved_dispatch_edges,
        &mut stats,
    );

    // Tentative dispatch arms that failed validation must not remain owned by
    // the function merely because they were decoded once. Retain only blocks
    // still reachable from the semantic entry through validated edges.
    let mut reachable = std::collections::BTreeSet::from([entry.value]);
    let mut reachable_queue = VecDeque::from([entry.value]);
    while let Some(source) = reachable_queue.pop_front() {
        for target in edges
            .iter()
            .filter_map(|(edge_source, target, _)| (*edge_source == source).then_some(*target))
        {
            if blocks.contains_key(&target) && reachable.insert(target) {
                reachable_queue.push_back(target);
            }
        }
    }
    blocks.retain(|start, _| reachable.contains(start));
    edges.retain(|(source, target, _)| reachable.contains(source) && reachable.contains(target));
    call_edges.retain(|xref| {
        blocks
            .iter()
            .any(|(start, (end, _))| xref.callsite_va >= *start && xref.callsite_va < *end)
    });
    stats.resolved_dispatches.retain(|(site, _)| {
        blocks
            .iter()
            .any(|(start, (end, _))| *site >= *start && *site < *end)
    });
    stats.unresolved_indirect.retain(|(site, _)| {
        blocks
            .iter()
            .any(|(start, (end, _))| *site >= *start && *site < *end)
    });

    let func = build_function(
        &entry,
        bits,
        arm32_mode,
        &blocks,
        &edges,
        &call_edges,
        &stats,
    )?;

    Some((func, call_edges, stats))
}
