//! Bounded function discovery and CFG construction.
//!
//! This module implements a conservative, deterministic function discovery pass
//! with strict budgets. It seeds from an entrypoint (and can be extended later to
//! exports/PLT/etc.), disassembles within executable ranges only, splits basic
//! blocks on control flow, and emits `Function`s plus a `CallGraph`.

use crate::analysis::jump_table::discover_jump_tables;
use crate::analysis::vtable::discover_vtables;
use crate::core::address::{Address, AddressKind};
use crate::core::address_range::AddressRange;
use crate::core::basic_block::BasicBlock;
use crate::core::binary::{Arch as BArch, Endianness};
use crate::core::call_graph::{CallGraph, CallGraphEdge, CallType};
use crate::core::control_flow_graph::ControlFlowEdgeKind;
use crate::core::disassembler::Disassembler;
use crate::core::function::{Function, FunctionFlags, FunctionKind};
use crate::core::instruction::Instruction;
use crate::debug::dwarf::{extract_dwarf_functions, DwarfFunction};
use crate::disasm::registry;
use crate::flirt::{
    apply_flirt_overrides, discover_flirt_seeds, load_default_library, FlirtLibrary,
};
use crate::triage::heuristics;

use object::{Object, ObjectSegment, SectionKind};
use object::{ObjectSection, ObjectSymbol};

#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    pub max_functions: usize,
    pub max_blocks: usize,
    pub max_instructions: usize,
    pub timeout_ms: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_functions: 64,
            max_blocks: 2048,
            max_instructions: 50_000,
            timeout_ms: 100,
        }
    }
}

#[derive(Debug, Clone)]
struct ExecRegion {
    start: u64, // VA
    end: u64,   // VA exclusive
    _file_off_start: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoverySeedKind {
    Trusted,
    BodyOverlapGated,
    Xref,
}

impl DiscoverySeedKind {
    fn is_body_overlap_gated(self) -> bool {
        matches!(self, Self::BodyOverlapGated | Self::Xref)
    }
}

#[derive(Debug, Clone)]
struct FunctionCallEdge {
    callsite_va: u64,
    target_va: Option<u64>,
    target_name: Option<String>,
    call_type: CallType,
}

#[derive(Debug, Clone)]
struct RecordedCallEdge {
    caller_entry_va: u64,
    callsite_va: u64,
    target_va: Option<u64>,
    target_name: Option<String>,
    call_type: CallType,
}

fn parse_exec_regions(data: &[u8]) -> (Vec<ExecRegion>, BArch, Endianness, Option<Address>) {
    let mut regions = Vec::new();
    let mut arch = BArch::Unknown;
    let mut endian = Endianness::Little;
    let mut entry: Option<Address> = None;
    if let Ok(obj) = object::read::File::parse(data) {
        arch = match obj.architecture() {
            object::Architecture::I386 => BArch::X86,
            object::Architecture::X86_64 => BArch::X86_64,
            object::Architecture::Arm => BArch::ARM,
            object::Architecture::Aarch64 => BArch::AArch64,
            object::Architecture::Mips => BArch::MIPS,
            object::Architecture::Mips64 => BArch::MIPS64,
            object::Architecture::PowerPc => BArch::PPC,
            object::Architecture::PowerPc64 => BArch::PPC64,
            object::Architecture::Riscv32 => BArch::RISCV,
            object::Architecture::Riscv64 => BArch::RISCV64,
            _ => BArch::Unknown,
        };
        // Default endian by architecture family; object::File doesn't expose global endianness
        endian = match arch {
            BArch::PPC | BArch::PPC64 => Endianness::Big,
            _ => Endianness::Little,
        };

        let entry_va = obj.entry();
        if entry_va != 0 {
            let bits = if arch.is_64_bit() { 64 } else { 32 };
            if let Ok(a) = Address::new(AddressKind::VA, entry_va, bits, None, None) {
                entry = Some(a);
            }
        }

        // Prefer segments with execute permissions
        for seg in obj.segments() {
            let addr = seg.address();
            let size = seg.size();
            if size == 0 {
                continue;
            }
            let file = seg.file_range().0;
            // Heuristic: treat segments mapped into memory as candidate code; object doesn't expose perms uniformly across formats here
            // We will filter by sections if possible below.
            regions.push(ExecRegion {
                start: addr,
                end: addr.saturating_add(size),
                _file_off_start: file,
            });
        }

        // Refine by every section whose object-classified kind is Text.
        // Object's PE backend reads IMAGE_SCN_MEM_EXECUTE to set kind, so
        // this catches Win64 driver / kernel layouts where many code
        // sections exist with non-".text" names (PAGE, PAGELK, KVASCODE,
        // INIT, RETPOL, POOLCODE, ...). Previously we filtered with a
        // ".text" / "code" substring heuristic that dropped most of
        // ntoskrnl's executable bytes -- the dominant cause of the
        // 49 % recall observed on the ntoskrnl fixture in the iter 14
        // sweep.
        let mut refined = Vec::new();
        for sec in obj.sections() {
            let size = sec.size();
            if size == 0 {
                continue;
            }
            if sec.kind() != SectionKind::Text {
                // Fall back to the legacy name heuristic for formats
                // where object can't classify (e.g. some odd COFFs).
                let name = sec.name().unwrap_or("").to_ascii_lowercase();
                if !(name.contains(".text") || name.contains("code") || name == "text") {
                    continue;
                }
            }
            let addr = sec.address();
            if let Some((foff, _)) = sec.file_range() {
                refined.push(ExecRegion {
                    start: addr,
                    end: addr.saturating_add(size),
                    _file_off_start: foff,
                });
            }
        }
        if !refined.is_empty() {
            regions = refined;
        }
    }

    if regions.is_empty() {
        // As a last resort, decode from start of file as VA=0 range
        let (e, _conf) = heuristics::endianness::guess(data);
        endian = e;
        let (arch_guess, _ac) = heuristics::architecture::infer(data)
            .first()
            .cloned()
            .unwrap_or((BArch::Unknown, 0.0));
        arch = arch_guess;
        regions.push(ExecRegion {
            start: 0,
            end: data.len() as u64,
            _file_off_start: 0,
        });
        let bits = 64;
        entry = Address::new(AddressKind::VA, 0, bits, None, None).ok();
    }
    (regions, arch, endian, entry)
}

fn in_exec_regions(regions: &[ExecRegion], va: u64) -> Option<&ExecRegion> {
    regions.iter().find(|r| va >= r.start && va < r.end)
}

fn classify_ctrl_flow(mnemonic: &str, arch: BArch) -> (bool, bool, bool) {
    let m = mnemonic.to_ascii_lowercase();
    // returns (is_branch, is_call, is_ret)
    match arch {
        BArch::X86 | BArch::X86_64 => {
            if m == "ret" || m == "retq" || m == "int3" || m == "ud2" || m == "hlt" {
                return (false, false, true);
            }
            if m == "call" {
                return (false, true, false);
            }
            if m.starts_with('j') {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::ARM | BArch::AArch64 => {
            if m == "ret" {
                return (false, false, true);
            }
            if m == "bl" || m == "blr" {
                return (false, true, false);
            }
            if m == "b"
                || m.starts_with("b.")
                || m == "cbz"
                || m == "cbnz"
                || m == "tbz"
                || m == "tbnz"
            {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::MIPS | BArch::MIPS64 => {
            if m == "jal" {
                return (false, true, false);
            }
            if m == "jr" {
                return (true, false, false);
            } // jr ra acts like return often; treat as branch
            if m == "j" || m.starts_with("b") {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::RISCV | BArch::RISCV64 => {
            if m == "jal" {
                return (false, true, false);
            }
            if m == "jalr" {
                return (false, true, false);
            } // often indirect call
            if m.starts_with('b') {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::PPC | BArch::PPC64 => {
            if m == "bl" {
                return (false, true, false);
            }
            if m.starts_with('b') {
                return (true, false, false);
            }
            (false, false, false)
        }
        _ => (false, false, false),
    }
}

fn immediate_target(ins: &Instruction) -> Option<u64> {
    // Heuristic: use first immediate operand if present (our adapters parse simple immediates)
    ins.operands
        .iter()
        .find_map(|op| op.immediate)
        .map(|v| v as u64)
}

fn iat_memory_call_target(ins: &Instruction, arch: BArch) -> Option<u64> {
    if !matches!(arch, BArch::X86 | BArch::X86_64) {
        return None;
    }

    ins.operands.iter().find_map(|op| {
        if !op.is_memory() || op.index.is_some() {
            return None;
        }
        let disp = op.displacement?;
        if disp < 0 {
            return None;
        }
        let base = op.base.as_deref().unwrap_or("").to_ascii_lowercase();
        match arch {
            BArch::X86_64 if base.is_empty() || base == "rip" => Some(disp as u64),
            BArch::X86 if base.is_empty() => Some(disp as u64),
            _ => None,
        }
    })
}

fn add_callgraph_edge_dedup(
    cg: &mut CallGraph,
    caller: &str,
    callee: &str,
    call_type: CallType,
    callsite: Option<Address>,
) {
    cg.add_node(caller.to_string());
    cg.add_node(callee.to_string());

    if let Some(existing) = cg
        .edges
        .iter_mut()
        .find(|edge| edge.caller == caller && edge.callee == callee && edge.call_type == call_type)
    {
        if let Some(site) = callsite {
            existing.add_call_site(site);
        }
        return;
    }

    let mut edge = CallGraphEdge::new(caller.to_string(), callee.to_string(), call_type);
    if let Some(site) = callsite {
        edge.add_call_site(site);
    }
    cg.add_edge(edge);
}

fn function_owns_callsite(func: &Function, callsite_va: u64) -> bool {
    if !func.basic_blocks.is_empty() {
        return func.basic_blocks.iter().any(|bb| {
            let start = bb.start_address.value;
            let end = bb.end_address.value;
            callsite_va >= start && callsite_va < end
        });
    }

    func.all_ranges().into_iter().any(|range| {
        let start = range.start.value;
        let end = start.saturating_add(range.size);
        callsite_va >= start && callsite_va < end
    })
}

fn callsite_owner_name(
    functions: &[Function],
    fallback_entry_va: u64,
    callsite_va: u64,
) -> Option<String> {
    functions
        .iter()
        .filter(|func| function_owns_callsite(func, callsite_va))
        // Overlap can happen when recursive discovery finds a mid-function
        // label. Prefer the innermost/highest entry that owns the callsite so
        // one physical instruction is attributed to one final function.
        .max_by_key(|func| func.entry_point.value)
        .or_else(|| {
            functions
                .iter()
                .find(|func| func.entry_point.value == fallback_entry_va)
        })
        .map(|func| func.name.clone())
}

/// Discover a single function starting at `entry` within executable regions.
fn discover_function(
    data: &[u8],
    arch: BArch,
    end: Endianness,
    entry: Address,
    regions: &[ExecRegion],
    budgets: &Budgets,
    pe_iat_name_by_va: &std::collections::HashMap<u64, String>,
    known_function_starts: &std::collections::HashSet<u64>,
) -> Option<(Function, Vec<FunctionCallEdge>, Vec<u64>)> {
    let darch: crate::core::disassembler::Architecture = arch.into();
    let backend = registry::for_arch(darch, end)?;
    let bits = darch.address_bits();
    let t0 = std::time::Instant::now();

    // BFS over basic block starts
    use std::collections::{HashMap, VecDeque};
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut blocks: HashMap<u64, (u64, u32)> = HashMap::new(); // start_va -> (end_va, instr_count)
    let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = Vec::new();
    let mut call_edges: Vec<FunctionCallEdge> = Vec::new();
    // Tail-call jmp targets we detected and intentionally did NOT queue
    // into this function's body. The orchestrator turns these into new
    // discovery seeds so the callee gets its own Function.
    let mut tail_call_targets: Vec<u64> = Vec::new();

    if let Some(r) = in_exec_regions(regions, entry.value) {
        let _ = r;
    } else {
        return None;
    }
    queue.push_back(entry.value);
    seen.insert(entry.value);

    let mut decoded_instructions = 0usize;

    while let Some(start_va) = queue.pop_front() {
        if blocks.len() >= budgets.max_blocks {
            break;
        }
        if t0.elapsed().as_millis() as u64 > budgets.timeout_ms {
            break;
        }
        // Decode sequentially until a terminating control flow or budget hit
        let mut cur_va = start_va;
        let mut instrs = 0u32;
        'block: loop {
            if decoded_instructions >= budgets.max_instructions {
                break 'block;
            }
            if t0.elapsed().as_millis() as u64 > budgets.timeout_ms {
                break 'block;
            }
            // Map VA -> file offset using shared helper for robustness
            let fo = match crate::analysis::entry::va_to_file_offset(data, cur_va) {
                Some(v) => v,
                None => break 'block,
            };
            if fo >= data.len() {
                break 'block;
            }
            let slice = &data[fo..];
            let addr = Address::new(AddressKind::VA, cur_va, bits, None, None).ok()?;
            let ins = match backend.disassemble_instruction(&addr, slice) {
                Ok(i) => i,
                Err(_) => break 'block,
            };
            decoded_instructions += 1;
            instrs = instrs.saturating_add(1);
            let end_va = cur_va.saturating_add(ins.length as u64);
            let (is_branch, is_call, is_ret) = classify_ctrl_flow(&ins.mnemonic, arch);
            if is_call {
                // Fallthrough continues; preserve the exact instruction VA
                // so downstream xref tables can report callsites, not just
                // caller-function granularity.
                if let Some(tgt) = immediate_target(&ins) {
                    call_edges.push(FunctionCallEdge {
                        callsite_va: cur_va,
                        target_va: Some(tgt),
                        target_name: None,
                        call_type: CallType::Direct,
                    });
                } else if let Some(slot_va) = iat_memory_call_target(&ins, arch) {
                    if let Some(name) = pe_iat_name_by_va.get(&slot_va) {
                        call_edges.push(FunctionCallEdge {
                            callsite_va: cur_va,
                            target_va: Some(slot_va),
                            target_name: Some(name.clone()),
                            call_type: CallType::Indirect,
                        });
                    }
                }
                // continue to fallthrough
            } else if is_branch {
                // Determine conditional vs unconditional by mnemonic content
                let unconditional = ins.mnemonic.eq_ignore_ascii_case("jmp")
                    || ins.mnemonic.eq_ignore_ascii_case("b");
                if let Some(tgt) = immediate_target(&ins) {
                    // Tail-call detection. An unconditional jmp to a target
                    // that is ALREADY a known function start (PDB symbol,
                    // export, prior seed, prior thunk-emitted target, etc.)
                    // is a tail call, NOT a same-function jump. Without this
                    // gate, a 5-byte `jmp impl` thunk absorbs the callee's
                    // entire body — Ghidra cross-validation on dnsapi.dll
                    // showed glaurung over-merging 6.4% of functions, max
                    // 97,907x (e.g. DnsConnectionFreeProxyInfo: Ghidra
                    // bounded as 5 bytes, glaurung as 489,534).
                    //
                    // Also: an unconditional jmp out of the function's
                    // ENTRY block (no preceding non-trivial code) IS a
                    // thunk by definition. Treat the target as a tail
                    // call regardless of whether it's known yet.
                    let is_thunk_pattern = unconditional
                        && start_va == entry.value
                        && instrs == 1;
                    // Stronger heuristic: an unconditional jmp whose target
                    // disassembles to a recognised function-prologue pattern
                    // (push rbp / sub rsp / mov rax,rsp / jmp [iat] / etc.)
                    // is almost certainly a tail call, even when the current
                    // function has run several instructions of epilogue-
                    // style cleanup before the jmp. This catches the cases
                    // the thunk_pattern test misses (e.g. dnsapi's
                    // Dns_AllocateRecord, IsDnsRecordTypeSupported — 22-32
                    // byte functions that end with `jmp helper`).
                    let target_looks_like_fn_start =
                        pe_xref_seed_looks_like_function_start(data, tgt);
                    let target_is_known_fn =
                        known_function_starts.contains(&tgt);
                    // Tail-call gate. For UNCONDITIONAL jmp it fires
                    // on the standard set of triggers (thunk, known
                    // function start, prologue-pattern target).
                    //
                    // For CONDITIONAL branches (jne to a cold-path
                    // out-of-line handler), MSVC's hot/cold function
                    // splitting puts the cold half at a separate VA
                    // that's already a function in its own right. If
                    // the target is in our `known` set, treat the
                    // branch as a boundary. We additionally treat a
                    // FAR conditional branch (target >= 64KB away)
                    // with a prologue-looking destination as a hot-
                    // cold split — those are essentially never real
                    // intra-function jumps. This catches dnsapi's
                    // remaining outlier `Dns_RecordListAppend` which
                    // jne's ~666KB to its cold-path slow handler.
                    let target_is_far_prologue = !unconditional
                        && target_looks_like_fn_start
                        && tgt.abs_diff(start_va) >= 0x10000;
                    let is_tail_call = if unconditional {
                        target_is_known_fn
                            || is_thunk_pattern
                            || target_looks_like_fn_start
                    } else {
                        target_is_known_fn || target_is_far_prologue
                    };
                    if is_tail_call {
                        // Record the target as a tail-call edge but do NOT
                        // queue it into this function's body. Surface it as
                        // a new seed so the orchestrator can discover it
                        // as its own function.
                        tail_call_targets.push(tgt);
                        call_edges.push(FunctionCallEdge {
                            callsite_va: cur_va,
                            target_va: Some(tgt),
                            target_name: None,
                            call_type: CallType::Direct,
                        });
                    } else {
                        // Queue target if new and in region
                        if in_exec_regions(regions, tgt).is_some() && seen.insert(tgt) {
                            queue.push_back(tgt);
                        }
                        // Use block start as source for CFG edges
                        edges.push((start_va, tgt, ControlFlowEdgeKind::Branch));
                    }
                }
                if !unconditional {
                    // Fallthrough edge
                    if in_exec_regions(regions, end_va).is_some() && seen.insert(end_va) {
                        queue.push_back(end_va);
                    }
                    edges.push((start_va, end_va, ControlFlowEdgeKind::Fallthrough));
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
    }

    // Build Function object
    let fname = format!("sub_{:x}", entry.value);
    let mut func = Function::new(fname, entry.clone(), FunctionKind::Normal).ok()?;

    // Build BasicBlocks with successor/predecessor IDs
    let mut bb_ids: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    for (&start, &(end, instrs)) in &blocks {
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
    for (src_va, dst_va, kind) in &edges {
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
    // Patch blocks with relationships (best-effort): replace blocks with enriched copies
    for bb in &mut func.basic_blocks {
        let id = bb.id.clone();
        if let Some(s) = succs.get(&id) {
            bb.successor_ids = s.clone();
        }
        if let Some(p) = preds.get(&id) {
            bb.predecessor_ids = p.clone();
        }
        bb.relationships_known = true;
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

    Some((func, call_edges, tail_call_targets))
}

/// Heuristic: does `data[file_off..]` look like the start of a real
/// function?
///
/// Used to gate xref-target promotion in the recursive worklist.
/// Trusted seeds (symbol table, .pdata, FLIRT, vtable, jump-table,
/// entrypoint) MUST NOT be subjected to this gate -- it's only for
/// the addresses we follow via direct-call/jump xrefs, which can
/// land in the middle of an existing function's body (mid-fn
/// continuation labels) or even mid-instruction.
///
/// "Looks like a fn start" rule:
///
/// 1. **Strong yes**: the byte just before `file_off` is a function-
///    boundary marker emitted by the MSVC compiler:
///    - `0xcc` (INT3 padding, the dominant case on Win64)
///    - `0xc3` (RET; previous function ended)
///    - `0x90` (single-byte NOP padding)
///    - `0x66 0x90` (2-byte NOP via `xchg ax, ax`)
///    - `0x0f 0x1f ..` (3+ byte NOP families)
/// 2. **Otherwise**: byte 0 must match a recognised x86-64 prologue
///    pattern (REX-prefix push, parameter spill, frame setup, IAT
///    thunk, RET stub, ...).
///
/// Returns `true` if either signal fires, `false` if neither does.
/// Empirical validation on ntoskrnl's 31,729 g-only seeds (asb
/// iter 14 sweep): ~77 % have neither signal and are rejected as
/// likely mid-instruction xref landings.
#[allow(dead_code)]
fn looks_like_fn_start(data: &[u8], file_off: usize) -> bool {
    if file_off == 0 || file_off >= data.len() {
        return false;
    }
    let prev = data[file_off - 1];
    if prev == 0xcc || prev == 0xc3 || prev == 0x90 {
        return true;
    }
    // 2-byte NOP via `xchg ax, ax`
    if file_off >= 2 && data[file_off - 2] == 0x66 && prev == 0x90 {
        return true;
    }
    // Multi-byte NOP encodings (0f 1f .. /0 series)
    if file_off >= 3 && data[file_off - 3] == 0x0f && data[file_off - 2] == 0x1f {
        return true;
    }
    if file_off >= 4
        && data[file_off - 4] == 0x0f
        && data[file_off - 3] == 0x1f
        && data[file_off - 2] == 0x40
    {
        return true;
    }
    let head_end = std::cmp::min(file_off + 8, data.len());
    let head = &data[file_off..head_end];
    if head.is_empty() {
        return false;
    }
    // Recognised x86-64 function prologue patterns.
    match head {
        // mov [rsp+disp8], rXX (REX.W parameter spill: 48 89 X 24 ..)
        [0x48, 0x89, _, 0x24, ..] => true,
        // REX-prefixed push rbx/rbp/rsi/rdi (40 53/55/56/57)
        [0x40, 0x53 | 0x55 | 0x56 | 0x57, ..] => true,
        // push r12-r15 (41 54/55/56/57)
        [0x41, 0x54 | 0x55 | 0x56 | 0x57, ..] => true,
        // sub rsp, imm8 / imm32
        [0x48, 0x83, 0xec, ..] => true,
        [0x48, 0x81, 0xec, ..] => true,
        // mov rax, rsp (SEH frame setup)
        [0x48, 0x8b, 0xc4, ..] => true,
        // jmp rel32 (tail-call thunk)
        [0xe9, ..] => true,
        // jmp [rip+rel32] (IAT thunk)
        [0xff, 0x25, ..] => true,
        // mov eax, imm32 (HRESULT stub / syscall stub)
        [0xb8, ..] => true,
        // xor eax, eax; ret (tiny RET stub)
        [0x33, 0xc0, 0xc3, ..] => true,
        // mov rax, gs:[imm32] (TEB-access prologue)
        [0x65, 0x48, 0x8b, 0x04, 0x25, ..] => true,
        _ => false,
    }
}

fn va_in_function_body(func: &Function, va: u64) -> bool {
    if va == func.entry_point.value {
        return false;
    }
    if !func.basic_blocks.is_empty() {
        return func.basic_blocks.iter().any(|bb| {
            let start = bb.start_address.value;
            let end = bb.end_address.value;
            va > start && va < end
        });
    }
    for range in func.all_ranges() {
        let start = range.start.value;
        let end = start.saturating_add(range.size);
        if va >= start && va < end {
            return true;
        }
    }
    false
}

fn va_in_discovered_body(functions: &[Function], current: Option<&Function>, va: u64) -> bool {
    if let Some(f) = current {
        if va_in_function_body(f, va) {
            return true;
        }
    }
    functions.iter().any(|f| va_in_function_body(f, va))
}

fn pe_xref_seed_looks_like_function_start(data: &[u8], va: u64) -> bool {
    match pe_va_to_file_off(data, va) {
        Some(file_off) => looks_like_fn_start(data, file_off),
        None => false,
    }
}

fn unwind_info_has_chain_info(data: &[u8], file_off: usize) -> bool {
    match data.get(file_off) {
        Some(first) => {
            let flags = first >> 3;
            flags & 0x04 != 0
        }
        None => false,
    }
}

/// Resolve a VA to a file offset by walking the section headers
/// directly. Used by the prologue-sanity gate during xref-target
/// promotion -- the existing `pe::sections::SectionTable` is built
/// per-PeParser instance; this helper avoids constructing one
/// inside the cfg worklist (where we already have raw `data` and
/// the `ExecRegion` list, but not the full section table).
#[allow(dead_code)]
fn pe_va_to_file_off(data: &[u8], va: u64) -> Option<usize> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    let n_sections = u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().ok()?) as usize;
    let opt_off = coff_off + 20;
    let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().ok()?);
    let image_base = if magic == 0x20B {
        let b = data.get(opt_off + 24..opt_off + 32)?;
        let lo = u32::from_le_bytes(b[..4].try_into().ok()?) as u64;
        let hi = u32::from_le_bytes(b[4..].try_into().ok()?) as u64;
        (hi << 32) | lo
    } else if magic == 0x10B {
        u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().ok()?) as u64
    } else {
        return None;
    };
    if va < image_base {
        return None;
    }
    let rva = (va - image_base) as usize;
    let sec_off = opt_off + opt_size;
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_sz = u32::from_le_bytes(data[s + 8..s + 12].try_into().ok()?) as usize;
        let virt_addr = u32::from_le_bytes(data[s + 12..s + 16].try_into().ok()?) as usize;
        let raw_sz = u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?) as usize;
        let raw_ptr = u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?) as usize;
        let span = std::cmp::max(virt_sz, raw_sz);
        if rva >= virt_addr && rva < virt_addr + span {
            return Some(raw_ptr + (rva - virt_addr));
        }
    }
    None
}

/// Read every `RUNTIME_FUNCTION::BeginAddress` from the Win64 PE
/// exception directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`, index 3).
///
/// On x86-64 Windows the calling convention mandates an unwind record
/// in `.pdata` for every non-leaf function (and most leaf functions
/// emit one too). The exception directory is therefore a near-complete
/// function index, free for the asking, and the single highest-leverage
/// source of function starts on stripped Windows PE.
///
/// Returns an empty vector for non-PE32+ files, files missing the
/// exception directory, or 32-bit PEs (which use SEH on the stack and
/// don't have an equivalent table). ARM64 PE has a different unwind
/// format we don't yet decode.
fn parse_pdata_function_starts(data: &[u8], regions: &[ExecRegion], arch: BArch) -> Vec<u64> {
    if !arch.is_64_bit() {
        return Vec::new();
    }
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let read_u16 = |off: usize| -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        data.get(off..off + 8).map(|b| {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
            (hi << 32) | lo
        })
    };
    let e_lfanew = match read_u32(0x3c) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let coff_off = e_lfanew + 4;
    let n_sections = match read_u16(coff_off + 2) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let opt_size = match read_u16(coff_off + 16) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let opt_off = coff_off + 20;
    if read_u16(opt_off) != Some(0x20B) {
        // not PE32+ (Win64)
        return Vec::new();
    }
    let image_base = match read_u64(opt_off + 24) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let num_dirs = match read_u32(opt_off + 108) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if num_dirs < 4 {
        return Vec::new();
    }
    let dd_off = opt_off + 112;
    let exc_rva = match read_u32(dd_off + 3 * 8) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let exc_size = match read_u32(dd_off + 3 * 8 + 4) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if exc_rva == 0 || exc_size == 0 {
        return Vec::new();
    }
    // Resolve RVAs to file offsets via the section table.
    let sec_off = opt_off + opt_size;
    let mut sections_view: Vec<(usize, usize, usize)> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_sz = read_u32(s + 8).unwrap_or(0) as usize;
        let virt_addr = read_u32(s + 12).unwrap_or(0) as usize;
        let raw_sz = read_u32(s + 16).unwrap_or(0) as usize;
        let raw_ptr = read_u32(s + 20).unwrap_or(0) as usize;
        let span = std::cmp::max(virt_sz, raw_sz);
        sections_view.push((virt_addr, span, raw_ptr));
    }
    let rva_to_off = |rva: usize| -> Option<usize> {
        for (va, span, rp) in &sections_view {
            if rva >= *va && rva < *va + *span {
                return Some(rp + (rva - va));
            }
        }
        None
    };
    let exc_file_off = match rva_to_off(exc_rva) {
        Some(v) => v,
        None => return Vec::new(),
    };
    // Walk RUNTIME_FUNCTION entries (12 bytes each on x64:
    //   u32 BeginAddress, u32 EndAddress, u32 UnwindInfoAddress).
    let entry_size = 12usize;
    let n_entries = exc_size / entry_size;
    let cap = 2_000_000usize.min(n_entries);
    let mut starts = Vec::with_capacity(cap);
    for i in 0..cap {
        let off = exc_file_off + i * entry_size;
        if off + 4 > data.len() {
            break;
        }
        let begin_rva = match read_u32(off) {
            Some(v) => v,
            None => break,
        };
        if begin_rva == 0 {
            continue;
        }
        let unwind_rva = match read_u32(off + 8) {
            Some(v) => v as usize,
            None => break,
        };
        if let Some(unwind_off) = rva_to_off(unwind_rva) {
            if unwind_info_has_chain_info(data, unwind_off) {
                continue;
            }
        }
        let va = image_base + begin_rva as u64;
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        }
    }
    starts
}

/// Read PE TLS callback VAs as trusted loader-dispatched function starts.
///
/// TLS callbacks execute before the ordinary image entrypoint and often have
/// no static call xref, so they need to be treated like metadata-provided
/// entrypoints instead of recursive-discovery byproducts.
fn parse_pe_tls_callback_starts(data: &[u8], regions: &[ExecRegion]) -> Vec<u64> {
    let parser = match crate::formats::pe::PeParser::new(data) {
        Ok(parser) => parser,
        Err(_) => return Vec::new(),
    };
    let tls = match parser.tls() {
        Ok(tls) => tls,
        Err(_) => return Vec::new(),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut starts = Vec::new();
    for &va in &tls.callbacks {
        if va == 0 || !seen.insert(va) {
            continue;
        }
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        }
    }
    starts
}

/// Read PE Control Flow Guard function-id table entries as function starts.
///
/// GuardCFFunctionTable is a linker/loader-maintained array of valid indirect
/// call targets. On modern Windows DLLs it is often a large function-start
/// index that complements `.pdata`: it captures address-taken functions that
/// may not be reachable from direct calls during bounded recursive discovery.
fn parse_pe_guard_cf_function_starts(data: &[u8], regions: &[ExecRegion]) -> Vec<u64> {
    const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF000_0000;
    const MAX_GUARD_CF_FUNCTIONS: usize = 2_000_000;

    let parser = match crate::formats::pe::PeParser::new(data) {
        Ok(parser) => parser,
        Err(_) => return Vec::new(),
    };
    let load_config =
        match parser.data_directory(crate::formats::pe::types::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
            Ok(dir) => dir,
            Err(_) => return Vec::new(),
        };
    if load_config.virtual_address == 0 || load_config.size == 0 {
        return Vec::new();
    }
    let load_config_off = match parser.rva_to_offset(load_config.virtual_address) {
        Some(off) => off,
        None => return Vec::new(),
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        data.get(off..off + 8).map(|b| {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
            (hi << 32) | lo
        })
    };

    // IMAGE_LOAD_CONFIG_DIRECTORY64:
    //   GuardCFFunctionTable @ +0x80, Count @ +0x88, GuardFlags @ +0x90.
    // IMAGE_LOAD_CONFIG_DIRECTORY32:
    //   GuardCFFunctionTable @ +0x50, Count @ +0x54, GuardFlags @ +0x58.
    let (table_va, count, guard_flags) = if parser.is_64bit() {
        if load_config_off + 0x94 > data.len() {
            return Vec::new();
        }
        let table_va = match read_u64(load_config_off + 0x80) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let count = match read_u64(load_config_off + 0x88) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let flags = match read_u32(load_config_off + 0x90) {
            Some(v) => v,
            None => return Vec::new(),
        };
        (table_va, count, flags)
    } else {
        if load_config_off + 0x5c > data.len() {
            return Vec::new();
        }
        let table_va = match read_u32(load_config_off + 0x50) {
            Some(v) => v as u64,
            None => return Vec::new(),
        };
        let count = match read_u32(load_config_off + 0x54) {
            Some(v) => v as u64,
            None => return Vec::new(),
        };
        let flags = match read_u32(load_config_off + 0x58) {
            Some(v) => v,
            None => return Vec::new(),
        };
        (table_va, count, flags)
    };

    if table_va == 0 || count == 0 {
        return Vec::new();
    }
    let image_base = parser.image_base();
    let table_rva = match table_va.checked_sub(image_base) {
        Some(rva) if rva <= u32::MAX as u64 => rva as u32,
        _ => return Vec::new(),
    };
    let table_off = match parser.rva_to_offset(table_rva) {
        Some(off) => off,
        None => return Vec::new(),
    };
    // The high nibble encodes additional per-entry flag bytes. A value of
    // 1 means 5-byte entries: u32 target RVA + u8 flags.
    let extra_entry_bytes =
        ((guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> 28) as usize;
    let stride = 4usize.saturating_add(extra_entry_bytes).max(4);
    let cap = std::cmp::min(count as usize, MAX_GUARD_CF_FUNCTIONS);
    let mut seen = std::collections::BTreeSet::new();
    let mut starts = Vec::new();
    for i in 0..cap {
        let off = table_off.saturating_add(i.saturating_mul(stride));
        let rva = match read_u32(off) {
            Some(v) if v != 0 => v,
            _ => continue,
        };
        let va = image_base.saturating_add(rva as u64);
        if !seen.insert(va) {
            continue;
        }
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        }
    }
    starts
}

/// Read every export-table function VA from a PE.
///
/// The `object` crate's `dynamic_symbols()` returns nothing for PE
/// targets even when the binary has an `IMAGE_DIRECTORY_ENTRY_EXPORT`
/// table (verified empirically on kernel32.dll: 1671 exports, 0
/// returned by `obj.dynamic_symbols()`). We walk the directory
/// directly to keep export-driven fn discovery working.
///
/// Without this seed source, kernel32.dll (~1700 exports, most of
/// them tiny `jmp [iat]` thunks not covered by `.pdata`) yields
/// only 58 % recall on the iter-14 comparison sweep. With it, every
/// `IMAGE_EXPORT_DIRECTORY::AddressOfFunctions[i]` lands as a seed.
///
/// Returns an empty vector for non-PE files or PEs with no export
/// directory.
fn parse_pe_export_function_starts(data: &[u8], regions: &[ExecRegion], arch: BArch) -> Vec<u64> {
    if !arch.is_64_bit() && arch != BArch::X86 {
        return Vec::new();
    }
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let read_u16 = |off: usize| -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        data.get(off..off + 8).map(|b| {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
            (hi << 32) | lo
        })
    };
    let e_lfanew = match read_u32(0x3c) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let coff_off = e_lfanew + 4;
    let n_sections = match read_u16(coff_off + 2) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let opt_size = match read_u16(coff_off + 16) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let opt_off = coff_off + 20;
    let magic = match read_u16(opt_off) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let (image_base, dd_off) = if magic == 0x20B {
        let base = match read_u64(opt_off + 24) {
            Some(v) => v,
            None => return Vec::new(),
        };
        (base, opt_off + 112)
    } else if magic == 0x10B {
        let base = match read_u32(opt_off + 28) {
            Some(v) => v as u64,
            None => return Vec::new(),
        };
        (base, opt_off + 96)
    } else {
        return Vec::new();
    };
    // IMAGE_DIRECTORY_ENTRY_EXPORT = index 0
    let exp_rva = match read_u32(dd_off) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let exp_size = match read_u32(dd_off + 4) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if exp_rva == 0 || exp_size == 0 {
        return Vec::new();
    }
    // Resolve via section table.
    let sec_off = opt_off + opt_size;
    let mut sections_view: Vec<(usize, usize, usize, usize)> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_sz = read_u32(s + 8).unwrap_or(0) as usize;
        let virt_addr = read_u32(s + 12).unwrap_or(0) as usize;
        let raw_sz = read_u32(s + 16).unwrap_or(0) as usize;
        let raw_ptr = read_u32(s + 20).unwrap_or(0) as usize;
        sections_view.push((virt_addr, std::cmp::max(virt_sz, raw_sz), raw_ptr, raw_sz));
    }
    let rva_to_off = |rva: usize| -> Option<usize> {
        for (va, span, rp, _rs) in &sections_view {
            if rva >= *va && rva < *va + *span {
                return Some(rp + (rva - va));
            }
        }
        None
    };
    let exp_off = match rva_to_off(exp_rva) {
        Some(v) => v,
        None => return Vec::new(),
    };
    // IMAGE_EXPORT_DIRECTORY layout:
    //   u32 Characteristics
    //   u32 TimeDateStamp
    //   u16 MajorVersion, u16 MinorVersion
    //   u32 Name (RVA)
    //   u32 Base
    //   u32 NumberOfFunctions
    //   u32 NumberOfNames
    //   u32 AddressOfFunctions (RVA -> array of u32 RVAs)
    //   u32 AddressOfNames     (RVA -> ...)
    //   u32 AddressOfNameOrdinals (RVA -> ...)
    if exp_off + 40 > data.len() {
        return Vec::new();
    }
    let n_funcs = match read_u32(exp_off + 0x14) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let addr_of_funcs_rva = match read_u32(exp_off + 0x1c) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if n_funcs == 0 || addr_of_funcs_rva == 0 {
        return Vec::new();
    }
    let addrs_off = match rva_to_off(addr_of_funcs_rva) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let cap = std::cmp::min(n_funcs, 1_000_000);
    let mut starts = Vec::with_capacity(cap);
    for i in 0..cap {
        let off = addrs_off + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let rva = read_u32(off).unwrap_or(0) as u64;
        if rva == 0 {
            continue;
        }
        let va = image_base + rva;
        // Skip forwarder exports: their "address" actually points
        // inside the export directory itself (an ASCII string like
        // "NTDLL.RtlAddAccessAllowedAce"), NOT a code byte. The
        // forwarder RVA always falls inside the export directory
        // span [exp_rva, exp_rva + exp_size).
        let rva_us = rva as usize;
        if rva_us >= exp_rva && rva_us < exp_rva + exp_size {
            continue;
        }
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        }
    }
    starts
}

fn parse_pe_export_function_names(
    data: &[u8],
    regions: &[ExecRegion],
) -> std::collections::HashMap<u64, String> {
    let mut out = std::collections::HashMap::new();
    let parser = match crate::formats::pe::PeParser::new(data) {
        Ok(parser) => parser,
        Err(_) => return out,
    };
    let image_base = parser.image_base();
    let exports = match parser.exports() {
        Ok(exports) => exports,
        Err(_) => return out,
    };
    for export in &exports.exports {
        if export.forwarder.is_some() || export.rva == 0 {
            continue;
        }
        let Some(name) = export.name else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let va = image_base.saturating_add(u64::from(export.rva));
        if in_exec_regions(regions, va).is_some() {
            out.entry(va).or_insert_with(|| name.to_string());
        }
    }
    out
}

fn parse_function_seeds(data: &[u8], regions: &[ExecRegion], arch: BArch) -> Vec<Address> {
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let mut seeds: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    if let Ok(obj) = object::read::File::parse(data) {
        // Symbols defined in executable regions
        for sym in obj.symbols() {
            if sym.is_definition() {
                let addr = sym.address();
                if addr == 0 {
                    continue;
                }
                if in_exec_regions(regions, addr).is_some() {
                    seeds.insert(addr);
                }
            }
        }
        // Also consider dynamic symbols (ELF .plt entries often appear here)
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                let addr = sym.address();
                if addr == 0 {
                    continue;
                }
                if in_exec_regions(regions, addr).is_some() {
                    seeds.insert(addr);
                }
            }
        }
    }
    seeds
        .into_iter()
        .filter_map(|va| Address::new(AddressKind::VA, va, bits, None, None).ok())
        .collect()
}

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
fn apply_dwarf_overrides(data: &[u8], functions: &mut [Function]) -> usize {
    let entries = extract_dwarf_functions(data);
    if entries.is_empty() {
        return 0;
    }
    use std::collections::HashMap;
    let mut by_va: HashMap<u64, &DwarfFunction> = HashMap::new();
    for e in &entries {
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

/// Merge compiler-emitted split children (`main.cold`, `foo.part.0`, ...)
/// into their parent function's `chunks` list and drop them from the
/// flat function list. Returns the number of children folded in.
///
/// Pass this *after* symbol renaming so child names are already canonical.
fn merge_compiler_split_chunks(functions: &mut Vec<Function>) -> usize {
    use std::collections::HashMap;

    // entry_va → index into `functions` for fast parent lookup.
    let by_name: HashMap<String, usize> = functions
        .iter()
        .enumerate()
        .map(|(i, f)| (f.name.clone(), i))
        .collect();

    let mut to_remove: Vec<usize> = Vec::new();
    let mut merges: Vec<(usize, usize)> = Vec::new(); // (parent_idx, child_idx)

    for (child_idx, child) in functions.iter().enumerate() {
        let parent_name = match split_parent_name(&child.name) {
            Some(n) => n,
            None => continue,
        };
        let parent_idx = match by_name.get(parent_name) {
            Some(&i) if i != child_idx => i,
            _ => continue,
        };
        merges.push((parent_idx, child_idx));
        to_remove.push(child_idx);
    }

    for (parent_idx, child_idx) in &merges {
        // Take chunks/range from child without removing the child yet — the
        // post-loop removal pass uses indices, so we can't shift the list
        // in place here.
        let child_ranges: Vec<AddressRange> = {
            let child = &functions[*child_idx];
            if !child.chunks.is_empty() {
                child.chunks.clone()
            } else {
                child.range.clone().map(|r| vec![r]).unwrap_or_default()
            }
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
        if !parent.has_flag(FunctionFlags::HAS_EH) {
            parent.add_flag(FunctionFlags::HAS_EH);
        }
    }

    // Remove children in descending index order so earlier indices stay valid.
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.iter().rev() {
        functions.remove(*idx);
    }

    merges.len()
}

/// Analyze bytes and return discovered functions and a callgraph (best-effort).
pub fn analyze_functions_bytes(data: &[u8], budgets: &Budgets) -> (Vec<Function>, CallGraph) {
    let (regions, arch, end, entry) = parse_exec_regions(data);
    let mut functions: Vec<Function> = Vec::new();
    let mut cg = CallGraph::new();
    if regions.is_empty() {
        return (functions, cg);
    }

    // Seeds: entrypoint + symbol-defined function addresses (exec region)
    let mut seeds: Vec<(Address, DiscoverySeedKind)> = parse_function_seeds(data, &regions, arch)
        .into_iter()
        .map(|addr| (addr, DiscoverySeedKind::Trusted))
        .collect();
    if let Some(ep) = entry.clone() {
        // Ensure entrypoint first
        seeds.retain(|(a, _kind)| a.value != ep.value);
        let mut ordered = vec![(ep, DiscoverySeedKind::Trusted)];
        ordered.extend(seeds);
        seeds = ordered;
    }

    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let is_pe_image = data.len() >= 2 && &data[..2] == b"MZ";
    let mut known: std::collections::HashSet<u64> = seeds.iter().map(|(a, _)| a.value).collect();

    // PE TLS callbacks are loader-dispatched entry points: they can execute
    // before DllMain / main and may have no direct call xref from code. Promote
    // them early so tight function budgets still preserve this reachability
    // surface instead of burying it behind broad signature scans.
    let pe_tls_callbacks = if is_pe_image {
        parse_pe_tls_callback_starts(data, &regions)
    } else {
        Vec::new()
    };
    let pe_tls_callback_name_by_va: std::collections::HashMap<u64, String> = pe_tls_callbacks
        .iter()
        .enumerate()
        .map(|(idx, va)| (*va, format!("tls_callback_{}_{:x}", idx, va)))
        .collect();
    for va in &pe_tls_callbacks {
        if known.contains(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, *va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Trusted));
            known.insert(*va);
        }
    }

    // PE GuardCF function-id table seeds. Modern Windows images often carry a
    // large load-config table of valid indirect-call targets. Treat those as
    // metadata-backed function starts before broad signature scanning, but gate
    // body overlaps like `.pdata` so a malformed table cannot split already
    // discovered function bodies.
    let pe_guard_cf_functions = if is_pe_image {
        parse_pe_guard_cf_function_starts(data, &regions)
    } else {
        Vec::new()
    };
    for va in pe_guard_cf_functions {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::BodyOverlapGated));
            known.insert(va);
        }
    }

    // FLIRT seed augmentation. On stripped binaries (no symbol table),
    // the seed list is otherwise just the entrypoint, so the analyser
    // never finds any of the dozens of functions that exist. Scan exec
    // regions for FLIRT prologue matches and seed those VAs too. A name
    // mapping is also kept so we can rename `sub_*` → real_name once
    // discovery completes (see post-processing below).
    let flirt_lib_for_seeds: Option<FlirtLibrary> = load_default_library();
    let flirt_seeds: Vec<(u64, String)> = if let Some(ref lib) = flirt_lib_for_seeds {
        discover_flirt_seeds(data, &functions, lib)
    } else {
        Vec::new()
    };
    let pe_import_thunks = if is_pe_image {
        crate::analysis::pe_iat::pe_import_thunk_map(data)
    } else {
        Vec::new()
    };
    let pe_iat_name_by_va: std::collections::HashMap<u64, String> = if is_pe_image {
        crate::analysis::pe_iat::pe_iat_map(data)
            .into_iter()
            .collect()
    } else {
        std::collections::HashMap::new()
    };
    let pe_import_thunk_name_by_va: std::collections::HashMap<u64, String> =
        pe_import_thunks.iter().cloned().collect();
    let flirt_name_by_va: std::collections::HashMap<u64, String> =
        flirt_seeds.iter().cloned().collect();
    for (va, _name) in &flirt_seeds {
        if known.contains(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, *va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Trusted));
            known.insert(*va);
        }
    }

    // Vtable discovery (#160 v1). For each rodata-resident array of
    // code-pointers (>= 3 consecutive pointers, all landing in exec
    // regions), seed every target VA as a discovery candidate. C++
    // virtual methods are otherwise unreachable from `_start`/`main`
    // because they're called indirectly through `this->vtable[N]`.
    let regions_for_check = regions.clone();
    let is_executable = |va: u64| -> bool {
        regions_for_check
            .iter()
            .any(|r| va >= r.start && va < r.end)
    };
    let vtable_entries = discover_vtables(data, is_executable);
    let mut vtable_method_count = 0usize;
    for entry in &vtable_entries {
        if known.contains(&entry.target_va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, entry.target_va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Trusted));
            known.insert(entry.target_va);
            vtable_method_count += 1;
        }
    }
    let _ = vtable_method_count; // available for telemetry; unused for now.

    // Jump-table discovery (#177). For non-PE stripped binaries this
    // preserves the historical behavior of surfacing switch case bodies
    // as discoverable functions. For PE function-discovery parity, do
    // not promote case labels into the top-level function list: Ghidra
    // keeps them as intra-function blocks, and switch reconstruction has
    // its own comparison area.
    if !is_pe_image {
        let regions_for_check2 = regions.clone();
        let is_executable2 = move |va: u64| -> bool {
            regions_for_check2
                .iter()
                .any(|r| va >= r.start && va < r.end)
        };
        let jump_tables = discover_jump_tables(data, is_executable2);
        for jt in &jump_tables {
            for tgt in &jt.targets {
                if known.contains(tgt) {
                    continue;
                }
                if let Ok(addr) = Address::new(AddressKind::VA, *tgt, bits, None, None) {
                    seeds.push((addr, DiscoverySeedKind::Trusted));
                    known.insert(*tgt);
                }
            }
        }
    }

    // PE export-table seeds. The `object` crate's `dynamic_symbols()`
    // returns 0 entries for PE files (verified on kernel32.dll: 1671
    // exports, 0 returned). We parse IMAGE_DIRECTORY_ENTRY_EXPORT
    // directly so every export address becomes a discovery seed.
    // Closes the 58 % recall observed on kernel32 in the iter 14
    // sweep (most kernel32 exports are tiny `jmp [iat]` thunks not
    // covered by .pdata). Exports are trusted entry points, so insert
    // them before the body-overlap-gated .pdata seeds below.
    let export_starts = parse_pe_export_function_starts(data, &regions, arch);
    let pe_export_name_by_va = if is_pe_image {
        parse_pe_export_function_names(data, &regions)
    } else {
        std::collections::HashMap::new()
    };
    for va in export_starts {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Trusted));
            known.insert(va);
        }
    }

    // PE import-thunk seeds. Many Windows binaries keep import thunks as tiny
    // executable `jmp [IAT]` stubs. They are legitimate analyst-visible
    // functions in Ghidra, but they often have no `.pdata` entry and may never
    // be reached by direct-call backtracking. Seed them explicitly from the IAT
    // scanner and retain the imported API name for post-discovery labelling.
    for (va, _name) in &pe_import_thunks {
        if known.contains(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, *va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Trusted));
            known.insert(*va);
        }
    }

    // Win64 exception-directory seeds. On x86-64 Windows the calling
    // convention emits a RUNTIME_FUNCTION unwind record for nearly
    // every function; IMAGE_DIRECTORY_ENTRY_EXCEPTION is therefore a
    // near-complete function index for free. This is the single
    // highest-leverage seed source on stripped Windows PE -- it
    // closed most of the ~98% recall gap vs Ghidra on ntdll.dll
    // observed in asb's iter 13 comparison.
    let pdata_starts = parse_pdata_function_starts(data, &regions, arch);
    for va in pdata_starts {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::BodyOverlapGated));
            known.insert(va);
        }
    }

    // Recursive multi-pass discovery. Each discovered function's
    // direct-call targets feed back as new seeds; without this the
    // discovery pass terminates as soon as the initial seed list is
    // exhausted, missing every internal function not reached by any
    // other seed source. Worklist-based to keep the iteration bounded
    // by `max_functions` while still propagating xrefs to a fixed
    // point.
    let mut calls_all: Vec<RecordedCallEdge> = Vec::new();
    let mut worklist: std::collections::VecDeque<(Address, DiscoverySeedKind)> =
        seeds.into_iter().collect();
    while let Some((seed, seed_kind)) = worklist.pop_front() {
        if functions.len() >= budgets.max_functions.max(1) {
            break;
        }
        if seed_kind.is_body_overlap_gated() && va_in_discovered_body(&functions, None, seed.value)
        {
            continue;
        }
        if seed_kind == DiscoverySeedKind::Xref
            && is_pe_image
            && !pe_xref_seed_looks_like_function_start(data, seed.value)
        {
            continue;
        }
        if let Some((f, calls, tail_calls)) = discover_function(
            data,
            arch,
            end,
            seed.clone(),
            &regions,
            budgets,
            &pe_iat_name_by_va,
            &known,
        ) {
            // Every tail-call jmp target the inner discoverer found needs
            // to become its own seed so the callee gets a separate
            // Function. Without this, a `jmp impl` thunk would correctly
            // stop at the jmp (per the inner gate) but the implementation
            // would never be discovered because nothing else seeds it.
            for tgt in tail_calls {
                if known.contains(&tgt) {
                    continue;
                }
                if in_exec_regions(&regions, tgt).is_none() {
                    continue;
                }
                if is_pe_image && !pe_xref_seed_looks_like_function_start(data, tgt) {
                    continue;
                }
                if let Ok(addr) = Address::new(AddressKind::VA, tgt, bits, None, None) {
                    worklist.push_back((addr, DiscoverySeedKind::Xref));
                    known.insert(tgt);
                }
            }
            for call in &calls {
                calls_all.push(RecordedCallEdge {
                    caller_entry_va: f.entry_point.value,
                    callsite_va: call.callsite_va,
                    target_va: call.target_va,
                    target_name: call.target_name.clone(),
                    call_type: call.call_type,
                });
                // Xref-backtracking seed: any direct call/jump target
                // landing in an exec region that we haven't already
                // queued becomes a new candidate function entry.
                let Some(callee_va) = call.target_va else {
                    continue;
                };
                if call.call_type == CallType::Direct
                    && !known.contains(&callee_va)
                    && in_exec_regions(&regions, callee_va).is_some()
                    && !va_in_discovered_body(&functions, Some(&f), callee_va)
                    && (!is_pe_image || pe_xref_seed_looks_like_function_start(data, callee_va))
                {
                    if let Ok(addr) = Address::new(AddressKind::VA, callee_va, bits, None, None) {
                        worklist.push_back((addr, DiscoverySeedKind::Xref));
                        known.insert(callee_va);
                    }
                }
            }
            functions.push(f);
        }
    }

    // Post-process: rename functions by matching defined symbol names at their entry VAs
    if let Ok(obj) = object::read::File::parse(data) {
        use object::read::ObjectSymbol;
        // Build VA->name map from defined symbols in executable regions
        let mut sym_by_va: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();
        for sym in obj.symbols() {
            if sym.is_definition() {
                let addr = sym.address();
                if addr != 0 && in_exec_regions(&regions, addr).is_some() {
                    if let Ok(name) = sym.name() {
                        if !name.is_empty() {
                            sym_by_va.entry(addr).or_insert_with(|| name.to_string());
                        }
                    }
                }
            }
        }
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                let addr = sym.address();
                if addr != 0 && in_exec_regions(&regions, addr).is_some() {
                    if let Ok(name) = sym.name() {
                        if !name.is_empty() {
                            sym_by_va.entry(addr).or_insert_with(|| name.to_string());
                        }
                    }
                }
            }
        }
        // Apply renames
        for f in &mut functions {
            if let Some(name) = sym_by_va.get(&f.entry_point.value) {
                f.name = name.clone();
            }
        }
    }

    // PE export aliases are runtime-visible names. The object crate does not
    // expose PE exports through dynamic_symbols(), so apply the parsed export
    // table directly for stripped DLLs while preserving stronger symbol names.
    if !pe_export_name_by_va.is_empty() {
        for f in &mut functions {
            if !f.name.starts_with("sub_") {
                continue;
            }
            if let Some(name) = pe_export_name_by_va.get(&f.entry_point.value) {
                f.name = name.clone();
            }
        }
    }

    // Import-thunk aliases are runtime names for local executable stubs. They
    // should improve `sub_*` readability without overriding real symbols,
    // exports, PDB, or later FLIRT names.
    if !pe_import_thunk_name_by_va.is_empty() {
        for f in &mut functions {
            if !f.name.starts_with("sub_") {
                continue;
            }
            if let Some(name) = pe_import_thunk_name_by_va.get(&f.entry_point.value) {
                f.name = name.clone();
            }
        }
    }

    // Apply DWARF authoritative ground truth where available. DWARF
    // gives us the canonical function name, multi-chunk address ranges
    // (DW_AT_ranges), parameter count, and source language — all of
    // which beat the heuristic discovery output on -g builds. We only
    // *override* fields that DWARF has hard answers for; heuristic
    // basic-block CFG and edges remain.
    apply_dwarf_overrides(data, &mut functions);

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
    if let Some(ref lib) = flirt_lib_for_seeds {
        apply_flirt_overrides(data, &mut functions, lib);
    }

    // TLS callback labels are PE metadata names for anonymous loader entry
    // points. Apply them after symbol/DWARF/FLIRT processing so real names win.
    if !pe_tls_callback_name_by_va.is_empty() {
        for f in &mut functions {
            if !f.name.starts_with("sub_") {
                continue;
            }
            if let Some(name) = pe_tls_callback_name_by_va.get(&f.entry_point.value) {
                f.name = name.clone();
            }
        }
    }

    // Fold compiler-emitted split chunks (e.g. GCC -O2 `<fn>.cold`) into
    // their parent function's `chunks` list so downstream consumers see
    // one logical function instead of N siblings. Runs after DWARF —
    // DWARF chunks are already canonical, but a binary may have a mix
    // (some functions DWARF-covered, some not), and this pass handles
    // the heuristic side.
    merge_compiler_split_chunks(&mut functions);

    // Build callgraph using final post-rename function names. Earlier seed
    // names are intentionally discarded here; otherwise edges can reference
    // renamed callers that are absent from the graph node set.
    cg = CallGraph::new();
    for f in &functions {
        cg.add_node(f.name.clone());
    }

    let name_by_va: std::collections::HashMap<u64, String> = functions
        .iter()
        .map(|f| (f.entry_point.value, f.name.clone()))
        .collect();

    for call in calls_all {
        let caller = callsite_owner_name(&functions, call.caller_entry_va, call.callsite_va)
            .unwrap_or_else(|| format!("sub_{:x}", call.caller_entry_va));
        let callee = call
            .target_name
            .or_else(|| call.target_va.and_then(|va| name_by_va.get(&va).cloned()))
            .or_else(|| call.target_va.map(|va| format!("sub_{:x}", va)))
            .unwrap_or_else(|| format!("indirect_{:x}", call.callsite_va));
        let callsite = Address::new(AddressKind::VA, call.callsite_va, bits, None, None).ok();
        add_callgraph_edge_dedup(&mut cg, &caller, &callee, call.call_type, callsite);
    }

    (functions, cg)
}

#[cfg(test)]
mod prologue_gate_tests {
    use super::looks_like_fn_start;

    fn data_with_pre(prev: &[u8], head: &[u8]) -> (Vec<u8>, usize) {
        let mut d = Vec::with_capacity(prev.len() + head.len());
        d.extend_from_slice(prev);
        let off = d.len();
        d.extend_from_slice(head);
        (d, off)
    }

    #[test]
    fn accepts_cc_padded_boundary() {
        let (d, off) = data_with_pre(&[0xcc, 0xcc], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_c3_ret_boundary() {
        let (d, off) = data_with_pre(&[0xc3], &[0x40, 0x53]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_90_nop_boundary() {
        let (d, off) = data_with_pre(&[0x90, 0x90], &[0x48, 0x83, 0xec, 0x28]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_recognised_prologue_no_marker() {
        // No fn-boundary marker before, but byte 0 is a textbook
        // parameter-spill prologue.
        let (d, off) = data_with_pre(&[0xaa], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_iat_thunk() {
        let (d, off) = data_with_pre(&[0xaa], &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_tiny_ret_stub() {
        let (d, off) = data_with_pre(&[0xaa], &[0x33, 0xc0, 0xc3]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn rejects_mid_fn_continuation_no_marker() {
        // No fn-boundary marker; byte 0 is `cmp edi, 2` which is
        // valid x86 but not a recognised prologue. This is exactly
        // the false-positive pattern xref backtracking introduces.
        let (d, off) = data_with_pre(&[0xaa], &[0x83, 0xff, 0x02, 0x0f, 0x85]);
        assert!(!looks_like_fn_start(&d, off));
    }

    #[test]
    fn rejects_mid_instruction_landing() {
        // No marker, byte 0 is a ModR/M byte (0x24) -- xref-target
        // landed in the middle of an existing instruction.
        let (d, off) = data_with_pre(&[0xaa], &[0x24, 0x10, 0x00, 0x00]);
        assert!(!looks_like_fn_start(&d, off));
    }

    #[test]
    fn rejects_file_off_zero() {
        let d = vec![0x48, 0x89, 0x5c, 0x24];
        assert!(!looks_like_fn_start(&d, 0));
    }
}

#[cfg(test)]
mod body_overlap_gate_tests {
    use super::*;

    fn _va_range(start: u64, size: u64) -> AddressRange {
        let s = Address::new(AddressKind::VA, start, 64, None, None).unwrap();
        AddressRange::new(s, size, None).unwrap()
    }

    fn _func(entry_va: u64, ranges: &[(u64, u64)]) -> Function {
        let entry = Address::new(AddressKind::VA, entry_va, 64, None, None).unwrap();
        let mut func =
            Function::new(format!("sub_{entry_va:x}"), entry, FunctionKind::Normal).unwrap();
        for (start, size) in ranges {
            func.add_chunk(_va_range(*start, *size));
        }
        func
    }

    fn _func_with_block(entry_va: u64, range: (u64, u64), block: (u64, u64)) -> Function {
        let mut func = _func(entry_va, &[range]);
        let bb = BasicBlock::new(
            format!("bb_{:x}", block.0),
            Address::new(AddressKind::VA, block.0, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, block.1, 64, None, None).unwrap(),
            1,
            None,
            None,
        );
        func.add_basic_block(bb);
        func
    }

    #[test]
    fn body_gate_keeps_function_entry() {
        let f = _func(0x1000, &[(0x1000, 0x80)]);
        assert!(!va_in_function_body(&f, 0x1000));
    }

    #[test]
    fn body_gate_rejects_primary_body_address() {
        let f = _func(0x1000, &[(0x1000, 0x80)]);
        assert!(va_in_function_body(&f, 0x1040));
    }

    #[test]
    fn body_gate_uses_half_open_ranges() {
        let f = _func(0x1000, &[(0x1000, 0x80)]);
        assert!(!va_in_function_body(&f, 0x1080));
        assert!(!va_in_function_body(&f, 0x0fff));
    }

    #[test]
    fn body_gate_treats_auxiliary_chunks_as_owned_body() {
        let f = _func(0x1000, &[(0x1000, 0x80), (0x2000, 0x20)]);
        assert!(va_in_function_body(&f, 0x2000));
    }

    #[test]
    fn body_gate_prefers_decoded_block_interiors_over_wide_ranges() {
        let f = _func_with_block(0x1000, (0x1000, 0x5000), (0x1000, 0x1010));
        assert!(va_in_function_body(&f, 0x1008));
        assert!(!va_in_function_body(&f, 0x1010));
        assert!(!va_in_function_body(&f, 0x2000));
    }

    #[test]
    fn discovered_body_checks_current_and_prior_functions() {
        let prior = _func(0x1000, &[(0x1000, 0x80)]);
        let current = _func(0x3000, &[(0x3000, 0x80)]);
        assert!(va_in_discovered_body(&[prior], Some(&current), 0x1040));
        assert!(va_in_discovered_body(&[], Some(&current), 0x3040));
        assert!(!va_in_discovered_body(&[], Some(&current), 0x4000));
    }
}

#[cfg(test)]
mod pe_import_thunk_seed_tests {
    use super::{analyze_functions_bytes, Budgets};
    use std::collections::BTreeSet;
    use std::path::Path;

    #[test]
    fn pe_import_thunks_are_discovered_as_functions() {
        let path = Path::new(
            "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).expect("read sample");
        let thunk_map = crate::analysis::pe_iat::pe_import_thunk_map(&data);
        assert!(!thunk_map.is_empty(), "fixture has no PE import thunks");

        let budgets = Budgets {
            max_functions: 1024,
            max_blocks: 1_000_000,
            max_instructions: 30_000_000,
            timeout_ms: 30_000,
        };
        let (functions, _cg) = analyze_functions_bytes(&data, &budgets);
        let discovered: BTreeSet<u64> = functions.iter().map(|f| f.entry_point.value).collect();
        let names_by_va: std::collections::BTreeMap<u64, &str> = functions
            .iter()
            .map(|f| (f.entry_point.value, f.name.as_str()))
            .collect();
        let missing: Vec<_> = thunk_map
            .iter()
            .filter(|(va, _name)| !discovered.contains(va))
            .collect();

        assert!(
            missing.is_empty(),
            "missing import thunk functions: {:?}",
            missing
        );
        assert!(
            thunk_map.iter().any(|(va, name)| {
                name == "LeaveCriticalSection"
                    && names_by_va.get(va) == Some(&"LeaveCriticalSection")
            }),
            "expected a named LeaveCriticalSection import thunk function"
        );
    }
}

#[cfg(test)]
mod pe_iat_callgraph_tests {
    use super::{analyze_functions_bytes, Budgets};
    use crate::core::call_graph::CallType;
    use std::collections::HashSet;
    use std::path::Path;

    fn count_indirect_import_callsite(
        cg: &crate::core::call_graph::CallGraph,
        callee: &str,
        callsite_va: u64,
    ) -> usize {
        cg.edges
            .iter()
            .filter(|edge| {
                edge.call_type == CallType::Indirect
                    && edge.callee == callee
                    && edge.call_sites.iter().any(|site| site.value == callsite_va)
            })
            .count()
    }

    #[test]
    fn pe_iat_memory_calls_are_named_indirect_callgraph_edges() {
        let path = Path::new(
            "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).expect("read sample");
        let iat = crate::analysis::pe_iat::pe_iat_map(&data);
        for expected in ["GetStartupInfoA", "VirtualQuery", "VirtualProtect"] {
            assert!(
                iat.iter().any(|(_va, name)| name == expected),
                "fixture IAT does not expose {expected}"
            );
        }

        let budgets = Budgets {
            max_functions: 1024,
            max_blocks: 1_000_000,
            max_instructions: 30_000_000,
            timeout_ms: 30_000,
        };
        let (_functions, cg) = analyze_functions_bytes(&data, &budgets);
        cg.validate()
            .expect("post-rename callgraph should reference known nodes");

        assert_eq!(
            count_indirect_import_callsite(&cg, "GetStartupInfoA", 0x140001473),
            1,
            "expected one named GetStartupInfoA IAT call edge"
        );
        assert_eq!(
            count_indirect_import_callsite(&cg, "VirtualQuery", 0x140001a69),
            1,
            "expected one named VirtualQuery IAT call edge"
        );
        assert_eq!(
            count_indirect_import_callsite(&cg, "VirtualProtect", 0x140001b4e),
            1,
            "expected one named VirtualProtect IAT call edge"
        );

        let mut seen = HashSet::new();
        for edge in &cg.edges {
            for site in &edge.call_sites {
                assert!(
                    seen.insert((
                        edge.caller.as_str(),
                        edge.callee.as_str(),
                        edge.call_type,
                        site.value,
                    )),
                    "duplicate callsite edge: {} -> {} {:?} {:#x}",
                    edge.caller,
                    edge.callee,
                    edge.call_type,
                    site.value
                );
            }
        }
    }
}

#[cfg(test)]
mod pe_tls_callback_seed_tests {
    use super::{
        analyze_functions_bytes, parse_exec_regions, parse_pe_tls_callback_starts, Budgets,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    fn read_u16(data: &[u8], off: usize) -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(data: &[u8], off: usize) -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn zero_range(data: &mut [u8], off: usize, len: usize) -> Option<()> {
        for byte in data.get_mut(off..off + len)? {
            *byte = 0;
        }
        Some(())
    }

    fn strip_coff_symbols_and_exception_directory(data: &mut [u8]) -> Option<()> {
        if data.len() < 0x40 || data.get(0..2)? != b"MZ" {
            return None;
        }
        let e_lfanew = read_u32(data, 0x3c)? as usize;
        if e_lfanew + 24 > data.len() || data.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
            return None;
        }
        let coff_off = e_lfanew + 4;
        let opt_size = read_u16(data, coff_off + 16)? as usize;
        let opt_off = coff_off + 20;
        if opt_off + opt_size > data.len() {
            return None;
        }
        zero_range(data, coff_off + 8, 8)?;

        let dd_off = match read_u16(data, opt_off)? {
            // PE32+
            0x20b => opt_off + 112,
            // PE32
            0x10b => opt_off + 96,
            _ => return None,
        };
        // IMAGE_DIRECTORY_ENTRY_EXCEPTION. Removing it makes the test prove
        // TLS callback prioritisation independently of Win64 .pdata seeds.
        zero_range(data, dd_off + 3 * 8, 8)?;
        Some(())
    }

    #[test]
    fn pe_tls_callbacks_are_priority_function_seeds() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/pe_tls_callbacks-x86_64-mingw.exe",
        );
        if !path.exists() {
            return;
        }
        let mut data = std::fs::read(path).expect("read sample");
        strip_coff_symbols_and_exception_directory(&mut data)
            .expect("strip symbol and exception metadata");

        let (regions, _arch, _end, _entry) = parse_exec_regions(&data);
        let callbacks = parse_pe_tls_callback_starts(&data, &regions);
        assert!(!callbacks.is_empty(), "fixture has no PE TLS callbacks");

        let budgets = Budgets {
            max_functions: callbacks.len() + 1,
            max_blocks: 1_000_000,
            max_instructions: 30_000_000,
            timeout_ms: 30_000,
        };
        let (functions, _cg) = analyze_functions_bytes(&data, &budgets);
        let discovered: BTreeSet<u64> = functions.iter().map(|f| f.entry_point.value).collect();
        let names_by_va: BTreeMap<u64, &str> = functions
            .iter()
            .map(|f| (f.entry_point.value, f.name.as_str()))
            .collect();
        let missing: Vec<u64> = callbacks
            .iter()
            .copied()
            .filter(|va| !discovered.contains(va))
            .collect();

        assert!(
            missing.is_empty(),
            "missing TLS callback functions under tight budget: {:?}",
            missing
        );
        for va in callbacks {
            let name = names_by_va
                .get(&va)
                .copied()
                .expect("callback function should be named");
            assert!(
                name.starts_with("tls_callback_"),
                "anonymous TLS callback {va:#x} kept non-metadata name {name}"
            );
        }
    }
}

#[cfg(test)]
mod pe_guard_cf_seed_tests {
    use super::{
        analyze_functions_bytes, parse_exec_regions, parse_pe_guard_cf_function_starts, Budgets,
    };
    use std::collections::BTreeSet;
    use std::path::Path;

    #[test]
    fn pe_guard_cf_table_entries_are_discovery_seeds_when_corpus_is_present() {
        let path = Path::new(
            "/nas4/data/binary-analysis/glaurung/binaries/windows-10-x64/HologramWorld.dll",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).expect("read HologramWorld.dll corpus sample");
        let (regions, _arch, _end, _entry) = parse_exec_regions(&data);
        let guard_cf = parse_pe_guard_cf_function_starts(&data, &regions);
        assert!(
            guard_cf.len() > 1_000,
            "expected a large GuardCF function table"
        );

        let budgets = Budgets {
            // entrypoint + two TLS callbacks + the first GuardCF entries
            max_functions: 10,
            max_blocks: 1_000_000,
            max_instructions: 30_000_000,
            timeout_ms: 30_000,
        };
        let (functions, _cg) = analyze_functions_bytes(&data, &budgets);
        let discovered: BTreeSet<u64> = functions.iter().map(|f| f.entry_point.value).collect();
        let first_guard_cf = guard_cf[0];
        assert!(
            discovered.contains(&first_guard_cf),
            "first GuardCF seed {first_guard_cf:#x} was not discovered under tight budget"
        );
    }
}

#[cfg(test)]
mod pe_export_name_tests {
    use super::{
        analyze_functions_bytes, parse_exec_regions, parse_pe_export_function_names, Budgets,
    };
    use object::{Object, ObjectSymbol};
    use std::collections::BTreeSet;
    use std::path::Path;

    fn read_u16(data: &[u8], off: usize) -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(data: &[u8], off: usize) -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn zero_range(data: &mut [u8], off: usize, len: usize) -> Option<()> {
        for byte in data.get_mut(off..off + len)? {
            *byte = 0;
        }
        Some(())
    }

    fn strip_coff_symbols_and_debug_sections(data: &mut [u8]) -> Option<()> {
        if data.len() < 0x40 || data.get(0..2)? != b"MZ" {
            return None;
        }
        let e_lfanew = read_u32(data, 0x3c)? as usize;
        if e_lfanew + 24 > data.len() || data.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
            return None;
        }
        let coff_off = e_lfanew + 4;
        let n_sections = read_u16(data, coff_off + 2)? as usize;
        let opt_size = read_u16(data, coff_off + 16)? as usize;
        let opt_off = coff_off + 20;
        if opt_off + opt_size > data.len() {
            return None;
        }

        // COFF PointerToSymbolTable + NumberOfSymbols.
        zero_range(data, coff_off + 8, 8)?;

        let magic = read_u16(data, opt_off)?;
        let dd_off = match magic {
            0x20b => opt_off + 112,
            0x10b => opt_off + 96,
            _ => return None,
        };
        let num_dirs_off = if magic == 0x20b {
            opt_off + 108
        } else {
            opt_off + 92
        };
        if read_u32(data, num_dirs_off).unwrap_or(0) > 6 {
            // IMAGE_DIRECTORY_ENTRY_DEBUG.
            zero_range(data, dd_off + 6 * 8, 8)?;
        }

        let sec_off = opt_off + opt_size;
        for idx in 0..n_sections {
            let off = sec_off + idx * 40;
            if off + 40 > data.len() {
                break;
            }
            let raw_name = data.get(off..off + 8)?;
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..end]).to_ascii_lowercase();
            if !name.starts_with(".debug") {
                continue;
            }
            // Hide DWARF sections from object::section_by_name without
            // touching exports or executable code.
            zero_range(data, off, 8)?;
            zero_range(data, off + 8, 4)?;
            zero_range(data, off + 16, 4)?;
        }
        Some(())
    }

    #[test]
    fn pe_export_names_label_stripped_cfg_functions() {
        let path =
            Path::new("samples/binaries/platforms/linux/amd64/export/libraries/shared/mathlib.dll");
        if !path.exists() {
            return;
        }
        let mut data = std::fs::read(path).expect("read mathlib.dll sample");
        strip_coff_symbols_and_debug_sections(&mut data).expect("strip symbols/debug metadata");

        let obj = object::read::File::parse(&data[..]).expect("parse stripped PE");
        let has_mathlib_add_symbol = obj
            .symbols()
            .any(|sym| sym.name().ok() == Some("mathlib_add"))
            || obj
                .dynamic_symbols()
                .any(|sym| sym.name().ok() == Some("mathlib_add"));
        assert!(
            !has_mathlib_add_symbol,
            "test fixture still exposes mathlib_add through object symbols"
        );
        assert!(
            crate::debug::dwarf::extract_dwarf_functions(&data).is_empty(),
            "test fixture still exposes DWARF functions"
        );

        let (regions, _arch, _endian, _entry) = parse_exec_regions(&data);
        let export_names = parse_pe_export_function_names(&data, &regions);
        let expected = [
            "mathlib_add",
            "mathlib_array_sum",
            "mathlib_random",
            "mathlib_version",
        ];
        for name in expected {
            assert!(
                export_names.values().any(|candidate| candidate == name),
                "missing parsed PE export name {name}"
            );
        }

        let budgets = Budgets {
            max_functions: 256,
            max_blocks: 1_000_000,
            max_instructions: 30_000_000,
            timeout_ms: 30_000,
        };
        let (functions, _cg) = analyze_functions_bytes(&data, &budgets);
        let names: BTreeSet<&str> = functions.iter().map(|f| f.name.as_str()).collect();
        for name in expected {
            assert!(
                names.contains(name),
                "stripped CFG did not apply PE export name {name}"
            );
        }
    }
}

#[cfg(test)]
mod pe_pdata_int3_boundary_tests {
    use super::{analyze_functions_bytes, Budgets};
    use std::collections::BTreeSet;
    use std::path::Path;

    #[test]
    fn int3_padding_does_not_swallow_next_pdata_function() {
        let path =
            Path::new("/nas4/data/binary-analysis/glaurung/binaries/windows-10-x64/migstore.dll");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).expect("read migstore.dll corpus sample");
        let budgets = Budgets {
            max_functions: 512,
            max_blocks: 1_000_000,
            max_instructions: 30_000_000,
            timeout_ms: 30_000,
        };
        let (functions, _cg) = analyze_functions_bytes(&data, &budgets);
        let discovered: BTreeSet<u64> = functions.iter().map(|f| f.entry_point.value).collect();

        assert!(
            discovered.contains(&0x180004900),
            "the .pdata function at 0x180004900 was hidden by prior int3 padding"
        );
        for func in &functions {
            for block in &func.basic_blocks {
                let start = block.start_address.value;
                let end = block.end_address.value;
                assert!(
                    !(start < 0x180004900 && 0x180004900 < end),
                    "block {start:#x}..{end:#x} in {} crosses the .pdata function start",
                    func.name
                );
            }
        }
    }
}

#[cfg(test)]
mod unwind_info_tests {
    use super::unwind_info_has_chain_info;

    #[test]
    fn detects_chaininfo_flag_in_unwind_info_header() {
        // UNWIND_INFO byte 0 packs Version in bits 0..2 and Flags in
        // bits 3..7. UNW_FLAG_CHAININFO is flag bit 0x04.
        let data = [0x01, (0x04 << 3) | 0x01, (0x03 << 3) | 0x01];
        assert!(!unwind_info_has_chain_info(&data, 0));
        assert!(unwind_info_has_chain_info(&data, 1));
        assert!(!unwind_info_has_chain_info(&data, 2));
    }

    #[test]
    fn missing_unwind_info_header_is_not_chained() {
        let data = [0x21];
        assert!(!unwind_info_has_chain_info(&data, 2));
    }
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
        let merged = merge_compiler_split_chunks(&mut funcs);
        assert_eq!(merged, 1);
        assert_eq!(funcs.len(), 2, "child symbol should be dropped");
        let main = funcs.iter().find(|f| f.name == "main").unwrap();
        assert_eq!(main.chunks.len(), 2);
        assert_eq!(main.total_size(), 0x80 + 0x20);
        assert!(main.has_flag(FunctionFlags::HAS_EH));
        assert!(main.contains_va(0x2010));
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
