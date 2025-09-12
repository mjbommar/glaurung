//! Bounded function discovery and CFG construction.
//!
//! This module implements a conservative, deterministic function discovery pass
//! with strict budgets. It seeds from an entrypoint (and can be extended later to
//! exports/PLT/etc.), disassembles within executable ranges only, splits basic
//! blocks on control flow, and emits `Function`s plus a `CallGraph`.

use crate::core::address::{Address, AddressKind};
use crate::core::basic_block::BasicBlock;
use crate::core::binary::{Arch as BArch, Endianness};
use crate::core::call_graph::{CallGraph, CallGraphEdge, CallType};
use crate::core::control_flow_graph::ControlFlowEdgeKind;
use crate::core::disassembler::Disassembler;
use crate::core::function::{Function, FunctionKind};
use crate::core::instruction::Instruction;
use crate::disasm::registry;
use crate::triage::heuristics;

use object::{Object, ObjectSegment};
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

        // If we can refine by sections with execute-like names, do so
        let mut refined = Vec::new();
        for sec in obj.sections() {
            let name = sec.name().unwrap_or("").to_ascii_lowercase();
            let addr = sec.address();
            let size = sec.size();
            if size == 0 {
                continue;
            }
            // Simple heuristic for code sections
            let looks_exec = name.contains(".text") || name.contains("code") || name == "text";
            if looks_exec {
                if let Some((foff, _)) = sec.file_range() {
                    refined.push(ExecRegion {
                        start: addr,
                        end: addr.saturating_add(size),
                        _file_off_start: foff,
                    });
                }
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
            if m == "ret" || m == "retq" {
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

/// Discover a single function starting at `entry` within executable regions.
fn discover_function(
    data: &[u8],
    arch: BArch,
    end: Endianness,
    entry: Address,
    regions: &[ExecRegion],
    budgets: &Budgets,
) -> Option<(Function, Vec<(u64, u64)>)> {
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
    let mut call_edges: Vec<(u64, u64)> = Vec::new();

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
                // Fallthrough continues; capture call edge to unknown for now. We use placeholder callee id.
                if let Some(tgt) = immediate_target(&ins) {
                    // Track call edge (caller block start -> callee target)
                    call_edges.push((start_va, tgt));
                }
                // continue to fallthrough
            } else if is_branch {
                // Determine conditional vs unconditional by mnemonic content
                let unconditional = ins.mnemonic.eq_ignore_ascii_case("jmp")
                    || ins.mnemonic.eq_ignore_ascii_case("b");
                if let Some(tgt) = immediate_target(&ins) {
                    // Queue target if new and in region
                    if in_exec_regions(regions, tgt).is_some() && seen.insert(tgt) {
                        queue.push_back(tgt);
                    }
                    // Use block start as source for CFG edges
                    edges.push((start_va, tgt, ControlFlowEdgeKind::Branch));
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

    Some((func, call_edges))
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

/// Analyze bytes and return discovered functions and a callgraph (best-effort).
pub fn analyze_functions_bytes(data: &[u8], budgets: &Budgets) -> (Vec<Function>, CallGraph) {
    let (regions, arch, end, entry) = parse_exec_regions(data);
    let mut functions: Vec<Function> = Vec::new();
    let mut cg = CallGraph::new();
    if regions.is_empty() {
        return (functions, cg);
    }

    // Seeds: entrypoint + symbol-defined function addresses (exec region)
    let mut seeds = parse_function_seeds(data, &regions, arch);
    if let Some(ep) = entry.clone() {
        // Ensure entrypoint first
        seeds.retain(|a| a.value != ep.value);
        let mut ordered = vec![ep];
        ordered.extend(seeds);
        seeds = ordered;
    }

    // Discover functions up to budget
    let mut calls_all: Vec<(String, u64)> = Vec::new(); // (caller_name, callee_va)
    for seed in seeds.into_iter().take(budgets.max_functions.max(1)) {
        if let Some((f, calls)) =
            discover_function(data, arch, end, seed.clone(), &regions, budgets)
        {
            calls_all.extend(calls.into_iter().map(|(_c, tgt)| (f.name.clone(), tgt)));
            cg.add_node(f.name.clone());
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

    // Build callgraph using discovered functions where possible
    let name_by_va: std::collections::HashMap<u64, String> = functions
        .iter()
        .map(|f| (f.entry_point.value, f.name.clone()))
        .collect();

    for (caller, callee_va) in calls_all {
        let callee = name_by_va
            .get(&callee_va)
            .cloned()
            .unwrap_or_else(|| format!("sub_{:x}", callee_va));
        cg.add_node(callee.clone());
        let edge = CallGraphEdge::new(caller.clone(), callee, CallType::Direct);
        cg.add_edge(edge);
    }

    (functions, cg)
}
