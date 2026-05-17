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

    Some((func, call_edges))
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

/// Resolve a VA to a file offset by walking the section headers
/// directly. Used by the prologue-sanity gate during xref-target
/// promotion -- the existing `pe::sections::SectionTable` is built
/// per-PeParser instance; this helper avoids constructing one
/// inside the cfg worklist (where we already have raw `data` and
/// the `ExecRegion` list, but not the full section table).
fn pe_va_to_file_off(data: &[u8], va: u64) -> Option<usize> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    let n_sections = u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().ok()?)
        as usize;
    let opt_size = u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().ok()?)
        as usize;
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
    // Resolve exc_rva to a file offset via the section table.
    let sec_off = opt_off + opt_size;
    let mut exc_file_off: Option<usize> = None;
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
        if exc_rva >= virt_addr && exc_rva < virt_addr + span {
            exc_file_off = Some(raw_ptr + (exc_rva - virt_addr));
            break;
        }
    }
    let exc_file_off = match exc_file_off {
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
        let va = image_base + begin_rva as u64;
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        }
    }
    starts
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
    let mut seeds = parse_function_seeds(data, &regions, arch);
    if let Some(ep) = entry.clone() {
        // Ensure entrypoint first
        seeds.retain(|a| a.value != ep.value);
        let mut ordered = vec![ep];
        ordered.extend(seeds);
        seeds = ordered;
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
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let flirt_name_by_va: std::collections::HashMap<u64, String> =
        flirt_seeds.iter().cloned().collect();
    let mut known: std::collections::HashSet<u64> = seeds.iter().map(|a| a.value).collect();
    for (va, _name) in &flirt_seeds {
        if known.contains(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, *va, bits, None, None) {
            seeds.push(addr);
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
            seeds.push(addr);
            known.insert(entry.target_va);
            vtable_method_count += 1;
        }
    }
    let _ = vtable_method_count; // available for telemetry; unused for now.

    // Jump-table discovery (#177). Scans rodata for relative-offset
    // tables (i32 entries encoding `target_va - table_va`); each entry
    // is a switch-statement case label and would otherwise be a dead
    // code branch as far as direct-call discovery is concerned.
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
                seeds.push(addr);
                known.insert(*tgt);
            }
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
            seeds.push(addr);
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
    let mut calls_all: Vec<(String, u64)> = Vec::new(); // (caller_name, callee_va)
    let mut worklist: std::collections::VecDeque<Address> = seeds.into_iter().collect();
    while let Some(seed) = worklist.pop_front() {
        if functions.len() >= budgets.max_functions.max(1) {
            break;
        }
        if let Some((f, calls)) =
            discover_function(data, arch, end, seed.clone(), &regions, budgets)
        {
            for (_caller, callee_va) in &calls {
                calls_all.push((f.name.clone(), *callee_va));
                // Xref-backtracking seed: any direct call/jump target
                // landing in an exec region that we haven't already
                // queued becomes a new candidate function entry.
                if !known.contains(callee_va)
                    && in_exec_regions(&regions, *callee_va).is_some()
                {
                    if let Ok(addr) =
                        Address::new(AddressKind::VA, *callee_va, bits, None, None)
                    {
                        worklist.push_back(addr);
                        known.insert(*callee_va);
                    }
                }
            }
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

    // Fold compiler-emitted split chunks (e.g. GCC -O2 `<fn>.cold`) into
    // their parent function's `chunks` list so downstream consumers see
    // one logical function instead of N siblings. Runs after DWARF —
    // DWARF chunks are already canonical, but a binary may have a mix
    // (some functions DWARF-covered, some not), and this pass handles
    // the heuristic side.
    merge_compiler_split_chunks(&mut functions);

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
