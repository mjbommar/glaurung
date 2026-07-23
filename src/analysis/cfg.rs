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
            // Zero means "no function-count cap"; use the other budgets
            // to keep full-corpus analysis bounded.
            max_functions: 0,
            max_blocks: 2048,
            max_instructions: 50_000,
            timeout_ms: 100,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FunctionDiscoveryStats {
    pub max_functions: usize,
    pub max_blocks: usize,
    pub max_instructions: usize,
    pub timeout_ms: u64,
    pub functions_discovered: usize,
    pub callgraph_functions: usize,
    pub callgraph_edges: usize,
    pub seeds_initial: usize,
    pub seeds_processed: usize,
    pub seeds_remaining: usize,
    pub xref_seeds_added: usize,
    pub direct_call_targets: usize,
    pub tail_call_targets: usize,
    pub indirect_call_targets: usize,
    pub direct_call_seeds_added: usize,
    pub tail_call_seeds_added: usize,
    pub indirect_call_seeds_added: usize,
    pub export_function_starts: usize,
    pub export_seeds_inserted: usize,
    pub pdata_entries: usize,
    pub pdata_function_starts: usize,
    pub pdata_seeds_inserted: usize,
    pub pdata_zero_begin_rejected: usize,
    pub pdata_zero_size_rejected: usize,
    pub pdata_overlapping_entries: usize,
    pub pdata_chained_unwind_rejected: usize,
    pub pdata_chained_unwind_parsed: usize,
    pub pdata_chained_unwind_parse_failed: usize,
    pub pdata_chained_parent_starts: usize,
    pub pdata_nonexec_rejected: usize,
    pub prologue_scan_candidates: usize,
    pub prologue_scan_seeds_inserted: usize,
    pub thunk_scan_candidates: usize,
    pub thunk_scan_seeds_inserted: usize,
    pub tiny_stub_scan_candidates: usize,
    pub tiny_stub_scan_seeds_inserted: usize,
    pub raw_call_target_candidates: usize,
    pub raw_call_target_seeds_inserted: usize,
    pub raw_call_target_body_split_seeds_inserted: usize,
    pub data_ref_code_pointer_candidates: usize,
    pub data_ref_code_pointer_seeds_inserted: usize,
    pub data_ref_code_pointer_table_count: usize,
    pub pdata_body_overlap_starts: usize,
    pub code_label_count: usize,
    pub seed_kind_counts: std::collections::BTreeMap<String, usize>,
    pub scan_rejection_counts: std::collections::BTreeMap<String, usize>,
    pub scan_rejections: Vec<ScanRejection>,
    pub function_seed_kinds: Vec<(u64, String)>,
    pub seed_provenance: Vec<SeedProvenance>,
    pub code_labels: Vec<CodeLabel>,
    pub thunk_functions: usize,
    pub import_thunk_functions: usize,
    pub tail_thunk_functions: usize,
    pub tiny_functions_le8: usize,
    pub tiny_functions_le32: usize,
    pub hit_function_limit: bool,
    pub hit_block_limit: bool,
    pub hit_instruction_limit: bool,
    pub hit_timeout: bool,
}

#[derive(Debug, Clone)]
pub struct ScanRejection {
    pub va: u64,
    pub source_va: Option<u64>,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
struct SingleFunctionDiscoveryStats {
    hit_block_limit: bool,
    hit_instruction_limit: bool,
    hit_timeout: bool,
}

#[derive(Debug, Clone, Default)]
struct FunctionShapeStats {
    thunk_functions: usize,
    import_thunk_functions: usize,
    tail_thunk_functions: usize,
    tiny_functions_le8: usize,
    tiny_functions_le32: usize,
}

#[derive(Debug, Clone, Default)]
struct PdataSeedStats {
    entries: usize,
    accepted_starts: usize,
    zero_begin_rejected: usize,
    zero_begin_rejected_starts: Vec<u64>,
    zero_size_rejected: usize,
    zero_size_rejected_starts: Vec<u64>,
    overlapping_entries: usize,
    chained_unwind_rejected: usize,
    chained_unwind_rejected_starts: Vec<u64>,
    chained_unwind_parsed: usize,
    chained_unwind_parse_failed: usize,
    chained_parent_starts: usize,
    nonexec_rejected: usize,
    nonexec_rejected_starts: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct FunctionXref {
    callsite_va: u64,
    target_va: u64,
    call_type: CallType,
}

#[derive(Debug, Clone)]
pub struct SeedProvenance {
    pub target_va: u64,
    pub source_va: Option<u64>,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct CodeLabel {
    pub va: u64,
    pub function_va: u64,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct PeCodePointer {
    pub pointer_va: u64,
    pub target_va: u64,
    pub section_name: String,
    pub slot_size: usize,
    pub table_index: usize,
    pub table_length: usize,
    pub confidence: String,
}

#[derive(Debug, Clone)]
struct ExecRegion {
    start: u64, // VA
    end: u64,   // VA exclusive
    _file_off_start: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoverySeedKind {
    EntryPoint,
    Symbol,
    Flirt,
    Vtable,
    JumpTable,
    Export,
    Pdata,
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
    fn is_body_overlap_gated(self) -> bool {
        matches!(
            self,
            Self::Prologue
                | Self::Thunk
                | Self::TinyStub
                | Self::DirectCall
                | Self::IndirectCall
                | Self::TailCall
                | Self::DataRef
        )
    }

    fn label(self) -> &'static str {
        match self {
            Self::EntryPoint => "entrypoint",
            Self::Symbol => "symbol",
            Self::Flirt => "flirt",
            Self::Vtable => "vtable",
            Self::JumpTable => "jump_table",
            Self::Export => "export",
            Self::Pdata => "trusted_pdata",
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

/// True when `m` is an ARM condition-suffixed branch (`bne`, `beq`, `bhi`, …):
/// a `b` followed by exactly one of the 16 ARM condition codes. Excludes
/// non-branch `b*` mnemonics such as `bl`, `bx`, `bic`, `bkpt`, `bfi`.
fn is_arm_cond_branch(m: &str) -> bool {
    let Some(cc) = m.strip_prefix('b') else {
        return false;
    };
    matches!(
        cc,
        "eq" | "ne"
            | "cs"
            | "hs"
            | "cc"
            | "lo"
            | "mi"
            | "pl"
            | "vs"
            | "vc"
            | "hi"
            | "ls"
            | "ge"
            | "lt"
            | "gt"
            | "le"
    )
}

/// True when `ins` is an ARM `pop`/`ldm*` that writes `pc` — i.e. a function
/// return. Resolved on operands because the mnemonic alone (`pop`) does not say
/// whether the register list includes `pc`.
fn arm_pop_writes_pc(ins: &Instruction) -> bool {
    let m = ins.mnemonic.to_ascii_lowercase();
    if m == "pop" || m.starts_with("ldm") {
        return ins
            .operands
            .iter()
            .any(|o| o.register.as_deref() == Some("pc"));
    }
    false
}

fn classify_ctrl_flow(mnemonic: &str, arch: BArch) -> (bool, bool, bool) {
    let lower = mnemonic.to_ascii_lowercase();
    // Strip the Thumb-2 `.w`/`.n` width qualifier so `bne.w`, `bl.w`, `b.w`
    // classify the same as their base mnemonics.
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower)
        .to_string();
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
        BArch::ARM => {
            // ARM32/Thumb-2. Returns are `bx lr` / `pop {…,pc}` (the pc-list
            // case is resolved operand-aware in the caller); `bx`/`bxns` end a
            // block either way. Calls are `bl`/`blx`. Branches are `b`, the
            // condition-suffixed `b<cond>` (bne/beq/…), and Thumb `cbz`/`cbnz`.
            if m == "bx" || m == "bxns" || m == "ret" {
                return (false, false, true);
            }
            if m == "bl" || m == "blx" {
                return (false, true, false);
            }
            if m == "b" || m == "b.w" || m == "cbz" || m == "cbnz" || is_arm_cond_branch(&m) {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::AArch64 => {
            // Returns, including ARMv8.3 pointer-authenticated returns
            // (RETAA/RETAB) that a PAC-hardened Pixel binary emits instead of
            // a plain RET at every function epilogue.
            if m == "ret" || m == "retaa" || m == "retab" {
                return (false, false, true);
            }
            // Calls: direct BL plus register-indirect BLR and its
            // pointer-authenticated forms (BLRAA/BLRAAZ/BLRAB/BLRABZ).
            if m == "bl"
                || m == "blr"
                || m == "blraa"
                || m == "blraaz"
                || m == "blrab"
                || m == "blrabz"
            {
                return (false, true, false);
            }
            // Unconditional and conditional branches. BR and its authenticated
            // variants (BRAA/BRAAZ/BRAB/BRABZ) are register-indirect branches —
            // typically tail calls or jump tables; without them the linear
            // sweep would run straight through a tail call into unrelated code.
            if m == "b"
                || m == "br"
                || m == "braa"
                || m == "braaz"
                || m == "brab"
                || m == "brabz"
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

/// Whether a branch mnemonic is unconditional (no fallthrough edge).
///
/// Conditional branches (`b.<cond>`, `cbz`/`cbnz`, `tbz`/`tbnz`, x86 `j<cc>`)
/// must still queue their fallthrough successor; unconditional ones must not,
/// or the sweep spills into the literal pool / next function that follows a
/// tail call.
fn is_unconditional_branch_mnemonic(mnemonic: &str, arch: BArch) -> bool {
    let m = mnemonic.to_ascii_lowercase();
    match arch {
        BArch::ARM | BArch::AArch64 => matches!(
            m.as_str(),
            // `b.w` is the Thumb-2 wide unconditional branch.
            "b" | "b.w" | "br" | "braa" | "braaz" | "brab" | "brabz"
        ),
        BArch::X86 | BArch::X86_64 => m == "jmp",
        // Preserve the historical (arch-agnostic) semantics for the remaining
        // architectures so this refactor is behaviour-preserving for them.
        _ => m == "jmp" || m == "b",
    }
}

fn immediate_target(ins: &Instruction) -> Option<u64> {
    // Heuristic: use first immediate operand if present (our adapters parse simple immediates)
    ins.operands
        .iter()
        .find_map(|op| op.immediate)
        .map(|v| v as u64)
}

fn memory_operand_va(ins: &Instruction) -> Option<u64> {
    ins.operands.iter().find_map(|op| {
        let disp = op.displacement?;
        if disp < 0 {
            return None;
        }
        if op.base.as_deref() == Some("rip") || op.base.is_none() {
            Some(disp as u64)
        } else {
            None
        }
    })
}

fn read_pointer_at_va(data: &[u8], va: u64, bits: u8) -> Option<u64> {
    let file_off = crate::analysis::entry::va_to_file_offset(data, va)
        .or_else(|| pe_va_to_file_off(data, va))?;
    if bits >= 64 {
        let raw = data.get(file_off..file_off + 8)?;
        Some(u64::from_le_bytes(raw.try_into().ok()?))
    } else {
        let raw = data.get(file_off..file_off + 4)?;
        Some(u32::from_le_bytes(raw.try_into().ok()?) as u64)
    }
}

fn indirect_memory_target(data: &[u8], ins: &Instruction, bits: u8) -> Option<u64> {
    let slot_va = memory_operand_va(ins)?;
    read_pointer_at_va(data, slot_va, bits)
}

fn is_code_padding_terminator(mnemonic: &str, arch: BArch) -> bool {
    if !(arch == BArch::X86 || arch == BArch::X86_64) {
        return false;
    }
    matches!(mnemonic.to_ascii_lowercase().as_str(), "int3" | "ud2")
}

fn pe_tail_target_looks_like_function_start(data: &[u8], target_va: u64) -> bool {
    let Some(file_off) = pe_va_to_file_off(data, target_va) else {
        return false;
    };
    if file_off >= data.len() {
        return false;
    }
    if has_function_boundary_marker(data, file_off) {
        return true;
    }
    let head_end = std::cmp::min(file_off.saturating_add(16), data.len());
    classify_pe_thunk_head(target_va, &data[file_off..head_end]).is_some()
}

/// Discover a single function starting at `entry` within executable regions.
fn discover_function(
    data: &[u8],
    arch: BArch,
    end: Endianness,
    entry: Address,
    regions: &[ExecRegion],
    budgets: &Budgets,
) -> Option<(Function, Vec<FunctionXref>, SingleFunctionDiscoveryStats)> {
    let darch: crate::core::disassembler::Architecture = arch.into();
    let mut backend = registry::for_arch(darch, end)?;
    // ARM32 is decoded as Thumb-2 (Cortex-M is Thumb-only; modern
    // arm-linux-gnueabihf defaults to Thumb). Matches the lifter default in
    // `ir::lift_function`. A32-only binaries are a documented follow-up.
    if matches!(arch, BArch::ARM) {
        // Best-effort: on the off chance the backend rejects the mode switch we
        // fall back to A32 decoding rather than aborting discovery.
        let _ = backend.set_thumb_mode(true);
    }
    let bits = darch.address_bits();
    let t0 = std::time::Instant::now();
    let mut stats = SingleFunctionDiscoveryStats::default();

    // BFS over basic block starts
    use std::collections::{HashMap, VecDeque};
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut blocks: HashMap<u64, (u64, u32)> = HashMap::new(); // start_va -> (end_va, instr_count)
    let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = Vec::new();
    let mut call_edges: Vec<FunctionXref> = Vec::new();

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
            stats.hit_block_limit = true;
            break;
        }
        if t0.elapsed().as_millis() as u64 > budgets.timeout_ms {
            stats.hit_timeout = true;
            break;
        }
        // Decode sequentially until a terminating control flow or budget hit
        let mut cur_va = start_va;
        let mut instrs = 0u32;
        'block: loop {
            if decoded_instructions >= budgets.max_instructions {
                stats.hit_instruction_limit = true;
                break 'block;
            }
            if t0.elapsed().as_millis() as u64 > budgets.timeout_ms {
                stats.hit_timeout = true;
                break 'block;
            }
            // Basic-block leader rule: if the linear sweep has reached the start
            // of another already-discovered block (a branch/fallthrough target
            // in `seen`), the current block ends here and falls through to it.
            // Without this a block that falls into a jump-target (e.g. a rotated
            // `-O0` loop's body falling into its condition block) would swallow
            // the successor's instructions and inherit its edges, destroying the
            // back-edge so no natural loop is recovered.
            if cur_va != start_va && seen.contains(&cur_va) {
                edges.push((start_va, cur_va, ControlFlowEdgeKind::Fallthrough));
                blocks.insert(start_va, (cur_va, instrs));
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
            if is_code_padding_terminator(&ins.mnemonic, arch) {
                blocks.insert(start_va, (end_va, instrs));
                break 'block;
            }
            let (is_branch, is_call, mut is_ret) = classify_ctrl_flow(&ins.mnemonic, arch);
            // ARM `pop {…, pc}` / `ldm …, pc` is a return; the mnemonic alone
            // can't say so, so resolve it on the operands here.
            if matches!(arch, BArch::ARM) && arm_pop_writes_pc(&ins) {
                is_ret = true;
            }
            if is_call {
                // Fallthrough continues; preserve the exact instruction VA
                // so downstream xref tables can report callsites, not just
                // caller-function granularity.
                if let Some(tgt) = immediate_target(&ins) {
                    call_edges.push(FunctionXref {
                        callsite_va: cur_va,
                        target_va: tgt,
                        call_type: CallType::Direct,
                    });
                } else if let Some(tgt) = indirect_memory_target(data, &ins, bits) {
                    call_edges.push(FunctionXref {
                        callsite_va: cur_va,
                        target_va: tgt,
                        call_type: CallType::Indirect,
                    });
                }
                // continue to fallthrough
            } else if is_branch {
                // Determine conditional vs unconditional by mnemonic content
                let unconditional = is_unconditional_branch_mnemonic(&ins.mnemonic, arch);
                if let Some(tgt) = immediate_target(&ins) {
                    let is_exec_target = in_exec_regions(regions, tgt).is_some();
                    let is_pe_tail_target = unconditional
                        && data.len() >= 2
                        && &data[..2] == b"MZ"
                        && is_exec_target
                        && pe_tail_target_looks_like_function_start(data, tgt);
                    if is_pe_tail_target {
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
                    }
                } else if unconditional {
                    if let Some(tgt) = indirect_memory_target(data, &ins, bits) {
                        call_edges.push(FunctionXref {
                            callsite_va: cur_va,
                            target_va: tgt,
                            call_type: CallType::Tail,
                        });
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

    Some((func, call_edges, stats))
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
    has_function_boundary_marker(data, file_off) || head_looks_like_fn_start(&data[file_off..])
}

fn has_function_boundary_marker(data: &[u8], file_off: usize) -> bool {
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
    false
}

fn head_looks_like_fn_start(head: &[u8]) -> bool {
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

fn cap_discovered_functions_at_va(functions: &mut [Function], va: u64) -> usize {
    let mut capped = 0usize;
    for func in functions.iter_mut() {
        if va <= func.entry_point.value || !va_in_function_body(func, va) {
            continue;
        }
        let mut changed = false;
        for block in &mut func.basic_blocks {
            let start = block.start_address.value;
            let end = block.end_address.value;
            if start < va && va < end {
                block.end_address.value = va;
                changed = true;
            }
        }
        let before_blocks = func.basic_blocks.len();
        func.basic_blocks.retain(|block| {
            block.start_address.value < va && block.end_address.value > block.start_address.value
        });
        changed |= func.basic_blocks.len() != before_blocks;
        let before_chunks = func.chunks.len();
        for chunk in &mut func.chunks {
            let start = chunk.start.value;
            let end = start.saturating_add(chunk.size);
            if start < va && va < end {
                chunk.size = va - start;
                changed = true;
            }
        }
        func.chunks
            .retain(|chunk| chunk.start.value < va && chunk.size > 0);
        changed |= func.chunks.len() != before_chunks;
        if let Some(range) = &mut func.range {
            let start = range.start.value;
            let end = start.saturating_add(range.size);
            if start < va && va < end {
                range.size = va - start;
                func.size = Some(range.size);
                changed = true;
            } else if start >= va {
                func.range = None;
                func.size = Some(0);
                changed = true;
            }
        }
        func.edges
            .retain(|(from, to)| from.value < va && to.value < va);
        if changed {
            if func.range.is_none() {
                if let Some(first) = func.chunks.first().cloned() {
                    func.size = Some(first.size);
                    func.range = Some(first);
                }
            }
            capped = capped.saturating_add(1);
        }
    }
    capped
}

fn pe_xref_seed_looks_like_function_start(data: &[u8], va: u64) -> bool {
    match pe_va_to_file_off(data, va) {
        Some(file_off) => {
            if file_off >= data.len() {
                return false;
            }
            !pe_head_looks_like_simd_continuation(&data[file_off..])
                && looks_like_fn_start(data, file_off)
        }
        None => false,
    }
}

fn record_seed_provenance(
    stats: &mut FunctionDiscoveryStats,
    target_va: u64,
    source_va: Option<u64>,
    kind: DiscoverySeedKind,
    detail: impl Into<String>,
) {
    let label = kind.label().to_string();
    stats
        .seed_kind_counts
        .entry(label.clone())
        .and_modify(|count| *count = count.saturating_add(1))
        .or_insert(1);
    stats.seed_provenance.push(SeedProvenance {
        target_va,
        source_va,
        kind: label,
        detail: detail.into(),
    });
}

fn record_scan_rejection(
    stats: &mut FunctionDiscoveryStats,
    va: u64,
    source_va: Option<u64>,
    reason: impl Into<String>,
    detail: impl Into<String>,
) {
    let reason = reason.into();
    stats
        .scan_rejection_counts
        .entry(reason.clone())
        .and_modify(|count| *count = count.saturating_add(1))
        .or_insert(1);
    stats.scan_rejections.push(ScanRejection {
        va,
        source_va,
        reason,
        detail: detail.into(),
    });
}

fn align_up_u64(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .unwrap_or(value)
}

fn pe_prologue_scan_candidate(data: &[u8], file_off: usize) -> bool {
    has_function_boundary_marker(data, file_off) && head_looks_like_fn_start(&data[file_off..])
}

/// Conservative PE start-pattern scan for leaf/tiny functions that are not
/// exported, covered by `.pdata`, or reached by direct calls.
///
/// This intentionally scans only 16-byte-aligned executable VAs and requires
/// both an MSVC-style boundary marker and a recognized prologue/thunk head.
/// Candidates are queued after trusted export/`.pdata` seeds, so the later
/// body-overlap gate can discard candidates that fall inside an already
/// discovered function.
// AArch64 hardened function-entry signatures (little-endian 32-bit words).
const AARCH64_PACIASP: u32 = 0xd503_233f;
const AARCH64_PACIBSP: u32 = 0xd503_237f;
const AARCH64_BTI_C: u32 = 0xd503_245f;
const AARCH64_BTI_JC: u32 = 0xd503_24df;

/// Scan AArch64 executable regions for pointer-authentication function
/// prologues, recovering entry points on **stripped** hardened binaries where
/// no symbol table survives.
///
/// The reliable entry signal is `PACIASP`/`PACIBSP` — a function that signs its
/// return address does so as its first real instruction. When the function is
/// also a BTI target the compiler emits a `BTI c`/`BTI jc` landing pad one word
/// earlier, which is the true entry, so we rewind to it. A bare `BTI c` is *not*
/// used as a seed: it also guards internal branch targets and would over-generate.
fn scan_aarch64_prologue_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if arch != BArch::AArch64 {
        return Vec::new();
    }
    let read_word = |va: u64| -> Option<u32> {
        let off = crate::analysis::entry::va_to_file_offset(data, va)?;
        let b = data.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    let mut starts = Vec::new();
    for region in regions {
        let mut va = align_up_u64(region.start, 4);
        while va + 4 <= region.end {
            if let Some(word) = read_word(va) {
                if word == AARCH64_PACIASP || word == AARCH64_PACIBSP {
                    // Rewind to a preceding BTI landing pad if present.
                    let start = match va.checked_sub(4) {
                        Some(prev)
                            if prev >= region.start
                                && matches!(read_word(prev), Some(AARCH64_BTI_C | AARCH64_BTI_JC)) =>
                        {
                            prev
                        }
                        _ => va,
                    };
                    starts.push(start);
                }
            }
            va = match va.checked_add(4) {
                Some(next) => next,
                None => break,
            };
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

fn scan_pe_prologue_function_starts(data: &[u8], regions: &[ExecRegion], arch: BArch) -> Vec<u64> {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let mut starts = Vec::new();
    for region in regions {
        let mut va = align_up_u64(region.start, 16);
        while va < region.end {
            if let Some(file_off) = pe_va_to_file_off(data, va) {
                if file_off < data.len() && pe_prologue_scan_candidate(data, file_off) {
                    starts.push(va);
                }
            }
            va = match va.checked_add(16) {
                Some(next) => next,
                None => break,
            };
        }
    }
    starts
}

fn thunk_scan_has_padding(data: &[u8], file_off: usize, len: usize) -> bool {
    if has_function_boundary_marker(data, file_off) {
        return true;
    }
    matches!(
        data.get(file_off.saturating_add(len)),
        Some(0xcc | 0x90 | 0xc3)
    )
}

fn pe_thunk_scan_candidate(data: &[u8], file_off: usize, va: u64, _regions: &[ExecRegion]) -> bool {
    if file_off >= data.len() {
        return false;
    }
    let Some(matched) = classify_pe_thunk_head(va, &data[file_off..]) else {
        return false;
    };
    match matched.kind {
        PeThunkKind::ImportMemory => {
            ((matched.length == 6 && data.get(file_off..file_off + 2) == Some(&[0xff, 0x25]))
                || (matched.length == 7
                    && data.get(file_off..file_off + 3) == Some(&[0x48, 0xff, 0x25])))
                && (file_off == 0 || data.get(file_off - 1) != Some(&0x48))
                && va % 8 == 0
                && thunk_scan_has_padding(data, file_off, matched.length)
        }
        PeThunkKind::TailJump => false,
    }
}

fn pe_head_looks_like_simd_continuation(head: &[u8]) -> bool {
    matches!(
        head,
        // movups/movaps and related SSE load/store forms commonly appear
        // after alignment NOPs inside vectorized loops. A raw xref landing
        // there is a block label, not a function entry.
        [0x0f, 0x10 | 0x11 | 0x28 | 0x29 | 0x6f | 0x7f, ..]
            // VEX/EVEX vector op prefixes.
            | [0xc4 | 0xc5 | 0x62, ..]
    )
}

fn is_exec_va(regions: &[ExecRegion], va: u64) -> bool {
    regions.iter().any(|r| va >= r.start && va < r.end)
}

fn is_padding_after(data: &[u8], file_off: usize) -> bool {
    matches!(data.get(file_off), None | Some(0xcc | 0x90 | 0xc3))
}

fn rel32_target_from(data: &[u8], file_off: usize, va: u64, insn_len: u64) -> Option<u64> {
    rel_target(va, insn_len, read_i32_le_at(data, file_off + 1)? as i64)
}

fn pe_adjustor_jump_stub_len(
    data: &[u8],
    file_off: usize,
    va: u64,
    regions: &[ExecRegion],
) -> Option<usize> {
    let head = data.get(file_off..)?;
    if head.len() < 12 || head[0] != 0x48 || !matches!(head[1], 0x8b | 0x8d) {
        return None;
    }
    // mov/lea rcx|rbx, [rdx+disp32]
    if !matches!(head[2], 0x8a | 0x9a) {
        return None;
    }
    let mut jmp_off = file_off + 7;
    let mut len = 12usize;
    if data.get(jmp_off) != Some(&0xe9) {
        // Optional add rcx/rbx, imm8 before the jump.
        if head.len() < 16 || head[7] != 0x48 || head[8] != 0x83 {
            return None;
        }
        match (head[2], head[9]) {
            (0x8a, 0xc1) | (0x9a, 0xc3) => {}
            _ => return None,
        }
        jmp_off = file_off + 11;
        len = 16;
    }
    if data.get(jmp_off) != Some(&0xe9) {
        return None;
    }
    let jmp_va = va.checked_add((jmp_off - file_off) as u64)?;
    let target = rel32_target_from(data, jmp_off, jmp_va, 5)?;
    if !is_exec_va(regions, target) {
        return None;
    }
    Some(len)
}

fn pe_tiny_return_helper_len(data: &[u8], file_off: usize) -> Option<usize> {
    let head = data.get(file_off..)?;
    if head.len() >= 3 && head[0] == 0xc2 {
        return Some(3);
    }
    if head.len() >= 3 && head[0..3] == [0x33, 0xc0, 0xc3] {
        return Some(3);
    }
    if head.len() >= 6 && head[0] == 0xb8 && head[5] == 0xc3 {
        return Some(6);
    }
    // Tiny move/lea/load/store helper ending in ret, bounded tightly to avoid
    // mistaking vectorized loop labels for functions.
    if !matches!(
        head.first(),
        Some(0x32 | 0x33 | 0x40 | 0x45 | 0x48 | 0x49 | 0x4c | 0x4d | 0x8a | 0x8b)
    ) {
        return None;
    }
    if pe_head_looks_like_simd_continuation(head) {
        return None;
    }
    let max_len = std::cmp::min(32, head.len());
    for idx in 1..max_len {
        if head[idx] == 0xc3 {
            if head[..idx]
                .iter()
                .any(|b| matches!(*b, 0xe8 | 0xe9 | 0xeb | 0xcc))
            {
                return None;
            }
            return Some(idx + 1);
        }
    }
    None
}

fn pe_tiny_stub_scan_candidate(
    data: &[u8],
    file_off: usize,
    va: u64,
    regions: &[ExecRegion],
) -> bool {
    if file_off >= data.len() {
        return false;
    }
    if pe_head_looks_like_simd_continuation(&data[file_off..]) {
        return false;
    }
    if let Some(len) = pe_adjustor_jump_stub_len(data, file_off, va, regions) {
        return is_padding_after(data, file_off.saturating_add(len))
            || has_function_boundary_marker(data, file_off)
            || data.get(file_off.saturating_add(len)..).is_some_and(|_| {
                pe_adjustor_jump_stub_len(data, file_off + len, va + len as u64, regions).is_some()
                    || pe_prologue_scan_candidate(data, file_off + len)
                    || head_looks_like_fn_start(&data[file_off + len..])
            });
    }
    if va % 4 != 0 {
        return false;
    }
    if !has_function_boundary_marker(data, file_off) {
        return false;
    }
    pe_tiny_return_helper_len(data, file_off)
        .map(|len| is_padding_after(data, file_off.saturating_add(len)))
        .unwrap_or(false)
}

fn pe_tiny_stub_scan_promotes_candidate(
    data: &[u8],
    file_off: usize,
    va: u64,
    regions: &[ExecRegion],
    code_pointer_targets: &std::collections::HashSet<u64>,
) -> bool {
    pe_tiny_stub_scan_candidate(data, file_off, va, regions)
        && (pe_adjustor_jump_stub_len(data, file_off, va, regions).is_none()
            || code_pointer_targets.contains(&va))
}

#[derive(Debug, Clone, Default)]
struct PeTinyStubScanResult {
    starts: Vec<u64>,
    pdata_rejected: Vec<u64>,
    unpromoted_candidates: Vec<u64>,
}

fn scan_pe_tiny_stub_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
    pdata_starts: &std::collections::HashSet<u64>,
    code_pointer_targets: &std::collections::HashSet<u64>,
) -> PeTinyStubScanResult {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return PeTinyStubScanResult::default();
    }
    let mut result = PeTinyStubScanResult::default();
    for region in regions {
        let mut va = region.start;
        while va < region.end {
            if pdata_starts.contains(&va) {
                result.pdata_rejected.push(va);
            } else if let Some(file_off) = pe_va_to_file_off(data, va) {
                if file_off < data.len() && pe_tiny_stub_scan_candidate(data, file_off, va, regions)
                {
                    if pe_tiny_stub_scan_promotes_candidate(
                        data,
                        file_off,
                        va,
                        regions,
                        code_pointer_targets,
                    ) {
                        result.starts.push(va);
                    } else {
                        result.unpromoted_candidates.push(va);
                    }
                }
            }
            va = match va.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
    }
    result
}

fn pe_low_confidence_call_target_head(data: &[u8], file_off: usize) -> bool {
    if file_off >= data.len() {
        return false;
    }
    if pe_head_looks_like_simd_continuation(&data[file_off..]) {
        return false;
    }
    let head = &data[file_off..];
    if head_looks_like_fn_start(head) || pe_tiny_return_helper_len(data, file_off).is_some() {
        return true;
    }
    matches!(
        head,
        [0x48, 0x3b | 0x63 | 0x83 | 0x8b | 0x8d | 0x89, ..]
            | [0x4c, 0x3b | 0x63 | 0x8b | 0x8d | 0x89, ..]
            | [0x45, 0x33 | 0x85, ..]
            | [0x33, 0xd2, 0x33, 0xc9, ..]
            | [0xc7, 0x44, 0x24, ..]
            | [0x8b | 0x0f, ..]
    )
}

fn classify_code_label(data: &[u8], va: u64) -> String {
    let Some(file_off) = pe_va_to_file_off(data, va) else {
        return "block_label".to_string();
    };
    if file_off >= data.len() {
        return "block_label".to_string();
    }
    let head = &data[file_off..];
    if pe_head_looks_like_simd_continuation(head) {
        return "simd_block_label".to_string();
    }
    if matches!(head, [0x48, 0x8b, _, 0x24, ..] | [0x48, 0x83, 0xc4, ..])
        || pe_tiny_return_helper_len(data, file_off).is_some()
    {
        return "epilogue_label".to_string();
    }
    if matches!(head, [0xe8, ..] | [0xe9, ..] | [0xeb, ..]) {
        return "block_label".to_string();
    }
    "block_label".to_string()
}

fn collect_code_labels(data: &[u8], functions: &[Function]) -> Vec<CodeLabel> {
    let mut labels = Vec::new();
    for func in functions {
        for bb in &func.basic_blocks {
            let va = bb.start_address.value;
            if va == func.entry_point.value {
                continue;
            }
            labels.push(CodeLabel {
                va,
                function_va: func.entry_point.value,
                kind: classify_code_label(data, va),
            });
        }
    }
    labels.sort_by_key(|label| (label.function_va, label.va));
    labels.dedup_by_key(|label| (label.function_va, label.va));
    labels
}

#[derive(Debug, Clone, Copy)]
struct PeRawCallFunctionStart {
    va: u64,
    allow_body_split: bool,
}

fn scan_pe_raw_call_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
    pdata_starts: &std::collections::HashSet<u64>,
) -> Vec<PeRawCallFunctionStart> {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let mut target_counts: std::collections::BTreeMap<u64, usize> =
        std::collections::BTreeMap::new();
    for region in regions {
        let Some(region_off) = pe_va_to_file_off(data, region.start) else {
            continue;
        };
        let span = std::cmp::min(
            (region.end - region.start) as usize,
            data.len().saturating_sub(region_off),
        );
        for rel in 0..span.saturating_sub(5) {
            let file_off = region_off + rel;
            if data.get(file_off) != Some(&0xe8) {
                continue;
            }
            let call_va = region.start + rel as u64;
            let Some(target_va) = rel32_target_from(data, file_off, call_va, 5) else {
                continue;
            };
            *target_counts.entry(target_va).or_default() += 1;
        }
    }
    target_counts
        .into_iter()
        .filter_map(|(target_va, count)| {
            if pdata_starts.contains(&target_va) || !is_exec_va(regions, target_va) {
                return None;
            }
            let target_off = pe_va_to_file_off(data, target_va)?;
            if target_off >= data.len()
                || pe_head_looks_like_simd_continuation(&data[target_off..])
                || pe_tiny_stub_scan_candidate(data, target_off, target_va, regions)
            {
                return None;
            }
            let boundary = has_function_boundary_marker(data, target_off);
            let boundary_low_confidence =
                boundary && pe_low_confidence_call_target_head(data, target_off);
            let repeated_strong_head = count >= 2
                && (head_looks_like_fn_start(&data[target_off..])
                    || pe_tiny_return_helper_len(data, target_off).is_some());
            let repeated_low_confidence =
                count >= 3 && pe_low_confidence_call_target_head(data, target_off);
            if boundary_low_confidence || repeated_strong_head || repeated_low_confidence {
                Some(PeRawCallFunctionStart {
                    va: target_va,
                    allow_body_split: boundary_low_confidence && count >= 3,
                })
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct PeSectionScan {
    name: String,
    virtual_address: u32,
    raw_pointer: u32,
    raw_size: u32,
    characteristics: u32,
}

fn parse_pe_image_base_and_sections(data: &[u8]) -> Option<(u64, Vec<PeSectionScan>)> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
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
    let e_lfanew = read_u32(0x3c)? as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    let n_sections = read_u16(coff_off + 2)? as usize;
    let opt_size = read_u16(coff_off + 16)? as usize;
    let opt_off = coff_off + 20;
    let magic = read_u16(opt_off)?;
    let image_base = match magic {
        0x20B => read_u64(opt_off + 24)?,
        0x10B => read_u32(opt_off + 28)? as u64,
        _ => return None,
    };
    let sec_off = opt_off + opt_size;
    let mut sections = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_name = data.get(s..s + 8)?;
        let name_len = raw_name
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_len]).to_string();
        sections.push(PeSectionScan {
            name,
            virtual_address: read_u32(s + 12).unwrap_or(0),
            raw_pointer: read_u32(s + 20).unwrap_or(0),
            raw_size: read_u32(s + 16).unwrap_or(0),
            characteristics: read_u32(s + 36).unwrap_or(0),
        });
    }
    Some((image_base, sections))
}

fn pe_code_pointer_target_confidence(data: &[u8], target_off: usize) -> Option<&'static str> {
    if target_off >= data.len() || pe_head_looks_like_simd_continuation(&data[target_off..]) {
        return None;
    }
    if has_function_boundary_marker(data, target_off) {
        return Some("boundary");
    }
    if head_looks_like_fn_start(&data[target_off..])
        || pe_tiny_return_helper_len(data, target_off).is_some()
    {
        return Some("head");
    }
    if pe_low_confidence_call_target_head(data, target_off) {
        return Some("low_confidence_head");
    }
    None
}

/// Scan PE data sections for image-VA pointers that land in executable code.
///
/// This is intentionally data-reference provenance, not a broad code sweep:
/// it scans aligned pointer slots in readable, non-executable PE sections and
/// only accepts targets that already look like plausible function starts.
pub fn scan_pe_code_pointers(data: &[u8]) -> Vec<PeCodePointer> {
    let (regions, arch, _end, _entry) = parse_exec_regions(data);
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let Some((image_base, sections)) = parse_pe_image_base_and_sections(data) else {
        return Vec::new();
    };
    let pointer_size = 8usize;
    let mut pointers = Vec::new();
    for section in sections {
        let executable = section.characteristics & 0x2000_0000 != 0;
        let readable = section.characteristics & 0x4000_0000 != 0;
        if executable || !readable || section.raw_size < pointer_size as u32 {
            continue;
        }
        let name_lower = section.name.to_ascii_lowercase();
        if matches!(
            name_lower.as_str(),
            ".rsrc" | ".reloc" | ".debug" | ".pdata" | ".xdata"
        ) {
            continue;
        }
        let raw_start = section.raw_pointer as usize;
        if raw_start >= data.len() {
            continue;
        }
        let raw_len = std::cmp::min(section.raw_size as usize, data.len() - raw_start);
        let mut section_hits: Vec<(u64, u64, &'static str, usize)> = Vec::new();
        for slot_size in [8usize, 4usize] {
            let mut rel = 0usize;
            while rel + slot_size <= raw_len {
                let slot_off = raw_start + rel;
                let raw = if slot_size == 8 {
                    u64::from_le_bytes(match data.get(slot_off..slot_off + slot_size) {
                        Some(bytes) => match bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => break,
                        },
                        None => break,
                    })
                } else {
                    u32::from_le_bytes(match data.get(slot_off..slot_off + slot_size) {
                        Some(bytes) => match bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => break,
                        },
                        None => break,
                    }) as u64
                };
                let candidates: [Option<u64>; 2] = if slot_size == 8 {
                    [Some(raw), None]
                } else {
                    [image_base.checked_add(raw), None]
                };
                for target_va in candidates.into_iter().flatten() {
                    if target_va >= image_base && is_exec_va(&regions, target_va) {
                        if let Some(target_off) = pe_va_to_file_off(data, target_va) {
                            if let Some(confidence) =
                                pe_code_pointer_target_confidence(data, target_off)
                            {
                                let pointer_va =
                                    image_base + section.virtual_address as u64 + rel as u64;
                                section_hits.push((pointer_va, target_va, confidence, slot_size));
                            }
                        }
                    }
                }
                rel = rel.saturating_add(slot_size);
            }
        }
        section_hits.sort_by_key(|hit| (hit.0, hit.1));
        section_hits.dedup_by_key(|hit| (hit.0, hit.1));
        let mut table_index = 0usize;
        let mut idx = 0usize;
        while idx < section_hits.len() {
            let run_start = idx;
            while idx + 1 < section_hits.len()
                && section_hits[idx + 1].0 == section_hits[idx].0 + section_hits[idx].3 as u64
            {
                idx += 1;
            }
            let run_end = idx;
            let table_length = run_end - run_start + 1;
            for (pointer_va, target_va, confidence, slot_size) in &section_hits[run_start..=run_end]
            {
                pointers.push(PeCodePointer {
                    pointer_va: *pointer_va,
                    target_va: *target_va,
                    section_name: section.name.clone(),
                    slot_size: *slot_size,
                    table_index,
                    table_length,
                    confidence: (*confidence).to_string(),
                });
            }
            table_index = table_index.saturating_add(1);
            idx += 1;
        }
    }
    pointers.sort_by_key(|ptr| (ptr.pointer_va, ptr.target_va));
    pointers.dedup_by_key(|ptr| (ptr.pointer_va, ptr.target_va));
    pointers
}

fn should_seed_pe_code_pointer(ptr: &PeCodePointer) -> bool {
    if ptr.slot_size == 8 {
        return true;
    }
    ptr.slot_size == 4 && ptr.table_length >= 8 && ptr.confidence == "boundary"
}

/// Scan executable PE bytes for compact thunk-table entries that are not
/// necessarily 16-byte aligned and may not carry unwind metadata.
fn scan_pe_thunk_function_starts(data: &[u8], regions: &[ExecRegion], arch: BArch) -> Vec<u64> {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let mut starts = Vec::new();
    for region in regions {
        let mut va = region.start;
        while va < region.end {
            if let Some(file_off) = pe_va_to_file_off(data, va) {
                if file_off < data.len() && pe_thunk_scan_candidate(data, file_off, va, regions) {
                    starts.push(va);
                }
            }
            va = match va.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
    }
    starts
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeThunkKind {
    /// A direct jump to another code address.
    TailJump,
    /// A jump/call wrapper through an IAT-like memory slot.
    ImportMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeThunkMatch {
    kind: PeThunkKind,
    target_va: u64,
    length: usize,
}

fn add_signed_u64(base: u64, disp: i64) -> Option<u64> {
    if disp >= 0 {
        base.checked_add(disp as u64)
    } else {
        base.checked_sub(disp.unsigned_abs())
    }
}

fn read_i32_le_at(data: &[u8], off: usize) -> Option<i32> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_le_bytes)
}

fn rel_target(entry_va: u64, insn_len: u64, disp: i64) -> Option<u64> {
    add_signed_u64(entry_va.checked_add(insn_len)?, disp)
}

/// Classify PE/x86 function heads that are really tiny thunk wrappers.
///
/// This is intentionally narrower than `looks_like_fn_start`: that helper
/// decides whether an xref target is safe to promote into a function seed,
/// while this one mutates the resulting `Function` metadata. Only canonical
/// one-block jump/call-wrapper shapes are labelled `FunctionKind::Thunk`.
fn classify_pe_thunk_head(entry_va: u64, head: &[u8]) -> Option<PeThunkMatch> {
    // jmp rel32
    if head.len() >= 5 && head[0] == 0xe9 {
        let target_va = rel_target(entry_va, 5, read_i32_le_at(head, 1)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::TailJump,
            target_va,
            length: 5,
        });
    }
    // jmp rel8
    if head.len() >= 2 && head[0] == 0xeb {
        let target_va = rel_target(entry_va, 2, head[1] as i8 as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::TailJump,
            target_va,
            length: 2,
        });
    }
    // jmp qword ptr [rip+disp32] / call qword ptr [rip+disp32]; ret
    if head.len() >= 6 && head[0] == 0xff && (head[1] == 0x25 || head[1] == 0x15) {
        if head[1] == 0x15 && head.get(6) != Some(&0xc3) {
            return None;
        }
        let target_va = rel_target(entry_va, 6, read_i32_le_at(head, 2)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::ImportMemory,
            target_va,
            length: if head[1] == 0x15 { 7 } else { 6 },
        });
    }
    // REX.W jmp/call qword ptr [rip+disp32].
    if head.len() >= 7 && head[0] == 0x48 && head[1] == 0xff && (head[2] == 0x25 || head[2] == 0x15)
    {
        if head[2] == 0x15 && head.get(7) != Some(&0xc3) {
            return None;
        }
        let target_va = rel_target(entry_va, 7, read_i32_le_at(head, 3)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::ImportMemory,
            target_va,
            length: if head[2] == 0x15 { 8 } else { 7 },
        });
    }
    // mov rax, qword ptr [rip+disp32]; jmp rax
    if head.len() >= 9 && head[0..3] == [0x48, 0x8b, 0x05] && head[7..9] == [0xff, 0xe0] {
        let target_va = rel_target(entry_va, 7, read_i32_le_at(head, 3)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::ImportMemory,
            target_va,
            length: 9,
        });
    }
    None
}

fn classify_function_shapes(
    data: &[u8],
    arch: BArch,
    functions: &mut [Function],
) -> FunctionShapeStats {
    let mut stats = FunctionShapeStats::default();
    let is_pe_image = data.len() >= 2 && &data[..2] == b"MZ";
    let bits = if arch.is_64_bit() { 64 } else { 32 };

    for func in functions {
        let size = func.total_size();
        if size <= 8 {
            stats.tiny_functions_le8 = stats.tiny_functions_le8.saturating_add(1);
        }
        if size <= 32 {
            stats.tiny_functions_le32 = stats.tiny_functions_le32.saturating_add(1);
        }
        if !is_pe_image || !(arch.is_64_bit() || arch == BArch::X86) || size > 32 {
            continue;
        }
        let Some(file_off) = pe_va_to_file_off(data, func.entry_point.value) else {
            continue;
        };
        if file_off >= data.len() {
            continue;
        }
        let head_end = std::cmp::min(file_off.saturating_add(16), data.len());
        let Some(matched) =
            classify_pe_thunk_head(func.entry_point.value, &data[file_off..head_end])
        else {
            continue;
        };
        if let Ok(target) = Address::new(AddressKind::VA, matched.target_va, bits, None, None) {
            func.kind = FunctionKind::Thunk;
            func.thunk_target = Some(target);
            stats.thunk_functions = stats.thunk_functions.saturating_add(1);
            match matched.kind {
                PeThunkKind::TailJump => {
                    stats.tail_thunk_functions = stats.tail_thunk_functions.saturating_add(1);
                }
                PeThunkKind::ImportMemory => {
                    stats.import_thunk_functions = stats.import_thunk_functions.saturating_add(1);
                }
            }
        }
    }

    stats
}

fn unwind_info_flags(data: &[u8], file_off: usize) -> Option<u8> {
    data.get(file_off).map(|first| first >> 3)
}

fn unwind_info_has_chain_info(data: &[u8], file_off: usize) -> bool {
    unwind_info_flags(data, file_off)
        .map(|flags| flags & 0x04 != 0)
        .unwrap_or(false)
}

fn parse_unwind_chain_info(data: &[u8], file_off: usize) -> Option<(u32, u32, u32)> {
    if !unwind_info_has_chain_info(data, file_off) {
        return None;
    }
    let unwind_code_count = *data.get(file_off + 2)? as usize;
    // UNWIND_CODE entries are 2 bytes and the optional trailer starts on
    // a 4-byte boundary, so odd code counts carry one 2-byte padding slot.
    let aligned_code_count = (unwind_code_count + 1) & !1;
    let chain_off = file_off.checked_add(4 + aligned_code_count * 2)?;
    let begin = u32::from_le_bytes(data.get(chain_off..chain_off + 4)?.try_into().ok()?);
    let end = u32::from_le_bytes(data.get(chain_off + 4..chain_off + 8)?.try_into().ok()?);
    let unwind = u32::from_le_bytes(data.get(chain_off + 8..chain_off + 12)?.try_into().ok()?);
    Some((begin, end, unwind))
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
fn parse_pdata_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> (Vec<u64>, PdataSeedStats) {
    let mut stats = PdataSeedStats::default();
    if !arch.is_64_bit() {
        return (Vec::new(), stats);
    }
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return (Vec::new(), stats);
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
        None => return (Vec::new(), stats),
    };
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return (Vec::new(), stats);
    }
    let coff_off = e_lfanew + 4;
    let n_sections = match read_u16(coff_off + 2) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    let opt_size = match read_u16(coff_off + 16) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    let opt_off = coff_off + 20;
    if read_u16(opt_off) != Some(0x20B) {
        // not PE32+ (Win64)
        return (Vec::new(), stats);
    }
    let image_base = match read_u64(opt_off + 24) {
        Some(v) => v,
        None => return (Vec::new(), stats),
    };
    let num_dirs = match read_u32(opt_off + 108) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    if num_dirs < 4 {
        return (Vec::new(), stats);
    }
    let dd_off = opt_off + 112;
    let exc_rva = match read_u32(dd_off + 3 * 8) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    let exc_size = match read_u32(dd_off + 3 * 8 + 4) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    if exc_rva == 0 || exc_size == 0 {
        return (Vec::new(), stats);
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
        None => return (Vec::new(), stats),
    };
    // Walk RUNTIME_FUNCTION entries (12 bytes each on x64:
    //   u32 BeginAddress, u32 EndAddress, u32 UnwindInfoAddress).
    let entry_size = 12usize;
    let n_entries = exc_size / entry_size;
    let cap = 2_000_000usize.min(n_entries);
    let mut starts = Vec::with_capacity(cap);
    let mut previous_range_end: Option<u32> = None;
    for i in 0..cap {
        let off = exc_file_off + i * entry_size;
        if off + 4 > data.len() {
            break;
        }
        let begin_rva = match read_u32(off) {
            Some(v) => v,
            None => break,
        };
        stats.entries = stats.entries.saturating_add(1);
        if begin_rva == 0 {
            stats.zero_begin_rejected = stats.zero_begin_rejected.saturating_add(1);
            stats.zero_begin_rejected_starts.push(image_base);
            continue;
        }
        let end_rva = match read_u32(off + 4) {
            Some(v) => v,
            None => break,
        };
        if end_rva <= begin_rva {
            stats.zero_size_rejected = stats.zero_size_rejected.saturating_add(1);
            stats
                .zero_size_rejected_starts
                .push(image_base + begin_rva as u64);
            continue;
        }
        if previous_range_end
            .map(|prev_end| begin_rva < prev_end)
            .unwrap_or(false)
        {
            stats.overlapping_entries = stats.overlapping_entries.saturating_add(1);
        }
        previous_range_end = Some(previous_range_end.map_or(end_rva, |prev| prev.max(end_rva)));
        let unwind_rva = match read_u32(off + 8) {
            Some(v) => v as usize,
            None => break,
        };
        if let Some(unwind_off) = rva_to_off(unwind_rva) {
            if unwind_info_has_chain_info(data, unwind_off) {
                stats.chained_unwind_rejected = stats.chained_unwind_rejected.saturating_add(1);
                stats
                    .chained_unwind_rejected_starts
                    .push(image_base + begin_rva as u64);
                if let Some((parent_begin, parent_end, _parent_unwind)) =
                    parse_unwind_chain_info(data, unwind_off)
                {
                    stats.chained_unwind_parsed = stats.chained_unwind_parsed.saturating_add(1);
                    if parent_begin != 0 && parent_end > parent_begin {
                        let parent_va = image_base + parent_begin as u64;
                        if in_exec_regions(regions, parent_va).is_some() {
                            stats.chained_parent_starts =
                                stats.chained_parent_starts.saturating_add(1);
                        }
                    }
                } else {
                    stats.chained_unwind_parse_failed =
                        stats.chained_unwind_parse_failed.saturating_add(1);
                }
                continue;
            }
        }
        let va = image_base + begin_rva as u64;
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        } else {
            stats.nonexec_rejected = stats.nonexec_rejected.saturating_add(1);
            stats.nonexec_rejected_starts.push(va);
        }
    }
    stats.accepted_starts = starts.len();
    (starts, stats)
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

/// Normalise a symbol/target VA to its code address. On ARM, function symbols
/// and branch targets for Thumb code carry the T-bit (LSB=1); the actual
/// instruction stream is at the even address, so clear it. No-op elsewhere.
fn code_addr(va: u64, arch: BArch) -> u64 {
    if matches!(arch, BArch::ARM) {
        va & !1
    } else {
        va
    }
}

fn parse_function_seeds(data: &[u8], regions: &[ExecRegion], arch: BArch) -> Vec<Address> {
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let mut seeds: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    if let Ok(obj) = object::read::File::parse(data) {
        // Symbols defined in executable regions. We do NOT special-case
        // addr==0: `in_exec_regions` already excludes address 0 in linked
        // binaries (where it is never executable), while keeping a genuine
        // function at offset 0 in a relocatable object — e.g. the first Thumb
        // function, whose symbol value is the T-bit `1` masked to `0`.
        for sym in obj.symbols() {
            if sym.is_definition() {
                let addr = code_addr(sym.address(), arch);
                if in_exec_regions(regions, addr).is_some() {
                    seeds.insert(addr);
                }
            }
        }
        // Also consider dynamic symbols (ELF .plt entries often appear here)
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                let addr = code_addr(sym.address(), arch);
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
    let (functions, cg, _stats) = analyze_functions_bytes_with_stats(data, budgets);
    (functions, cg)
}

/// Analyze bytes and return discovered functions, callgraph, and budget telemetry.
pub fn analyze_functions_bytes_with_stats(
    data: &[u8],
    budgets: &Budgets,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    let (regions, arch, end, entry) = parse_exec_regions(data);
    let mut functions: Vec<Function> = Vec::new();
    let mut cg = CallGraph::new();
    let mut stats = FunctionDiscoveryStats {
        max_functions: budgets.max_functions,
        max_blocks: budgets.max_blocks,
        max_instructions: budgets.max_instructions,
        timeout_ms: budgets.timeout_ms,
        ..FunctionDiscoveryStats::default()
    };
    if regions.is_empty() {
        return (functions, cg, stats);
    }

    // Seeds: entrypoint + symbol-defined function addresses (exec region)
    let mut seeds: Vec<(Address, DiscoverySeedKind)> = parse_function_seeds(data, &regions, arch)
        .into_iter()
        .map(|addr| (addr, DiscoverySeedKind::Symbol))
        .collect();
    if let Some(ep) = entry.clone() {
        // Ensure entrypoint first
        seeds.retain(|(a, _kind)| a.value != ep.value);
        let mut ordered = vec![(ep, DiscoverySeedKind::EntryPoint)];
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
    let is_pe_image = data.len() >= 2 && &data[..2] == b"MZ";
    let flirt_name_by_va: std::collections::HashMap<u64, String> =
        flirt_seeds.iter().cloned().collect();
    let mut known: std::collections::HashSet<u64> = seeds.iter().map(|(a, _)| a.value).collect();
    let mut seed_kind_by_va: std::collections::HashMap<u64, DiscoverySeedKind> =
        std::collections::HashMap::new();
    for (addr, kind) in &seeds {
        seed_kind_by_va.entry(addr.value).or_insert(*kind);
        record_seed_provenance(&mut stats, addr.value, None, *kind, "initial_seed");
    }
    for (va, _name) in &flirt_seeds {
        if known.contains(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, *va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Flirt));
            known.insert(*va);
            seed_kind_by_va.insert(*va, DiscoverySeedKind::Flirt);
            record_seed_provenance(&mut stats, *va, None, DiscoverySeedKind::Flirt, "flirt");
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
            seeds.push((addr, DiscoverySeedKind::Vtable));
            known.insert(entry.target_va);
            seed_kind_by_va.insert(entry.target_va, DiscoverySeedKind::Vtable);
            record_seed_provenance(
                &mut stats,
                entry.target_va,
                Some(entry.source_va),
                DiscoverySeedKind::Vtable,
                "vtable",
            );
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
                    seeds.push((addr, DiscoverySeedKind::JumpTable));
                    known.insert(*tgt);
                    seed_kind_by_va.insert(*tgt, DiscoverySeedKind::JumpTable);
                    record_seed_provenance(
                        &mut stats,
                        *tgt,
                        Some(jt.table_va),
                        DiscoverySeedKind::JumpTable,
                        "jump_table",
                    );
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
    stats.export_function_starts = export_starts.len();
    for va in export_starts {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Export));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Export);
            record_seed_provenance(&mut stats, va, None, DiscoverySeedKind::Export, "pe_export");
            stats.export_seeds_inserted = stats.export_seeds_inserted.saturating_add(1);
        }
    }

    // Win64 exception-directory seeds. On x86-64 Windows the calling
    // convention emits a RUNTIME_FUNCTION unwind record for nearly
    // every function; IMAGE_DIRECTORY_ENTRY_EXCEPTION is therefore a
    // near-complete function index for free. This is the single
    // highest-leverage seed source on stripped Windows PE -- it
    // closed most of the ~98% recall gap vs Ghidra on ntdll.dll
    // observed in asb's iter 13 comparison.
    let (pdata_starts, pdata_stats) = parse_pdata_function_starts(data, &regions, arch);
    let pdata_start_set: std::collections::HashSet<u64> = pdata_starts.iter().copied().collect();
    stats.pdata_entries = pdata_stats.entries;
    stats.pdata_function_starts = pdata_stats.accepted_starts;
    stats.pdata_zero_begin_rejected = pdata_stats.zero_begin_rejected;
    stats.pdata_zero_size_rejected = pdata_stats.zero_size_rejected;
    stats.pdata_overlapping_entries = pdata_stats.overlapping_entries;
    stats.pdata_chained_unwind_rejected = pdata_stats.chained_unwind_rejected;
    stats.pdata_chained_unwind_parsed = pdata_stats.chained_unwind_parsed;
    stats.pdata_chained_unwind_parse_failed = pdata_stats.chained_unwind_parse_failed;
    stats.pdata_chained_parent_starts = pdata_stats.chained_parent_starts;
    stats.pdata_nonexec_rejected = pdata_stats.nonexec_rejected;
    for va in &pdata_stats.zero_begin_rejected_starts {
        record_scan_rejection(
            &mut stats,
            *va,
            None,
            "pdata:zero_begin",
            "PE exception directory entry has BeginAddress == 0",
        );
    }
    for va in &pdata_stats.zero_size_rejected_starts {
        record_scan_rejection(
            &mut stats,
            *va,
            None,
            "pdata:zero_size",
            "PE exception directory entry has EndAddress <= BeginAddress",
        );
    }
    for va in &pdata_stats.chained_unwind_rejected_starts {
        record_scan_rejection(
            &mut stats,
            *va,
            None,
            "pdata:chained_unwind",
            "PE exception directory entry is a chained unwind record",
        );
    }
    for va in &pdata_stats.nonexec_rejected_starts {
        record_scan_rejection(
            &mut stats,
            *va,
            None,
            "pdata:nonexec",
            "PE exception directory entry does not start in executable code",
        );
    }
    for va in pdata_starts {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Pdata));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Pdata);
            record_seed_provenance(&mut stats, va, None, DiscoverySeedKind::Pdata, "pe_pdata");
            stats.pdata_seeds_inserted = stats.pdata_seeds_inserted.saturating_add(1);
        }
    }

    let mut prologue_starts = scan_pe_prologue_function_starts(data, &regions, arch);
    // AArch64 ELF PAC prologues recover functions on stripped hardened binaries
    // (Pixel device .so files) where the PE-specific scan does not apply.
    prologue_starts.extend(scan_aarch64_prologue_function_starts(data, &regions, arch));
    stats.prologue_scan_candidates = prologue_starts.len();
    for va in prologue_starts {
        if known.contains(&va) {
            record_scan_rejection(
                &mut stats,
                va,
                None,
                "prologue_scan:known_seed",
                "candidate already present in trusted seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Prologue));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Prologue);
            record_seed_provenance(
                &mut stats,
                va,
                None,
                DiscoverySeedKind::Prologue,
                "prologue_scan",
            );
            stats.prologue_scan_seeds_inserted =
                stats.prologue_scan_seeds_inserted.saturating_add(1);
        }
    }

    let thunk_starts = scan_pe_thunk_function_starts(data, &regions, arch);
    stats.thunk_scan_candidates = thunk_starts.len();
    for va in thunk_starts {
        if known.contains(&va) {
            record_scan_rejection(
                &mut stats,
                va,
                None,
                "thunk_scan:known_seed",
                "candidate already present in trusted seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Thunk));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Thunk);
            record_seed_provenance(&mut stats, va, None, DiscoverySeedKind::Thunk, "thunk_scan");
            stats.thunk_scan_seeds_inserted = stats.thunk_scan_seeds_inserted.saturating_add(1);
        }
    }

    let pe_code_pointers = scan_pe_code_pointers(data);
    stats.data_ref_code_pointer_candidates = pe_code_pointers.len();
    let code_pointer_tables: std::collections::BTreeSet<(String, usize)> = pe_code_pointers
        .iter()
        .map(|ptr| (ptr.section_name.clone(), ptr.table_index))
        .collect();
    stats.data_ref_code_pointer_table_count = code_pointer_tables.len();
    let code_pointer_target_set: std::collections::HashSet<u64> =
        pe_code_pointers.iter().map(|ptr| ptr.target_va).collect();

    let tiny_stub_scan = scan_pe_tiny_stub_function_starts(
        data,
        &regions,
        arch,
        &pdata_start_set,
        &code_pointer_target_set,
    );
    stats.tiny_stub_scan_candidates = tiny_stub_scan.starts.len();
    for va in &tiny_stub_scan.pdata_rejected {
        record_scan_rejection(
            &mut stats,
            *va,
            None,
            "tiny_stub_scan:pdata_start",
            "candidate already covered by PE exception directory",
        );
    }
    for va in &tiny_stub_scan.unpromoted_candidates {
        record_scan_rejection(
            &mut stats,
            *va,
            None,
            "tiny_stub_scan:unpromoted_candidate",
            "tiny-stub shape lacks promotion provenance",
        );
    }
    for va in tiny_stub_scan.starts {
        if known.contains(&va) {
            record_scan_rejection(
                &mut stats,
                va,
                None,
                "tiny_stub_scan:known_seed",
                "candidate already present in trusted seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::TinyStub));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::TinyStub);
            record_seed_provenance(
                &mut stats,
                va,
                None,
                DiscoverySeedKind::TinyStub,
                "tiny_stub_scan",
            );
            stats.tiny_stub_scan_seeds_inserted =
                stats.tiny_stub_scan_seeds_inserted.saturating_add(1);
        }
    }

    let raw_call_starts = scan_pe_raw_call_function_starts(data, &regions, arch, &pdata_start_set);
    stats.raw_call_target_candidates = raw_call_starts.len();
    for start in raw_call_starts {
        if known.contains(&start.va) {
            record_scan_rejection(
                &mut stats,
                start.va,
                None,
                "raw_call_scan:known_seed",
                "raw direct-call candidate already present in seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, start.va, bits, None, None) {
            let seed_kind = if start.allow_body_split {
                DiscoverySeedKind::DirectCallBodySplit
            } else {
                DiscoverySeedKind::DirectCall
            };
            seeds.push((addr, seed_kind));
            known.insert(start.va);
            seed_kind_by_va.insert(start.va, seed_kind);
            record_seed_provenance(
                &mut stats,
                start.va,
                None,
                seed_kind,
                "raw_direct_call_scan",
            );
            stats.raw_call_target_seeds_inserted =
                stats.raw_call_target_seeds_inserted.saturating_add(1);
            if start.allow_body_split {
                stats.raw_call_target_body_split_seeds_inserted = stats
                    .raw_call_target_body_split_seeds_inserted
                    .saturating_add(1);
            }
        }
    }

    for ptr in &pe_code_pointers {
        if !should_seed_pe_code_pointer(ptr) {
            record_scan_rejection(
                &mut stats,
                ptr.target_va,
                Some(ptr.pointer_va),
                "data_ref:weak_pointer",
                format!(
                    "{}:slot{}:table{}:len{}:{}",
                    ptr.section_name,
                    ptr.slot_size,
                    ptr.table_index,
                    ptr.table_length,
                    ptr.confidence
                ),
            );
            continue;
        }
        if known.contains(&ptr.target_va) || pdata_start_set.contains(&ptr.target_va) {
            record_scan_rejection(
                &mut stats,
                ptr.target_va,
                Some(ptr.pointer_va),
                "data_ref:known_or_pdata",
                format!(
                    "{}:slot{}:table{}:len{}:{}",
                    ptr.section_name,
                    ptr.slot_size,
                    ptr.table_index,
                    ptr.table_length,
                    ptr.confidence
                ),
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, ptr.target_va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::DataRef));
            known.insert(ptr.target_va);
            seed_kind_by_va.insert(ptr.target_va, DiscoverySeedKind::DataRef);
            record_seed_provenance(
                &mut stats,
                ptr.target_va,
                Some(ptr.pointer_va),
                DiscoverySeedKind::DataRef,
                format!(
                    "pe_code_pointer:{}:slot{}:table{}:len{}:{}",
                    ptr.section_name,
                    ptr.slot_size,
                    ptr.table_index,
                    ptr.table_length,
                    ptr.confidence
                ),
            );
            stats.data_ref_code_pointer_seeds_inserted =
                stats.data_ref_code_pointer_seeds_inserted.saturating_add(1);
        }
    }

    // Recursive multi-pass discovery. Each discovered function's
    // direct-call targets feed back as new seeds; without this the
    // discovery pass terminates as soon as the initial seed list is
    // exhausted, missing every internal function not reached by any
    // other seed source. Worklist-based to keep the iteration bounded
    // by a positive `max_functions` while still propagating xrefs to a
    // fixed point. `max_functions == 0` means no function-count cap.
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
        stats.seeds_processed = stats.seeds_processed.saturating_add(1);
        let seed_overlaps_body = va_in_discovered_body(&functions, None, seed.value);
        if seed_kind == DiscoverySeedKind::Pdata && seed_overlaps_body {
            stats.pdata_body_overlap_starts = stats.pdata_body_overlap_starts.saturating_add(1);
            cap_discovered_functions_at_va(&mut functions, seed.value);
        } else if seed_kind.is_body_overlap_gated() && seed_overlaps_body {
            record_scan_rejection(
                &mut stats,
                seed.value,
                None,
                format!("body_overlap:{}", seed_kind.label()),
                "candidate lies inside an already discovered function body",
            );
            continue;
        }
        if let Some((f, calls, func_stats)) =
            discover_function(data, arch, end, seed.clone(), &regions, budgets)
        {
            stats.function_seed_kinds.push((
                f.entry_point.value,
                seed_kind_by_va
                    .get(&f.entry_point.value)
                    .copied()
                    .unwrap_or(seed_kind)
                    .label()
                    .to_string(),
            ));
            stats.hit_block_limit |= func_stats.hit_block_limit;
            stats.hit_instruction_limit |= func_stats.hit_instruction_limit;
            stats.hit_timeout |= func_stats.hit_timeout;
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
                    && !va_in_discovered_body(&functions, Some(&f), xref.target_va)
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
            functions.push(f);
        }
    }
    stats.seeds_remaining = worklist.len();

    // Post-process: rename functions by matching defined symbol names at their entry VAs
    if let Ok(obj) = object::read::File::parse(data) {
        use object::read::ObjectSymbol;
        // Build VA->name map from defined symbols in executable regions
        let mut sym_by_va: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();
        for sym in obj.symbols() {
            if sym.is_definition() {
                let addr = code_addr(sym.address(), arch);
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
                let addr = code_addr(sym.address(), arch);
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

    (functions, cg, stats)
}

#[cfg(test)]
mod aarch64_ctrl_flow_tests {
    use super::{classify_ctrl_flow, is_unconditional_branch_mnemonic, BArch};

    fn class(m: &str) -> (bool, bool, bool) {
        classify_ctrl_flow(m, BArch::AArch64)
    }

    #[test]
    fn pac_authenticated_returns_are_returns() {
        // Plain and pointer-authenticated epilogue returns.
        for m in ["ret", "retaa", "retab"] {
            assert_eq!(class(m), (false, false, true), "{m} should be a return");
        }
    }

    #[test]
    fn authenticated_indirect_calls_are_calls() {
        for m in ["bl", "blr", "blraa", "blraaz", "blrab", "blrabz"] {
            assert_eq!(class(m), (false, true, false), "{m} should be a call");
        }
    }

    #[test]
    fn register_indirect_branches_are_unconditional_branches() {
        // BR and its authenticated variants: previously unclassified, so the
        // sweep ran past a tail call into unrelated bytes.
        for m in ["br", "braa", "braaz", "brab", "brabz"] {
            assert_eq!(class(m), (true, false, false), "{m} should be a branch");
            assert!(
                is_unconditional_branch_mnemonic(m, BArch::AArch64),
                "{m} must not add a fallthrough edge"
            );
        }
    }

    #[test]
    fn conditional_branches_keep_fallthrough() {
        for m in ["b.eq", "b.ne", "cbz", "cbnz", "tbz", "tbnz"] {
            assert_eq!(class(m), (true, false, false), "{m} is a branch");
            assert!(
                !is_unconditional_branch_mnemonic(m, BArch::AArch64),
                "{m} is conditional and must keep its fallthrough"
            );
        }
        // Plain unconditional B has no fallthrough.
        assert!(is_unconditional_branch_mnemonic("b", BArch::AArch64));
    }

    #[test]
    fn landing_pads_and_pac_signing_are_not_terminators() {
        // BTI and PAC-sign instructions are ordinary (non-control-flow) ops;
        // they must not split or end a basic block.
        for m in ["bti", "paciasp", "pacibsp", "autiasp", "autibsp", "nop"] {
            assert_eq!(class(m), (false, false, false), "{m} is not control flow");
        }
    }
}

#[cfg(test)]
mod prologue_gate_tests {
    use super::{
        classify_pe_thunk_head, is_code_padding_terminator, looks_like_fn_start, memory_operand_va,
        pe_adjustor_jump_stub_len, pe_head_looks_like_simd_continuation,
        pe_low_confidence_call_target_head, pe_prologue_scan_candidate, pe_tiny_return_helper_len,
        pe_tiny_stub_scan_candidate, pe_tiny_stub_scan_promotes_candidate, BArch, ExecRegion,
        PeThunkKind,
    };
    use crate::core::instruction::{Access, Instruction, Operand};
    use std::collections::HashSet;

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
    fn prologue_scan_requires_marker_and_recognised_head() {
        let (d, off) = data_with_pre(&[0xcc], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(pe_prologue_scan_candidate(&d, off));

        let (d, off) = data_with_pre(&[0xaa], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(!pe_prologue_scan_candidate(&d, off));

        let (d, off) = data_with_pre(&[0xcc], &[0x83, 0xff, 0x02, 0x0f, 0x85]);
        assert!(!pe_prologue_scan_candidate(&d, off));
    }

    #[test]
    fn x86_int3_and_ud2_are_padding_terminators() {
        assert!(is_code_padding_terminator("Int3", BArch::X86_64));
        assert!(is_code_padding_terminator("ud2", BArch::X86));
        assert!(!is_code_padding_terminator("int3", BArch::AArch64));
        assert!(!is_code_padding_terminator("nop", BArch::X86_64));
    }

    #[test]
    fn tiny_stub_scan_accepts_adjustor_jump_table_entries() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8d, 0x8a, 0x28, 0x00, 0x00, 0x00, 0xe9, 0xf4, 0x0f, 0x00, 0x00, 0xcc,
        ];
        assert_eq!(
            pe_adjustor_jump_stub_len(&data, 0, 0x1000, &regions),
            Some(12)
        );
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1001, &regions));
    }

    #[test]
    fn tiny_stub_scan_promotes_adjustors_only_with_code_pointer_target() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8d, 0x8a, 0x28, 0x00, 0x00, 0x00, 0xe9, 0xf4, 0x0f, 0x00, 0x00, 0xcc,
        ];
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
        assert!(!pe_tiny_stub_scan_promotes_candidate(
            &data,
            0,
            0x1000,
            &regions,
            &HashSet::new()
        ));

        let mut targets = HashSet::new();
        targets.insert(0x1000);
        assert!(pe_tiny_stub_scan_promotes_candidate(
            &data, 0, 0x1000, &regions, &targets
        ));
    }

    #[test]
    fn tiny_stub_scan_accepts_adjustor_before_prologue() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8d, 0x8a, 0x28, 0x00, 0x00, 0x00, 0xe9, 0xf4, 0x0f, 0x00, 0x00, 0x48, 0x89,
            0x54, 0x24, 0x10,
        ];
        assert_eq!(
            pe_adjustor_jump_stub_len(&data, 0, 0x1000, &regions),
            Some(12)
        );
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
    }

    #[test]
    fn tiny_stub_scan_accepts_adjustor_jump_table_entry_with_add() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8b, 0x8a, 0x50, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc1, 0x08, 0xe9, 0xf0, 0x0f,
            0x00, 0x00, 0xcc,
        ];
        assert_eq!(
            pe_adjustor_jump_stub_len(&data, 0, 0x1000, &regions),
            Some(16)
        );
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
    }

    #[test]
    fn tiny_stub_scan_accepts_bounded_return_helpers() {
        let (data, off) = data_with_pre(&[0xcc], &[0xc2, 0x00, 0x00, 0xcc]);
        assert_eq!(pe_tiny_return_helper_len(&data, off), Some(3));
        assert!(pe_tiny_stub_scan_candidate(&data, off, 0x1000, &[]));

        let (data, off) = data_with_pre(&[0xcc], &[0x33, 0xc0, 0xc3, 0xcc]);
        assert_eq!(pe_tiny_return_helper_len(&data, off), Some(3));
        assert!(pe_tiny_stub_scan_candidate(&data, off, 0x1000, &[]));

        let (data, off) = data_with_pre(&[0xcc], &[0x4d, 0x3b, 0xc8, 0x0f, 0x94, 0xc0, 0xc3, 0xcc]);
        assert_eq!(pe_tiny_return_helper_len(&data, off), Some(7));
        assert!(pe_tiny_stub_scan_candidate(&data, off, 0x1000, &[]));
    }

    #[test]
    fn simd_heads_are_not_low_confidence_function_starts() {
        let data = [0x90, 0x0f, 0x10, 0x0c, 0x11, 0xc3];
        assert!(pe_head_looks_like_simd_continuation(&data[1..]));
        assert!(!pe_low_confidence_call_target_head(&data, 1));
    }

    #[test]
    fn low_confidence_call_targets_require_a_start_shape() {
        let data = [0xcc, 0xba, 0x02, 0x00, 0x00, 0x00, 0x33, 0xc9];
        assert!(!pe_low_confidence_call_target_head(&data, 1));

        let data = [0x90, 0xc7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00];
        assert!(pe_low_confidence_call_target_head(&data, 1));
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

    #[test]
    fn classifies_tail_jump_thunk() {
        let matched = classify_pe_thunk_head(0x1000, &[0xe9, 0xfb, 0x0f, 0x00, 0x00]).unwrap();
        assert_eq!(matched.kind, PeThunkKind::TailJump);
        assert_eq!(matched.target_va, 0x2000);
        assert_eq!(matched.length, 5);
    }

    #[test]
    fn classifies_rip_import_jump_thunk() {
        let matched =
            classify_pe_thunk_head(0x1000, &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1016);
        assert_eq!(matched.length, 6);
    }

    #[test]
    fn classifies_cfg_dispatch_memory_jump_thunk() {
        let matched =
            classify_pe_thunk_head(0x1000, &[0x48, 0xff, 0x25, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1017);
        assert_eq!(matched.length, 7);
    }

    #[test]
    fn classifies_import_call_ret_wrapper() {
        let matched =
            classify_pe_thunk_head(0x1000, &[0x48, 0xff, 0x15, 0x20, 0x00, 0x00, 0x00, 0xc3])
                .unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1027);
        assert_eq!(matched.length, 8);
    }

    #[test]
    fn rejects_non_wrapper_import_call() {
        assert!(
            classify_pe_thunk_head(0x1000, &[0x48, 0xff, 0x15, 0x20, 0x00, 0x00, 0x00, 0x90],)
                .is_none()
        );
    }

    #[test]
    fn classifies_mov_rax_import_jump_thunk() {
        let matched = classify_pe_thunk_head(
            0x1000,
            &[0x48, 0x8b, 0x05, 0x30, 0x00, 0x00, 0x00, 0xff, 0xe0],
        )
        .unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1037);
        assert_eq!(matched.length, 9);
    }

    #[test]
    fn thunk_scan_accepts_padded_jump_table_entry() {
        let mut data = vec![0xff, 0x25, 0x02, 0x12, 0x00, 0x00, 0xcc];
        assert!(super::pe_thunk_scan_candidate(&data, 0, 0x14000ee48, &[]));

        data[6] = 0x48;
        assert!(!super::pe_thunk_scan_candidate(&data, 0, 0x14000ee48, &[]));
    }

    #[test]
    fn thunk_scan_rejects_unpadded_neighboring_import_thunks() {
        let data = vec![
            0xff, 0x25, 0x02, 0x12, 0x00, 0x00, 0xff, 0x25, 0x0c, 0x12, 0x00, 0x00,
        ];
        assert!(!super::pe_thunk_scan_candidate(&data, 6, 0x14000ee48, &[]));
    }

    #[test]
    fn thunk_scan_accepts_padded_rex_import_jump_forms() {
        let data = vec![0x48, 0xff, 0x25, 0x30, 0x2c, 0x00, 0x00, 0xcc];
        assert!(super::pe_thunk_scan_candidate(&data, 0, 0x140001470, &[]));
    }

    #[test]
    fn resolves_rip_relative_memory_operand_va() {
        let ins = Instruction {
            address: crate::core::address::Address::new(
                crate::core::address::AddressKind::VA,
                0x1000,
                64,
                None,
                None,
            )
            .unwrap(),
            bytes: vec![0xff, 0x25, 0x10, 0x00, 0x00, 0x00],
            mnemonic: "jmp".to_string(),
            operands: vec![Operand::memory(
                0,
                Access::Read,
                Some(0x1016),
                Some("rip".to_string()),
                None,
                None,
            )],
            length: 6,
            arch: "x86_64".to_string(),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        };

        assert_eq!(memory_operand_va(&ins), Some(0x1016));
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

    #[test]
    fn pdata_cap_truncates_prior_decoded_body() {
        let mut prior = _func_with_block(0x1000, (0x1000, 0x100), (0x1000, 0x1100));
        prior.add_edge(
            Address::new(AddressKind::VA, 0x1010, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x1090, 64, None, None).unwrap(),
        );
        let mut functions = vec![prior];

        assert_eq!(cap_discovered_functions_at_va(&mut functions, 0x1080), 1);
        assert!(!va_in_function_body(&functions[0], 0x1080));
        assert_eq!(functions[0].basic_blocks[0].end_address.value, 0x1080);
        assert_eq!(functions[0].range.as_ref().unwrap().size, 0x80);
        assert!(functions[0].edges.is_empty());
    }
}

#[cfg(test)]
mod unwind_info_tests {
    use super::{parse_unwind_chain_info, unwind_info_has_chain_info};

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

    #[test]
    fn parses_chained_runtime_function_trailer() {
        let mut data = vec![0x21, 0x05, 0x01, 0x00, 0xaa, 0xbb, 0x00, 0x00];
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x1234u32.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());

        assert_eq!(
            parse_unwind_chain_info(&data, 0),
            Some((0x1000, 0x1234, 0x2000))
        );
    }

    #[test]
    fn parse_chain_rejects_missing_trailer() {
        let data = [0x21, 0x05, 0x02, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(parse_unwind_chain_info(&data, 0), None);
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
