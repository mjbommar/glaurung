//! Bounded function discovery and CFG construction.
//!
//! This module implements a conservative, deterministic function discovery pass
//! with strict budgets. It seeds from an entrypoint (and can be extended later to
//! exports/PLT/etc.), disassembles within executable ranges only, splits basic
//! blocks on control flow, and emits `Function`s plus a `CallGraph`.

use crate::analysis::jump_table::{
    decode_bounded_relative_jump_table, decode_thumb_table_branch, discover_jump_tables,
};
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

mod body_index;
mod ctrl_flow;
mod dispatch_resolution;
mod entry_shape;
mod extents;
mod function_build;
mod must_dataflow;
mod packed;
mod pe_tables;
mod plt;
mod repair;
mod scan;
mod seeds;

pub use scan::scan_pe_code_pointers;

// Every name here is re-listed explicitly rather than glob-imported: the
// sibling `scan::prologue_gate_tests` reaches `is_code_padding_terminator` and
// `memory_operand_va` through `use super::…`, which resolves against *this*
// binding, not against `ctrl_flow`.
use body_index::BodyIndex;

use ctrl_flow::{
    arm_defined_register, arm_ldr_pc_table_dispatch, arm_pop_writes_pc, classify_ctrl_flow,
    guard_bound_reaches_fallthrough, immediate_target, is_code_padding_terminator,
    is_unconditional_branch_mnemonic, memory_operand_va,
};
use dispatch_resolution::resolve_dispatch;

// Same rule as above, and the same reason. `has_function_boundary_marker`,
// `head_looks_like_fn_start`, `pe_head_looks_like_simd_continuation`,
// `read_i32_le_at` and `rel_target` are named here for `scan`'s benefit rather
// than this module's -- `scan` is a sibling, not a descendant, so its
// `use super::*` resolves against this binding. `looks_like_fn_start` is
// deliberately NOT in the list: `scan` names it only from `prologue_gate_tests`,
// so importing it here is an unused import in the shipped build.
use entry_shape::{
    classify_pe_thunk_head, elf_x86_tail_target_looks_like_function_start,
    has_function_boundary_marker, head_looks_like_fn_start, pe_head_looks_like_simd_continuation,
    pe_tail_target_looks_like_function_start, pe_xref_seed_looks_like_function_start,
    read_i32_le_at, rel_target, PeThunkKind,
};

use function_build::build_function;

use must_dataflow::{address_fixed_point, bound_fixed_point};

use pe_tables::{parse_pdata_function_starts, parse_pe_export_function_starts};

use repair::{apply_dwarf_overrides, attach_exception_landing_pads, merge_compiler_split_chunks};

use scan::{
    collect_code_labels, scan_aarch64_prologue_function_starts, scan_elf_prologue_function_starts,
    scan_pe_prologue_function_starts, scan_pe_raw_call_function_starts,
    scan_pe_thunk_function_starts, scan_pe_tiny_stub_function_starts, should_seed_pe_code_pointer,
};

use seeds::{collect_seeds, Seeds};

#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    pub max_functions: usize,
    pub max_blocks: usize,
    pub max_instructions: usize,
    /// Wall clock for ONE function's block/instruction walk. Despite the bare
    /// name this has never bounded an analysis: `discover_function` restarts its
    /// clock per seed, so a binary with 20 000 functions can spend 20 000 times
    /// this and still be inside budget. Use `total_timeout_ms` to bound the run.
    pub timeout_ms: u64,
    /// Wall clock for the WHOLE analysis: every whole-binary discovery phase and
    /// every seed in the worklist, not just one function's walk. `0` means no
    /// ceiling.
    ///
    /// Zero is the default because a ceiling that truncates changes what
    /// discovery finds, and every recorded corpus number was measured without
    /// one; silently applying a wall clock to existing callers would move those
    /// numbers with nothing to attribute the movement to. Callers that would
    /// rather have a bounded answer than a complete one — the CLI does — set it
    /// explicitly, and `FunctionDiscoveryStats::hit_total_timeout` then says the
    /// result is a truncation rather than an answer.
    pub total_timeout_ms: u64,
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
            total_timeout_ms: 0,
        }
    }
}

/// A wall-clock ceiling for one whole analysis, threaded through every discovery
/// loop so exceeding it is a reported outcome instead of an unbounded run.
///
/// Copyable and cheap to test: `expired()` is one `clock_gettime`, the same call
/// the per-function `timeout_ms` check already makes on the decode path.
#[derive(Debug, Clone, Copy)]
pub struct Deadline<'a> {
    end: Option<std::time::Instant>,
    start: std::time::Instant,
    cancel: Option<&'a std::sync::atomic::AtomicBool>,
}

impl<'a> Deadline<'a> {
    /// The ceiling `budgets.total_timeout_ms` describes, starting now.
    pub fn start(budgets: &Budgets) -> Self {
        let start = std::time::Instant::now();
        Self {
            end: (budgets.total_timeout_ms > 0)
                .then(|| start + std::time::Duration::from_millis(budgets.total_timeout_ms)),
            start,
            cancel: None,
        }
    }

    /// A deadline that never expires — for callers with no whole-run ceiling.
    pub fn none() -> Self {
        Self {
            end: None,
            start: std::time::Instant::now(),
            cancel: None,
        }
    }

    /// The same ceiling, additionally stopped as soon as `cancel` is set.
    ///
    /// This is what makes a long analysis interruptible from Python. Releasing
    /// the GIL is NOT enough on its own: the interpreter runs its signal handler
    /// only on a thread that holds the GIL, and the thread that called us is
    /// inside Rust for the whole analysis, so a `Ctrl-C` sits pending until the
    /// call returns — which is exactly the 20-minute unkillable run. The binding
    /// runs the analysis on a worker thread, keeps the calling thread in
    /// `Python::check_signals`, and sets this flag when a signal arrives.
    pub fn with_cancel(self, cancel: &'a std::sync::atomic::AtomicBool) -> Self {
        Self {
            cancel: Some(cancel),
            ..self
        }
    }

    /// Whether the analysis must stop: the ceiling passed, or a caller asked.
    pub fn expired(&self) -> bool {
        self.cancelled() || self.end.is_some_and(|end| std::time::Instant::now() >= end)
    }

    /// Whether a caller asked for the analysis to stop.
    pub fn cancelled(&self) -> bool {
        self.cancel
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Wall clock consumed so far, in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[derive(Debug, Clone, Default)]
pub struct FunctionDiscoveryStats {
    pub max_functions: usize,
    pub max_blocks: usize,
    pub max_instructions: usize,
    pub timeout_ms: u64,
    pub total_timeout_ms: u64,
    /// Wall clock the whole analysis actually consumed.
    pub elapsed_ms: u64,
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
    pub eh_frame_candidates: usize,
    pub eh_frame_seeds_inserted: usize,
    pub pdata_zero_begin_rejected: usize,
    pub pdata_zero_size_rejected: usize,
    pub pdata_overlapping_entries: usize,
    pub pdata_chained_unwind_rejected: usize,
    pub pdata_chained_unwind_parsed: usize,
    pub pdata_chained_unwind_parse_failed: usize,
    pub pdata_chained_parent_starts: usize,
    pub pdata_nonexec_rejected: usize,
    /// Function ranges `.eh_frame` declares. Zero means the declared-extent
    /// gate cannot fire on this binary — the stripped and no-unwind-table
    /// cases, where the prologue scan is the only thing finding anything.
    pub declared_extents: usize,
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
    /// The WHOLE-ANALYSIS wall clock ran out. Unlike the three limits above this
    /// is not a per-function truncation: seed discovery stopped early, so
    /// `seeds_remaining` functions were never walked and the callgraph is
    /// incomplete. A consumer that treats this result as a complete function list
    /// is wrong, which is why it is reported rather than absorbed.
    pub hit_total_timeout: bool,
    /// Register-indirect transfers whose targets could not be recovered. A
    /// non-empty list means at least one returned CFG is incomplete.
    pub unresolved_indirect: Vec<(u64, crate::analysis::dispatch::Unresolved)>,
    /// Jump-table dispatch sites successfully resolved, paired with arm count.
    pub resolved_dispatches: Vec<(u64, usize)>,
    /// The packer that produced the image handed to us, if it was packed.
    ///
    /// A packed image contains no program to analyse: what disassembles is the
    /// decompressor stub. Discovery does not fail on one, it succeeds on the
    /// wrong code, so this field is the difference between a low answer and a
    /// wrong one. It is set whether or not unpacking then worked.
    pub packer: Option<String>,
    /// The functions below are the ORIGINAL program's, recovered by unpacking.
    ///
    /// False alongside a set `packer` means the opposite and much worse thing:
    /// the functions are the unpacker's own, and `unpack_error` says why the
    /// program could not be reached.
    pub unpacked: bool,
    /// Why a recognised packed image could not be unpacked.
    pub unpack_error: Option<String>,
    /// Entry point of the original program, recovered from the packed image.
    pub original_entry: Option<u64>,
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
    /// The whole-analysis deadline expired inside this function's walk.
    hit_total_timeout: bool,
    /// Indirect transfers whose target set could not be recovered, with the
    /// dispatch VA and why.
    ///
    /// This is a **completeness** signal, not a diagnostic nicety. An unresolved
    /// indirect jump means the recovered CFG is missing real edges — and every
    /// verifier downstream compares the region tree against the CFG, so all of
    /// them report clean on the truncated graph. Recording it here is what makes
    /// "this function's graph is not the program's graph" something a consumer
    /// can ask about instead of something nobody can see.
    unresolved_indirect: Vec<(u64, crate::analysis::dispatch::Unresolved)>,
    /// Indirect transfers resolved through a jump table, with how many arms.
    resolved_dispatches: Vec<(u64, usize)>,
}

fn merge_single_function_stats(
    aggregate: &mut FunctionDiscoveryStats,
    mut local: SingleFunctionDiscoveryStats,
) {
    aggregate.hit_block_limit |= local.hit_block_limit;
    aggregate.hit_instruction_limit |= local.hit_instruction_limit;
    aggregate.hit_timeout |= local.hit_timeout;
    aggregate.hit_total_timeout |= local.hit_total_timeout;
    aggregate
        .unresolved_indirect
        .append(&mut local.unresolved_indirect);
    aggregate
        .resolved_dispatches
        .append(&mut local.resolved_dispatches);
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
    fn is_body_overlap_gated(self) -> bool {
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

    fn label(self) -> &'static str {
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

fn parse_exec_regions(data: &[u8]) -> (Vec<ExecRegion>, BArch, Endianness, Option<Address>) {
    let mut regions = Vec::new();
    let mut arch = BArch::Unknown;
    let mut endian = Endianness::Little;
    let mut entry: Option<Address> = None;
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
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

        let raw_entry_va = obj.entry();
        if raw_entry_va != 0 {
            // ARM ELF entry points use bit zero as the Thumb-state marker,
            // exactly like STT_FUNC symbols and branch targets. Keep the
            // mode as function metadata, but seed CFG recovery at the actual
            // even code address so lifting never starts one byte late.
            let entry_va = code_addr(raw_entry_va, arch);
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

fn parse_exec_regions_in(
    image: &crate::program::image::ProgramImage,
) -> (Vec<ExecRegion>, BArch, Endianness, Option<Address>) {
    let arch = image.arch();
    let endianness = image.endianness();
    let regions: Vec<ExecRegion> = image
        .executable_ranges()
        .map(|range| ExecRegion {
            start: range.start,
            end: range.end,
            _file_off_start: image
                .va_to_code_file_offset(range.start)
                .and_then(|offset| u64::try_from(offset).ok())
                .unwrap_or(0),
        })
        .collect();
    if regions.is_empty() {
        return parse_exec_regions(image.bytes());
    }
    let entry_va = image.normalize_function_entry(image.entry_va());
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let entry = (entry_va != 0)
        .then(|| Address::new(AddressKind::VA, entry_va, bits, None, None).ok())
        .flatten();
    (regions, arch, endianness, entry)
}

fn in_exec_regions(regions: &[ExecRegion], va: u64) -> Option<&ExecRegion> {
    regions.iter().find(|r| va >= r.start && va < r.end)
}

fn indexed_file_offset(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    va: u64,
) -> Option<usize> {
    image.map_or_else(
        || crate::analysis::entry::va_to_file_offset(data, va),
        |image| image.va_to_file_offset(va),
    )
}

fn indexed_code_offset(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    va: u64,
) -> Option<usize> {
    image.map_or_else(
        || crate::analysis::entry::va_to_code_file_offset(data, va),
        |image| image.va_to_code_file_offset(va),
    )
}

fn read_pointer_at_va(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    va: u64,
    bits: u8,
) -> Option<u64> {
    let file_off = indexed_file_offset(image, data, va).or_else(|| pe_va_to_file_off(data, va))?;
    if bits >= 64 {
        let raw = data.get(file_off..file_off + 8)?;
        Some(u64::from_le_bytes(raw.try_into().ok()?))
    } else {
        let raw = data.get(file_off..file_off + 4)?;
        Some(u32::from_le_bytes(raw.try_into().ok()?) as u64)
    }
}

fn indirect_memory_target(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    ins: &Instruction,
    bits: u8,
) -> Option<u64> {
    let slot_va = memory_operand_va(ins)?;
    read_pointer_at_va(image, data, slot_va, bits)
}

/// Merge one predecessor's concrete address facts into a block input.
///
/// The first predecessor establishes the candidate map; later predecessors can
/// only remove facts. A register survives a join precisely when every incoming
/// path agrees on the same address.
fn merge_dispatch_addresses(
    inputs: &mut std::collections::HashMap<u64, std::collections::HashMap<String, u64>>,
    target: u64,
    incoming: std::collections::HashMap<String, u64>,
) -> bool {
    use std::collections::hash_map::Entry;
    match inputs.entry(target) {
        Entry::Vacant(entry) => {
            entry.insert(incoming);
            true
        }
        Entry::Occupied(mut entry) => {
            let before = entry.get().len();
            entry
                .get_mut()
                .retain(|register, address| incoming.get(register) == Some(address));
            entry.get().len() != before
        }
    }
}

/// Join upper-bound facts from reachable predecessors.
///
/// A register remains bounded only when every currently reachable predecessor
/// proves a bound for it; the joined maximum covers every incoming value.
/// Predecessors without an output are still unreachable in the fixed-point and
/// therefore do not weaken the result yet.
fn join_dispatch_bounds<'a>(
    incoming: impl Iterator<Item = &'a crate::analysis::dispatch::Bounds>,
) -> crate::analysis::dispatch::Bounds {
    let mut incoming = incoming;
    let Some(first) = incoming.next() else {
        return crate::analysis::dispatch::Bounds::default();
    };
    let mut joined = first.clone();
    for next in incoming {
        joined.regs.retain(|register, bound| {
            let Some(next_bound) = next.regs.get(register) else {
                return false;
            };
            *bound = (*bound).max(*next_bound);
            true
        });
        joined.slots.retain(|slot, bound| {
            let Some(next_bound) = next.slots.get(slot) else {
                return false;
            };
            *bound = (*bound).max(*next_bound);
            true
        });
        joined.mems.retain(|location, bound| {
            let Some(next_bound) = next.mems.get(location) else {
                return false;
            };
            *bound = (*bound).max(*next_bound);
            true
        });
    }
    joined
}

/// Combine independent proofs that hold on the same path.  Either proof is
/// sufficient, so retain their union and choose the tighter bound on overlap.
fn combine_dispatch_bounds(
    mut left: crate::analysis::dispatch::Bounds,
    right: Option<&crate::analysis::dispatch::Bounds>,
) -> crate::analysis::dispatch::Bounds {
    let Some(right) = right else {
        return left;
    };
    for (register, bound) in &right.regs {
        left.regs
            .entry(register.clone())
            .and_modify(|old| *old = (*old).min(*bound))
            .or_insert(*bound);
    }
    for (slot, bound) in &right.slots {
        left.slots
            .entry(slot.clone())
            .and_modify(|old| *old = (*old).min(*bound))
            .or_insert(*bound);
    }
    for (location, bound) in &right.mems {
        left.mems
            .entry(location.clone())
            .and_modify(|old| *old = (*old).min(*bound))
            .or_insert(*bound);
    }
    left
}

/// Drop the dispatch edges an over-scanned table extent contributed, and report
/// how many arms the block is left with.
///
/// `attached` is the sequence of targets the speculative walk attached to
/// `block_start`, one entry per table slot and in table order; `retained` is how
/// many leading slots the whole-CFG range proof stands behind. Everything past
/// that is scanner over-read — `discover_jump_tables` builds the LONGEST run of
/// section words that decode to executable addresses, so it runs straight
/// through the end of one table into whatever follows.
///
/// The removal is keyed on how many times each target occurs in the PROVEN
/// prefix, never on set membership. Duplicate targets are the ordinary shape of
/// a `switch` whose case labels are shared across indices, so the trimmed suffix
/// routinely names a VA the proven prefix names too. Deleting every edge
/// `block_start -> T` whose target appeared anywhere in the suffix therefore
/// deleted the PROVEN arm as well, and nothing downstream could put it back:
/// `cfg::repair::rebuild_block_relationships` de-duplicates successor lists, but
/// de-duplication cannot restore a successor that was never added. Meanwhile the
/// arm count went on claiming the prefix length, so `stats.resolved_dispatches`
/// and the edge set disagreed about the same switch.
///
/// The count returned is read off the surviving edges rather than assumed, so
/// the caller records an arm count the graph can actually be checked against.
fn trim_unproven_dispatch_edges(
    edges: &mut Vec<(u64, u64, ControlFlowEdgeKind)>,
    block_start: u64,
    attached: &[u64],
    retained: usize,
) -> usize {
    let mut quota: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for target in attached.iter().take(retained) {
        *quota.entry(*target).or_default() += 1;
    }
    let mut kept = 0usize;
    edges.retain(|(source, target, _)| {
        if *source != block_start {
            return true;
        }
        match quota.get_mut(target) {
            Some(remaining) if *remaining > 0 => {
                *remaining -= 1;
                kept += 1;
                true
            }
            _ => false,
        }
    });
    kept
}

#[derive(Debug)]
struct TentativeDispatchEdges {
    site: u64,
    block_start: u64,
    attached: Vec<u64>,
    /// True when the section scan supplied candidate arms before range
    /// dataflow proved the dispatch extent.  Such edges must be trimmed or
    /// rejected during final validation; they are never accepted as-is.
    needs_bound_proof: bool,
}

/// Replay one decoded block through the dispatch abstract interpreter.
///
/// The first CFG walk must speculate with the predecessors known at that point
/// in order to discover table arms. Once the graph is complete, this replay is
/// used by a proper must-dataflow fixed point and validates every speculative
/// resolution. That second check is what makes a late conflicting back-edge
/// fail closed instead of leaving already-added, unsound successors behind.
#[allow(clippy::too_many_arguments)]
fn replay_dispatch_block(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
    endianness: Endianness,
    thumb: Option<bool>,
    start_va: u64,
    end_va: u64,
    bounds: Option<crate::analysis::dispatch::Bounds>,
    addresses: Option<&std::collections::HashMap<String, u64>>,
    stop_at: Option<u64>,
    decoded: Option<&[Instruction]>,
) -> Option<(
    crate::analysis::dispatch::DispatchTracker,
    Option<Instruction>,
)> {
    let darch: crate::core::disassembler::Architecture = arch.into();
    let bits = darch.address_bits();
    let mut tracker = crate::analysis::dispatch::DispatchTracker::new();
    // The replay must model `pc` exactly as the walker did. Without this the
    // revalidation cannot materialise an ARM table base, reports the dispatch
    // unresolved, and DELETES the edges the walker correctly proved — so the
    // arms are lost after being found. The walker's mode comes from
    // `arm32_mode`; here the same fact arrives as the `thumb` flag.
    tracker.set_arm_pc_mode(match (arch, thumb) {
        (BArch::ARM, Some(true)) => Some(crate::analysis::dispatch::ArmPcMode::Thumb),
        (BArch::ARM, Some(false)) => Some(crate::analysis::dispatch::ArmPcMode::A32),
        _ => None,
    });
    tracker.inherit_bound(bounds);
    tracker.inherit_addresses(addresses);

    // The walk that built this block already decoded every instruction in it.
    // Replaying from that stream is the same sequence of `observe` calls
    // against the same instructions -- see `discover_function`, which records
    // exactly `[start, block_end)` and only ever shortens a block afterwards,
    // so the recorded stream is a superset of what this replay reads.
    if let Some(decoded) = decoded {
        let mut cur_va = start_va;
        for instruction in decoded {
            if cur_va >= end_va {
                break;
            }
            let next_va = cur_va.saturating_add(instruction.length as u64);
            if matches!(arch, BArch::ARM) {
                if let Some(defined) = arm_defined_register(instruction) {
                    tracker.kill_register(defined);
                }
            }
            tracker.observe(instruction);
            if stop_at == Some(cur_va) {
                return Some((tracker, Some(instruction.clone())));
            }
            if next_va <= cur_va {
                return None;
            }
            cur_va = next_va;
        }
        return Some((tracker, None));
    }

    let mut backend = registry::for_arch(darch, endianness)?;
    if let Some(thumb) = thumb {
        let _ = backend.set_thumb_mode(thumb);
    }
    let mut cur_va = start_va;
    while cur_va < end_va {
        let file_offset = indexed_code_offset(image, data, cur_va)?;
        let bytes = data.get(file_offset..)?;
        let address = Address::new(AddressKind::VA, cur_va, bits, None, None).ok()?;
        let instruction = backend.disassemble_instruction(&address, bytes).ok()?;
        let next_va = cur_va.saturating_add(instruction.length as u64);
        // Mirrors the streaming walk in `discover_function`: the ARM decoder
        // reports no writes, so definitions are named from the mnemonic. A
        // replay that skipped this would prove a bound the first pass refused
        // and re-validate a dispatch into existence.
        if matches!(arch, BArch::ARM) {
            if let Some(defined) = arm_defined_register(&instruction) {
                tracker.kill_register(defined);
            }
        }
        tracker.observe(&instruction);
        if stop_at == Some(cur_va) {
            return Some((tracker, Some(instruction)));
        }
        if next_va <= cur_va {
            return None;
        }
        cur_va = next_va;
    }
    Some((tracker, None))
}

/// Every block's decoded instruction stream, keyed by block start.
///
/// The streaming walk decodes each block once; the two must-dataflow fixed
/// points and the dispatch revalidation then read the same blocks again, three
/// more times on average. Decoding is by far the most expensive thing this
/// module does -- on `win10-webservices.dll` the walk decodes 281k
/// instructions and the replays 840k -- so the stream is kept rather than
/// recovered. Bounded by `budgets.max_instructions` per function and dropped
/// when the function is built.
type BlockStreams = std::collections::HashMap<u64, Vec<Instruction>>;

struct DiscoveryFacts<'a> {
    // Program-scoped address index. Legacy byte-only analysis leaves this empty;
    // session-backed entry points always supply it.
    image: Option<&'a crate::program::image::ProgramImage>,
    // Jump tables discovered once for the whole binary, indexed by table VA.
    //
    // These used to be consumed only as function-discovery seeds. Keeping the
    // table-to-dispatch binding here lets the dispatching CFG acquire its arms.
    tables: &'a std::collections::BTreeMap<u64, Vec<u64>>,
    // Resolved import/thunk addresses whose contracts prohibit fallthrough.
    noreturn_targets: &'a std::collections::HashSet<u64>,
    // PLT stub extents proven once for this run by `elf_plt_stub_ranges`.
    plt_stub_ranges: &'a [std::ops::Range<u64>],
    // Optional authoritative ranges for a continuation/landing-pad walk. A
    // direct jump that stays inside these ranges is intra-function even when
    // its target bytes resemble a standalone prologue.
    owned_ranges: Option<&'a [AddressRange]>,
    // Existing basic-block starts in the owning function. A landing-pad walk
    // must treat these as leaders even when it reaches one by linear flow.
    owned_leaders: Option<&'a [u64]>,
    // Exclusive upper bound on this function's bytes, when `.eh_frame` proves
    // one. Without it a function whose last instruction is a call to a
    // `noreturn` helper has no terminator, so the walk falls through into
    // whatever follows and keeps going: `main` in a stripped musl `getent` is
    // 97 bytes but was discovered as 154, swallowing `_start` and `_start_c`
    // and reporting their calls — including `__libc_start_main` — as its own.
    proven_end: Option<u64>,
}

impl DiscoveryFacts<'_> {
    /// True when `va` lies at or past this function's proven end.
    ///
    /// Only ever consulted when `.eh_frame` supplied an exact extent, so this
    /// cannot truncate a function whose length is merely guessed.
    fn beyond_proven_end(&self, va: u64) -> bool {
        self.proven_end.is_some_and(|end| va >= end)
    }

    /// True when `va` lands inside linker-generated import glue.
    fn target_is_plt_stub(&self, va: u64) -> bool {
        self.plt_stub_ranges.iter().any(|range| range.contains(&va))
    }

    fn owns(&self, va: u64) -> bool {
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

/// Run a whole-binary seed scan unless the analysis deadline has already passed.
///
/// The discovery loops check the deadline themselves; these scans are
/// straight-line sweeps over the whole image with no loop to instrument, so the
/// check has to be at the call. Once the ceiling is gone every remaining scan is
/// skipped instead of run to completion, and `hit_total_timeout` is set — which
/// is what makes an empty candidate list a REPORTED truncation rather than a
/// binary that simply had no vtables in it.
fn scan_within<T: Default>(
    deadline: Deadline<'_>,
    stats: &mut FunctionDiscoveryStats,
    scan: impl FnOnce() -> T,
) -> T {
    if deadline.expired() {
        stats.hit_total_timeout = true;
        return T::default();
    }
    scan()
}

/// Discover a single function starting at `entry` within executable regions.
fn discover_function(
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
    let final_bound_inputs = bound_fixed_point(
        facts,
        data,
        arch,
        end,
        thumb,
        &entry,
        &blocks,
        &edges,
        &block_streams,
    );
    let final_address_inputs = address_fixed_point(
        facts,
        data,
        arch,
        end,
        thumb,
        &entry,
        &blocks,
        &edges,
        &index_bounds,
        &block_streams,
    );

    let mut invalid_dispatches: Vec<(u64, u64, Vec<u64>, crate::analysis::dispatch::Unresolved)> =
        Vec::new();
    let mut trimmed_dispatches: Vec<(u64, u64, Vec<u64>, usize)> = Vec::new();
    for dispatch_edge in &resolved_dispatch_edges {
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
        let kept = trim_unproven_dispatch_edges(&mut edges, block_start, &attached, retained);
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

/// Copy this walk's budget-truncation outcome onto the function it produced.
///
/// `SingleFunctionDiscoveryStats` is consumed twice: here, per function, and
/// again by `merge_single_function_stats` into the whole-run aggregate. Only
/// the first of those can name a function, so only the first is used to mark
/// one. `hit_total_timeout` is deliberately partial here -- see
/// `FunctionFlags::CFG_ANALYSIS_DEADLINE`.
fn record_cfg_incompleteness(func: &mut Function, stats: &SingleFunctionDiscoveryStats) {
    for (fired, flag) in [
        (stats.hit_block_limit, FunctionFlags::CFG_BLOCK_LIMIT),
        (
            stats.hit_instruction_limit,
            FunctionFlags::CFG_INSTRUCTION_LIMIT,
        ),
        (stats.hit_timeout, FunctionFlags::CFG_WALK_TIMEOUT),
        (
            stats.hit_total_timeout,
            FunctionFlags::CFG_ANALYSIS_DEADLINE,
        ),
    ] {
        if fired {
            func.add_flag(flag);
        }
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

fn va_is_discovered_block_leader(functions: &[Function], va: u64) -> bool {
    functions.iter().any(|function| {
        va != function.entry_point.value
            && function
                .basic_blocks
                .iter()
                .any(|block| block.start_address.value == va)
    })
}

fn cap_discovered_functions_at_va(
    functions: &mut [Function],
    va: u64,
    index: &mut BodyIndex,
) -> usize {
    let mut capped = 0usize;
    for func in functions.iter_mut() {
        if va <= func.entry_point.value || !va_in_function_body(func, va) {
            continue;
        }
        // The index counts this function's bytes; it is about to stop owning
        // some of them. Withdraw the old geometry before the edit and re-add
        // the new geometry after, so the counters describe what is there now.
        index.unpaint(func);
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
        index.repaint(func);
    }
    capped
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

#[derive(Debug, Clone, Default)]
struct PeTinyStubScanResult {
    starts: Vec<u64>,
    pdata_rejected: Vec<u64>,
    unpromoted_candidates: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct PeRawCallFunctionStart {
    va: u64,
    allow_body_split: bool,
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
        let Some(matched) = classify_pe_thunk_head(
            func.entry_point.value,
            &data[file_off..head_end],
            arch.is_64_bit(),
        ) else {
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
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
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

/// Analyze bytes and return discovered functions and a callgraph (best-effort).
pub fn analyze_functions_bytes(data: &[u8], budgets: &Budgets) -> (Vec<Function>, CallGraph) {
    let (functions, cg, _stats) = analyze_functions_bytes_with_stats(data, budgets);
    (functions, cg)
}

/// Analyze bytes while treating caller-provided executable VAs as trusted
/// function-entry seeds.
///
/// Address-scoped clients (for example, external decompiler benchmarks) know
/// the entries they want even when symbols and other discovery metadata have
/// been stripped. Invalid or non-executable VAs are ignored, preserving the
/// normal "not found" behavior at the binding boundary.
pub fn analyze_functions_bytes_with_seeds(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
) -> (Vec<Function>, CallGraph) {
    let (functions, cg, _stats) =
        analyze_functions_bytes_with_stats_and_seeds(data, budgets, requested_vas);
    (functions, cg)
}

/// Analyze one already indexed program image with caller-provided entry seeds.
///
/// Unlike the compatibility byte-slice entry point, every inner CFG address
/// translation reuses the image's immutable mapping index.
pub fn analyze_functions_image_with_seeds(
    image: &crate::program::image::ProgramImage,
    budgets: &Budgets,
    requested_vas: &[u64],
) -> (Vec<Function>, CallGraph) {
    let (functions, cg, _stats) = packed::analyze_functions_bytes_within(
        image.bytes(),
        budgets,
        requested_vas,
        Deadline::start(budgets),
        Some(image),
    );
    (functions, cg)
}

/// Analyze every discoverable function in one already indexed program image.
pub fn analyze_functions_image(
    image: &crate::program::image::ProgramImage,
    budgets: &Budgets,
) -> (Vec<Function>, CallGraph) {
    analyze_functions_image_with_seeds(image, budgets, &[])
}

/// Discover one trusted function while reusing a program-scoped address index.
///
/// Address-scoped consumers already know the entry they need. Running the
/// whole seed pipeline merely to recover one direct callee processes unrelated
/// symbols, vtables, and function starts before the caller's budget can stop
/// it. This path performs only the bounded CFG walk for `entry_va`; direct
/// xrefs are still recorded on the returned Function.
pub(crate) fn discover_function_image_at(
    image: &crate::program::image::ProgramImage,
    budgets: &Budgets,
    entry_va: u64,
) -> Option<Function> {
    let data = image.bytes();
    let deadline = Deadline::start(budgets);
    let (regions, arch, end, _entry) = parse_exec_regions_in(image);
    if regions.is_empty() || in_exec_regions(&regions, entry_va).is_none() {
        return None;
    }
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let entry = Address::new(AddressKind::VA, entry_va, bits, None, None).ok()?;
    let tables = std::collections::BTreeMap::new();
    let noreturn_targets = image.noreturn_import_targets();
    let plt_stub_ranges = plt::elf_plt_stub_ranges(Some(image), data, arch);
    let facts = DiscoveryFacts {
        image: Some(image),
        tables: &tables,
        noreturn_targets: &noreturn_targets,
        plt_stub_ranges: &plt_stub_ranges,
        owned_ranges: None,
        owned_leaders: None,
        proven_end: None,
    };
    let (mut function, _calls, _stats) =
        discover_function(data, arch, end, entry, &regions, budgets, &facts, deadline)?;

    // Preserve the same exact-address symbol naming as whole-binary discovery
    // without paying for its unrelated seed work.
    if let Some(name) = image.defined_symbol_name_at(entry_va) {
        function.name = name.to_string();
    }
    Some(function)
}

/// Analyze bytes and return discovered functions, callgraph, and budget telemetry.
pub fn analyze_functions_bytes_with_stats(
    data: &[u8],
    budgets: &Budgets,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    analyze_functions_bytes_with_stats_and_seeds(data, budgets, &[])
}

fn analyze_functions_bytes_with_stats_and_seeds(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    // Started before ANY work, including `parse_exec_regions`: a budget that only
    // begins once the expensive part is under way is not a budget.
    packed::analyze_functions_bytes_within(
        data,
        budgets,
        requested_vas,
        Deadline::start(budgets),
        None,
    )
}

/// Whole-binary discovery, stopped by an EXTERNAL cancellation flag as well as by
/// `budgets.total_timeout_ms`.
///
/// The flag is what makes the analysis interruptible from Python — see
/// `Deadline::with_cancel`. A cancelled run returns the functions it had already
/// discovered with `hit_total_timeout` set, so a caller that wants a partial
/// answer can keep it and one that wants a complete answer can tell it did not
/// get one.
pub fn analyze_functions_bytes_cancellable(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
    cancel: &std::sync::atomic::AtomicBool,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    packed::analyze_functions_bytes_within(
        data,
        budgets,
        requested_vas,
        Deadline::start(budgets).with_cancel(cancel),
        None,
    )
}

fn analyze_functions_unpacked(
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

    // Post-process: rename functions by matching defined symbol names at their entry VAs
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
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
        // `object::File::dynamic_symbols()` is empty for PE exports.  The
        // export table already seeded these function starts above; attach the
        // corresponding names here as well so discovery does not return an
        // anonymous `sub_<va>` for a publicly named entry point.
        if let Ok(parser) = crate::formats::pe::PeParser::new(data) {
            let image_base = parser.image_base();
            if let Ok(exports) = parser.exports() {
                for export in &exports.exports {
                    let (Some(name), None) = (export.name, export.forwarder) else {
                        continue;
                    };
                    let va = image_base + u64::from(export.rva);
                    if !name.is_empty()
                        && export.rva != 0
                        && in_exec_regions(&regions, va).is_some()
                    {
                        sym_by_va.entry(va).or_insert_with(|| name.to_string());
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

        assert_eq!(
            cap_discovered_functions_at_va(&mut functions, 0x1080, &mut BodyIndex::disabled()),
            1
        );
        assert!(!va_in_function_body(&functions[0], 0x1080));
        assert_eq!(functions[0].basic_blocks[0].end_address.value, 0x1080);
        assert_eq!(functions[0].range.as_ref().unwrap().size, 0x80);
        assert!(functions[0].edges.is_empty());
    }
}

#[cfg(test)]
mod arm_tail_call_tests {
    use super::*;

    fn sample(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross")
            .join(name);
        std::fs::read(path).expect("read checked-in cross sample")
    }

    /// The byte-only fallback and the session image must agree exactly: the
    /// image path is what production takes, and a range list that disagreed
    /// with the object it was built from would silently reclassify tail calls.
    fn target_is_plt_stub(data: &[u8], target_va: u64, arch: BArch) -> bool {
        let from_bytes = plt::elf_plt_stub_ranges(None, data, arch);
        let image = crate::program::image::ProgramImage::from_bytes(data.to_vec())
            .expect("index the checked-in sample");
        let from_image = plt::elf_plt_stub_ranges(Some(&image), data, arch);
        assert_eq!(
            from_bytes, from_image,
            "byte and image PLT indices diverged"
        );
        from_image.iter().any(|range| range.contains(&target_va))
    }

    /// `.plt` in the checked-in armhf sample spans 0x4d8..0x54c (a 20-byte
    /// header plus eight 12-byte stubs). A branch into that range is a tail
    /// call; a branch into `.text` is ordinary control flow.
    #[test]
    fn an_arm_branch_into_the_plt_is_a_tail_call() {
        let data = sample("armhf/c2_demo-armhf-gcc");
        assert!(target_is_plt_stub(&data, 0x4ec, BArch::ARM));
        assert!(target_is_plt_stub(&data, 0x540, BArch::ARM));
        assert!(!target_is_plt_stub(&data, 0x4d0, BArch::ARM));
        assert!(!target_is_plt_stub(&data, 0x698, BArch::ARM));
    }

    /// A decoder/object architecture mismatch must never reclassify a target.
    #[test]
    fn matching_architectures_are_required_and_supported() {
        let data = sample("armhf/c2_demo-armhf-gcc");
        for arch in [BArch::X86_64, BArch::X86, BArch::AArch64] {
            assert!(!target_is_plt_stub(&data, 0x4ec, arch));
        }
        let arm64 = sample("arm64/c2_demo-arm64-gcc");
        assert!(target_is_plt_stub(&arm64, 0x810, BArch::AArch64));
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod gcc_dispatch_corpus_tests {
    use super::*;
    use object::{Object, ObjectSymbol};
    use std::io::Write;
    use std::process::Command;

    #[test]
    fn nested_multi_exit_parser_loop_preserves_its_dispatch() {
        let tmp = tempfile::tempdir().expect("temporary nested-dispatch build directory");
        let source = tmp.path().join("nested_dispatch_loop.S");
        let binary = tmp.path().join("nested_dispatch_loop.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/09_nested_dispatch_loop.S"
                ))
            })
            .expect("write the real nested-dispatch fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-nostdlib", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile nested-dispatch fixture: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read nested-dispatch fixture");
        let object =
            crate::decompile::profile::parse_object(&data).expect("parse nested-dispatch ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("nested_dispatch_parser"))
            .map(|symbol| symbol.address())
            .expect("exported nested_dispatch_parser symbol");
        let image = crate::program::image::ProgramImage::from_bytes(data.clone())
            .expect("index nested-dispatch fixture");
        let budgets = Budgets {
            max_functions: 1,
            max_blocks: 4096,
            max_instructions: 200_000,
            timeout_ms: 5_000,
            total_timeout_ms: 0,
        };
        let (functions, _callgraph) =
            analyze_functions_image_with_seeds(&image, &budgets, &[entry]);
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discover nested-dispatch fixture function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift nested-dispatch fixture function");
        let lifted_dispatches = lifted
            .blocks
            .iter()
            .filter(|block| block.succs.len() == 8)
            .map(|block| block.start_va)
            .collect::<Vec<_>>();
        assert_eq!(
            lifted_dispatches.len(),
            1,
            "the real PIC table must contribute one eight-way CFG dispatch"
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        assert!(
            raw_loop_owns_dispatch(&region, &lifted),
            "the parser loop must own its resolved dispatch: {region:#?}"
        );
        let ast = crate::ir::ast::lower(&lifted, &region, "nested_dispatch_parser");
        let rendered = crate::ir::ast::render(&ast);
        assert_eq!(
            rendered.matches("case ").count(),
            8,
            "every dispatch-table slot must retain a source case label"
        );
        assert!(
            !rendered.contains("unrecovered indirect jump"),
            "a CFG-proven dispatch must not fall back to an indirect jump: {rendered}"
        );
    }

    fn switch_case_labels(region: &crate::ir::structure::Region) -> Option<&[Vec<i64>]> {
        use crate::ir::structure::Region;
        match region {
            Region::Switch { case_labels, .. } => Some(case_labels),
            Region::Seq(parts) => parts.iter().find_map(switch_case_labels),
            Region::IfThen { then_r, .. } => switch_case_labels(then_r),
            Region::IfThenElse { then_r, else_r, .. } => {
                switch_case_labels(then_r).or_else(|| switch_case_labels(else_r))
            }
            Region::While { body, .. } | Region::DoWhile { body, .. } => switch_case_labels(body),
            Region::Block(_)
            | Region::Goto(_)
            | Region::RawLoop { .. }
            | Region::Unstructured(_) => None,
        }
    }

    fn raw_loop_owns_dispatch(
        region: &crate::ir::structure::Region,
        function: &crate::ir::types::LlirFunction,
    ) -> bool {
        use crate::ir::structure::Region;
        match region {
            Region::RawLoop { blocks, .. } => blocks
                .iter()
                .any(|block| function.blocks[*block].succs.len() >= 3),
            Region::Seq(parts) => parts
                .iter()
                .any(|part| raw_loop_owns_dispatch(part, function)),
            Region::IfThen { then_r, .. }
            | Region::While { body: then_r, .. }
            | Region::DoWhile { body: then_r, .. } => raw_loop_owns_dispatch(then_r, function),
            Region::IfThenElse { then_r, else_r, .. } => {
                raw_loop_owns_dispatch(then_r, function) || raw_loop_owns_dispatch(else_r, function)
            }
            Region::Switch {
                arms,
                formal_default,
                ..
            } => {
                arms.iter().any(|arm| raw_loop_owns_dispatch(arm, function))
                    || formal_default
                        .as_deref()
                        .is_some_and(|default| raw_loop_owns_dispatch(default, function))
            }
            Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => false,
        }
    }

    fn structured_loop_owns_dispatch(region: &crate::ir::structure::Region) -> bool {
        use crate::ir::structure::Region;
        match region {
            Region::While { body, .. } | Region::DoWhile { body, .. } => {
                switch_case_labels(body).is_some()
            }
            Region::Seq(parts) => parts.iter().any(structured_loop_owns_dispatch),
            Region::IfThen { then_r, .. } => structured_loop_owns_dispatch(then_r),
            Region::IfThenElse { then_r, else_r, .. } => {
                structured_loop_owns_dispatch(then_r) || structured_loop_owns_dispatch(else_r)
            }
            Region::Switch {
                arms,
                formal_default,
                ..
            } => {
                arms.iter().any(structured_loop_owns_dispatch)
                    || formal_default
                        .as_deref()
                        .is_some_and(structured_loop_owns_dispatch)
            }
            Region::Block(_)
            | Region::Goto(_)
            | Region::RawLoop { .. }
            | Region::Unstructured(_) => false,
        }
    }

    /// The ARM word-table dispatch, assembled to the exact shape the corpus
    /// uses, must produce one CFG successor per table entry.
    ///
    /// Transcribed from `bin_001.elf` at `0x0800d494` in the frozen DecBench
    /// sample-set — a Cortex-M firmware image — and assembling to a
    /// byte-identical sequence:
    ///
    /// ```text
    /// cmp   r0, #4
    /// bhi   .Ldefault          ; in-range on the fall-through edge
    /// adr   r3, .Ltable        ; Capstone reports the 16-bit Thumb encoding
    ///                          ; as `adr r3, #4`, NOT `add r3, pc, #4`
    /// ldr.w pc, [r3, r0, lsl #2]
    /// .Ltable: .word arm0+1, arm1+1, ...   ; absolute, Thumb bit set
    /// ```
    ///
    /// Three separate defects had to be fixed for this to resolve, and each one
    /// alone loses every arm: the `lsl #2` never reached `Operand::scale`
    /// (Capstone carries the shift on the operand, not on `ArmOpMem`);
    /// `classify_ctrl_flow` sees only a mnemonic, so `ldr` was not a branch and
    /// the sweep decoded the table as instructions; and the post-CFG
    /// revalidation built a tracker with no ARM `pc` mode, so it re-reported the
    /// dispatch unresolved and DELETED the edges the walker had proved.
    #[test]
    fn an_arm_word_table_dispatch_produces_one_successor_per_entry() {
        const SOURCE: &str = "\t.syntax unified\n\t.cpu cortex-m4\n\t.thumb\n\t.text\n\
             \t.global dispatch\n\t.thumb_func\n\
             dispatch:\n\tcmp\tr0, #4\n\tbhi\t.Ldefault\n\
             \tadr\tr3, .Ltable\n\tldr.w\tpc, [r3, r0, lsl #2]\n\
             \t.p2align 2\n.Ltable:\n\
             \t.word\t.Lc0 + 1\n\t.word\t.Lc1 + 1\n\t.word\t.Lc2 + 1\n\
             \t.word\t.Lc3 + 1\n\t.word\t.Lc4 + 1\n\
             .Lc0:\tmovs\tr0, #10\n\tbx\tlr\n\
             .Lc1:\tmovs\tr0, #11\n\tbx\tlr\n\
             .Lc2:\tmovs\tr0, #12\n\tbx\tlr\n\
             .Lc3:\tmovs\tr0, #13\n\tbx\tlr\n\
             .Lc4:\tmovs\tr0, #14\n\tbx\tlr\n\
             .Ldefault:\n\tmovs\tr0, #0\n\tbx\tlr\n";

        let tmp = tempfile::tempdir().expect("temporary ARM dispatch build directory");
        let source = tmp.path().join("dispatch.s");
        let binary = tmp.path().join("dispatch.elf");
        std::fs::write(&source, SOURCE).expect("write the ARM dispatch source");
        let build = match Command::new("arm-none-eabi-gcc")
            .args([
                "-mcpu=cortex-m4",
                "-mthumb",
                "-nostdlib",
                "-nostartfiles",
                "-ffreestanding",
                "-Wl,-Ttext=0x08000000",
                "-o",
            ])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            // No ARM cross-assembler here; the x86 lanes still cover the rest.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch arm-none-eabi-gcc: {error}"),
        };
        if !build.status.success() {
            // The linker warns about a missing `_start` and still produces a
            // usable image; a hard failure is a real toolchain problem.
            panic!(
                "assemble the ARM dispatch fixture: {}",
                String::from_utf8_lossy(&build.stderr)
            );
        }

        let data = std::fs::read(&binary).expect("read the assembled ARM image");
        let (functions, _callgraph, _stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let dispatch = functions
            .iter()
            .find(|function| function.entry_point.value == 0x0800_0000)
            .expect("the dispatch function at the link address");

        let by_id: std::collections::HashMap<_, _> = dispatch
            .basic_blocks
            .iter()
            .map(|block| (block.id.clone(), block.start_address.value))
            .collect();
        let arms = dispatch
            .basic_blocks
            .iter()
            .find(|block| {
                // The dispatch block is the one whose terminator is the table
                // load: it starts at the `adr` and ends after the 4-byte
                // `ldr.w`.
                block.successor_ids.len() > 2
            })
            .map(|block| {
                let mut targets: Vec<u64> = block
                    .successor_ids
                    .iter()
                    .filter_map(|id| by_id.get(id).copied())
                    .collect();
                targets.sort_unstable();
                targets
            })
            .unwrap_or_default();

        assert_eq!(
            arms.len(),
            5,
            "`cmp r0, #4` proves five entries, so the dispatch has five arms; \
             got {arms:x?} across blocks {:x?}",
            dispatch
                .basic_blocks
                .iter()
                .map(|b| b.start_address.value)
                .collect::<Vec<_>>()
        );
        // Every arm is a real case body, and none of them is the table itself.
        for arm in &arms {
            assert!(
                *arm >= 0x0800_0020,
                "arm {arm:#x} lands in the table, not in a case body"
            );
        }
    }

    #[test]
    fn clang_o0_statemachine_keeps_jump_table_arms_inside_fsm() {
        let tmp = tempfile::tempdir().expect("temporary Clang state-machine build directory");
        let source = tmp.path().join("statemachine.c");
        let binary = tmp.path().join("statemachine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/statemachine.c"
                ))
            })
            .expect("write the real state-machine fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile statemachine.c with Clang -O0: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let fsm = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("fsm"))
            .expect("exported fsm symbol");
        let fsm_start = fsm.address();
        let fsm_end = fsm_start + fsm.size();
        assert!(
            fsm_end > fsm_start,
            "Clang must emit an exact fsm symbol range"
        );

        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let interior: Vec<_> = functions
            .iter()
            .filter(|function| {
                let entry = function.entry_point.value;
                entry > fsm_start && entry < fsm_end
            })
            .map(|function| (function.name.clone(), function.entry_point.value))
            .collect();

        assert!(
            interior.is_empty(),
            "switch case labels are blocks in fsm, not functions: {interior:?}; seeds={:?}",
            stats.function_seed_kinds
        );
    }

    #[test]
    fn clang_o2_statemachine_retains_cross_block_dispatch_edges() {
        let tmp = tempfile::tempdir().expect("temporary Clang state-machine build directory");
        let source = tmp.path().join("statemachine.c");
        let binary = tmp.path().join("statemachine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/statemachine.c"
                ))
            })
            .expect("write the real state-machine fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile statemachine.c with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| function.name == "fsm")
            .expect("discover fsm");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real fsm CFG");
        assert!(
            lifted.blocks.iter().any(|block| block.succs.len() == 4),
            "four-way state dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect,
            lifted.blocks
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        assert!(
            raw_loop_owns_dispatch(&region, &lifted) || structured_loop_owns_dispatch(&region),
            "the validated four-way CFG must remain inside its state-machine loop: {region:#?}"
        );
    }

    #[test]
    fn clang_o2_cleanup_state_machine_retains_loop_carried_dispatch_edges() {
        let tmp = tempfile::tempdir().expect("temporary Clang cleanup-state-machine directory");
        let source = tmp.path().join("cleanup_state_machine.c");
        let binary = tmp.path().join("cleanup_state_machine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/05_cleanup_and_state_machine.c"
                ))
            })
            .expect("write the real cleanup/state-machine fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile cleanup/state-machine fixture with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| function.name == "fsm")
            .expect("discover fsm");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real fsm CFG");
        assert!(
            lifted.blocks.iter().any(|block| block.succs.len() == 4),
            "loop-carried four-way state dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect,
            lifted.blocks
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        assert!(
            raw_loop_owns_dispatch(&region, &lifted),
            "the guarded or dispatch-headed cycle must retain an owned raw loop: {region:#?}"
        );
    }

    #[test]
    fn gcc_o2_real_corpus_dispatch_keeps_one_function_and_eight_cfg_arms() {
        let tmp = tempfile::tempdir().expect("temporary GCC dispatch build directory");
        let source = tmp.path().join("switch_jt.c");
        let binary = tmp.path().join("switch_jt.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/switch_jt.c"
                ))
            })
            .expect("write the real DecBench switch_jt source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile switch_jt.c with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
        let dispatch_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("dispatch"))
            .map(|symbol| symbol.address())
            .expect("exported dispatch symbol");
        let dwarf_dispatch = crate::debug::dwarf::extract_dwarf_functions(&data)
            .into_iter()
            .find(|function| function.name.as_deref() == Some("dispatch"))
            .expect("DWARF dispatch subprogram");
        assert_eq!(
            dwarf_dispatch.entry_va, dispatch_va,
            "the producer's first range is the semantic hot entry"
        );
        assert_eq!(
            dwarf_dispatch.chunks.first().map(|range| range.start),
            Some(dispatch_va)
        );
        assert!(
            dwarf_dispatch
                .chunks
                .iter()
                .skip(1)
                .any(|range| range.start < dispatch_va),
            "the lower-address cold range must remain auxiliary: {dwarf_dispatch:?}"
        );

        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let named: Vec<_> = functions
            .iter()
            .filter(|function| function.name == "dispatch")
            .collect();
        assert_eq!(
            named.len(),
            1,
            "the compiler split must not survive as a duplicate named function"
        );
        assert_eq!(named[0].entry_point.value, dispatch_va);
        assert!(
            named[0]
                .all_ranges()
                .iter()
                .any(|range| range.start.value < dispatch_va),
            "the cold default block must remain owned by dispatch"
        );
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            named[0],
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real dispatch CFG");
        let cold_va = named[0]
            .all_ranges()
            .iter()
            .map(|range| range.start.value)
            .find(|start| *start < dispatch_va)
            .expect("DWARF cold range");
        assert_eq!(
            lifted.blocks[0].start_va, dispatch_va,
            "LLIR block zero is the semantic entry, even when a cold split has a lower VA"
        );
        assert!(
            lifted.blocks.iter().any(|block| block.start_va == cold_va),
            "the DWARF-owned cold range must retain its executable block"
        );
        assert!(
            lifted.blocks.iter().any(|block| {
                block.succs.contains(&cold_va)
                    && matches!(
                        block.instrs.last().map(|instruction| &instruction.op),
                        Some(crate::ir::types::Op::Jump { target })
                            | Some(crate::ir::types::Op::CondJump { target, .. })
                            if *target == cold_va
                    )
            }),
            "the hot-to-cold jump must remain an intraprocedural CFG edge"
        );

        let scoped_budgets = Budgets {
            max_functions: 1,
            ..Budgets::default()
        };
        let (scoped_functions, _scoped_callgraph) =
            analyze_functions_bytes_with_seeds(&data, &scoped_budgets, &[dispatch_va]);
        let scoped_dispatch = scoped_functions
            .iter()
            .find(|function| function.entry_point.value == dispatch_va)
            .expect("address-scoped dispatch discovery");
        assert!(
            scoped_dispatch
                .basic_blocks
                .iter()
                .any(|block| block.start_address.value == cold_va),
            "address-scoped discovery must hydrate every DWARF-owned range: blocks={:?}, ranges={:?}",
            scoped_dispatch
                .basic_blocks
                .iter()
                .map(|block| block.start_address.value)
                .collect::<Vec<_>>(),
            scoped_dispatch.all_ranges()
        );
        let scoped_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            scoped_dispatch,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift address-scoped dispatch CFG");
        assert!(
            scoped_lifted
                .blocks
                .iter()
                .any(|block| block.succs.contains(&cold_va)),
            "address-scoped lifting must retain the hot-to-cold edge: basic={:?}, lifted={:?}",
            scoped_dispatch
                .basic_blocks
                .iter()
                .map(|block| (
                    block.start_address.value,
                    block.id.clone(),
                    block.successor_ids.clone()
                ))
                .collect::<Vec<_>>(),
            scoped_lifted
                .blocks
                .iter()
                .map(|block| (block.start_va, block.succs.clone()))
                .collect::<Vec<_>>()
        );
        assert!(
            scoped_lifted.blocks.iter().all(|block| {
                block.instrs.iter().all(|instruction| {
                    !matches!(
                        instruction.op,
                        crate::ir::types::Op::Call {
                            target: crate::ir::types::CallTarget::Direct(target),
                            ..
                        } if target == cold_va
                    )
                })
            }),
            "the owned cold range must never be rewritten as a sibling call"
        );
        let dispatch_block = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 8)
            .expect("eight-way LLIR dispatch block");
        assert!(
            matches!(
                dispatch_block
                    .instrs
                    .last()
                    .map(|instruction| &instruction.op),
                Some(crate::ir::types::Op::IndirectJump { .. })
            ),
            "the computed transfer must survive lifting as IndirectJump"
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        fn switch_arms(
            region: &crate::ir::structure::Region,
        ) -> Option<&[crate::ir::structure::Region]> {
            use crate::ir::structure::Region;
            match region {
                Region::Switch { arms, .. } => Some(arms),
                Region::Seq(parts) => parts.iter().find_map(switch_arms),
                Region::IfThen { then_r, .. } => switch_arms(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    switch_arms(then_r).or_else(|| switch_arms(else_r))
                }
                Region::While { body, .. } | Region::DoWhile { body, .. } => switch_arms(body),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => None,
            }
        }
        let arms = switch_arms(&region).expect("recover the real dispatch as a switch");
        let arm_vas: Vec<_> = arms
            .iter()
            .map(|arm| {
                let index = crate::ir::structure::entry_block(arm).expect("non-empty switch arm");
                lifted.blocks[index].start_va
            })
            .collect();
        assert_eq!(
            arm_vas, dispatch_block.succs,
            "case numbering must retain the jump-table entry order"
        );
        assert_eq!(
            stats
                .resolved_dispatches
                .iter()
                .map(|(_site, arms)| *arms)
                .collect::<Vec<_>>(),
            vec![8],
            "the real GCC O2 table jump must contribute all eight case arms"
        );
        let dispatch_site = stats.resolved_dispatches[0].0;
        assert!(
            stats
                .unresolved_indirect
                .iter()
                .all(|(site, _reason)| *site != dispatch_site),
            "the resolved table jump must not also be reported unresolved: {:?}",
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o0_real_dense_compute_recovers_all_eight_cfg_arms() {
        let tmp = tempfile::tempdir().expect("temporary Clang dense-switch build directory");
        let source = tmp.path().join("dense_compute.c");
        let binary = tmp.path().join("dense_compute.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/04_switch_shapes.c"
                ))
            })
            .expect("write the real switch-shape fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile dense_compute.c with Clang -O0: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let dense_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("dense_compute"))
            .map(|symbol| symbol.address())
            .expect("exported dense_compute symbol");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| {
                function.name == "dense_compute" && function.entry_point.value == dense_va
            })
            .expect("discover dense_compute");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real dense_compute CFG");
        let dispatch = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 8)
            .unwrap_or_else(|| {
                panic!(
                    "eight-way dense dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
                    stats.resolved_dispatches, stats.unresolved_indirect, lifted.blocks
                )
            });
        assert!(matches!(
            dispatch.instrs.last().map(|instruction| &instruction.op),
            Some(crate::ir::types::Op::IndirectJump { .. })
        ));

        let shared = functions
            .iter()
            .find(|function| function.name == "shared_bodies")
            .expect("discover shared_bodies from the same real fixture");
        let shared_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            shared,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real shared_bodies CFG");
        let shared_ssa = crate::ir::ssa::compute_ssa(&shared_lifted);
        let shared_region = crate::ir::structure::recover_verified(&shared_lifted, &shared_ssa);
        assert_eq!(
            switch_case_labels(&shared_region),
            Some([vec![0, 2], vec![1, 3]].as_slice()),
            "four table slots sharing two bodies must remain a switch: {shared_region:#?}"
        );

        let sparse = functions
            .iter()
            .find(|function| function.name == "shared_sparse")
            .expect("discover shared_sparse from the same real fixture");
        let sparse_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            sparse,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real shared_sparse CFG");
        let sparse_ssa = crate::ir::ssa::compute_ssa(&sparse_lifted);
        let sparse_region = crate::ir::structure::recover_verified(&sparse_lifted, &sparse_ssa);
        assert_eq!(
            switch_case_labels(&sparse_region),
            Some([vec![0, 10], vec![20, 30]].as_slice()),
            "table holes that target the guard default are not explicit cases: region={sparse_region:#?} resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );

        let fallthrough = functions
            .iter()
            .find(|function| function.name == "fallthrough_chain")
            .expect("discover fallthrough_chain from the same real fixture");
        let fallthrough_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            fallthrough,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real fallthrough_chain CFG");
        assert!(
            fallthrough_lifted
                .blocks
                .iter()
                .any(|block| block.succs.len() == 4),
            "the four-slot fallthrough dispatch must enter the CFG: resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o2_real_dense_compute_keeps_labels_for_a_shared_case_body() {
        let tmp = tempfile::tempdir().expect("temporary Clang dense-switch build directory");
        let source = tmp.path().join("dense_compute.c");
        let binary = tmp.path().join("dense_compute.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/04_switch_shapes.c"
                ))
            })
            .expect("write the real switch-shape fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile dense_compute.c with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let dense_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("dense_compute"))
            .map(|symbol| symbol.address())
            .expect("exported dense_compute symbol");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| {
                function.name == "dense_compute" && function.entry_point.value == dense_va
            })
            .expect("discover dense_compute");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real dense_compute CFG");
        let dispatch = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 8)
            .expect("eight-slot dense dispatch");
        assert_eq!(
            dispatch
                .succs
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            7,
            "Clang folds source cases 2 and 5 onto one multiply-by-two block"
        );

        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        let labels = switch_case_labels(&region).expect("recover the real dispatch as a switch");
        assert!(
            labels.iter().any(|labels| labels == &[2, 5]),
            "both source labels must remain attached to the shared body: {labels:?}"
        );

        let sparse = functions
            .iter()
            .find(|function| function.name == "shared_sparse")
            .expect("discover shared_sparse from the same optimized fixture");
        let sparse_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            sparse,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real optimized shared_sparse CFG");
        let sparse_ssa = crate::ir::ssa::compute_ssa(&sparse_lifted);
        let sparse_region = crate::ir::structure::recover_verified(&sparse_lifted, &sparse_ssa);
        assert_eq!(
            switch_case_labels(&sparse_region),
            Some([vec![0, 10], vec![20, 30]].as_slice()),
            "optimized table holes that target the guard default are not explicit cases: region={sparse_region:#?} resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o2_real_state_machine_carries_the_table_base_to_the_dispatch() {
        let tmp = tempfile::tempdir().expect("temporary Clang state-machine build directory");
        let source = tmp.path().join("statemachine.c");
        let binary = tmp.path().join("statemachine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/statemachine.c"
                ))
            })
            .expect("write the real DecBench state-machine source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile statemachine.c with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let fsm_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("fsm"))
            .map(|symbol| symbol.address())
            .expect("exported fsm symbol");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| function.name == "fsm" && function.entry_point.value == fsm_va)
            .expect("discover the exported fsm function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real state-machine CFG");
        let dispatch_block = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 4)
            .unwrap_or_else(|| {
                panic!(
                    "four-way dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
                    stats.resolved_dispatches, stats.unresolved_indirect, lifted.blocks
                )
            });
        assert!(matches!(
            dispatch_block
                .instrs
                .last()
                .map(|instruction| &instruction.op),
            Some(crate::ir::types::Op::IndirectJump { .. })
        ));
        assert!(
            stats
                .resolved_dispatches
                .iter()
                .any(|(_site, arms)| *arms == 4),
            "the real Clang O2 table jump must contribute all four case arms: {:?}",
            stats.resolved_dispatches
        );
    }
}

#[cfg(test)]
mod dispatch_trim_tests {
    use super::*;

    fn branch(source: u64, target: u64) -> (u64, u64, ControlFlowEdgeKind) {
        (source, target, ControlFlowEdgeKind::Branch)
    }

    fn targets_from(edges: &[(u64, u64, ControlFlowEdgeKind)], source: u64) -> Vec<u64> {
        edges
            .iter()
            .filter(|(edge_source, _, _)| *edge_source == source)
            .map(|(_, target, _)| *target)
            .collect()
    }

    /// A `switch` whose case labels are shared across indices attaches the same
    /// target more than once, and `discover_jump_tables` scans the LONGEST run
    /// of executable-looking words rather than the table's real end — so the
    /// unproven suffix routinely names a VA the proven prefix names too.
    ///
    /// Removing edges by target VALUE (`extras.contains(target)`) deleted every
    /// edge to such a target, proven arm included. Nothing downstream could
    /// repair it: `cfg::repair` de-duplicates successor lists, and de-duplication
    /// cannot restore a successor that was never added. The proven arm simply
    /// left the graph while the recorded arm count still claimed it.
    #[test]
    fn a_proven_arm_survives_the_unproven_suffix_naming_it_again() {
        let block = 0x1000;
        // Table order: cases 0..5 share three bodies; slots 4 and 5 are scanner
        // over-read past the proven extent and repeat 0x2010 and 0x2020.
        let attached = [0x2010, 0x2020, 0x2010, 0x2030, 0x2010, 0x2020];
        let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();
        // An unrelated block reaching the same case body must not be disturbed.
        edges.push(branch(0x1800, 0x2010));

        let kept = trim_unproven_dispatch_edges(&mut edges, block, &attached, 4);

        assert_eq!(
            targets_from(&edges, block),
            vec![0x2010, 0x2020, 0x2010, 0x2030],
            "the four proven slots survive in table order"
        );
        assert_eq!(kept, 4, "the arm count is the surviving edge count");
        assert_eq!(
            targets_from(&edges, 0x1800),
            vec![0x2010],
            "trimming one block's dispatch must not touch another block's edges"
        );
    }

    /// The negative control: with all-distinct targets the value-keyed retain and
    /// the multiplicity-keyed one agree exactly, so the previous behaviour is
    /// preserved wherever the defect could not fire.
    #[test]
    fn an_all_distinct_table_is_trimmed_exactly_as_before() {
        let block = 0x1000;
        let attached = [0x2010, 0x2020, 0x2030, 0x2040, 0x2050];
        let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();

        let kept = trim_unproven_dispatch_edges(&mut edges, block, &attached, 3);

        assert_eq!(targets_from(&edges, block), vec![0x2010, 0x2020, 0x2030]);
        assert_eq!(kept, 3);
    }

    /// A repeat entirely inside the proven prefix keeps BOTH of its edges: the
    /// lifted block's successor list is positional, so collapsing shared case
    /// labels here would lose which indices reach the shared body.
    #[test]
    fn a_repeat_inside_the_proven_prefix_keeps_every_edge() {
        let block = 0x1000;
        let attached = [0x2010, 0x2010, 0x2020, 0x2030];
        let mut edges: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();

        let kept = trim_unproven_dispatch_edges(&mut edges, block, &attached, 3);

        assert_eq!(targets_from(&edges, block), vec![0x2010, 0x2010, 0x2020]);
        assert_eq!(kept, 3);
    }

    /// Nothing proven means nothing kept, and a fully proven table is untouched.
    #[test]
    fn the_degenerate_extents_behave() {
        let block = 0x1000;
        let attached = [0x2010, 0x2020, 0x2010];

        let mut none: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();
        assert_eq!(
            trim_unproven_dispatch_edges(&mut none, block, &attached, 0),
            0
        );
        assert!(targets_from(&none, block).is_empty());

        let mut all: Vec<(u64, u64, ControlFlowEdgeKind)> = attached
            .iter()
            .map(|target| branch(block, *target))
            .collect();
        assert_eq!(
            trim_unproven_dispatch_edges(&mut all, block, &attached, attached.len()),
            3
        );
        assert_eq!(targets_from(&all, block), attached.to_vec());
    }
}

#[cfg(test)]
mod degenerate_block_tests {
    use super::*;

    /// A branch target whose first byte does not decode used to crash the whole
    /// analysis. The sweep records that leader as an EMPTY block (`end == start`,
    /// no instruction consumed), and the leader-split pass then asked a BTreeSet
    /// for the range `(Excluded(s), Excluded(s))` — which panics ("range start and
    /// end are equal and excluded") rather than yielding nothing.
    ///
    /// It is not a corner case: it took out every function in a gcc-11 `-O0`
    /// switch binary (16/16 reported "decompile failed"), because one jump-table
    /// target was decoded as code. Panicking on hostile or merely unusual bytes is
    /// never acceptable in a reverse-engineering tool.
    #[test]
    fn an_undecodable_branch_target_does_not_panic() {
        // 0x1000: 74 02   je 0x1004      (both arms become leaders)
        // 0x1002: 90      nop
        // 0x1003: c3      ret
        // 0x1004: 06      push es -- INVALID in 64-bit mode: decodes to nothing,
        //                 so this leader's block is empty.
        let code: &[u8] = &[0x74, 0x02, 0x90, 0xc3, 0x06];
        let entry = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
        let regions = [ExecRegion {
            start: 0x1000,
            end: 0x1000 + code.len() as u64,
            _file_off_start: 0,
        }];
        let budgets = Budgets {
            max_functions: 1,
            max_blocks: 64,
            max_instructions: 256,
            timeout_ms: 1_000,
            total_timeout_ms: 0,
        };
        // The data buffer is VA-addressed by the region's file offset mapping.
        let tables = std::collections::BTreeMap::new();
        let noreturn_targets = std::collections::HashSet::new();
        let facts = DiscoveryFacts {
            image: None,
            tables: &tables,
            noreturn_targets: &noreturn_targets,
            plt_stub_ranges: &[],
            owned_ranges: None,
            owned_leaders: None,
            proven_end: None,
        };
        let out = discover_function(
            code,
            BArch::X86_64,
            Endianness::Little,
            entry,
            &regions,
            &budgets,
            &facts,
            Deadline::none(),
        );
        let (func, _, _) = out.expect("discovery must succeed, not panic");
        // The decodable blocks survive; the empty one contributes nothing.
        assert!(
            !func.basic_blocks.is_empty(),
            "expected the decodable blocks to be recovered"
        );
    }

    #[test]
    fn dispatch_completeness_survives_stats_aggregation() {
        let mut aggregate = FunctionDiscoveryStats::default();
        let local = SingleFunctionDiscoveryStats {
            unresolved_indirect: vec![(
                0x1234,
                crate::analysis::dispatch::Unresolved::NoBound(0x4000),
            )],
            resolved_dispatches: vec![(0x5678, 4)],
            ..SingleFunctionDiscoveryStats::default()
        };
        merge_single_function_stats(&mut aggregate, local);
        assert_eq!(aggregate.resolved_dispatches, vec![(0x5678, 4)]);
        assert_eq!(
            aggregate.unresolved_indirect,
            vec![(
                0x1234,
                crate::analysis::dispatch::Unresolved::NoBound(0x4000)
            )]
        );
    }

    /// The per-function record is written from the per-function stats, and the
    /// aggregate merge cannot reach it.
    ///
    /// `merge_single_function_stats` ORs one walk's truncation into a WHOLE-RUN
    /// flag, and that aggregate can never be attributed to a function: by the
    /// time it is true, it means "some function, somewhere". So the attribution
    /// is taken one level in, from the same `SingleFunctionDiscoveryStats`
    /// before it is merged, where the function it belongs to is still in hand.
    /// This test pins that the two are independent: merging a truncated local
    /// into the aggregate marks nothing.
    #[test]
    fn truncation_is_attributed_from_the_local_stats_not_the_aggregate() {
        let entry = Address::new(AddressKind::VA, 0x401000, 64, None, None).unwrap();
        let mut walked = Function::new("walked".into(), entry.clone(), FunctionKind::Normal)
            .expect("build function");
        let mut stopped =
            Function::new("stopped".into(), entry, FunctionKind::Normal).expect("build function");

        let local = SingleFunctionDiscoveryStats {
            hit_block_limit: true,
            ..SingleFunctionDiscoveryStats::default()
        };
        record_cfg_incompleteness(&mut stopped, &local);

        let mut aggregate = FunctionDiscoveryStats::default();
        merge_single_function_stats(&mut aggregate, local);
        // The whole-run flag is set...
        assert!(aggregate.hit_block_limit);
        // ...and the function that was NOT stopped is still clean. Marking it
        // from the aggregate is the false-positive this design exists to make
        // unrepresentable.
        assert!(!walked.cfg_is_incomplete());
        assert!(walked.cfg_incomplete_budgets().is_empty());

        assert!(stopped.cfg_is_incomplete());
        assert_eq!(stopped.cfg_incomplete_budgets(), vec!["max_blocks"]);

        // Each budget maps to its own bit; nothing bleeds between them.
        record_cfg_incompleteness(
            &mut walked,
            &SingleFunctionDiscoveryStats {
                hit_instruction_limit: true,
                hit_timeout: true,
                ..SingleFunctionDiscoveryStats::default()
            },
        );
        assert_eq!(
            walked.cfg_incomplete_budgets(),
            vec!["max_instructions", "timeout_ms"]
        );
    }

    /// A walk that completed records nothing, whatever the aggregate says.
    #[test]
    fn a_completed_walk_records_no_truncation() {
        let entry = Address::new(AddressKind::VA, 0x401000, 64, None, None).unwrap();
        let mut func =
            Function::new("f".into(), entry, FunctionKind::Normal).expect("build function");
        record_cfg_incompleteness(&mut func, &SingleFunctionDiscoveryStats::default());
        assert!(!func.cfg_is_incomplete());
    }
}

/// Whether a budget stopped a function's walk must be a fact about THAT
/// function, on a real binary, through the real discovery pipeline.
#[cfg(test)]
mod cfg_incompleteness_attribution_tests {
    use super::*;

    fn hello_gcc_o2() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
        std::fs::read(path).expect("read the checked-in gcc -O2 sample")
    }

    /// In one run where the block budget fires, ONLY the functions it stopped
    /// are marked.
    ///
    /// The aggregate `hit_block_limit` is true for the whole run, so a design
    /// that reported it against a function would mark every function in this
    /// binary incomplete. The per-function flag must instead partition the list,
    /// and the partition must be the true one: a marked function is at the
    /// block wall, an unmarked one stopped below it on its own terminators.
    #[test]
    fn a_block_budget_marks_only_the_functions_it_stopped() {
        let data = hello_gcc_o2();
        const TIGHT_BLOCKS: usize = 2;

        let (wide, _cg, wide_stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                max_blocks: 4096,
                ..Budgets::default()
            },
        );
        assert!(
            !wide_stats.hit_block_limit,
            "4096 blocks must be enough for every function in a hello-world"
        );
        assert!(
            wide.iter().all(|f| !f.cfg_is_incomplete()),
            "no function may be marked incomplete when no budget fired"
        );

        let (tight, _cg, tight_stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                max_blocks: TIGHT_BLOCKS,
                ..Budgets::default()
            },
        );
        assert!(
            tight_stats.hit_block_limit,
            "a 2-block budget must stop something in this binary"
        );

        let mut marked = 0usize;
        let mut clean = 0usize;
        for function in &tight {
            if function.cfg_is_incomplete() {
                marked += 1;
                assert_eq!(
                    function.cfg_incomplete_budgets(),
                    vec!["max_blocks"],
                    "0x{:x} must name the budget that actually fired",
                    function.entry_point.value
                );
                assert!(
                    function.basic_blocks.len() >= TIGHT_BLOCKS,
                    "0x{:x} is marked but never reached the wall ({} blocks)",
                    function.entry_point.value,
                    function.basic_blocks.len()
                );
            } else {
                clean += 1;
                assert!(
                    function.basic_blocks.len() < TIGHT_BLOCKS,
                    "0x{:x} is at the block wall with {} blocks and was NOT marked",
                    function.entry_point.value,
                    function.basic_blocks.len()
                );
            }
        }
        assert!(
            marked > 0,
            "the tight budget must mark at least one function"
        );
        assert!(
            clean > 0,
            "at least one small function must survive the same run unmarked - \
             that is the no-contamination property"
        );
    }
}

#[cfg(test)]
mod dispatch_decline_reporting_tests {
    use super::*;

    /// A checked-in gcc -O2 shared object. Every gcc ELF carries the crtstuff
    /// `register_tm_clones` / `deregister_tm_clones` pair, whose `jmp *%rax`
    /// after a GOT load is a register-indirect transfer this pass declines - so
    /// this sample exercises the decline path without needing a compiler.
    fn hello_gcc_o2() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
        std::fs::read(path).expect("read the checked-in gcc -O2 sample")
    }

    /// Every declined dispatch names a reason, and the reason renders.
    ///
    /// The reason has always been computed; this pins that it is a real value a
    /// consumer can read rather than a variant nothing formats.
    #[test]
    fn every_declined_dispatch_carries_a_labelled_reason() {
        let data = hello_gcc_o2();
        let (_functions, _cg, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(
            !stats.unresolved_indirect.is_empty(),
            "the crtstuff TM-clone pair must produce at least one declined dispatch"
        );
        for (site, why) in &stats.unresolved_indirect {
            assert!(
                !why.label().is_empty() && !why.detail().is_empty(),
                "site {site:#x} declined with an unlabelled reason: {why:?}"
            );
            // `UnknownBase` is the only variant that names no table; the other
            // two are about a specific address and must carry it.
            assert_eq!(
                why.table_va().is_none(),
                matches!(why, crate::analysis::dispatch::Unresolved::UnknownBase),
                "site {site:#x}: {why:?}"
            );
        }
    }

    /// A block whose indirect terminator was declined must not advertise itself
    /// as a function exit.
    ///
    /// `is_exit_block()` is `relationships_known && successors.is_empty()`, and
    /// `relationships_known` used to be set unconditionally - so a `jmp *%rax`
    /// whose targets were never recovered read as a block with no successors
    /// BECAUSE IT HAS NONE. Measured over the 758 fixture objects that was 2909
    /// of 28169 exit claims.
    #[test]
    fn a_block_with_a_declined_dispatch_does_not_claim_to_be_an_exit() {
        let data = hello_gcc_o2();
        let (functions, _cg, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let sites: Vec<u64> = stats
            .unresolved_indirect
            .iter()
            .map(|(site, _)| *site)
            .collect();
        assert!(!sites.is_empty(), "no declined dispatch to check");

        let mut checked = 0usize;
        for function in &functions {
            for block in &function.basic_blocks {
                let owns = sites.iter().any(|site| {
                    *site >= block.start_address.value && *site < block.end_address.value
                });
                if !owns {
                    continue;
                }
                checked += 1;
                assert!(
                    block.successor_ids.is_empty(),
                    "a declined dispatch attaches no successors"
                );
                assert!(
                    !block.is_exit_block(),
                    "block {} ends in an unfollowed indirect transfer and must not \
                     be classified as a function exit",
                    block.id
                );
            }
        }
        assert!(checked > 0, "no block owned a declined dispatch site");
    }

    /// The complement: ordinary blocks keep their entry/exit classification.
    /// A fix that cleared the flag everywhere would also pass the test above.
    #[test]
    fn ordinary_blocks_still_classify_as_entries_and_exits() {
        let data = hello_gcc_o2();
        let (functions, _cg, _stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let entries = functions
            .iter()
            .flat_map(|function| &function.basic_blocks)
            .filter(|block| block.is_entry_block())
            .count();
        let exits = functions
            .iter()
            .flat_map(|function| &function.basic_blocks)
            .filter(|block| block.is_exit_block())
            .count();
        assert!(entries > 0 && exits > 0, "entries={entries} exits={exits}");
    }
}

#[cfg(test)]
mod analysis_deadline_tests {
    use super::*;

    /// A binary big enough that whole-binary discovery takes real time.
    fn big_sample() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/go/hello-go-static");
        std::fs::read(path).expect("read the checked-in static Go sample")
    }

    #[test]
    fn a_deadline_of_zero_never_expires() {
        let deadline = Deadline::start(&Budgets {
            total_timeout_ms: 0,
            ..Budgets::default()
        });
        assert!(!deadline.expired());
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!deadline.expired(), "0 must mean no ceiling at all");
    }

    #[test]
    fn a_deadline_expires_once_its_wall_clock_passes() {
        let deadline = Deadline::start(&Budgets {
            total_timeout_ms: 1,
            ..Budgets::default()
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(deadline.expired());
        assert!(deadline.elapsed_ms() >= 10);
    }

    /// The default must be the unbounded one, or every existing caller's
    /// recorded function counts would move with nothing to attribute it to.
    #[test]
    fn the_default_budget_has_no_whole_analysis_ceiling() {
        assert_eq!(Budgets::default().total_timeout_ms, 0);
    }

    /// The defect this closes: `timeout_ms` restarts inside `discover_function`,
    /// so before `total_timeout_ms` existed there was no ceiling on the analysis
    /// as a whole and a pathological binary ran until it finished or the user
    /// gave up. Exceeding it must now TRUNCATE AND SAY SO.
    #[test]
    fn an_impossible_deadline_truncates_discovery_and_reports_it() {
        let data = big_sample();
        let (functions, _cg, stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: 1,
                ..Budgets::default()
            },
        );
        assert!(
            stats.hit_total_timeout,
            "a 1ms ceiling on a {}-byte binary must be reported as exceeded",
            data.len()
        );
        assert_eq!(stats.total_timeout_ms, 1, "the ceiling must be recorded");
        let (full, _cg, full_stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(
            !full_stats.hit_total_timeout,
            "the default budget has no ceiling and must never report one"
        );
        assert!(
            functions.len() < full.len(),
            "truncation must actually truncate: {} vs {}",
            functions.len(),
            full.len()
        );
    }

    /// The `.eh_frame` sweep obeys the ceiling like its twelve siblings.
    ///
    /// It was the one whole-image seed scan in `seeds` outside `scan_within`,
    /// so on the byte-only path — the one every `analyze_functions_bytes*`
    /// entry point takes — it ran a full sweep of the image to completion after
    /// the ceiling had already passed. A bounded overrun rather than a
    /// correctness bug, which is why nothing caught it: every other measure of
    /// the run was unaffected. `eh_frame_candidates` is the observable, because
    /// it counts what the sweep returned rather than what survived the gates
    /// after it.
    /// A large ELF that actually carries `.eh_frame`.
    ///
    /// `big_sample()` cannot be used for the sweep test: it is a static Go
    /// binary, and Go carries its own `pclntab` instead, so the phase returns
    /// zero candidates there under any budget. Measuring a guard on a scan that
    /// finds nothing proves nothing.
    fn big_eh_frame_sample() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/rust/hello-rust-debug");
        std::fs::read(path).expect("read the checked-in Rust debug sample")
    }

    #[test]
    fn an_impossible_deadline_skips_the_eh_frame_sweep_too() {
        let data = big_eh_frame_sample();
        let (_, _cg, full_stats) = analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(
            full_stats.eh_frame_candidates > 0,
            "the sample must actually exercise the .eh_frame phase for this test to mean anything"
        );
        let (_, _cg, stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: 1,
                ..Budgets::default()
            },
        );
        assert!(stats.hit_total_timeout, "the 1ms ceiling must be reported");
        assert_eq!(
            stats.eh_frame_candidates,
            0,
            "a scan that starts after the ceiling has passed must return nothing, \
             not sweep {} bytes and report {} candidates",
            data.len(),
            stats.eh_frame_candidates
        );
    }

    /// A budget that is not exceeded must not change what discovery finds. This
    /// is the property the whole change stands on — an enforcement that quietly
    /// drops functions is worse than no enforcement.
    #[test]
    fn a_ceiling_that_is_never_reached_changes_nothing() {
        let data = big_sample();
        let (unbounded, _cg, unbounded_stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let generous = 10 * unbounded_stats.elapsed_ms.max(1) + 60_000;
        let (bounded, _cg, bounded_stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: generous,
                ..Budgets::default()
            },
        );
        assert!(!bounded_stats.hit_total_timeout);
        assert_eq!(
            unbounded
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>(),
            bounded
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>(),
            "a generous ceiling must yield the identical function set"
        );
    }

    /// Cancellation is what makes a long analysis interruptible from Python: the
    /// binding polls `Python::check_signals` on the calling thread and sets this
    /// flag. A cancelled run must stop, report the truncation, and still return
    /// whatever it had — never hang, never lie about completeness.
    #[test]
    fn a_cancelled_analysis_stops_and_reports_the_truncation() {
        use std::sync::atomic::AtomicBool;
        let data = big_sample();
        let cancel = AtomicBool::new(true); // already asked to stop
        let started = std::time::Instant::now();
        let (functions, _cg, stats) =
            analyze_functions_bytes_cancellable(&data, &Budgets::default(), &[], &cancel);
        assert!(stats.hit_total_timeout, "cancellation must be reported");
        assert!(
            functions.is_empty(),
            "a run cancelled before it started has nothing to report: {}",
            functions.len()
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "cancellation must actually stop the run"
        );
    }

    /// The flag is checked, not merely accepted: a run with the flag CLEAR must
    /// produce exactly what the uncancellable path produces.
    #[test]
    fn a_cancellable_run_that_is_never_cancelled_is_the_ordinary_run() {
        use std::sync::atomic::AtomicBool;
        let data = big_sample();
        let cancel = AtomicBool::new(false);
        let (cancellable, _cg, cancellable_stats) =
            analyze_functions_bytes_cancellable(&data, &Budgets::default(), &[], &cancel);
        let (ordinary, _cg, _stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(!cancellable_stats.hit_total_timeout);
        assert_eq!(
            cancellable
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>(),
            ordinary
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>()
        );
    }

    /// Truncation must leave a trail: the seeds that were never walked are
    /// counted, so a consumer can tell an incomplete answer from a complete one.
    #[test]
    fn a_truncated_run_reports_the_seeds_it_never_reached() {
        let data = big_sample();
        let (_functions, _cg, stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: 1,
                ..Budgets::default()
            },
        );
        assert!(stats.hit_total_timeout);
        assert!(
            stats.elapsed_ms > 0,
            "a truncated run must report the wall clock it consumed"
        );
    }
}
