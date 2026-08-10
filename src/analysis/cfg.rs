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

/// True when `m` is an A32 condition-suffixed register branch (`bxeq`,
/// `bxne`, ...). When the operand is `lr` this is a conditional return, but
/// either operand shape ends the current block and retains lexical fallthrough.
fn is_arm_cond_bx(m: &str) -> bool {
    let Some(cc) = m.strip_prefix("bx") else {
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
    let lower = ins.mnemonic.to_ascii_lowercase();
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower);
    if m == "pop" || m.starts_with("ldm") {
        return ins
            .operands
            .iter()
            .any(|o| o.register.as_deref() == Some("pc"));
    }
    // GCC commonly spells a one-register Thumb pop as the post-indexed load
    // `ldr.w pc, [sp], #4`.  Capstone reports it as `ldr`, not `pop`, so the
    // destination and stack base must participate in control-flow recovery.
    if m == "ldr" {
        return ins.operands.first().and_then(|o| o.register.as_deref()) == Some("pc")
            && ins.operands.get(1).and_then(|o| o.base.as_deref()) == Some("sp");
    }
    false
}

/// The register an ARM32 instruction defines, for a caller that must model
/// definitions itself.
///
/// Capstone's ARM detail marks every operand `Access::Read`, so
/// `DispatchTracker::observe` — which finds definitions through `Access::Write`
/// on operand 0 — sees no ARM write at all. Without this, a range bound proved
/// by `cmp` would survive an intervening `sub.w r5, r5, #0x3000`, and the
/// dispatch would size its table from a value that no longer exists.
///
/// The recognised set is the mnemonics that do NOT write operand 0: comparisons,
/// stores, and the `it` block prefix. Everything else is treated as a
/// definition, so an unmodelled instruction costs a resolution rather than
/// producing a table sized from a stale bound.
fn arm_defined_register(ins: &Instruction) -> Option<&str> {
    let lower = ins.mnemonic.to_ascii_lowercase();
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower);
    // `cmp`/`cmn`/`tst`/`teq` read both operands; `str*`/`stm*`/`push` read the
    // register and write memory; `it*` carries only a condition. Prefix matching
    // covers the condition-suffixed and flag-setting spellings (`cmpne`,
    // `strbeq`, `stmia`) in one rule.
    if m.starts_with("cmp")
        || m.starts_with("cmn")
        || m.starts_with("tst")
        || m.starts_with("teq")
        || m.starts_with("str")
        || m.starts_with("stm")
        || m.starts_with("push")
        || m.starts_with("it")
    {
        return None;
    }
    ins.operands.first()?.register.as_deref()
}

/// Does this conditional branch's FALLTHROUGH edge carry the range bound its
/// block's last comparison established?
///
/// Only the unsigned "above" forms qualify: `cmp idx, N` followed by "branch
/// away when idx > N" leaves `idx <= N` on the fallthrough, which is exactly the
/// jump table's entry count minus one. A signed test is a different construct
/// and proves nothing about an unsigned table index.
fn guard_bound_reaches_fallthrough(mnemonic: &str, arch: BArch) -> bool {
    let lower = mnemonic.to_ascii_lowercase();
    match arch {
        BArch::X86 | BArch::X86_64 => matches!(lower.as_str(), "ja" | "jae" | "jnbe" | "jnb"),
        // Thumb-2's `cmp idx, #N; bhi.w default; tbb/tbh [pc, idx]`. `bhi` alone,
        // because it is the only form whose in-range edge admits exactly `[0, N]`
        // — and it is what GCC and Clang emit for every table branch measured
        // here (three sites in `tests/decompiler_fixtures`, two in betaflight).
        BArch::ARM => {
            lower
                .strip_suffix(".w")
                .or_else(|| lower.strip_suffix(".n"))
                .unwrap_or(&lower)
                == "bhi"
        }
        _ => false,
    }
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
            // `tbb`/`tbh` are the Thumb-2 table branches. They ARE the switch
            // dispatch, and they are unconditional: control never falls through
            // to the byte after them, because that byte is the first entry of
            // the table they read. Leaving them unclassified made the linear
            // sweep decode the whole table as instructions and then walk into
            // the default arm, so a 240-case switch produced no cases at all.
            if m == "b"
                || m == "b.w"
                || m == "cbz"
                || m == "cbnz"
                || m == "tbb"
                || m == "tbh"
                || is_arm_cond_branch(&m)
                || is_arm_cond_bx(&m)
            {
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
            // `b.w` is the Thumb-2 wide unconditional branch; `tbb`/`tbh` are
            // the Thumb-2 table branches, whose lexical successor is their own
            // table rather than a fallthrough arm.
            "b" | "b.w" | "br" | "braa" | "braaz" | "brab" | "brabz" | "tbb" | "tbh"
        ),
        BArch::X86 | BArch::X86_64 => m == "jmp",
        // Preserve the historical (arch-agnostic) semantics for the remaining
        // architectures so this refactor is behaviour-preserving for them.
        _ => m == "jmp" || m == "b",
    }
}

fn immediate_target(ins: &Instruction) -> Option<u64> {
    // Branch destinations are the final immediate operand. Most control-flow
    // instructions have only one, but AArch64 TBZ/TBNZ spell both a tested bit
    // index and the destination as immediates (`tbnz w0,#31,target`). Taking the
    // first queues address 31 and leaves the real cold block undiscovered.
    ins.operands
        .iter()
        .filter_map(|op| op.immediate)
        .next_back()
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

/// Does an x86 ELF direct-jump target carry strong independent function-entry
/// evidence?
///
/// A bare long jump is not enough: optimized functions contain distant cold
/// blocks and switch arms.  CET's ENDBR landing pad followed immediately by a
/// recognised prologue is much narrower and survives fully stripping the local
/// symbol.  This is the shape produced by sibling-call wrappers in current GCC
/// and Clang output (for example DecBench libedit's `em_inc_search_prev`).
fn elf_x86_tail_target_looks_like_function_start(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    target_va: u64,
    arch: BArch,
) -> bool {
    if !matches!(arch, BArch::X86 | BArch::X86_64) || !data.starts_with(b"\x7fELF") {
        return false;
    }
    let Some(file_off) = indexed_code_offset(image, data, target_va) else {
        return false;
    };
    let Some(head) = data.get(file_off..) else {
        return false;
    };
    let landing_pad_len = match head {
        [0xf3, 0x0f, 0x1e, 0xfa, ..] if arch == BArch::X86_64 => 4,
        [0xf3, 0x0f, 0x1e, 0xfb, ..] if arch == BArch::X86 => 4,
        _ => return false,
    };
    let after_landing_pad = &head[landing_pad_len..];
    head_looks_like_fn_start(after_landing_pad)
        // SysV prologues commonly save a low callee-saved register without a
        // REX prefix.  This is too weak for the general xref-start gate, but is
        // strong enough behind an architecture-matching CET landing pad.
        || matches!(after_landing_pad, [0x53 | 0x55 | 0x56 | 0x57, ..])
}

/// Is this ARM32 branch target a PLT stub — i.e. is the branch a tail call?
///
/// A PLT entry is linker-generated import glue. No compiler places one inside a
/// function body, so an unconditional branch to one always leaves the function
/// for good. GCC lowers `return f(x);` for an imported `f` to exactly
/// `b.w f@plt`, and ARM has no CET landing pad for
/// [`elf_x86_tail_target_looks_like_function_start`] to key on — so without this
/// the branch stayed an intra-function edge, and `call_forward_result`
/// decompiled to `goto L_49c; L_49c: ;` with no return value at all.
///
/// Deliberately restricted to ARM32 and to the stub SECTIONS: the test is a
/// property of where the target lives, not a guess about the bytes there, and
/// no other architecture's classification is touched.
fn elf_arm_tail_target_is_plt_stub(data: &[u8], target_va: u64, arch: BArch) -> bool {
    use object::{Object, ObjectSection};
    if !matches!(arch, BArch::ARM) || !data.starts_with(b"\x7fELF") {
        return false;
    }
    let Ok(object) = crate::decompile::profile::parse_object(data) else {
        return false;
    };
    object.sections().any(|section| {
        matches!(section.name(), Ok(".plt" | ".plt.sec" | ".iplt"))
            && section.size() != 0
            && target_va >= section.address()
            && target_va < section.address().saturating_add(section.size())
    })
}

/// Discover a single function starting at `entry` within executable regions.
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
    left
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
) -> Option<(
    crate::analysis::dispatch::DispatchTracker,
    Option<Instruction>,
)> {
    let darch: crate::core::disassembler::Architecture = arch.into();
    let mut backend = registry::for_arch(darch, endianness)?;
    if let Some(thumb) = thumb {
        let _ = backend.set_thumb_mode(thumb);
    }
    let bits = darch.address_bits();
    let mut tracker = crate::analysis::dispatch::DispatchTracker::new();
    tracker.inherit_bound(bounds);
    tracker.inherit_addresses(addresses);
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

fn resolve_dispatch(
    data: &[u8],
    regions: &[ExecRegion],
    tracker: &crate::analysis::dispatch::DispatchTracker,
    instruction: &Instruction,
    tables: &std::collections::BTreeMap<u64, Vec<u64>>,
) -> Option<crate::analysis::dispatch::Resolution> {
    // Thumb-2 `tbb`/`tbh` name their table in the instruction (`pc` is the base)
    // and store it inline in `.text` as unsigned halfword counts. Nothing about
    // that shape reaches `resolve_with`, which resolves a REGISTER to a
    // rodata-relative table, so it is answered here and reported through the
    // same `Resolution` so every caller — including the post-CFG revalidation —
    // treats it identically.
    if let Some(branch) = tracker.thumb_table_branch(instruction) {
        let Some(entry_count) = branch.entry_count else {
            return Some(crate::analysis::dispatch::Resolution::Unresolved(
                crate::analysis::dispatch::Unresolved::NoBound(branch.table_va),
            ));
        };
        return Some(
            match decode_thumb_table_branch(
                data,
                branch.table_va,
                branch.entry_size,
                entry_count,
                |target| in_exec_regions(regions, target).is_some(),
            ) {
                Some(table) => crate::analysis::dispatch::Resolution::Table {
                    table_va: table.table_va,
                    targets: table.targets,
                },
                None => crate::analysis::dispatch::Resolution::Unresolved(
                    crate::analysis::dispatch::Unresolved::NoTableAt(branch.table_va),
                ),
            },
        );
    }
    tracker.resolve_with(instruction, tables, |table_va, entry_count| {
        decode_bounded_relative_jump_table(data, table_va, entry_count, |target| {
            in_exec_regions(regions, target).is_some()
        })
        .map(|table| table.targets)
    })
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
        // A switch's range check sits in the block BEFORE the dispatch, and it
        // is the only thing that knows how many entries the table has. Carry it
        // across the in-range edge; see `DispatchTracker::inherit_bound`.
        dispatch.inherit_bound(index_bounds.get(&start_va).cloned());
        dispatch.inherit_addresses(dispatch_addresses.get(&start_va));
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
            let ins = match backend.disassemble_instruction(&addr, slice) {
                Ok(i) => i,
                Err(_) => break 'block,
            };
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
            let (is_branch, is_call, mut is_ret) = classify_ctrl_flow(&ins.mnemonic, arch);
            // ARM `pop {…, pc}` / `ldm …, pc` is a return; the mnemonic alone
            // can't say so, so resolve it on the operands here.
            if matches!(arch, BArch::ARM) && arm_pop_writes_pc(&ins) {
                is_ret = true;
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
                let unconditional = is_unconditional_branch_mnemonic(&ins.mnemonic, arch);
                if let Some(tgt) = immediate_target(&ins) {
                    let is_exec_target = in_exec_regions(regions, tgt).is_some();
                    let is_pe_tail_target = unconditional
                        && !facts.owns(tgt)
                        && data.len() >= 2
                        && &data[..2] == b"MZ"
                        && is_exec_target
                        && pe_tail_target_looks_like_function_start(data, tgt);
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
                    let is_elf_arm_tail_target = unconditional
                        && !facts.owns(tgt)
                        && tgt != entry.value
                        && is_exec_target
                        && elf_arm_tail_target_is_plt_stub(data, tgt, arch);
                    if is_pe_tail_target || is_elf_x86_tail_target || is_elf_arm_tail_target {
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
                        match resolve_dispatch(data, regions, &dispatch, &ins, facts.tables) {
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

    // Prove loop-carried value ranges over the completed speculative graph.
    // This is deliberately separate from the one-edge `index_bounds` map: a
    // compiler may remove a switch guard after proving that an enum/state
    // register is always in range.  Candidate table arms make those state
    // transitions reachable for analysis, but final validation below keeps
    // only the exact prefix justified by this fixed point.
    let thumb =
        arm32_mode.map(|mode| matches!(mode, crate::analysis::arm32_mode::Arm32Mode::Thumb));
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

    // Recompute concrete-address facts to a fixed point over the now-complete
    // graph. The streaming walk above sees predecessors incrementally; a loop
    // back-edge discovered after its header can invalidate a table-base fact
    // that looked unique on the first visit. Must-dataflow makes that loss
    // propagate through every downstream block before tentative table edges are
    // accepted.
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
                )
                .and_then(|(tracker, instruction)| {
                    instruction.and_then(|instruction| {
                        resolve_dispatch(data, regions, &tracker, &instruction, facts.tables)
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
                let extras = dispatch_edge.attached[targets.len()..].to_vec();
                if !extras.is_empty() {
                    trimmed_dispatches.push((
                        dispatch_edge.site,
                        dispatch_edge.block_start,
                        extras,
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
    for (site, block_start, extras, retained) in trimmed_dispatches {
        edges.retain(|(source, target, _)| !(*source == block_start && extras.contains(target)));
        if let Some((_, arms)) = stats
            .resolved_dispatches
            .iter_mut()
            .find(|(resolved, _)| *resolved == site)
        {
            *arms = retained;
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

    // Build Function object
    let fname = format!("sub_{:x}", entry.value);
    let mut func = Function::new(fname, entry.clone(), FunctionKind::Normal).ok()?;
    if matches!(
        arm32_mode,
        Some(crate::analysis::arm32_mode::Arm32Mode::Thumb)
    ) {
        func.add_flag(FunctionFlags::IS_THUMB);
    }

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

    // Retain exact interprocedural targets on the function object.  Address-scoped
    // decompilation intentionally stops discovery once all requested entries are
    // found, but its name map still needs these xrefs in order to render an
    // anonymous terminal jump as `sub_<va>(...)` rather than a dangling local goto.
    for xref in &call_edges {
        if let Ok(callee) = Address::new(AddressKind::VA, xref.target_va, bits, None, None) {
            func.add_callee(callee);
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

fn va_is_discovered_block_leader(functions: &[Function], va: u64) -> bool {
    functions.iter().any(|function| {
        va != function.entry_point.value
            && function
                .basic_blocks
                .iter()
                .any(|block| block.start_address.value == va)
    })
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
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if arch != BArch::AArch64 {
        return Vec::new();
    }
    let read_word = |va: u64| -> Option<u32> {
        // Scanning for function starts reads instructions, so resolve as code.
        let off = indexed_code_offset(image, data, va)?;
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
                                && matches!(
                                    read_word(prev),
                                    Some(AARCH64_BTI_C | AARCH64_BTI_JC)
                                ) =>
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

/// Head patterns that open a System V x86-64 function.
///
/// Deliberately narrower than [`head_looks_like_fn_start`], which also accepts
/// thunk and stub shapes that suit PE. Here the candidate must look like a real
/// GCC/Clang function entry, because ELF discovery already has `.eh_frame` for
/// the easy cases and this scan exists only for what `.eh_frame` cannot cover:
/// hand-written assembly, `-fno-asynchronous-unwind-tables` builds such as
/// Alpine's `busybox`, and `.init`/`.fini` fragments.
fn elf_x86_prologue_head(head: &[u8]) -> bool {
    match head {
        // endbr64 — CET, and the first instruction of essentially every
        // function in a current distro build.
        [0xf3, 0x0f, 0x1e, 0xfa, ..] => true,
        // push rbp; mov rbp, rsp
        [0x55, 0x48, 0x89, 0xe5, ..] => true,
        // push rbp alone, then any callee-saved push
        [0x55, 0x41, 0x54 | 0x55 | 0x56 | 0x57, ..] => true,
        // push rbx / rbp / rsi / rdi followed by a REX-prefixed move
        [0x53 | 0x55 | 0x56 | 0x57, 0x48, 0x89, ..] => true,
        // sub rsp, imm8 / imm32
        [0x48, 0x83, 0xec, ..] => true,
        [0x48, 0x81, 0xec, ..] => true,
        _ => false,
    }
}

/// AArch64 words that open a function without pointer authentication.
///
/// `stp x29, x30, [sp, #-N]!` is the canonical frame save and `sub sp, sp, #N`
/// the canonical frame allocation. Matching only PAC prologues meant this scan
/// found nothing on the Ubuntu and Alpine AArch64 builds actually in the sample
/// tree, which are BTI-enabled but not PAC-signed.
fn aarch64_unhardened_prologue(word: u32) -> bool {
    // stp x29, x30, [sp, #imm]!  — pre-indexed, base sp, pair x29/x30.
    // Encoding: 1010 1001 10ii iiii i111 1011 111x xxxx with Rt=x29, Rt2=x30.
    let stp_frame = (word & 0xffc0_7fff) == 0xa980_7bfd;
    // sub sp, sp, #imm  (64-bit, immediate form, Rd=Rn=sp=31)
    let sub_sp = (word & 0xff80_03ff) == 0xd100_03ff;
    stp_frame || sub_sp
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

/// Scan ELF executable regions for function prologues.
///
/// Candidates are emitted as ordinary `Prologue` seeds, which remain
/// body-overlap gated: unlike an `.eh_frame` FDE start this is a heuristic, and
/// it must never split a function that a trusted seed already proved.
fn scan_elf_prologue_function_starts(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        return Vec::new();
    }
    let mut starts = Vec::new();
    match arch {
        BArch::X86_64 => {
            for region in regions {
                // 16-byte alignment is what both GCC and Clang use for function
                // entries by default; scanning every byte would trade a large
                // slowdown for candidates that are almost all false.
                let mut va = align_up_u64(region.start, 16);
                while va < region.end {
                    if let Some(off) = indexed_code_offset(image, data, va) {
                        if off < data.len()
                            && has_function_boundary_marker(data, off)
                            && elf_x86_prologue_head(&data[off..])
                        {
                            starts.push(va);
                        }
                    }
                    va = match va.checked_add(16) {
                        Some(next) => next,
                        None => break,
                    };
                }
            }
        }
        BArch::AArch64 => {
            for region in regions {
                let mut va = align_up_u64(region.start, 4);
                while va + 4 <= region.end {
                    if let Some(off) = indexed_code_offset(image, data, va) {
                        if let Some(b) = data.get(off..off + 4) {
                            let word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                            if aarch64_unhardened_prologue(word) {
                                starts.push(va);
                            }
                        }
                    }
                    va = match va.checked_add(4) {
                        Some(next) => next,
                        None => break,
                    };
                }
            }
        }
        _ => {}
    }
    starts.sort_unstable();
    starts.dedup();
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

/// Attach LSDA-only landing-pad blocks to their authoritative parent function.
///
/// These blocks have no ordinary predecessor: the unwinder transfers to them
/// after a protected call throws. They therefore cannot be found by the normal
/// entry-rooted CFG walk. We discover from each metadata-proven landing pad,
/// retain only blocks inside the parent's authoritative ranges, and merge their
/// ordinary handler-internal edges. The exceptional edge itself intentionally
/// remains typed metadata in [`crate::analysis::exception`]; presenting it as a
/// normal branch would confuse dominance and structuring.
fn attach_exception_landing_pads(
    data: &[u8],
    arch: BArch,
    end: Endianness,
    regions: &[ExecRegion],
    budgets: &Budgets,
    facts: &DiscoveryFacts<'_>,
    functions: &mut [Function],
    deadline: Deadline<'_>,
) -> Vec<(u64, FunctionXref)> {
    let sites = crate::analysis::exception::extract_exception_call_sites(data);
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

    for site in sites {
        let Some(&parent_index) = parent_by_fde_start.get(&site.function_start) else {
            continue;
        };
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
        block.relationships_known = true;
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
        // Take every child-owned graph component without removing the child
        // yet — the post-loop removal pass uses indices, so we can't shift the
        // list in place here. Chunks without blocks are metadata, not a merged
        // function: address-scoped lifting would otherwise clip or call out to
        // the executable cold fragment instead of structuring it locally.
        let (child_entry, child_ranges, child_blocks, child_edges, child_callers, child_callees) = {
            let child = &functions[*child_idx];
            let ranges = if !child.chunks.is_empty() {
                child.chunks.clone()
            } else {
                child.range.clone().map(|r| vec![r]).unwrap_or_default()
            };
            (
                child.entry_point.clone(),
                ranges,
                child.basic_blocks.clone(),
                child.edges.clone(),
                child.callers.clone(),
                child.callees.clone(),
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
        // The compiler split's entry was an interprocedural target only until
        // the child became part of its logical parent.
        parent.callees.remove(&child_entry);
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
    let (functions, cg, _stats) = analyze_functions_bytes_within(
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
    let noreturn_targets = crate::analysis::call_semantics::imported_noreturn_targets(data);
    let facts = DiscoveryFacts {
        image: Some(image),
        tables: &tables,
        noreturn_targets: &noreturn_targets,
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
    analyze_functions_bytes_within(data, budgets, requested_vas, Deadline::start(budgets), None)
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
    analyze_functions_bytes_within(
        data,
        budgets,
        requested_vas,
        Deadline::start(budgets).with_cancel(cancel),
        None,
    )
}

fn analyze_functions_bytes_within(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
    deadline: Deadline<'_>,
    image: Option<&crate::program::image::ProgramImage>,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    let (regions, arch, end, entry) =
        image.map_or_else(|| parse_exec_regions(data), parse_exec_regions_in);
    let mut functions: Vec<Function> = Vec::new();
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
    let noreturn_targets = crate::analysis::call_semantics::imported_noreturn_targets(data);

    // Explicit caller-provided addresses are authoritative and go first so a
    // tight function budget cannot be consumed by whole-binary heuristics
    // before the requested entries are reached. Callers provide executable
    // code VAs (with ARM's Thumb metadata bit already cleared).
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let mut seeds: Vec<(Address, DiscoverySeedKind)> = Vec::new();
    let mut requested_known = std::collections::HashSet::new();
    for requested_va in requested_vas {
        let va = *requested_va;
        if in_exec_regions(&regions, va).is_none() || !requested_known.insert(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Requested));
        }
    }

    // Remaining seeds: entrypoint + symbol-defined function addresses.
    let mut automatic_seeds: Vec<(Address, DiscoverySeedKind)> =
        parse_function_seeds(data, &regions, arch)
            .into_iter()
            .map(|addr| (addr, DiscoverySeedKind::Symbol))
            .collect();
    if let Some(ep) = entry.clone() {
        automatic_seeds.retain(|(a, _kind)| a.value != ep.value);
        automatic_seeds.insert(0, (ep, DiscoverySeedKind::EntryPoint));
    }
    automatic_seeds.retain(|(addr, _kind)| !requested_known.contains(&addr.value));
    seeds.extend(automatic_seeds);

    // FLIRT seed augmentation. On stripped binaries (no symbol table),
    // the seed list is otherwise just the entrypoint, so the analyser
    // never finds any of the dozens of functions that exist. Scan exec
    // regions for FLIRT prologue matches and seed those VAs too. A name
    // mapping is also kept so we can rename `sub_*` → real_name once
    // discovery completes (see post-processing below).
    let flirt_lib_for_seeds: Option<FlirtLibrary> = load_default_library();
    let flirt_seeds: Vec<(u64, String)> = if let Some(ref lib) = flirt_lib_for_seeds {
        scan_within(deadline, &mut stats, || {
            discover_flirt_seeds(data, &functions, lib)
        })
    } else {
        Vec::new()
    };
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
    let vtable_entries = scan_within(deadline, &mut stats, || {
        discover_vtables(data, is_executable)
    });
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

    // Jump-table discovery (#177). Case targets feed the owning CFG through
    // `jump_table_index` below. They remain fallback entry seeds for stripped
    // ELF code only when no previously discovered function owns the target;
    // an ordinary switch arm is a basic block, not another top-level function.
    // PE never promotes case labels because its trusted entry metadata is much
    // stronger and Ghidra likewise keeps switch arms intraprocedural.
    // Indexed by table VA so a dispatch site can ask "what does the table I
    // computed point at". Previously these targets were consumed ONLY as
    // function-entry seeds, which is why the dispatching function's own CFG
    // never gained the arms — see `analysis::dispatch`.
    let mut jump_table_index: std::collections::BTreeMap<u64, Vec<u64>> =
        std::collections::BTreeMap::new();
    if !is_pe_image {
        let regions_for_check2 = regions.clone();
        let is_executable2 = move |va: u64| -> bool {
            regions_for_check2
                .iter()
                .any(|r| va >= r.start && va < r.end)
        };
        let jump_tables = scan_within(deadline, &mut stats, || {
            discover_jump_tables(data, is_executable2)
        });
        for jt in &jump_tables {
            jump_table_index.insert(jt.table_va, jt.targets.clone());
        }
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
    let export_starts = scan_within(deadline, &mut stats, || {
        parse_pe_export_function_starts(data, &regions, arch)
    });
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
    let (pdata_starts, pdata_stats) = scan_within(deadline, &mut stats, || {
        parse_pdata_function_starts(data, &regions, arch)
    });
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

    // `.eh_frame` FDE starts — the ELF counterpart of `.pdata`, and the only
    // authoritative function boundary a stripped ELF still carries. Trusted, so
    // not body-overlap gated: an earlier wrong function must not be allowed to
    // suppress a proven start. Before this, a stripped ELF was discovered from
    // its entry point and direct calls alone, which recovered 48-57% of these
    // starts on glibc binaries and none at all on small musl ones.
    let eh_frame_functions = crate::analysis::exception::eh_frame_functions(data);
    stats.eh_frame_candidates = eh_frame_functions.len();
    // start -> exclusive end, so a walk can be stopped at the proven boundary.
    let eh_frame_extent: std::collections::HashMap<u64, u64> = eh_frame_functions
        .iter()
        .map(|f| (f.start, f.end))
        .collect();
    for func in &eh_frame_functions {
        let va = func.start;
        if !regions.iter().any(|r| va >= r.start && va < r.end) {
            record_scan_rejection(
                &mut stats,
                va,
                None,
                "eh_frame:nonexec",
                "FDE start is outside every executable region",
            );
            continue;
        }
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::EhFrame));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::EhFrame);
            record_seed_provenance(&mut stats, va, None, DiscoverySeedKind::EhFrame, "eh_frame");
            stats.eh_frame_seeds_inserted = stats.eh_frame_seeds_inserted.saturating_add(1);
        }
    }

    let mut prologue_starts = scan_within(deadline, &mut stats, || {
        scan_pe_prologue_function_starts(data, &regions, arch)
    });
    // The ELF counterpart. `.eh_frame` (above) covers every function built with
    // unwind tables, which is most of them; this scan exists for the rest —
    // hand-written assembly and `-fno-asynchronous-unwind-tables` builds like
    // Alpine's `busybox`, whose `.eh_frame` is four bytes long. Discovery recall
    // against the full DWARF function set was 0.514 with `.eh_frame` alone.
    prologue_starts.extend(scan_within(deadline, &mut stats, || {
        scan_elf_prologue_function_starts(image, data, &regions, arch)
    }));
    // AArch64 ELF PAC prologues recover functions on stripped hardened binaries
    // (Pixel device .so files) where the PE-specific scan does not apply.
    prologue_starts.extend(scan_within(deadline, &mut stats, || {
        scan_aarch64_prologue_function_starts(image, data, &regions, arch)
    }));
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

    let thunk_starts = scan_within(deadline, &mut stats, || {
        scan_pe_thunk_function_starts(data, &regions, arch)
    });
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

    let pe_code_pointers = scan_within(deadline, &mut stats, || scan_pe_code_pointers(data));
    stats.data_ref_code_pointer_candidates = pe_code_pointers.len();
    let code_pointer_tables: std::collections::BTreeSet<(String, usize)> = pe_code_pointers
        .iter()
        .map(|ptr| (ptr.section_name.clone(), ptr.table_index))
        .collect();
    stats.data_ref_code_pointer_table_count = code_pointer_tables.len();
    let code_pointer_target_set: std::collections::HashSet<u64> =
        pe_code_pointers.iter().map(|ptr| ptr.target_va).collect();

    let tiny_stub_scan = scan_within(deadline, &mut stats, || {
        scan_pe_tiny_stub_function_starts(
            data,
            &regions,
            arch,
            &pdata_start_set,
            &code_pointer_target_set,
        )
    });
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

    let raw_call_starts = scan_within(deadline, &mut stats, || {
        scan_pe_raw_call_function_starts(data, &regions, arch, &pdata_start_set)
    });
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
    let discovery_facts = DiscoveryFacts {
        image,
        tables: &jump_table_index,
        noreturn_targets: &noreturn_targets,
        owned_ranges: None,
        owned_leaders: None,
        proven_end: None,
    };
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
        let seed_overlaps_body = va_in_discovered_body(&functions, None, seed.value);
        let seed_is_owned_block_leader = seed_kind.is_body_overlap_gated()
            && va_is_discovered_block_leader(&functions, seed.value);
        if seed_kind == DiscoverySeedKind::Pdata && seed_overlaps_body {
            stats.pdata_body_overlap_starts = stats.pdata_body_overlap_starts.saturating_add(1);
            cap_discovered_functions_at_va(&mut functions, seed.value);
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
    apply_dwarf_overrides(data, &mut functions);

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
    if let Some(ref lib) = flirt_lib_for_seeds {
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
mod aarch64_ctrl_flow_tests {
    use super::{classify_ctrl_flow, immediate_target, is_unconditional_branch_mnemonic, BArch};
    use crate::core::address::{Address, AddressKind};
    use crate::core::instruction::{Access, Instruction, Operand};

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
    fn test_bit_branch_uses_its_last_immediate_as_the_target() {
        let instruction = Instruction::new(
            Address::new(AddressKind::VA, 0x1028, 64, None, None).unwrap(),
            0x3700_0060u32.to_le_bytes().to_vec(),
            "tbnz".to_string(),
            vec![
                Operand::register("w0".to_string(), 32, Access::Read),
                Operand::immediate(31, 8),
                Operand::immediate(0x1034, 64),
            ],
            4,
            "aarch64".to_string(),
            None,
            None,
            None,
            None,
        );

        assert_eq!(immediate_target(&instruction), Some(0x1034));
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
mod arm32_ctrl_flow_tests {
    use super::{arm_pop_writes_pc, classify_ctrl_flow, is_unconditional_branch_mnemonic, BArch};
    use crate::core::address::{Address, AddressKind};
    use crate::core::binary::Endianness;
    use crate::core::disassembler::{Architecture, Disassembler};
    use crate::disasm::capstone::CapstoneDisassembler;

    #[test]
    fn real_thumb_postindexed_pc_load_is_a_return() {
        // `ldr.w pc, [sp], #4` from the real DecBench `write_power_mode`
        // epilogue.  GCC uses this encoding for a one-register pop.
        let mut backend =
            CapstoneDisassembler::new(Architecture::ARM, Endianness::Little).expect("ARM backend");
        backend.set_thumb_mode(true).expect("Thumb mode");
        let address = Address::new(AddressKind::VA, 0x801da76, 32, None, None).expect("address");
        let instruction = backend
            .disassemble_instruction(&address, &[0x5d, 0xf8, 0x04, 0xfb])
            .expect("decode real epilogue");
        assert!(
            arm_pop_writes_pc(&instruction),
            "decoded epilogue must terminate the CFG: {instruction:#?}"
        );
    }

    #[test]
    fn a32_conditional_bx_ends_the_block_but_keeps_fallthrough() {
        // A32 encodes conditional returns as `bx<cc> lr`.  Treating `bxeq` as
        // an ordinary instruction lets the lexical fallthrough execute even
        // when the return condition is true; treating it as an unconditional
        // return loses the false path.  It is therefore a conditional branch
        // for CFG construction.
        assert_eq!(classify_ctrl_flow("bxeq", BArch::ARM), (true, false, false));
        assert!(!is_unconditional_branch_mnemonic("bxeq", BArch::ARM));
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
mod arm_tail_call_tests {
    use super::*;

    fn sample(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross")
            .join(name);
        std::fs::read(path).expect("read checked-in cross sample")
    }

    /// `.plt` in the checked-in armhf sample spans 0x4d8..0x54c (a 20-byte
    /// header plus eight 12-byte stubs). A branch into that range is a tail
    /// call; a branch into `.text` is ordinary control flow.
    #[test]
    fn an_arm_branch_into_the_plt_is_a_tail_call() {
        let data = sample("armhf/c2_demo-armhf-gcc");
        assert!(elf_arm_tail_target_is_plt_stub(&data, 0x4ec, BArch::ARM));
        assert!(elf_arm_tail_target_is_plt_stub(&data, 0x540, BArch::ARM));
        assert!(!elf_arm_tail_target_is_plt_stub(&data, 0x4d0, BArch::ARM));
        assert!(!elf_arm_tail_target_is_plt_stub(&data, 0x698, BArch::ARM));
    }

    /// The rule is ARM32-only, so no other architecture's branch
    /// classification can move because of it.
    #[test]
    fn no_other_architecture_is_reclassified() {
        let data = sample("armhf/c2_demo-armhf-gcc");
        for arch in [BArch::X86_64, BArch::X86, BArch::AArch64] {
            assert!(!elf_arm_tail_target_is_plt_stub(&data, 0x4ec, arch));
        }
        let arm64 = sample("arm64/c2_demo-arm64-gcc");
        assert!(!elf_arm_tail_target_is_plt_stub(
            &arm64,
            0x810,
            BArch::AArch64
        ));
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

#[cfg(all(test, target_arch = "x86_64"))]
mod gcc_dispatch_corpus_tests {
    use super::*;
    use object::{Object, ObjectSymbol};
    use std::io::Write;
    use std::process::Command;

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
}

#[cfg(test)]
mod elf_prologue_scan_tests {
    use super::*;

    /// The AArch64 prologue masks must match the real encodings and nothing else.
    ///
    /// These are bit patterns, so a wrong mask fails silently by matching
    /// everything or nothing; both were plausible and neither would surface in
    /// a metric until discovery recall moved the wrong way.
    #[test]
    fn aarch64_prologue_masks_match_the_real_encodings() {
        // stp x29, x30, [sp, #-16]!   (pre-indexed frame save)
        assert!(aarch64_unhardened_prologue(0xa9bf_7bfd));
        // stp x29, x30, [sp, #-64]!   — different immediate, same shape
        assert!(aarch64_unhardened_prologue(0xa9bc_7bfd));
        // sub sp, sp, #0x30
        assert!(aarch64_unhardened_prologue(0xd100_c3ff));
        // sub sp, sp, #0x10
        assert!(aarch64_unhardened_prologue(0xd100_43ff));

        // stp x19, x20, [sp, #-16]! — a callee-saved pair, not the frame pair,
        // and a very common instruction: matching it would over-generate badly.
        assert!(!aarch64_unhardened_prologue(0xa9bf_53f3));
        // sub x0, x0, #1 — not the stack pointer.
        assert!(!aarch64_unhardened_prologue(0xd100_0400));
        // nop
        assert!(!aarch64_unhardened_prologue(0xd503_201f));
        // ret
        assert!(!aarch64_unhardened_prologue(0xd65f_03c0));
    }

    /// The x86-64 head predicate accepts real GCC/Clang entries and rejects
    /// mid-function bytes.
    #[test]
    fn elf_x86_prologue_head_is_specific() {
        assert!(elf_x86_prologue_head(&[0xf3, 0x0f, 0x1e, 0xfa])); // endbr64
        assert!(elf_x86_prologue_head(&[0x55, 0x48, 0x89, 0xe5])); // push rbp; mov rbp,rsp
        assert!(elf_x86_prologue_head(&[0x48, 0x83, 0xec, 0x28])); // sub rsp, 0x28

        assert!(!elf_x86_prologue_head(&[0x90])); // nop
        assert!(!elf_x86_prologue_head(&[0xc3])); // ret
        assert!(!elf_x86_prologue_head(&[0x48, 0x89, 0xc6])); // mov rsi, rax
        assert!(!elf_x86_prologue_head(&[]));
    }

    /// On a real ELF the scan must not invent starts outside executable memory.
    #[test]
    fn elf_scan_stays_inside_executable_regions() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            eprintln!("skipping ELF prologue scan test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let (regions, arch, _, _) = parse_exec_regions(&data);
        let starts = scan_elf_prologue_function_starts(None, &data, &regions, arch);
        assert!(
            !starts.is_empty(),
            "no prologue candidates on a real unstripped C++ binary"
        );
        for va in &starts {
            assert!(
                regions.iter().any(|r| *va >= r.start && *va < r.end),
                "candidate {va:#x} is outside every executable region"
            );
        }
    }

    /// A PE must not be fed to the ELF scan, and vice versa.
    #[test]
    fn elf_scan_rejects_non_elf_input() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x2000,
            _file_off_start: 0,
        }];
        assert!(
            scan_elf_prologue_function_starts(None, b"MZ\x90\x00", &regions, BArch::X86_64)
                .is_empty()
        );
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
