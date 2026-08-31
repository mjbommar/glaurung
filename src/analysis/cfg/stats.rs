//! Everything a discovery run says about itself.
//!
//! Discovery answers two questions at once: *what functions are in this
//! binary*, and *how much of the binary did we actually look at*. The second
//! answer lives here. [`FunctionDiscoveryStats`] is the whole-run census the
//! Python binding exposes; [`SingleFunctionDiscoveryStats`] is the per-walk
//! slice of it that `merge_single_function_stats` folds in and
//! `record_cfg_incompleteness` stamps onto the function as flags.
//!
//! The provenance vectors are the part that is easy to mistake for
//! bookkeeping. `seed_provenance` and `scan_rejections` are why a VA did or did
//! not become a function, and without them a missing function and a rejected
//! candidate look identical from outside. `unresolved_indirect` is stronger
//! still: a non-empty entry means a returned CFG is missing real edges, which
//! every downstream verifier would otherwise report clean.
//!
//! This module records; it never decides. Nothing here consults a budget, reads
//! a byte or walks a graph -- the callers hand it what they concluded.

use super::*;

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
pub(super) struct SingleFunctionDiscoveryStats {
    pub(super) hit_block_limit: bool,
    pub(super) hit_instruction_limit: bool,
    pub(super) hit_timeout: bool,
    /// The whole-analysis deadline expired inside this function's walk.
    pub(super) hit_total_timeout: bool,
    /// Indirect transfers whose target set could not be recovered, with the
    /// dispatch VA and why.
    ///
    /// This is a **completeness** signal, not a diagnostic nicety. An unresolved
    /// indirect jump means the recovered CFG is missing real edges — and every
    /// verifier downstream compares the region tree against the CFG, so all of
    /// them report clean on the truncated graph. Recording it here is what makes
    /// "this function's graph is not the program's graph" something a consumer
    /// can ask about instead of something nobody can see.
    pub(super) unresolved_indirect: Vec<(u64, crate::analysis::dispatch::Unresolved)>,
    /// Indirect transfers resolved through a jump table, with how many arms.
    pub(super) resolved_dispatches: Vec<(u64, usize)>,
}

pub(super) fn merge_single_function_stats(
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
pub(super) struct PdataSeedStats {
    pub(super) entries: usize,
    pub(super) accepted_starts: usize,
    pub(super) zero_begin_rejected: usize,
    pub(super) zero_begin_rejected_starts: Vec<u64>,
    pub(super) zero_size_rejected: usize,
    pub(super) zero_size_rejected_starts: Vec<u64>,
    pub(super) overlapping_entries: usize,
    pub(super) chained_unwind_rejected: usize,
    pub(super) chained_unwind_rejected_starts: Vec<u64>,
    pub(super) chained_unwind_parsed: usize,
    pub(super) chained_unwind_parse_failed: usize,
    pub(super) chained_parent_starts: usize,
    pub(super) nonexec_rejected: usize,
    pub(super) nonexec_rejected_starts: Vec<u64>,
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

/// Copy this walk's budget-truncation outcome onto the function it produced.
///
/// `SingleFunctionDiscoveryStats` is consumed twice: here, per function, and
/// again by `merge_single_function_stats` into the whole-run aggregate. Only
/// the first of those can name a function, so only the first is used to mark
/// one. `hit_total_timeout` is deliberately partial here -- see
/// `FunctionFlags::CFG_ANALYSIS_DEADLINE`.
pub(super) fn record_cfg_incompleteness(func: &mut Function, stats: &SingleFunctionDiscoveryStats) {
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

pub(super) fn record_seed_provenance(
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

pub(super) fn record_scan_rejection(
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
