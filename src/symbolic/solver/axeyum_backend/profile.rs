//! Diagnostic attribution records for one axeyum check, and their assembly.
//!
//! Two halves. The first is the record vocabulary: [`AxeyumCheckProfile`] for a
//! one-shot native check, [`WarmAxeyumCheckProfile`] for a retained one, plus
//! the [`WarmProfileContext`] carried between a check's start and finish and
//! the [`ProfiledSolveResult`] pairing a result with its attribution. These are
//! `Serialize` because they are written out as JSON records when
//! `GLAURUNG_AXEYUM_PROFILE_DIR` is set.
//!
//! The second is the assembly itself: [`start_warm_profile`] snapshots the
//! solver's counters before a check, [`finish_warm_profile`] diffs them
//! afterwards and writes the record, and the `*_work` / `*_mix` helpers project
//! axeyum's per-subsystem stats into the flat maps the record carries.
//!
//! `WarmProfileContext` and `WarmProfileEntry` stay in the parent for the
//! field-visibility reason given in `super::config`: `super::warm_paths` and
//! `super::snapshot` fill in the context's `profile` between a check's start
//! and its finish, and the module's tests build entries by hand.

use super::*;

/// Query-hash-keyed attribution for one diagnostic native Axeyum check.
///
/// All durations are integer nanoseconds so JSON artifacts preserve exact
/// values without relying on a platform-specific `Duration` representation.
/// The query hash is computed from the same SMT-LIB bytes as the corpus-capture
/// hook, but rendering/hashing happens before `total_nanos` starts so the
/// diagnostic key does not masquerade as solver work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AxeyumCheckProfile {
    /// Versioned JSON record schema.
    pub schema: &'static str,
    /// Operating-system process that produced the record.
    pub process_id: u32,
    /// Monotone process-local output order, assigned by the JSONL writer.
    pub sequence: Option<u64>,
    /// SHA-256 of the exact SMT-LIB bytes used by the capture hook.
    pub query_hash: String,
    /// Word-level assertion policy used by this check.
    pub word_policy: &'static str,
    /// Configured per-solve timeout in milliseconds.
    pub timeout_ms: u64,
    /// Stable result class: `sat`, `unsat`, `unknown`, or `error`.
    pub outcome: &'static str,
    /// Whether translation and solving completed without an operational error.
    pub complete: bool,
    /// Number of Glaurung assertions in the query.
    pub assertion_count: u64,
    /// Number of distinct Glaurung expressions translated through the memo.
    pub translated_exprs: u64,
    /// Number of interned Axeyum terms after translation.
    pub arena_terms: u64,
    /// Number of translated Glaurung symbols.
    pub symbols: u64,
    /// Number of values exposed in the client model.
    pub model_values: u64,
    /// Number of assertion roots added to the retained CNF.
    pub root_encodings: u64,
    /// Number of incremental solver checks attempted.
    pub checks: u64,
    /// Retained AIG node count at the end of the check.
    pub aig_nodes: u64,
    /// Retained CNF variable count at the end of the check.
    pub cnf_variables: u64,
    /// Retained CNF clause count at the end of the check.
    pub cnf_clauses: u64,
    /// Nanoseconds spent constructing the Axeyum arena.
    pub arena_create_nanos: u64,
    /// Nanoseconds spent translating Glaurung expressions and assertions.
    pub translation_nanos: u64,
    /// Nanoseconds spent constructing the incremental solver.
    pub solver_create_nanos: u64,
    /// Nanoseconds spent in configured word-level rewriting.
    pub word_rewrite_nanos: u64,
    /// Nanoseconds spent lowering terms into the retained AIG.
    pub bit_blast_nanos: u64,
    /// Nanoseconds spent extending the retained CNF.
    pub cnf_encode_nanos: u64,
    /// Nanoseconds spent in the SAT adapter.
    pub solve_nanos: u64,
    /// Nanoseconds spent reconstructing the Axeyum model.
    pub model_lift_nanos: u64,
    /// Nanoseconds spent replaying SAT candidates against original terms.
    pub replay_nanos: u64,
    /// Nanoseconds spent converting the Axeyum model into Glaurung's model.
    pub model_extract_nanos: u64,
    /// Total native-adapter nanoseconds, excluding query rendering and output.
    pub total_nanos: u64,
}

/// Exact-query attribution for one opt-in retained warm check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarmAxeyumCheckProfile {
    /// Versioned JSON record schema.
    pub schema: &'static str,
    /// Operating-system process that produced the record.
    pub process_id: u32,
    /// Monotone process-local order across cold and warm profile records.
    pub sequence: Option<u64>,
    /// SHA-256 of the exact SMT-LIB bytes used by the capture hook.
    pub query_hash: String,
    /// Explicit explorer path owner, absent for consecutive-snapshot mode.
    pub path_id: Option<u64>,
    /// Whether this check lazily created its retained path session.
    pub path_created: bool,
    /// Retained-entry contract used for this check: `snapshot` or
    /// `direct_delta`.
    pub entry_mode: &'static str,
    /// Stable result class: `sat`, `unsat`, `unknown`, or `error`.
    pub outcome: &'static str,
    /// Whether translation and solving completed without an operational error.
    pub complete: bool,
    /// Number of Glaurung assertions in the complete snapshot.
    pub assertion_count: u64,
    /// Persistent assertion roots in the complete query partition.
    pub persistent_assertion_count: u64,
    /// Trailing one-shot assumption roots in the complete query partition.
    pub temporary_assumption_count: u64,
    /// Number of assertion roots retained as the common prefix.
    pub common_prefix_assertions: u64,
    /// Number of newly asserted roots.
    pub assertions_added: u64,
    /// Number of divergent roots popped before this check.
    pub assertions_popped: u64,
    /// Persistent assertion roots translated during this check.
    pub persistent_assertions_translated: u64,
    /// Temporary assumption roots translated during this check.
    pub temporary_assumptions_translated: u64,
    /// Number of distinct Glaurung expressions translated during this check.
    pub translated_exprs: u64,
    /// Current retained Axeyum arena term count.
    pub arena_terms: u64,
    /// Number of translated Glaurung symbols.
    pub symbols: u64,
    /// Number of values exposed in the client model.
    pub model_values: u64,
    /// Time spent lazily constructing a new retained path session.
    pub session_create_nanos: u64,
    /// Time spent translating the complete client snapshot into the arena.
    pub translation_nanos: u64,
    /// Time spent in configured word-level rewriting for newly added roots.
    pub word_rewrite_nanos: u64,
    /// Time spent lowering newly required terms into the retained AIG.
    pub bit_blast_nanos: u64,
    /// Time spent extending CNF and asserting new roots.
    pub cnf_encode_nanos: u64,
    /// Time spent inside the retained SAT adapter.
    pub solve_nanos: u64,
    /// Time spent reconstructing the Axeyum model.
    pub model_lift_nanos: u64,
    /// Time spent replaying the candidate against original assertions.
    pub replay_nanos: u64,
    /// Time spent converting the Axeyum model into Glaurung's model.
    pub model_extract_nanos: u64,
    /// Total warm-adapter time, excluding query rendering, hashing, and output.
    pub total_nanos: u64,
    /// Adapter time not covered by the named non-overlapping phases.
    pub unattributed_nanos: u64,
    /// Newly encoded retained roots in this check.
    pub root_encodings: u64,
    /// Newly encoded persistent roots in this check.
    pub persistent_root_encodings: u64,
    /// Newly encoded one-shot assumption roots in this check.
    pub temporary_root_encodings: u64,
    /// Newly retained AIG nodes in this check.
    pub aig_nodes_added: u64,
    /// Newly retained CNF variables in this check.
    pub cnf_variables_added: u64,
    /// Newly retained CNF clauses in this check.
    pub cnf_clauses_added: u64,
    /// Current retained AIG nodes after this check.
    pub aig_nodes: u64,
    /// Current retained CNF variables after this check.
    pub cnf_variables: u64,
    /// Current retained CNF clauses after this check.
    pub cnf_clauses: u64,
    /// Per-check incremental CNF gate/root-family deltas.
    pub cnf_gate_mix: BTreeMap<&'static str, u64>,
    /// Per-check primitive AIG construction classification.
    pub aig_construction: BTreeMap<&'static str, u64>,
    /// Per-check term-memo, literal-copy, and lift-map work.
    pub lowering_work: BTreeMap<&'static str, u64>,
    /// Per-check model-lift subphase durations and operation counts.
    pub model_lift_work: BTreeMap<&'static str, u64>,
    /// Per-check replay-cache traffic plus current per-path gauges.
    pub replay_sat_cache: BTreeMap<&'static str, u64>,
}

impl AxeyumCheckProfile {
    /// Sum of non-overlapping attributed phase durations.
    pub fn attributed_nanos(&self) -> u64 {
        self.arena_create_nanos
            .saturating_add(self.translation_nanos)
            .saturating_add(self.solver_create_nanos)
            .saturating_add(self.word_rewrite_nanos)
            .saturating_add(self.bit_blast_nanos)
            .saturating_add(self.cnf_encode_nanos)
            .saturating_add(self.solve_nanos)
            .saturating_add(self.model_lift_nanos)
            .saturating_add(self.replay_nanos)
            .saturating_add(self.model_extract_nanos)
    }

    /// Time inside the native adapter not covered by a named phase.
    pub fn unattributed_nanos(&self) -> u64 {
        self.total_nanos.saturating_sub(self.attributed_nanos())
    }
}

/// Result plus diagnostic attribution from [`AxeyumSolver::check_profiled`].
#[derive(Debug)]
pub struct ProfiledSolveResult {
    /// Normal Glaurung solve result.
    pub result: SolveResult,
    /// Diagnostic attribution for the same solve.
    pub profile: AxeyumCheckProfile,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start_warm_profile(
    profiling: bool,
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    path_created: bool,
    session_create_nanos: u64,
    entry: WarmProfileEntry,
    solver_before: IncrementalBvStats,
    replay_sat_cache_before: ReplayCheckedSatCacheStats,
) -> Option<WarmProfileContext> {
    if !profiling {
        return None;
    }
    let (script, _) = pipe::build_script(pool, asserts);
    let query_hash = format!("sha256:{}", hex::encode(Sha256::digest(script.as_bytes())));
    Some(WarmProfileContext {
        profile: WarmAxeyumCheckProfile {
            schema: "glaurung-axeyum-warm-profile-v7",
            process_id: std::process::id(),
            sequence: None,
            query_hash,
            path_id,
            path_created,
            entry_mode: entry.mode,
            outcome: "error",
            complete: false,
            assertion_count: count(asserts.len()),
            persistent_assertion_count: count(entry.persistent_assertions),
            temporary_assumption_count: count(entry.temporary_assumptions),
            common_prefix_assertions: 0,
            assertions_added: 0,
            assertions_popped: 0,
            persistent_assertions_translated: count(entry.persistent_translated),
            temporary_assumptions_translated: count(entry.temporary_translated),
            translated_exprs: 0,
            arena_terms: 0,
            symbols: 0,
            model_values: 0,
            session_create_nanos,
            translation_nanos: 0,
            word_rewrite_nanos: 0,
            bit_blast_nanos: 0,
            cnf_encode_nanos: 0,
            solve_nanos: 0,
            model_lift_nanos: 0,
            replay_nanos: 0,
            model_extract_nanos: 0,
            total_nanos: 0,
            unattributed_nanos: 0,
            root_encodings: 0,
            persistent_root_encodings: 0,
            temporary_root_encodings: 0,
            aig_nodes_added: 0,
            cnf_variables_added: 0,
            cnf_clauses_added: 0,
            aig_nodes: 0,
            cnf_variables: 0,
            cnf_clauses: 0,
            cnf_gate_mix: BTreeMap::new(),
            aig_construction: BTreeMap::new(),
            lowering_work: BTreeMap::new(),
            model_lift_work: BTreeMap::new(),
            replay_sat_cache: BTreeMap::new(),
        },
        total_started: Instant::now(),
        solver_before,
        replay_sat_cache_before,
    })
}

pub(super) fn finish_warm_profile(
    context: Option<WarmProfileContext>,
    solver_after: IncrementalBvStats,
    replay_sat_cache_after: ReplayCheckedSatCacheStats,
    replay_sat_cache_policy: Option<ReplayCheckedSatCachePolicy>,
    arena_terms: usize,
    result: SolveResult,
    root_partition: Option<(u64, u64)>,
) -> SolveResult {
    let Some(mut context) = context else {
        return result;
    };
    let delta = solver_after.delta_since(context.solver_before);
    context.profile.word_rewrite_nanos = nanos(delta.word_rewrite);
    context.profile.bit_blast_nanos = nanos(delta.bit_blast);
    context.profile.cnf_encode_nanos = nanos(delta.cnf_encode);
    context.profile.solve_nanos = nanos(delta.solve);
    context.profile.model_lift_nanos = nanos(delta.model_lift);
    context.profile.replay_nanos = nanos(delta.replay);
    context.profile.root_encodings = delta.root_encodings;
    let (persistent_roots, temporary_roots) = root_partition.unwrap_or((delta.root_encodings, 0));
    debug_assert_eq!(
        delta.root_encodings,
        persistent_roots.saturating_add(temporary_roots)
    );
    context.profile.persistent_root_encodings = persistent_roots;
    context.profile.temporary_root_encodings = temporary_roots;
    context.profile.aig_nodes_added = delta.aig_nodes;
    context.profile.cnf_variables_added = delta.cnf_variables;
    context.profile.cnf_clauses_added = delta.cnf_clauses;
    context.profile.aig_nodes = solver_after.aig_nodes;
    context.profile.cnf_variables = solver_after.cnf_variables;
    context.profile.cnf_clauses = solver_after.cnf_clauses;
    context.profile.cnf_gate_mix = cnf_gate_mix(delta.cnf_gate_mix);
    context.profile.aig_construction = aig_construction(delta.aig_construction);
    context.profile.lowering_work = lowering_work(delta.lowering_work);
    context.profile.model_lift_work = model_lift_work(delta.model_lift_work);
    context.profile.replay_sat_cache = replay_sat_cache_profile(
        replay_sat_cache_policy,
        context.replay_sat_cache_before,
        replay_sat_cache_after,
    );
    context.profile.arena_terms = count(arena_terms);
    context.profile.outcome = result_name(&result);
    context.profile.complete = !matches!(&result, SolveResult::Error(_));
    context.profile.total_nanos =
        nanos(context.total_started.elapsed()).saturating_add(context.profile.session_create_nanos);
    let attributed = context
        .profile
        .session_create_nanos
        .saturating_add(context.profile.translation_nanos)
        .saturating_add(context.profile.word_rewrite_nanos)
        .saturating_add(context.profile.bit_blast_nanos)
        .saturating_add(context.profile.cnf_encode_nanos)
        .saturating_add(context.profile.solve_nanos)
        .saturating_add(context.profile.model_lift_nanos)
        .saturating_add(context.profile.replay_nanos)
        .saturating_add(context.profile.model_extract_nanos);
    context.profile.unattributed_nanos = context.profile.total_nanos.saturating_sub(attributed);
    let Some(output_dir) = profile_output_dir() else {
        return result;
    };
    if let Err(error) = write_profile_record(output_dir, &context.profile) {
        return SolveResult::Error(error);
    }
    result
}

pub(super) fn cnf_gate_mix(stats: IncrementalCnfStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("and_nodes_synced", stats.and_nodes_synced),
        ("up_half_definitions", stats.up_half_definitions),
        ("down_half_definitions", stats.down_half_definitions),
        ("xor_half_definitions", stats.xor_half_definitions),
        ("not_ite_half_definitions", stats.not_ite_half_definitions),
        ("not_and_half_definitions", stats.not_and_half_definitions),
        ("and_tree_half_definitions", stats.and_tree_half_definitions),
        (
            "binary_and_half_definitions",
            stats.binary_and_half_definitions,
        ),
        (
            "internal_positive_and_opportunities",
            stats.internal_positive_and_opportunities,
        ),
        (
            "internal_positive_and_opportunity_nodes",
            stats.internal_positive_and_opportunity_nodes,
        ),
        (
            "internal_positive_and_flattened",
            stats.internal_positive_and_flattened,
        ),
        (
            "internal_positive_and_immediate_clauses_avoided",
            stats.internal_positive_and_immediate_clauses_avoided,
        ),
        ("constant_clauses", stats.constant_clauses),
        ("definition_clauses", stats.definition_clauses),
        ("root_clauses", stats.root_clauses),
        ("direct_positive_and_roots", stats.direct_positive_and_roots),
        ("direct_positive_and_nodes", stats.direct_positive_and_nodes),
        (
            "direct_positive_and_leaves",
            stats.direct_positive_and_leaves,
        ),
        ("direct_xor_leaves", stats.direct_xor_leaves),
        ("direct_not_ite_leaves", stats.direct_not_ite_leaves),
        ("direct_negative_and_roots", stats.direct_negative_and_roots),
        ("fused_positive_and_roots", stats.fused_positive_and_roots),
        ("fused_positive_and_nodes", stats.fused_positive_and_nodes),
        ("fused_xor_leaves", stats.fused_xor_leaves),
        ("root_assertions", stats.root_assertions),
        ("guarded_root_assertions", stats.guarded_root_assertions),
        (
            "repeated_same_context_roots",
            stats.repeated_same_context_roots,
        ),
        (
            "deduplicated_root_assertions",
            stats.deduplicated_root_assertions,
        ),
        (
            "reused_cross_context_roots",
            stats.reused_cross_context_roots,
        ),
        ("guarded_root_clauses", stats.guarded_root_clauses),
        ("root_clause_attempts", stats.root_clause_attempts),
        ("unit_payload_root_clauses", stats.unit_payload_root_clauses),
        (
            "binary_payload_root_clauses",
            stats.binary_payload_root_clauses,
        ),
        ("wide_payload_root_clauses", stats.wide_payload_root_clauses),
        (
            "duplicate_definition_clauses",
            stats.duplicate_definition_clauses,
        ),
        ("duplicate_root_clauses", stats.duplicate_root_clauses),
        (
            "duplicate_prior_root_clauses",
            stats.duplicate_prior_root_clauses,
        ),
        (
            "root_clauses_duplicate_non_root",
            stats.root_clauses_duplicate_non_root,
        ),
        (
            "tautological_definition_clauses",
            stats.tautological_definition_clauses,
        ),
        ("tautological_root_clauses", stats.tautological_root_clauses),
        (
            "fresh_negative_root_definitions",
            stats.fresh_negative_root_definitions,
        ),
        (
            "reused_negative_root_definitions",
            stats.reused_negative_root_definitions,
        ),
    ])
}

pub(super) fn aig_construction(stats: AigConstructionStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("and_requests", stats.and_requests),
        (
            "and_trivial_simplifications",
            stats.and_trivial_simplifications,
        ),
        (
            "and_absorption_simplifications",
            stats.and_absorption_simplifications,
        ),
        ("and_structural_hash_hits", stats.and_structural_hash_hits),
        ("and_nodes_created", stats.and_nodes_created),
    ])
}

pub(super) fn lowering_work(stats: IncrementalLoweringStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("lower_calls", stats.lower_calls),
        ("term_memo_lookups", stats.term_memo_lookups),
        ("term_memo_hits", stats.term_memo_hits),
        ("terms_lowered", stats.terms_lowered),
        ("operand_vectors_copied", stats.operand_vectors_copied),
        ("operand_bits_copied", stats.operand_bits_copied),
        ("root_bits_copied", stats.root_bits_copied),
        ("term_bit_bindings_written", stats.term_bit_bindings_written),
        ("memoized_terms", stats.memoized_terms),
        ("term_bit_bindings", stats.term_bit_bindings),
        ("symbol_bit_inputs", stats.symbol_bit_inputs),
    ])
}

pub(super) fn model_lift_work(stats: IncrementalModelLiftStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("aig_recompute_nanos", nanos(stats.aig_recompute)),
        (
            "assignment_reconstruct_nanos",
            nanos(stats.assignment_reconstruct),
        ),
        ("model_completion_nanos", nanos(stats.model_completion)),
        ("aig_nodes_recomputed", stats.aig_nodes_recomputed),
        ("symbol_bit_inputs_scanned", stats.symbol_bit_inputs_scanned),
        (
            "assignment_symbols_produced",
            stats.assignment_symbols_produced,
        ),
        ("arena_symbols_scanned", stats.arena_symbols_scanned),
        ("completed_model_values", stats.completed_model_values),
    ])
}

pub(super) fn replay_sat_cache_profile(
    policy: Option<ReplayCheckedSatCachePolicy>,
    before: ReplayCheckedSatCacheStats,
    after: ReplayCheckedSatCacheStats,
) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("enabled", u64::from(policy.is_some())),
        (
            "max_entries",
            policy.map_or(0, |policy| count(policy.max_entries)),
        ),
        (
            "max_model_values",
            policy.map_or(0, |policy| count(policy.max_model_values)),
        ),
        (
            "max_model_bits",
            policy.map_or(0, |policy| count(policy.max_model_bits)),
        ),
        ("hits", after.hits.saturating_sub(before.hits)),
        ("misses", after.misses.saturating_sub(before.misses)),
        (
            "insertions",
            after.insertions.saturating_sub(before.insertions),
        ),
        (
            "evictions",
            after.evictions.saturating_sub(before.evictions),
        ),
        (
            "replay_failures",
            after.replay_failures.saturating_sub(before.replay_failures),
        ),
        (
            "declined_unsat",
            after.declined_unsat.saturating_sub(before.declined_unsat),
        ),
        (
            "declined_unknown",
            after
                .declined_unknown
                .saturating_sub(before.declined_unknown),
        ),
        (
            "declined_oversized_models",
            after
                .declined_oversized_models
                .saturating_sub(before.declined_oversized_models),
        ),
        (
            "declined_non_scalar_models",
            after
                .declined_non_scalar_models
                .saturating_sub(before.declined_non_scalar_models),
        ),
        ("entries", after.entries),
        ("model_values", after.model_values),
        ("model_bits", after.model_bits),
    ])
}
