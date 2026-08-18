//! The snapshot-to-incremental adapter: one retained solver per worker.
//!
//! Glaurung submits a complete assertion snapshot per check rather than
//! explicit push/pop scopes, so this adapter reconstructs the scope structure.
//! It compares the incoming snapshot against the assertions already asserted
//! into its live [`IncrementalAxeyumSolver`], reuses the common prefix, pops
//! what diverged and asserts only the delta -- falling back to a full
//! re-materialization when the prefix does not match at all.
//!
//! [`SnapshotReuseStats`] is the per-adapter accounting of that decision.

use super::*;

/// Cumulative behavior of [`SnapshotIncrementalAxeyumSolver`].
///
/// Counts describe assertion roots, not expression-DAG nodes. They make the
/// first Glaurung warm integration measurable before the explorer grows an
/// explicit lineage/scope API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotReuseStats {
    /// Complete snapshots checked.
    pub checks: u64,
    /// Checks whose complete assertion vector matched the preceding snapshot.
    pub exact_snapshot_reuses: u64,
    /// Assertion roots retained across snapshot transitions.
    pub prefix_assertions_reused: u64,
    /// New assertion roots encoded after the common prefix.
    pub assertions_added: u64,
    /// Divergent assertion scopes deactivated after the common prefix.
    pub assertions_popped: u64,
    /// Sessions discarded after a push/assert/check operational error.
    pub resets_after_error: u64,
}

/// Adapts Glaurung's complete assertion snapshots to Axeyum's warm scopes.
///
/// The retained [`TermArena`] structurally interns translated terms, so common
/// roots receive the same [`TermId`] even when Glaurung cloned an [`ExprPool`]
/// and sibling pools reused numeric [`ExprId`] values for different nodes. The
/// longest common structural prefix stays active; divergent suffix scopes are
/// popped and only the new suffix is asserted. Every SAT result still follows
/// Axeyum's original-term model replay before it reaches this adapter.
#[derive(Debug)]
pub struct SnapshotIncrementalAxeyumSolver {
    arena: TermArena,
    solver: IncrementalBvSolver,
    active: Vec<TermId>,
    has_snapshot: bool,
    preprocess: bool,
    profiling: bool,
    replay_sat_cache_policy: Option<ReplayCheckedSatCachePolicy>,
    stats: SnapshotReuseStats,
}

impl Default for SnapshotIncrementalAxeyumSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotIncrementalAxeyumSolver {
    /// Creates an empty raw-policy snapshot adapter.
    pub fn new() -> Self {
        Self::with_preprocessing(false)
    }

    /// Creates an empty adapter and optionally canonicalizes each newly added
    /// assertion. Existing prefix assertions are never reprocessed.
    pub fn with_preprocessing(preprocess: bool) -> Self {
        Self::with_preprocessing_and_profiling(preprocess, profile_output_dir().is_some())
    }

    fn with_preprocessing_and_profiling(preprocess: bool, profiling: bool) -> Self {
        Self::with_policy(preprocess, profiling, None)
    }

    pub(super) fn new_path_owned() -> Self {
        Self::with_policy(
            false,
            profile_output_dir().is_some(),
            replay_sat_cache_policy(),
        )
    }

    #[cfg(test)]
    pub(super) fn with_cache_for_test(policy: ReplayCheckedSatCachePolicy) -> Self {
        Self::with_policy(false, false, Some(policy))
    }

    fn with_policy(
        preprocess: bool,
        profiling: bool,
        replay_sat_cache_policy: Option<ReplayCheckedSatCachePolicy>,
    ) -> Self {
        let solver_config = config().with_preprocess(preprocess);
        let mut solver = if profiling {
            IncrementalBvSolver::with_config_and_profiling(solver_config)
        } else {
            IncrementalBvSolver::with_config(solver_config)
        };
        if let Some(policy) = replay_sat_cache_policy {
            solver
                .enable_replay_checked_sat_cache(policy)
                .expect("Glaurung replay-SAT-cache bounds are nonzero constants");
        }
        Self {
            arena: TermArena::new(),
            solver,
            active: Vec::new(),
            has_snapshot: false,
            preprocess,
            profiling,
            replay_sat_cache_policy,
            stats: SnapshotReuseStats::default(),
        }
    }

    /// Returns cumulative snapshot-reuse counters.
    pub fn stats(&self) -> SnapshotReuseStats {
        self.stats
    }

    pub(super) fn replay_sat_cache_stats(&self) -> ReplayCheckedSatCacheStats {
        self.solver.replay_checked_sat_cache_stats()
    }

    fn reset_session(&mut self) {
        self.arena = TermArena::new();
        let solver_config = config().with_preprocess(self.preprocess);
        self.solver = if self.profiling {
            IncrementalBvSolver::with_config_and_profiling(solver_config)
        } else {
            IncrementalBvSolver::with_config(solver_config)
        };
        if let Some(policy) = self.replay_sat_cache_policy {
            self.solver
                .enable_replay_checked_sat_cache(policy)
                .expect("Glaurung replay-SAT-cache bounds are nonzero constants");
        }
        self.active.clear();
        self.has_snapshot = false;
        self.stats.resets_after_error = self.stats.resets_after_error.saturating_add(1);
    }

    /// Checks one complete Glaurung assertion snapshot using retained Axeyum
    /// translation, AIG, CNF, and SAT state.
    pub fn check_snapshot(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        self.check_snapshot_for_path(pool, asserts, None, false, 0)
    }

    pub(super) fn check_snapshot_for_path(
        &mut self,
        pool: &ExprPool,
        asserts: &[Assert],
        path_id: Option<u64>,
        path_created: bool,
        session_create_nanos: u64,
    ) -> SolveResult {
        let mut profile =
            self.start_profile(pool, asserts, path_id, path_created, session_create_nanos);
        let translation_started = profile.as_ref().map(|_| Instant::now());
        let translated = match translate_query(pool, asserts, &mut self.arena) {
            Ok(translated) => translated,
            Err(err) => {
                if let (Some(profile), Some(started)) = (&mut profile, translation_started) {
                    profile.profile.translation_nanos = nanos(started.elapsed());
                }
                let solver_after = self.solver.stats();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(format!("axeyum translate: {err}")),
                );
            }
        };
        if let (Some(profile), Some(started)) = (&mut profile, translation_started) {
            profile.profile.translation_nanos = nanos(started.elapsed());
            profile.profile.translated_exprs = count(translated.exprs);
            profile.profile.symbols = count(translated.sym_map.len());
        }
        let common = self
            .active
            .iter()
            .zip(&translated.assertions)
            .take_while(|(active, next)| active == next)
            .count();
        if let Some(profile) = &mut profile {
            profile.profile.common_prefix_assertions = count(common);
        }

        self.stats.checks = self.stats.checks.saturating_add(1);
        self.stats.prefix_assertions_reused = self
            .stats
            .prefix_assertions_reused
            .saturating_add(count(common));
        if self.has_snapshot && common == self.active.len() && common == translated.assertions.len()
        {
            self.stats.exact_snapshot_reuses = self.stats.exact_snapshot_reuses.saturating_add(1);
        }

        let pop_count = self.active.len().saturating_sub(common);
        if let Some(profile) = &mut profile {
            profile.profile.assertions_popped = count(pop_count);
            profile.profile.assertions_added = count(translated.assertions.len() - common);
        }
        for _ in 0..pop_count {
            if !self.solver.pop() {
                let solver_after = self.solver.stats();
                self.reset_session();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(
                        "axeyum warm snapshot scope underflow; session reset".to_string(),
                    ),
                );
            }
        }
        self.active.truncate(common);
        self.stats.assertions_popped = self
            .stats
            .assertions_popped
            .saturating_add(count(pop_count));

        for &term in &translated.assertions[common..] {
            if let Err(err) = self.solver.push() {
                let solver_after = self.solver.stats();
                self.reset_session();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(format!("axeyum warm push: {err}")),
                );
            }
            if let Err(err) = self.solver.assert_configured(&mut self.arena, term) {
                let solver_after = self.solver.stats();
                self.reset_session();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(format!("axeyum warm assert: {err}")),
                );
            }
            self.active.push(term);
            self.stats.assertions_added = self.stats.assertions_added.saturating_add(1);
        }
        self.has_snapshot = true;

        let checked = self.solver.check(&self.arena);
        let solver_after = self.solver.stats();
        if checked.is_err() {
            self.reset_session();
        }
        let model_started = profile.as_ref().map(|_| Instant::now());
        let result = map_check_result(checked, &translated.sym_map);
        if let (Some(profile), Some(started)) = (&mut profile, model_started) {
            profile.profile.model_extract_nanos = nanos(started.elapsed());
            if let SolveResult::Sat(model) = &result {
                profile.profile.model_values = count(model.values.len());
            }
        }
        self.finish_profile(profile, solver_after, result)
    }

    fn start_profile(
        &self,
        pool: &ExprPool,
        asserts: &[Assert],
        path_id: Option<u64>,
        path_created: bool,
        session_create_nanos: u64,
    ) -> Option<WarmProfileContext> {
        start_warm_profile(
            self.profiling,
            pool,
            asserts,
            path_id,
            path_created,
            session_create_nanos,
            WarmProfileEntry {
                mode: "snapshot",
                persistent_assertions: asserts.len(),
                temporary_assumptions: 0,
                persistent_translated: asserts.len(),
                temporary_translated: 0,
            },
            self.solver.stats(),
            self.solver.replay_checked_sat_cache_stats(),
        )
    }

    fn finish_profile(
        &self,
        context: Option<WarmProfileContext>,
        solver_after: IncrementalBvStats,
        result: SolveResult,
    ) -> SolveResult {
        finish_warm_profile(
            context,
            solver_after,
            self.solver.replay_checked_sat_cache_stats(),
            self.replay_sat_cache_policy,
            self.arena.len(),
            result,
            None,
        )
    }
}
