//! Retained per-path solver lineages, and the thread-local entry points that
//! admit, drive and close them.
//!
//! Where `super::snapshot` keeps one retained solver per worker, this keeps
//! one per explorer-owned path, so sibling paths never share an
//! `IncrementalBvSolver`: a common prefix is replayed into separate sessions
//! rather than shared, which preserves push/pop ownership and learned-state
//! isolation. [`LineageIncrementalAxeyumSolver`] is the
//! snapshot-reconstructing form of that; [`DirectDeltaLineageAxeyumSolver`]
//! is the direct-delta form, which takes the explorer's own delta context
//! instead of rediscovering it.
//!
//! [`check_warm_thread_local`] is what `super::super::solve` actually calls.
//! It selects one of those adapters according to the configured
//! [`WarmReusePolicy`], enforces the process-wide admission limits (live
//! paths, assertions per path) before a path is allowed to retain anything,
//! runs the check, and records the outcome into the process counters that
//! `super::warm_stats` reports. The live-path limit is adaptive: a run starts
//! at a small ceiling and only expands to the configured one after enough
//! memory-pressure events, so a short exploration never pays for a large
//! retained pool.
//!
//! Admission and closure sit with the lineages themselves because they drive
//! those lineages through private methods; separating them would have meant
//! widening eight methods and a field to `pub(super)` for a boundary the
//! compiler could no longer enforce.
//!
//! `DirectCheckInput` and the retained-CNF snapshot records stay in the
//! parent for the field-visibility reason given in `super::config`.

use super::*;

/// One independently mutable retained solver per explorer-owned path.
///
/// A path's first check materializes its complete assertion snapshot. Later
/// checks on that same path reuse its prefix and add only the delta. Siblings
/// never share an [`IncrementalBvSolver`]; their common prefix is replayed into
/// separate sessions, preserving push/pop ownership and learned-state isolation.
#[derive(Debug, Default)]
pub(super) struct LineageIncrementalAxeyumSolver {
    paths: BTreeMap<u64, SnapshotIncrementalAxeyumSolver>,
}

/// Exact work counters for the direct-delta P5 session adapter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DirectDeltaStats {
    checks: u64,
    full_materializations: u64,
    exact_reuses: u64,
    prefix_assertions_reused: u64,
    persistent_assertions_translated: u64,
    temporary_assumptions_translated: u64,
    assertions_added: u64,
    assertions_popped: u64,
    resets_after_error: u64,
}

#[derive(Debug)]
struct DirectDeltaPath {
    solver: IncrementalAxeyumSolver,
    active_assertions: usize,
    active_prefix: WarmAssertionPrefix,
}

/// Path-owned retained sessions driven by explicit absolute-prefix deltas.
///
/// A missing path always materializes the complete persistent snapshot. An
/// existing path may retain only a prefix no deeper than both its current
/// session and the caller's persistent vector. Any invalid transition fails
/// closed and drops the entire session; a later call must materialize again.
#[derive(Debug, Default)]
pub(super) struct DirectDeltaLineageAxeyumSolver {
    paths: BTreeMap<u64, DirectDeltaPath>,
    stats: DirectDeltaStats,
}

#[derive(Debug, Clone, Copy, Default)]
struct DirectCheckMetrics {
    persistent_translation: DirectTranslationMetrics,
    temporary_translation: DirectTranslationMetrics,
    model_extract_nanos: u64,
    persistent_root_encodings: u64,
}

impl DirectDeltaLineageAxeyumSolver {
    fn has_path(&self, path_id: u64) -> bool {
        self.paths.contains_key(&path_id)
    }

    fn check_path(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        input: DirectCheckInput<'_>,
    ) -> (SolveResult, bool, Option<ReplayCheckedSatCacheStats>) {
        let DirectCheckInput {
            complete_asserts,
            persistent,
            persistent_prefix,
            retain_assertions,
            temporary,
        } = input;
        debug_assert_eq!(complete_asserts.len(), persistent.len() + temporary.len());
        let profiling = diagnostics_enabled();
        self.stats.checks = self.stats.checks.saturating_add(1);
        let created = !self.paths.contains_key(&path_id);
        let create_started = (created && profiling).then(Instant::now);
        if created {
            self.stats.full_materializations = self.stats.full_materializations.saturating_add(1);
            self.paths.insert(
                path_id,
                DirectDeltaPath {
                    solver: IncrementalAxeyumSolver::new_path_owned(profiling),
                    active_assertions: 0,
                    active_prefix: WarmAssertionPrefix::default(),
                },
            );
        }
        let session_create_nanos = create_started.map_or(0, |started| nanos(started.elapsed()));

        let profile_before = if profiling {
            let path = self
                .paths
                .get(&path_id)
                .expect("direct path was materialized before profiling");
            Some((
                path.solver.solver_stats(),
                path.solver.replay_sat_cache_stats(),
                path.active_assertions,
            ))
        } else {
            None
        };
        if persistent_prefix.depth() != persistent.len() || retain_assertions > persistent.len() {
            let result = SolveResult::Error(format!(
                "axeyum direct-delta source depth {}, retain {retain_assertions}, persistent {}",
                persistent_prefix.depth(),
                persistent.len()
            ));
            let removed_cache = self.close_path(path_id);
            self.stats.resets_after_error = self.stats.resets_after_error.saturating_add(1);
            return (result, false, removed_cache);
        }
        let effective_retain = if created {
            0
        } else {
            self.paths
                .get(&path_id)
                .expect("direct path exists while deriving source LCP")
                .active_prefix
                .common_depth(persistent_prefix)
        };
        let mut profile = profile_before.and_then(|(solver_before, cache_before, _)| {
            start_warm_profile(
                true,
                pool,
                complete_asserts,
                Some(path_id),
                created,
                session_create_nanos,
                WarmProfileEntry {
                    mode: "direct_delta",
                    persistent_assertions: persistent.len(),
                    temporary_assumptions: temporary.len(),
                    persistent_translated: 0,
                    temporary_translated: 0,
                },
                solver_before,
                cache_before,
            )
        });
        if let Some(profile) = &mut profile {
            let (_, _, active_before) =
                profile_before.expect("profile inputs exist when a profile was created");
            profile.profile.common_prefix_assertions =
                count(effective_retain.min(active_before).min(persistent.len()));
        }

        let exact_reuse = !created
            && self.paths.get(&path_id).is_some_and(|path| {
                effective_retain == path.active_assertions
                    && effective_retain == persistent.len()
                    && temporary.is_empty()
            });

        let added_before = self.stats.assertions_added;
        let popped_before = self.stats.assertions_popped;
        let (mut result, metrics) =
            self.transition_and_check(path_id, pool, input, effective_retain, profiling);
        let replay_cache_hit = profile_before.is_some_and(|(_, cache_before, _)| {
            self.paths
                .get(&path_id)
                .expect("direct path remains live after a successful transition")
                .solver
                .replay_sat_cache_stats()
                .hits
                > cache_before.hits
        });
        if let Some(profile) = &mut profile {
            profile.profile.assertions_added =
                self.stats.assertions_added.saturating_sub(added_before);
            profile.profile.assertions_popped =
                self.stats.assertions_popped.saturating_sub(popped_before);
            profile.profile.persistent_assertions_translated = metrics.persistent_translation.roots;
            profile.profile.temporary_assumptions_translated = metrics.temporary_translation.roots;
            profile.profile.translation_nanos = metrics
                .persistent_translation
                .nanos
                .saturating_add(metrics.temporary_translation.nanos);
            profile.profile.translated_exprs = metrics
                .persistent_translation
                .exprs
                .saturating_add(metrics.temporary_translation.exprs);
            profile.profile.symbols = metrics
                .persistent_translation
                .symbols
                .saturating_add(metrics.temporary_translation.symbols);
            profile.profile.model_extract_nanos = metrics.model_extract_nanos;
            if let SolveResult::Sat(model) = &result {
                profile.profile.model_values = count(model.values.len());
            }
        }
        if let Some(outcome) = match &result {
            SolveResult::Sat(_) => Some("sat"),
            SolveResult::Unsat => Some("unsat"),
            _ => None,
        }
        .filter(|_| !replay_cache_hit)
        {
            if let Some(output_dir) = cnf_snapshot_output_dir() {
                let query_hash = profile
                    .as_ref()
                    .map(|context| context.profile.query_hash.as_str())
                    .expect("CNF snapshot diagnostics create a warm profile context");
                let snapshot = self
                    .paths
                    .get(&path_id)
                    .expect("direct path remains live until CNF snapshot completion")
                    .solver
                    .profiled_last_cnf_snapshot();
                match snapshot.and_then(|snapshot| {
                    let snapshot = snapshot.ok_or_else(|| {
                        "axeyum retained CNF snapshot missing after solver decision".to_string()
                    })?;
                    write_retained_cnf_snapshot(output_dir, query_hash, path_id, outcome, &snapshot)
                }) {
                    Ok(()) => {}
                    Err(error) => result = SolveResult::Error(error),
                }
            }
        }
        let result = if profiling {
            let (solver_before, _, _) =
                profile_before.expect("profile inputs exist when profiling is enabled");
            let (solver_after, cache_after, arena_terms) = {
                let path = self
                    .paths
                    .get(&path_id)
                    .expect("direct path remains live until profile completion");
                (
                    path.solver.solver_stats(),
                    path.solver.replay_sat_cache_stats(),
                    path.solver.arena_len(),
                )
            };
            let total_root_encodings = solver_after
                .root_encodings
                .saturating_sub(solver_before.root_encodings);
            let temporary_root_encodings =
                total_root_encodings.saturating_sub(metrics.persistent_root_encodings);
            finish_warm_profile(
                profile,
                solver_after,
                cache_after,
                replay_sat_cache_policy(),
                arena_terms,
                result,
                Some((metrics.persistent_root_encodings, temporary_root_encodings)),
            )
        } else {
            result
        };
        let synced = !matches!(result, SolveResult::Error(_));
        if synced && !created {
            self.stats.prefix_assertions_reused = self
                .stats
                .prefix_assertions_reused
                .saturating_add(count(effective_retain));
            if exact_reuse {
                self.stats.exact_reuses = self.stats.exact_reuses.saturating_add(1);
            }
        } else if !synced {
            let removed_cache = self.close_path(path_id);
            self.stats.resets_after_error = self.stats.resets_after_error.saturating_add(1);
            return (result, false, removed_cache);
        }
        (result, true, None)
    }

    fn transition_and_check(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        input: DirectCheckInput<'_>,
        retain_assertions: usize,
        profiling: bool,
    ) -> (SolveResult, DirectCheckMetrics) {
        let DirectCheckInput {
            persistent,
            persistent_prefix,
            temporary,
            ..
        } = input;
        let mut metrics = DirectCheckMetrics::default();
        let path = self
            .paths
            .get_mut(&path_id)
            .expect("direct path was materialized before transition");
        if retain_assertions > path.active_assertions || retain_assertions > persistent.len() {
            return (
                SolveResult::Error(format!(
                    "axeyum direct-delta prefix {retain_assertions} exceeds active {} or persistent {}",
                    path.active_assertions,
                    persistent.len()
                )),
                metrics,
            );
        }

        let root_encodings_before = profiling
            .then(|| path.solver.solver_stats().root_encodings)
            .unwrap_or(0);

        let pop_count = path.active_assertions - retain_assertions;
        for _ in 0..pop_count {
            if !path.solver.pop() {
                return (
                    SolveResult::Error(
                        "axeyum direct-delta scope underflow; session reset".to_string(),
                    ),
                    metrics,
                );
            }
            path.active_assertions -= 1;
            self.stats.assertions_popped = self.stats.assertions_popped.saturating_add(1);
        }
        debug_assert_eq!(path.active_assertions, retain_assertions);

        let suffix = &persistent[retain_assertions..];
        for &assertion in suffix {
            if let Err(error) = path.solver.push() {
                return (SolveResult::Error(error), metrics);
            }
            let translated = match path.solver.assert_measured(pool, assertion, profiling) {
                Ok(translated) => translated,
                Err(error) => return (SolveResult::Error(error), metrics),
            };
            metrics.persistent_translation.add(translated);
            path.active_assertions += 1;
            self.stats.persistent_assertions_translated = self
                .stats
                .persistent_assertions_translated
                .saturating_add(1);
            self.stats.assertions_added = self.stats.assertions_added.saturating_add(1);
        }
        if profiling {
            metrics.persistent_root_encodings = path
                .solver
                .solver_stats()
                .root_encodings
                .saturating_sub(root_encodings_before);
        }

        if temporary.is_empty() {
            let (mut result, mut model_extract_nanos) = path.solver.check_measured(profiling);
            if warm_timeout_continue_enabled()
                && matches!(
                    result,
                    SolveResult::Unknown(SolveUnknownReason::WallTimeout)
                )
            {
                WARM_TIMEOUT_CONTINUATIONS.fetch_add(1, Ordering::Relaxed);
                let (continuation, continuation_model_extract_nanos) =
                    path.solver.check_measured(profiling);
                model_extract_nanos =
                    model_extract_nanos.saturating_add(continuation_model_extract_nanos);
                result = select_warm_timeout_continuation(result, continuation);
            }
            metrics.model_extract_nanos = model_extract_nanos;
            path.active_prefix = persistent_prefix.clone();
            (result, metrics)
        } else {
            let (result, translated, model_extract_nanos) = path.solver.check_assuming_measured(
                pool,
                temporary,
                profiling,
                warm_timeout_continue_enabled(),
            );
            metrics.temporary_translation = translated;
            metrics.model_extract_nanos = model_extract_nanos;
            self.stats.temporary_assumptions_translated = self
                .stats
                .temporary_assumptions_translated
                .saturating_add(translated.roots);
            path.active_prefix = persistent_prefix.clone();
            (result, metrics)
        }
    }

    #[cfg(test)]
    fn stats(&self) -> DirectDeltaStats {
        self.stats
    }

    fn snapshot_stats(&self) -> SnapshotReuseStats {
        SnapshotReuseStats {
            checks: self.stats.checks,
            exact_snapshot_reuses: self.stats.exact_reuses,
            prefix_assertions_reused: self.stats.prefix_assertions_reused,
            assertions_added: self.stats.assertions_added,
            assertions_popped: self.stats.assertions_popped,
            resets_after_error: self.stats.resets_after_error,
        }
    }

    fn replay_sat_cache_stats(&self, path_id: u64) -> ReplayCheckedSatCacheStats {
        self.paths
            .get(&path_id)
            .map_or_else(ReplayCheckedSatCacheStats::default, |path| {
                path.solver.replay_sat_cache_stats()
            })
    }

    fn close_path(&mut self, path_id: u64) -> Option<ReplayCheckedSatCacheStats> {
        self.paths
            .remove(&path_id)
            .map(|path| path.solver.replay_sat_cache_stats())
    }
}

/// Minimal GQ9 admission state: retain only IDs until a path proves reuse.
#[derive(Debug, Default)]
pub(super) struct AutoLineageAdmission {
    seen_once: BTreeSet<u64>,
}

impl AutoLineageAdmission {
    /// Returns true from the second observation onward.
    fn observe(&mut self, path_id: u64) -> bool {
        !self.seen_once.insert(path_id)
    }

    fn remove(&mut self, path_id: u64) -> bool {
        self.seen_once.remove(&path_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SerialLeaseRelease {
    Untracked,
    Retained,
    Final,
}

/// Reference counts for one serial DFS owner's active and queued states.
#[derive(Debug, Default)]
pub(super) struct SerialWarmOwnerLeases {
    references: BTreeMap<u64, u64>,
}

impl SerialWarmOwnerLeases {
    fn share_with_children(&mut self, path_id: u64, children: u64) -> (bool, u64) {
        let newly_tracked = !self.references.contains_key(&path_id);
        let references = self.references.entry(path_id).or_insert(1);
        *references = references.saturating_add(children);
        (newly_tracked, *references)
    }

    fn release(&mut self, path_id: u64) -> SerialLeaseRelease {
        let Some(references) = self.references.get_mut(&path_id) else {
            return SerialLeaseRelease::Untracked;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            self.references.remove(&path_id);
            SerialLeaseRelease::Final
        } else {
            SerialLeaseRelease::Retained
        }
    }
}

pub(crate) fn share_serial_warm_owner_with_children(path_id: u64, children: u64) {
    debug_assert!(children > 0);
    let (newly_tracked, references) = SERIAL_WARM_OWNER_LEASES
        .with(|leases| leases.borrow_mut().share_with_children(path_id, children));
    WARM_SERIAL_SHARE_EVENTS.fetch_add(1, Ordering::Relaxed);
    let added = if newly_tracked {
        WARM_SERIAL_TRACKED_OWNERS.fetch_add(1, Ordering::Relaxed);
        children.saturating_add(1)
    } else {
        children
    };
    let current = WARM_SERIAL_REFERENCES
        .fetch_add(added, Ordering::Relaxed)
        .saturating_add(added);
    debug_assert!(current >= references);
    WARM_SERIAL_PEAK_REFERENCES.fetch_max(current, Ordering::Relaxed);
}

fn release_serial_warm_owner(path_id: u64) -> bool {
    match SERIAL_WARM_OWNER_LEASES.with(|leases| leases.borrow_mut().release(path_id)) {
        SerialLeaseRelease::Untracked => true,
        SerialLeaseRelease::Retained => {
            WARM_SERIAL_REFERENCES.fetch_sub(1, Ordering::Relaxed);
            false
        }
        SerialLeaseRelease::Final => {
            WARM_SERIAL_REFERENCES.fetch_sub(1, Ordering::Relaxed);
            WARM_SERIAL_TRACKED_OWNERS.fetch_sub(1, Ordering::Relaxed);
            true
        }
    }
}

impl LineageIncrementalAxeyumSolver {
    fn has_path(&self, path_id: u64) -> bool {
        self.paths.contains_key(&path_id)
    }

    fn check_path(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        asserts: &[Assert],
    ) -> (
        SolveResult,
        SnapshotReuseStats,
        SnapshotReuseStats,
        ReplayCheckedSatCacheStats,
        ReplayCheckedSatCacheStats,
        bool,
    ) {
        let created = !self.paths.contains_key(&path_id);
        let create_started = (created && profile_output_dir().is_some()).then(Instant::now);
        let solver = self
            .paths
            .entry(path_id)
            .or_insert_with(SnapshotIncrementalAxeyumSolver::new_path_owned);
        let session_create_nanos = create_started.map_or(0, |started| nanos(started.elapsed()));
        let before = solver.stats();
        let cache_before = solver.replay_sat_cache_stats();
        let result = solver.check_snapshot_for_path(
            pool,
            asserts,
            Some(path_id),
            created,
            session_create_nanos,
        );
        (
            result,
            before,
            solver.stats(),
            cache_before,
            solver.replay_sat_cache_stats(),
            created,
        )
    }

    fn close_path(&mut self, path_id: u64) -> Option<ReplayCheckedSatCacheStats> {
        self.paths
            .remove(&path_id)
            .map(|solver| solver.replay_sat_cache_stats())
    }
}

/// Whether a retained snapshot-to-incremental policy is selected.
pub(crate) fn warm_reuse_enabled() -> bool {
    warm_reuse_policy() != WarmReusePolicy::Off
}

/// Checks through the selected retained worker-local adapter.
pub(crate) fn check_warm_thread_local(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
) -> (SolveResult, AxeyumExecutionClass) {
    let (result, execution) = check_warm_thread_local_selected(
        pool,
        asserts,
        path_id,
        delta,
        warm_reuse_policy(),
        direct_delta_enabled(),
    );
    if !matches!(
        result,
        SolveResult::Unknown(SolveUnknownReason::WallTimeout)
    ) || !last_direct_delta_synced()
        || !warm_timeout_cold_retry_enabled()
    {
        return (result, execution);
    }

    WARM_TIMEOUT_COLD_RETRIES.fetch_add(1, Ordering::Relaxed);
    let result = match AxeyumSolver::new().check(pool, asserts) {
        decided @ (SolveResult::Sat(_) | SolveResult::Unsat) => {
            WARM_TIMEOUT_COLD_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            decided
        }
        SolveResult::Unknown(_) => {
            WARM_TIMEOUT_COLD_UNKNOWNS.fetch_add(1, Ordering::Relaxed);
            result
        }
        SolveResult::Error(_) | SolveResult::NoSolver => {
            WARM_TIMEOUT_COLD_ERRORS.fetch_add(1, Ordering::Relaxed);
            result
        }
    };
    (result, AxeyumExecutionClass::WarmTimeoutColdRetry)
}

/// Run the fixed direct-lineage Axeyum cell used only by fair-shadow
/// diagnostics, independent of the product-path admission policy.
pub(crate) fn check_fair_warm_thread_local(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
) -> (SolveResult, AxeyumExecutionClass) {
    check_warm_thread_local_selected(
        pool,
        asserts,
        path_id,
        delta,
        WarmReusePolicy::Lineage,
        true,
    )
}

pub(super) fn check_warm_thread_local_selected(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
    policy: WarmReusePolicy,
    direct_delta_requested: bool,
) -> (SolveResult, AxeyumExecutionClass) {
    LAST_DIRECT_DELTA_SYNCED.with(|synced| synced.set(false));
    let mut execution = AxeyumExecutionClass::ColdOneShot;
    let (result, before, after) = match policy {
        WarmReusePolicy::Off => {
            return (
                AxeyumSolver::new().check(pool, asserts),
                AxeyumExecutionClass::ColdOneShot,
            );
        }
        WarmReusePolicy::Snapshot => WARM_SOLVER.with(|solver| {
            execution = AxeyumExecutionClass::WarmSnapshot;
            let mut solver = solver.borrow_mut();
            let before = solver.stats();
            let result = solver.check_snapshot(pool, asserts);
            (result, before, solver.stats())
        }),
        policy @ (WarmReusePolicy::Lineage | WarmReusePolicy::Auto | WarmReusePolicy::Adaptive) => {
            let Some(path_id) = path_id else {
                return (
                    AxeyumSolver::new().check(pool, asserts),
                    AxeyumExecutionClass::FallbackMissingPath,
                );
            };
            let direct = direct_delta_requested && delta.is_some();
            if direct {
                let delta = delta
                    .as_ref()
                    .expect("direct mode requires an explicit delta");
                if delta.retain_assertions > delta.persistent_assertions
                    || delta.persistent_assertions > asserts.len()
                {
                    let (before, after, closed_cache) = DIRECT_DELTA_SOLVERS.with(|lineage| {
                        let mut lineage = lineage.borrow_mut();
                        let before = lineage.snapshot_stats();
                        lineage.stats.checks = lineage.stats.checks.saturating_add(1);
                        let closed_cache = lineage.close_path(path_id);
                        if closed_cache.is_some() {
                            lineage.stats.resets_after_error =
                                lineage.stats.resets_after_error.saturating_add(1);
                        }
                        (before, lineage.snapshot_stats(), closed_cache)
                    });
                    if let Some(cache) = closed_cache {
                        subtract_replay_sat_cache_gauges(cache);
                        WARM_PATHS_CLOSED.fetch_add(1, Ordering::Relaxed);
                        WARM_PATHS_LIVE.fetch_sub(1, Ordering::Relaxed);
                    }
                    record_warm_delta(before, after);
                    return (
                        SolveResult::Error(format!(
                            "invalid axeyum direct delta: retain {}, persistent {}, total {}",
                            delta.retain_assertions,
                            delta.persistent_assertions,
                            asserts.len()
                        )),
                        AxeyumExecutionClass::InvalidDirectDelta,
                    );
                }
            }
            let limits = warm_reuse_limits();
            if count(asserts.len()) > limits.max_assertions_per_path {
                // A serial sibling continuation may still need this owner's
                // retained prefix. The oversized active state falls back
                // one-shot, then releases its lease only at real termination.
                if !warm_serial_sibling_reuse_enabled() {
                    close_warm_path(path_id);
                }
                WARM_ASSERTION_LIMIT_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                return (
                    AxeyumSolver::new().check(pool, asserts),
                    AxeyumExecutionClass::FallbackAssertionCap,
                );
            }
            let exists = if direct {
                DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow().has_path(path_id))
            } else {
                LINEAGE_SOLVERS.with(|lineage| lineage.borrow().has_path(path_id))
            };
            if policy == WarmReusePolicy::Auto && !exists {
                let repeated = AUTO_LINEAGE_ADMISSION
                    .with(|admission| admission.borrow_mut().observe(path_id));
                if !repeated {
                    WARM_AUTO_PROBES.fetch_add(1, Ordering::Relaxed);
                    return (
                        AxeyumSolver::new().check(pool, asserts),
                        AxeyumExecutionClass::FallbackAutoProbe,
                    );
                }
            }
            let reserved = if exists {
                false
            } else {
                let pressure = WARM_ADAPTIVE_PRESSURE_EVENTS.load(Ordering::Relaxed);
                let initial_limit = if policy == WarmReusePolicy::Adaptive {
                    adaptive_live_path_limit(limits.max_live_paths, pressure)
                } else {
                    limits.max_live_paths
                };
                if try_reserve_warm_path(initial_limit) {
                    true
                } else if policy == WarmReusePolicy::Adaptive
                    && initial_limit < limits.max_live_paths
                {
                    let pressure = WARM_ADAPTIVE_PRESSURE_EVENTS
                        .fetch_add(1, Ordering::Relaxed)
                        .saturating_add(1);
                    if pressure == ADAPTIVE_PRESSURE_THRESHOLD {
                        WARM_ADAPTIVE_EXPANSIONS.fetch_add(1, Ordering::Relaxed);
                    }
                    if pressure >= ADAPTIVE_PRESSURE_THRESHOLD
                        && try_reserve_warm_path(limits.max_live_paths)
                    {
                        true
                    } else {
                        WARM_PATH_LIMIT_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                        return (
                            AxeyumSolver::new().check(pool, asserts),
                            AxeyumExecutionClass::FallbackPathCap,
                        );
                    }
                } else {
                    WARM_PATH_LIMIT_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    return (
                        AxeyumSolver::new().check(pool, asserts),
                        AxeyumExecutionClass::FallbackPathCap,
                    );
                }
            };
            execution = if exists {
                AxeyumExecutionClass::WarmRetained
            } else {
                AxeyumExecutionClass::WarmCreated
            };
            if direct {
                let delta = delta
                    .as_ref()
                    .expect("direct mode requires an explicit delta");
                let persistent = &asserts[..delta.persistent_assertions];
                let temporary = &asserts[delta.persistent_assertions..];
                let (
                    result,
                    before,
                    after,
                    cache_before,
                    cache_after,
                    removed_cache,
                    created,
                    synced,
                ) = DIRECT_DELTA_SOLVERS.with(|lineage| {
                    let mut lineage = lineage.borrow_mut();
                    let created = !lineage.has_path(path_id);
                    let before = lineage.snapshot_stats();
                    let cache_before = lineage.replay_sat_cache_stats(path_id);
                    let (result, synced, removed_cache) = lineage.check_path(
                        path_id,
                        pool,
                        DirectCheckInput {
                            complete_asserts: asserts,
                            persistent,
                            persistent_prefix: &delta.persistent_prefix,
                            retain_assertions: delta.retain_assertions,
                            temporary,
                        },
                    );
                    (
                        result,
                        before,
                        lineage.snapshot_stats(),
                        cache_before,
                        removed_cache.unwrap_or_else(|| lineage.replay_sat_cache_stats(path_id)),
                        removed_cache,
                        created,
                        synced,
                    )
                });
                record_replay_sat_cache_delta(cache_before, cache_after);
                if let Some(cache) = removed_cache {
                    subtract_replay_sat_cache_gauges(cache);
                }
                debug_assert_eq!(created, reserved);
                LAST_DIRECT_DELTA_SYNCED.with(|state| state.set(synced));
                if created {
                    WARM_PATHS_CREATED.fetch_add(1, Ordering::Relaxed);
                    if policy == WarmReusePolicy::Auto {
                        AUTO_LINEAGE_ADMISSION.with(|admission| {
                            admission.borrow_mut().remove(path_id);
                        });
                        WARM_AUTO_ACTIVATIONS.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if !synced {
                    WARM_PATHS_CLOSED.fetch_add(1, Ordering::Relaxed);
                    WARM_PATHS_LIVE.fetch_sub(1, Ordering::Relaxed);
                }
                (result, before, after)
            } else {
                let (result, before, after, cache_before, cache_after, created) = LINEAGE_SOLVERS
                    .with(|lineage| {
                        let mut lineage = lineage.borrow_mut();
                        lineage.check_path(path_id, pool, asserts)
                    });
                record_replay_sat_cache_delta(cache_before, cache_after);
                debug_assert_eq!(created, reserved);
                if created {
                    WARM_PATHS_CREATED.fetch_add(1, Ordering::Relaxed);
                    if policy == WarmReusePolicy::Auto {
                        AUTO_LINEAGE_ADMISSION.with(|admission| {
                            admission.borrow_mut().remove(path_id);
                        });
                        WARM_AUTO_ACTIVATIONS.fetch_add(1, Ordering::Relaxed);
                    }
                }
                (result, before, after)
            }
        }
    };
    record_warm_delta(before, after);
    (result, execution)
}

pub(super) fn adaptive_live_path_limit(configured: u64, pressure_events: u64) -> u64 {
    if pressure_events >= ADAPTIVE_PRESSURE_THRESHOLD {
        configured
    } else {
        configured.min(ADAPTIVE_INITIAL_LIVE_PATHS)
    }
}

fn try_reserve_warm_path(limit: u64) -> bool {
    try_reserve_path_counter(&WARM_PATHS_LIVE, &WARM_PATHS_PEAK_LIVE, limit)
}

pub(super) fn try_reserve_path_counter(
    live_counter: &AtomicU64,
    peak_counter: &AtomicU64,
    limit: u64,
) -> bool {
    let mut live = live_counter.load(Ordering::Relaxed);
    loop {
        if live >= limit {
            return false;
        }
        match live_counter.compare_exchange_weak(
            live,
            live + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                peak_counter.fetch_max(live + 1, Ordering::Relaxed);
                return true;
            }
            Err(observed) => live = observed,
        }
    }
}

fn record_warm_delta(before: SnapshotReuseStats, after: SnapshotReuseStats) {
    WARM_CHECKS.fetch_add(
        after.checks.saturating_sub(before.checks),
        Ordering::Relaxed,
    );
    WARM_EXACT_REUSES.fetch_add(
        after
            .exact_snapshot_reuses
            .saturating_sub(before.exact_snapshot_reuses),
        Ordering::Relaxed,
    );
    WARM_PREFIX_REUSES.fetch_add(
        after
            .prefix_assertions_reused
            .saturating_sub(before.prefix_assertions_reused),
        Ordering::Relaxed,
    );
    WARM_ASSERTIONS_ADDED.fetch_add(
        after
            .assertions_added
            .saturating_sub(before.assertions_added),
        Ordering::Relaxed,
    );
    WARM_ASSERTIONS_POPPED.fetch_add(
        after
            .assertions_popped
            .saturating_sub(before.assertions_popped),
        Ordering::Relaxed,
    );
    WARM_RESETS.fetch_add(
        after
            .resets_after_error
            .saturating_sub(before.resets_after_error),
        Ordering::Relaxed,
    );
}

/// Release retained mutable state when an explorer path becomes terminal.
pub(crate) fn close_warm_path(path_id: u64) {
    if !matches!(
        warm_reuse_policy(),
        WarmReusePolicy::Lineage | WarmReusePolicy::Auto | WarmReusePolicy::Adaptive
    ) {
        return;
    }
    if !release_serial_warm_owner(path_id) {
        return;
    }
    AUTO_LINEAGE_ADMISSION.with(|admission| {
        admission.borrow_mut().remove(path_id);
    });
    close_retained_lineage_paths(path_id);
}

/// Release the fixed fair-shadow Axeyum session even when the product warm
/// policy is disabled.
pub(crate) fn close_fair_warm_path(path_id: u64) {
    if !release_serial_warm_owner(path_id) {
        return;
    }
    close_retained_lineage_paths(path_id);
}

fn close_retained_lineage_paths(path_id: u64) {
    let snapshot_cache = LINEAGE_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
    let direct_cache =
        DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
    for cache in [snapshot_cache, direct_cache].into_iter().flatten() {
        subtract_replay_sat_cache_gauges(cache);
        WARM_PATHS_CLOSED.fetch_add(1, Ordering::Relaxed);
        WARM_PATHS_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{bin, c, cmp, direct_input, expect_pred, solve_native};
    use super::*;
    use crate::ir::types::Width;

    #[test]
    fn direct_delta_lineage_materializes_once_then_translates_only_suffixes() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let six = c(&mut root, 6, Width::W32);
        let below_six = cmp(&mut root, CmpOp::Ult, x, six, Width::W32);

        let mut left = root.clone();
        let five = c(&mut left, 5, Width::W32);
        let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
        let mut right = root.clone();
        let seven = c(&mut right, 7, Width::W32);
        let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);

        let owner = 23;
        let mut lineage = DirectDeltaLineageAxeyumSolver::default();
        let mut base_prefix = WarmAssertionPrefix::default();
        base_prefix.push();
        let mut left_prefix = base_prefix.clone();
        left_prefix.push();
        assert!(matches!(
            lineage
                .check_path(
                    owner,
                    &root,
                    direct_input(
                        &[(below_six, true)],
                        &[(below_six, true)],
                        &base_prefix,
                        0,
                        &[],
                    ),
                )
                .0,
            SolveResult::Sat(_)
        ));
        match lineage
            .check_path(
                owner,
                &left,
                direct_input(
                    &[(below_six, true), (x_is_five, true)],
                    &[(below_six, true), (x_is_five, true)],
                    &left_prefix,
                    1,
                    &[],
                ),
            )
            .0
        {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected direct left SAT, got {other:?}"),
        }

        // Switch to the sibling prefix and use its branch condition as a true
        // one-shot assumption: one persistent scope is popped, no assumption
        // persists, and the shared base root is never translated again.
        assert_eq!(
            lineage
                .check_path(
                    owner,
                    &right,
                    direct_input(
                        &[(below_six, true), (x_is_seven, true)],
                        &[(below_six, true)],
                        &base_prefix,
                        1,
                        &[(x_is_seven, true)],
                    ),
                )
                .0,
            SolveResult::Unsat
        );
        assert!(matches!(
            lineage
                .check_path(
                    owner,
                    &right,
                    direct_input(
                        &[(below_six, true)],
                        &[(below_six, true)],
                        &base_prefix,
                        1,
                        &[],
                    ),
                )
                .0,
            SolveResult::Sat(_)
        ));
        assert_eq!(
            lineage.stats(),
            DirectDeltaStats {
                checks: 4,
                full_materializations: 1,
                exact_reuses: 1,
                prefix_assertions_reused: 3,
                persistent_assertions_translated: 2,
                temporary_assumptions_translated: 1,
                assertions_added: 2,
                assertions_popped: 1,
                resets_after_error: 0,
            }
        );
    }

    #[test]
    fn direct_delta_lineage_rewinds_stale_equal_depth_sibling_by_source_identity() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let ten = c(&mut root, 10, Width::W32);
        let below_ten = cmp(&mut root, CmpOp::Ult, x, ten, Width::W32);

        let mut left = root.clone();
        let five = c(&mut left, 5, Width::W32);
        let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
        let mut right = root.clone();
        let seven = c(&mut right, 7, Width::W32);
        let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);

        let mut base_prefix = WarmAssertionPrefix::default();
        base_prefix.push();
        let mut left_prefix = base_prefix.clone();
        left_prefix.push();
        let mut right_prefix = base_prefix.clone();
        right_prefix.push();

        let owner = 31;
        let mut lineage = DirectDeltaLineageAxeyumSolver::default();
        match lineage
            .check_path(
                owner,
                &left,
                direct_input(
                    &[(below_ten, true), (x_is_five, true)],
                    &[(below_ten, true), (x_is_five, true)],
                    &left_prefix,
                    0,
                    &[],
                ),
            )
            .0
        {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected left sibling SAT model, got {other:?}"),
        }

        // This marker is stale: the queued right sibling believes its complete
        // two-root prefix is retained, while the one mutable owner currently
        // contains the left sibling. Source ancestry, not depth, must rewind to
        // the one-root parent before asserting the right branch.
        match lineage
            .check_path(
                owner,
                &right,
                direct_input(
                    &[(below_ten, true), (x_is_seven, true)],
                    &[(below_ten, true), (x_is_seven, true)],
                    &right_prefix,
                    2,
                    &[],
                ),
            )
            .0
        {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&7)),
            other => panic!("expected source-rewound right sibling SAT model, got {other:?}"),
        }

        assert_eq!(left_prefix.common_depth(&right_prefix), 1);
        assert_eq!(lineage.stats().assertions_popped, 1);
        assert_eq!(lineage.stats().assertions_added, 3);
    }

    #[test]
    fn direct_delta_lineage_fails_closed_on_impossible_prefix() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = c(&mut pool, 1, Width::W8);
        let x_is_one = cmp(&mut pool, CmpOp::Eq, x, one, Width::W8);
        let assertion = (x_is_one, true);
        let owner = 29;
        let mut lineage = DirectDeltaLineageAxeyumSolver::default();
        let mut prefix = WarmAssertionPrefix::default();
        prefix.push();

        assert!(
            lineage
                .check_path(
                    owner,
                    &pool,
                    direct_input(&[assertion], &[assertion], &prefix, 0, &[]),
                )
                .1
        );
        let (invalid, synced, _) = lineage.check_path(
            owner,
            &pool,
            direct_input(&[assertion], &[assertion], &prefix, 2, &[]),
        );
        assert!(!synced);
        assert!(matches!(invalid, SolveResult::Error(_)));
        assert!(!lineage.paths.contains_key(&owner));

        // Missing state never applies a naked delta. It safely rematerializes
        // the complete persistent snapshot even when the caller's retain marker
        // refers to the lost owner.
        assert!(
            lineage
                .check_path(
                    owner,
                    &pool,
                    direct_input(&[assertion], &[assertion], &prefix, 1, &[]),
                )
                .1
        );
        assert_eq!(
            lineage.stats(),
            DirectDeltaStats {
                checks: 3,
                full_materializations: 2,
                exact_reuses: 0,
                prefix_assertions_reused: 0,
                persistent_assertions_translated: 2,
                temporary_assumptions_translated: 0,
                assertions_added: 2,
                assertions_popped: 0,
                resets_after_error: 1,
            }
        );
    }

    #[test]
    fn lineage_incremental_isolates_sibling_solver_state() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let ten = c(&mut root, 10, Width::W32);
        let below_ten = cmp(&mut root, CmpOp::Ult, x, ten, Width::W32);

        let mut left = root.clone();
        let five = c(&mut left, 5, Width::W32);
        let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
        let mut right = root.clone();
        let seven = c(&mut right, 7, Width::W32);
        let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);

        let mut lineage = LineageIncrementalAxeyumSolver::default();
        let left_snapshot = [(below_ten, true), (x_is_five, true)];
        let right_snapshot = [(below_ten, true), (x_is_seven, true)];
        assert!(matches!(
            lineage.check_path(11, &left, &left_snapshot).0,
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            lineage.check_path(12, &right, &right_snapshot).0,
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            lineage.check_path(11, &left, &left_snapshot).0,
            SolveResult::Sat(_)
        ));
        assert_eq!(
            lineage
                .paths
                .get(&11)
                .unwrap()
                .stats()
                .exact_snapshot_reuses,
            1
        );
        assert_eq!(
            lineage
                .paths
                .get(&12)
                .unwrap()
                .stats()
                .exact_snapshot_reuses,
            0
        );
        assert_eq!(lineage.paths.len(), 2);
        assert!(lineage.close_path(11).is_some());
        assert!(lineage.close_path(11).is_none());
        assert_eq!(lineage.paths.len(), 1);
    }

    #[test]
    fn serial_sibling_snapshots_pop_divergence_and_replay_originals() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let six = c(&mut root, 6, Width::W32);
        let below_six = cmp(&mut root, CmpOp::Ult, x, six, Width::W32);

        let mut left = root.clone();
        let five = c(&mut left, 5, Width::W32);
        let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
        let mut right = root.clone();
        let seven = c(&mut right, 7, Width::W32);
        let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);

        let left_snapshot = [(below_six, true), (x_is_five, true)];
        let right_snapshot = [(below_six, true), (x_is_seven, true)];
        let mut lineage = LineageIncrementalAxeyumSolver::default();
        let owner = 19;

        match lineage.check_path(owner, &left, &left_snapshot).0 {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected replayed left SAT model, got {other:?}"),
        }
        assert!(matches!(
            lineage.check_path(owner, &right, &right_snapshot).0,
            SolveResult::Unsat
        ));
        assert!(matches!(
            lineage.check_path(owner, &left, &left_snapshot).0,
            SolveResult::Sat(_)
        ));

        let stats = lineage.paths.get(&owner).unwrap().stats();
        assert_eq!(stats.checks, 3);
        assert_eq!(stats.prefix_assertions_reused, 2);
        assert_eq!(stats.assertions_added, 4);
        assert_eq!(stats.assertions_popped, 2);
        assert_eq!(lineage.paths.len(), 1);
    }

    #[test]
    fn auto_lineage_admits_only_after_same_path_repeats() {
        let mut admission = AutoLineageAdmission::default();

        assert!(!admission.observe(11));
        assert!(!admission.observe(12));
        assert!(admission.observe(11));
        assert!(admission.observe(11));
        assert!(admission.remove(11));
        assert!(!admission.observe(11));
        assert!(!admission.remove(99));
    }

    #[test]
    fn selected_direct_delta_adapter_reuses_prefix_and_keeps_assumptions_temporary() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W32);
        let six = c(&mut pool, 6, Width::W32);
        let five = c(&mut pool, 5, Width::W32);
        let seven = c(&mut pool, 7, Width::W32);
        let below_six = cmp(&mut pool, CmpOp::Ult, x, six, Width::W32);
        let x_is_five = cmp(&mut pool, CmpOp::Eq, x, five, Width::W32);
        let x_is_seven = cmp(&mut pool, CmpOp::Eq, x, seven, Width::W32);
        let owner = 0xd1ec_7de1_7a_u64;
        let mut base_prefix = WarmAssertionPrefix::default();
        base_prefix.push();
        let mut left_prefix = base_prefix.clone();
        left_prefix.push();

        let check = |asserts: &[Assert],
                     retain_assertions,
                     persistent_assertions,
                     persistent_prefix: &WarmAssertionPrefix| {
            check_warm_thread_local_selected(
                &pool,
                asserts,
                Some(owner),
                Some(WarmDeltaContext {
                    retain_assertions,
                    persistent_assertions,
                    persistent_prefix: persistent_prefix.clone(),
                }),
                WarmReusePolicy::Lineage,
                true,
            )
        };

        let (result, execution) = check(&[(below_six, true)], 0, 1, &base_prefix);
        assert!(matches!(result, SolveResult::Sat(_)));
        assert_eq!(execution, AxeyumExecutionClass::WarmCreated);
        assert!(last_direct_delta_synced());

        let (result, execution) =
            check(&[(below_six, true), (x_is_five, true)], 1, 2, &left_prefix);
        assert_eq!(execution, AxeyumExecutionClass::WarmRetained);
        match result {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected direct-delta SAT, got {other:?}"),
        }
        assert!(last_direct_delta_synced());

        let (result, execution) =
            check(&[(below_six, true), (x_is_seven, true)], 1, 1, &base_prefix);
        assert_eq!(result, SolveResult::Unsat);
        assert_eq!(execution, AxeyumExecutionClass::WarmRetained);
        assert!(last_direct_delta_synced());
        let (result, execution) = check(&[(below_six, true)], 1, 1, &base_prefix);
        assert!(matches!(result, SolveResult::Sat(_)));
        assert_eq!(execution, AxeyumExecutionClass::WarmRetained);
        assert!(last_direct_delta_synced());

        // Backend-local validation is fail-closed even if a caller bypasses
        // `solve_for_path_delta` and supplies an impossible partition.
        let (result, execution) = check(&[(below_six, true)], 1, 2, &left_prefix);
        assert!(matches!(result, SolveResult::Error(_)));
        assert_eq!(execution, AxeyumExecutionClass::InvalidDirectDelta);
        assert!(!last_direct_delta_synced());
        assert!(!DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow().has_path(owner)));
    }

    #[test]
    fn serial_owner_lease_closes_only_after_nested_continuations() {
        let mut leases = SerialWarmOwnerLeases::default();
        assert_eq!(leases.share_with_children(7, 2), (true, 3));
        assert_eq!(leases.share_with_children(7, 2), (false, 5));
        for _ in 0..4 {
            assert_eq!(leases.release(7), SerialLeaseRelease::Retained);
        }
        assert_eq!(leases.release(7), SerialLeaseRelease::Final);
        assert_eq!(leases.release(7), SerialLeaseRelease::Untracked);
        assert!(leases.references.is_empty());
    }

    #[test]
    fn path_owned_replay_sat_cache_hits_only_exact_sat_snapshots() {
        let policy = ReplayCheckedSatCachePolicy::new(4, 16, 128);
        let mut solver = SnapshotIncrementalAxeyumSolver::with_cache_for_test(policy);
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = c(&mut pool, 1, Width::W8);
        let two = c(&mut pool, 2, Width::W8);
        let x_is_one = cmp(&mut pool, CmpOp::Eq, x, one, Width::W8);
        let x_is_two = cmp(&mut pool, CmpOp::Eq, x, two, Width::W8);

        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true)]),
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true)]),
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true), (x_is_two, true)]),
            SolveResult::Unsat
        ));

        let stats = solver.replay_sat_cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.insertions, 1);
        assert_eq!(stats.declined_unsat, 1);
        assert_eq!(stats.replay_failures, 0);
        assert_eq!(
            SnapshotIncrementalAxeyumSolver::new().replay_sat_cache_stats(),
            ReplayCheckedSatCacheStats::default()
        );
    }
}
