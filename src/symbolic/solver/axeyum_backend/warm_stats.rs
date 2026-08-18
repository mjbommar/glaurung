//! The process-wide counter reporting surface.
//!
//! Everything in this module is a read of the `AtomicU64` counters the retained
//! solver paths increment. Each `*_stats()` function takes one consistent
//! snapshot into a plain `Serialize` struct, which is what `examples/ioctlance`
//! and `symbolic::ordered_replay` publish as run diagnostics.
//!
//! The replay-SAT-cache half is not purely a read: [`record_replay_sat_cache_delta`]
//! folds one session's before/after cache stats into the process counters, and
//! the gauge helpers move the current per-path entry/value/bit gauges as paths
//! open and close.

use super::*;

/// Process-wide explorer-path ownership counters for lineage warm reuse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarmPathReuseStats {
    /// Configured process-wide retained-session ceiling.
    pub max_live_paths: u64,
    /// Configured maximum assertion roots in one retained snapshot.
    pub max_assertions_per_path: u64,
    /// Path-owned solver sessions created lazily on first check.
    pub paths_created: u64,
    /// Path-owned solver sessions released at terminal path events.
    pub paths_closed: u64,
    /// Sessions currently retained across all explorer workers.
    pub live_paths: u64,
    /// Maximum simultaneously retained sessions observed in this process.
    pub peak_live_paths: u64,
    /// Checks sent one-shot because the process-wide live-path cap was full.
    pub path_limit_fallbacks: u64,
    /// Checks sent one-shot because their assertion snapshot exceeded the cap.
    pub assertion_limit_fallbacks: u64,
}

/// Process-wide GQ9 detected-reuse admission counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AutoLineageReuseStats {
    /// First observations solved one-shot without retaining a solver.
    pub probes: u64,
    /// Repeated paths promoted to bounded lineage sessions.
    pub activations: u64,
}

/// Process-wide counters for the bounded pressure-adaptive lineage policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdaptiveLineageReuseStats {
    /// Failed reservations observed while the initial cap was active.
    pub pressure_events: u64,
    /// One-way expansions from the initial cap to the configured hard cap.
    pub expansions: u64,
    /// Initial live-session cap used before sustained pressure is observed.
    pub initial_live_paths: u64,
    /// Pressure-event count that triggers the one-way expansion.
    pub pressure_threshold: u64,
}

/// Process-wide lifecycle counters for the opt-in serial sibling lease.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SerialSiblingReuseStats {
    /// Forks that created queued sibling references to one logical owner.
    pub share_events: u64,
    /// Owners with at least one active or queued reference.
    pub tracked_owners: u64,
    /// Active plus queued references across tracked owners.
    pub references: u64,
    /// Maximum tracked references observed at once.
    pub peak_references: u64,
}

/// Process-wide counters for the opt-in direct-warm timeout cold retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarmTimeoutColdRetryStats {
    /// Warm `Unknown` checks retried through a fresh one-shot solver.
    pub retries: u64,
    /// Retries that recovered a SAT or UNSAT decision.
    pub recoveries: u64,
    /// Retries that also returned `Unknown`.
    pub unknowns: u64,
    /// Retry errors/no-solver results hidden behind the original `Unknown`.
    pub errors: u64,
}

/// Process-wide counters for the bounded same-session timeout continuation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarmTimeoutContinuationStats {
    /// Synchronized warm `Unknown` checks granted one additional SAT call.
    pub continuations: u64,
    /// Continuations that recovered a SAT or UNSAT decision.
    pub recoveries: u64,
    /// Continuations that also returned `Unknown`.
    pub unknowns: u64,
    /// Continuation errors/no-solver results hidden behind the original `Unknown`.
    pub errors: u64,
}

/// Returns process-wide lineage ownership counters.
pub fn warm_path_reuse_stats() -> WarmPathReuseStats {
    let limits = warm_reuse_limits();
    WarmPathReuseStats {
        max_live_paths: limits.max_live_paths,
        max_assertions_per_path: limits.max_assertions_per_path,
        paths_created: WARM_PATHS_CREATED.load(Ordering::Relaxed),
        paths_closed: WARM_PATHS_CLOSED.load(Ordering::Relaxed),
        live_paths: WARM_PATHS_LIVE.load(Ordering::Relaxed),
        peak_live_paths: WARM_PATHS_PEAK_LIVE.load(Ordering::Relaxed),
        path_limit_fallbacks: WARM_PATH_LIMIT_FALLBACKS.load(Ordering::Relaxed),
        assertion_limit_fallbacks: WARM_ASSERTION_LIMIT_FALLBACKS.load(Ordering::Relaxed),
    }
}

/// Returns process-wide detected-reuse admission counters.
pub fn auto_lineage_reuse_stats() -> AutoLineageReuseStats {
    AutoLineageReuseStats {
        probes: WARM_AUTO_PROBES.load(Ordering::Relaxed),
        activations: WARM_AUTO_ACTIVATIONS.load(Ordering::Relaxed),
    }
}

/// Returns process-wide pressure-adaptive admission counters.
pub fn adaptive_lineage_reuse_stats() -> AdaptiveLineageReuseStats {
    AdaptiveLineageReuseStats {
        pressure_events: WARM_ADAPTIVE_PRESSURE_EVENTS.load(Ordering::Relaxed),
        expansions: WARM_ADAPTIVE_EXPANSIONS.load(Ordering::Relaxed),
        initial_live_paths: ADAPTIVE_INITIAL_LIVE_PATHS,
        pressure_threshold: ADAPTIVE_PRESSURE_THRESHOLD,
    }
}

/// Returns lifecycle counters for the opt-in serial sibling lease.
pub fn serial_sibling_reuse_stats() -> SerialSiblingReuseStats {
    SerialSiblingReuseStats {
        share_events: WARM_SERIAL_SHARE_EVENTS.load(Ordering::Relaxed),
        tracked_owners: WARM_SERIAL_TRACKED_OWNERS.load(Ordering::Relaxed),
        references: WARM_SERIAL_REFERENCES.load(Ordering::Relaxed),
        peak_references: WARM_SERIAL_PEAK_REFERENCES.load(Ordering::Relaxed),
    }
}

/// Returns traffic for the opt-in direct-warm timeout cold retry.
pub fn warm_timeout_cold_retry_stats() -> WarmTimeoutColdRetryStats {
    WarmTimeoutColdRetryStats {
        retries: WARM_TIMEOUT_COLD_RETRIES.load(Ordering::Relaxed),
        recoveries: WARM_TIMEOUT_COLD_RECOVERIES.load(Ordering::Relaxed),
        unknowns: WARM_TIMEOUT_COLD_UNKNOWNS.load(Ordering::Relaxed),
        errors: WARM_TIMEOUT_COLD_ERRORS.load(Ordering::Relaxed),
    }
}

/// Returns traffic for the bounded same-session timeout continuation.
pub fn warm_timeout_continuation_stats() -> WarmTimeoutContinuationStats {
    WarmTimeoutContinuationStats {
        continuations: WARM_TIMEOUT_CONTINUATIONS.load(Ordering::Relaxed),
        recoveries: WARM_TIMEOUT_CONTINUATION_RECOVERIES.load(Ordering::Relaxed),
        unknowns: WARM_TIMEOUT_CONTINUATION_UNKNOWNS.load(Ordering::Relaxed),
        errors: WARM_TIMEOUT_CONTINUATION_ERRORS.load(Ordering::Relaxed),
    }
}

/// Process-wide aggregate of warm snapshot reuse across explorer
/// threads. A fresh process starts all counters at zero.
pub fn warm_reuse_stats() -> SnapshotReuseStats {
    SnapshotReuseStats {
        checks: WARM_CHECKS.load(Ordering::Relaxed),
        exact_snapshot_reuses: WARM_EXACT_REUSES.load(Ordering::Relaxed),
        prefix_assertions_reused: WARM_PREFIX_REUSES.load(Ordering::Relaxed),
        assertions_added: WARM_ASSERTIONS_ADDED.load(Ordering::Relaxed),
        assertions_popped: WARM_ASSERTIONS_POPPED.load(Ordering::Relaxed),
        resets_after_error: WARM_RESETS.load(Ordering::Relaxed),
    }
}

/// Process-wide aggregate of the bounded path-owned replay-checked SAT cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplaySatCacheProcessStats {
    /// Whether newly created path-owned warm solvers enable the cache.
    pub enabled: bool,
    /// Maximum exact SAT entries retained by each live path solver.
    pub max_entries_per_path: u64,
    /// Maximum scalar model values retained by each live path solver.
    pub max_model_values_per_path: u64,
    /// Maximum Bool/BV model payload bits retained by each live path solver.
    pub max_model_bits_per_path: u64,
    /// Aggregate traffic and current gauges across live path solvers.
    pub cache: ReplayCheckedSatCacheStats,
}

/// Returns cache traffic accumulated across all retained path-owned solvers.
pub fn replay_sat_cache_stats() -> ReplaySatCacheProcessStats {
    let policy = replay_sat_cache_policy();
    let mut cache = ReplayCheckedSatCacheStats::default();
    cache.hits = REPLAY_SAT_CACHE_HITS.load(Ordering::Relaxed);
    cache.misses = REPLAY_SAT_CACHE_MISSES.load(Ordering::Relaxed);
    cache.insertions = REPLAY_SAT_CACHE_INSERTIONS.load(Ordering::Relaxed);
    cache.evictions = REPLAY_SAT_CACHE_EVICTIONS.load(Ordering::Relaxed);
    cache.replay_failures = REPLAY_SAT_CACHE_REPLAY_FAILURES.load(Ordering::Relaxed);
    cache.declined_unsat = REPLAY_SAT_CACHE_DECLINED_UNSAT.load(Ordering::Relaxed);
    cache.declined_unknown = REPLAY_SAT_CACHE_DECLINED_UNKNOWN.load(Ordering::Relaxed);
    cache.declined_oversized_models =
        REPLAY_SAT_CACHE_DECLINED_OVERSIZED_MODELS.load(Ordering::Relaxed);
    cache.declined_non_scalar_models =
        REPLAY_SAT_CACHE_DECLINED_NON_SCALAR_MODELS.load(Ordering::Relaxed);
    cache.entries = REPLAY_SAT_CACHE_ENTRIES.load(Ordering::Relaxed);
    cache.model_values = REPLAY_SAT_CACHE_MODEL_VALUES.load(Ordering::Relaxed);
    cache.model_bits = REPLAY_SAT_CACHE_MODEL_BITS.load(Ordering::Relaxed);
    ReplaySatCacheProcessStats {
        enabled: policy.is_some(),
        max_entries_per_path: policy.map_or(0, |policy| count(policy.max_entries)),
        max_model_values_per_path: policy.map_or(0, |policy| count(policy.max_model_values)),
        max_model_bits_per_path: policy.map_or(0, |policy| count(policy.max_model_bits)),
        cache,
    }
}

pub(super) fn record_replay_sat_cache_delta(
    before: ReplayCheckedSatCacheStats,
    after: ReplayCheckedSatCacheStats,
) {
    let monotone = [
        (&REPLAY_SAT_CACHE_HITS, before.hits, after.hits),
        (&REPLAY_SAT_CACHE_MISSES, before.misses, after.misses),
        (
            &REPLAY_SAT_CACHE_INSERTIONS,
            before.insertions,
            after.insertions,
        ),
        (
            &REPLAY_SAT_CACHE_EVICTIONS,
            before.evictions,
            after.evictions,
        ),
        (
            &REPLAY_SAT_CACHE_REPLAY_FAILURES,
            before.replay_failures,
            after.replay_failures,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_UNSAT,
            before.declined_unsat,
            after.declined_unsat,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_UNKNOWN,
            before.declined_unknown,
            after.declined_unknown,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_OVERSIZED_MODELS,
            before.declined_oversized_models,
            after.declined_oversized_models,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_NON_SCALAR_MODELS,
            before.declined_non_scalar_models,
            after.declined_non_scalar_models,
        ),
    ];
    for (counter, before, after) in monotone {
        counter.fetch_add(after.saturating_sub(before), Ordering::Relaxed);
    }
    update_replay_sat_cache_gauge(&REPLAY_SAT_CACHE_ENTRIES, before.entries, after.entries);
    update_replay_sat_cache_gauge(
        &REPLAY_SAT_CACHE_MODEL_VALUES,
        before.model_values,
        after.model_values,
    );
    update_replay_sat_cache_gauge(
        &REPLAY_SAT_CACHE_MODEL_BITS,
        before.model_bits,
        after.model_bits,
    );
}

fn update_replay_sat_cache_gauge(counter: &AtomicU64, before: u64, after: u64) {
    if after >= before {
        counter.fetch_add(after - before, Ordering::Relaxed);
    } else {
        counter.fetch_sub(before - after, Ordering::Relaxed);
    }
}

pub(super) fn subtract_replay_sat_cache_gauges(stats: ReplayCheckedSatCacheStats) {
    REPLAY_SAT_CACHE_ENTRIES.fetch_sub(stats.entries, Ordering::Relaxed);
    REPLAY_SAT_CACHE_MODEL_VALUES.fetch_sub(stats.model_values, Ordering::Relaxed);
    REPLAY_SAT_CACHE_MODEL_BITS.fetch_sub(stats.model_bits, Ordering::Relaxed);
}
