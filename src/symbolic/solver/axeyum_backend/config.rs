//! Environment-variable policy for the axeyum backends.
//!
//! Every retained-solver knob is read from the process environment exactly
//! once through a `OnceLock`, so a run's policy is fixed at first use and
//! cannot change under a worker mid-exploration. Each `GLAURUNG_AXEYUM_*`
//! variable has a `parse_*` function taking the raw string, which is what the
//! tests exercise; the `*_enabled` / `*_policy` wrappers are the cached
//! readers the solver paths call.
//!
//! Also here: [`config`] and [`config_with_work_budgets`], which build the
//! `SolverConfig` handed to every `IncrementalBvSolver` this module creates.
//!
//! `WarmReuseLimits` itself stays in the parent. The rule this split follows
//! throughout: a type whose *private fields* are read from more than one of
//! these modules stays where all of them can still see them, because a child
//! module can reach into its parent's private fields but not a sibling's.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WarmReusePolicy {
    Off,
    Snapshot,
    Lineage,
    Auto,
    Adaptive,
}

pub(super) fn warm_reuse_limits() -> WarmReuseLimits {
    *WARM_REUSE_LIMITS.get_or_init(|| WarmReuseLimits {
        max_live_paths: parse_warm_limit(
            std::env::var(WARM_MAX_LIVE_PATHS_ENV).ok(),
            DEFAULT_WARM_MAX_LIVE_PATHS,
        ),
        max_assertions_per_path: parse_warm_limit(
            std::env::var(WARM_MAX_ASSERTIONS_PER_PATH_ENV).ok(),
            DEFAULT_WARM_MAX_ASSERTIONS_PER_PATH,
        ),
    })
}

pub(super) fn parse_warm_limit(value: Option<String>, default: u64) -> u64 {
    match value {
        None => default,
        Some(value) => value.parse().unwrap_or(0),
    }
}

pub(super) fn warm_reuse_policy() -> WarmReusePolicy {
    let value = std::env::var(WARM_REUSE_ENV).ok();
    parse_warm_reuse_policy(value.as_deref())
}

pub(super) fn parse_warm_reuse_policy(value: Option<&str>) -> WarmReusePolicy {
    match value {
        None => WarmReusePolicy::Adaptive,
        Some(value) if value.eq_ignore_ascii_case("off") => WarmReusePolicy::Off,
        Some(value) if value.eq_ignore_ascii_case("false") => WarmReusePolicy::Off,
        Some("0") => WarmReusePolicy::Off,
        Some(value) if value.eq_ignore_ascii_case("auto") => WarmReusePolicy::Auto,
        Some(value) if value.eq_ignore_ascii_case("adaptive") => WarmReusePolicy::Adaptive,
        Some(value) if value.eq_ignore_ascii_case("lineage") => WarmReusePolicy::Lineage,
        Some(_) => WarmReusePolicy::Snapshot,
    }
}

pub(crate) fn direct_delta_enabled() -> bool {
    parse_direct_delta(std::env::var(DIRECT_DELTA_ENV).ok().as_deref())
}

pub(crate) fn warm_timeout_cold_retry_enabled() -> bool {
    parse_warm_timeout_cold_retry(std::env::var(WARM_TIMEOUT_COLD_RETRY_ENV).ok().as_deref())
}

pub(super) fn parse_warm_timeout_cold_retry(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
        || value.is_some_and(|value| {
            value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
        })
}

pub(crate) fn warm_timeout_continue_enabled() -> bool {
    parse_warm_timeout_continue(std::env::var(WARM_TIMEOUT_CONTINUE_ENV).ok().as_deref())
}

pub(super) fn parse_warm_timeout_continue(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    }
}

pub(super) fn select_warm_timeout_continuation(
    original: SolveResult,
    continuation: SolveResult,
) -> SolveResult {
    match continuation {
        decided @ (SolveResult::Sat(_) | SolveResult::Unsat) => {
            WARM_TIMEOUT_CONTINUATION_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            decided
        }
        SolveResult::Unknown(_) => {
            WARM_TIMEOUT_CONTINUATION_UNKNOWNS.fetch_add(1, Ordering::Relaxed);
            original
        }
        SolveResult::Error(_) | SolveResult::NoSolver => {
            WARM_TIMEOUT_CONTINUATION_ERRORS.fetch_add(1, Ordering::Relaxed);
            original
        }
    }
}

pub(super) fn parse_direct_delta(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
        || value.is_some_and(|value| {
            value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
        })
}

pub(crate) fn last_direct_delta_synced() -> bool {
    LAST_DIRECT_DELTA_SYNCED.with(Cell::get)
}

pub(crate) fn reset_direct_delta_sync() {
    LAST_DIRECT_DELTA_SYNCED.with(|synced| synced.set(false));
}

pub(crate) fn warm_owner_transfer_enabled() -> bool {
    parse_warm_owner_transfer(std::env::var(WARM_OWNER_TRANSFER_ENV).ok().as_deref())
}

pub(super) fn parse_warm_owner_transfer(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    }
}

pub(crate) fn warm_serial_sibling_reuse_enabled() -> bool {
    warm_reuse_policy() == WarmReusePolicy::Adaptive
        && parse_warm_serial_sibling_reuse(
            std::env::var(WARM_SERIAL_SIBLING_REUSE_ENV).ok().as_deref(),
        )
}

pub(super) fn parse_warm_serial_sibling_reuse(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    }
}

pub(super) fn replay_sat_cache_policy() -> Option<ReplayCheckedSatCachePolicy> {
    *REPLAY_SAT_CACHE_POLICY.get_or_init(|| {
        parse_replay_sat_cache_policy(std::env::var(REPLAY_SAT_CACHE_ENV).ok().as_deref())
    })
}

pub(super) fn parse_replay_sat_cache_policy(
    value: Option<&str>,
) -> Option<ReplayCheckedSatCachePolicy> {
    let enabled = match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    };
    enabled.then(|| {
        ReplayCheckedSatCachePolicy::new(
            DEFAULT_REPLAY_SAT_CACHE_ENTRIES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS,
        )
    })
}

/// The model preference `GLAURUNG_AXEYUM_MODEL_PREFERENCE` selects, read once.
///
/// `None` when the variable is unset: the `SolverConfig` then keeps Axeyum's
/// own default, which is `ModelPreference::Any` unless the process carries
/// Axeyum's `AXEYUM_MODEL_PREFERENCE` lever (ADR-2140). When both are set the
/// Glaurung variable wins, because it is the one this adapter documents. A
/// set-but-malformed value panics naming the variable, as
/// `GLAURUNG_CONCRETIZATION_POLICY` does: a typo must not measure the shipped
/// arm and report it as the other.
pub(super) fn model_preference() -> Option<ModelPreference> {
    *MODEL_PREFERENCE.get_or_init(|| {
        parse_model_preference(std::env::var(MODEL_PREFERENCE_ENV).ok().as_deref())
            .unwrap_or_else(|error| panic!("{error}"))
    })
}

/// `any` | `zero` | `least-unsigned` (Axeyum's own spellings, so
/// `prefer-zero` is accepted too; case-insensitive, whitespace trimmed).
/// `None` for an unset variable; `Err` names the variable and the value.
pub(super) fn parse_model_preference(
    value: Option<&str>,
) -> Result<Option<ModelPreference>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    ModelPreference::parse(&value.trim().to_ascii_lowercase())
        .map(Some)
        .ok_or_else(|| {
            format!(
                "{MODEL_PREFERENCE_ENV}={value:?} is not one of `any`, `zero`, `least-unsigned`; \
                 refusing to run the default arm under a lever that was set"
            )
        })
}

/// The canonical-constraint-cache setting `GLAURUNG_AXEYUM_CANONICAL_CACHE`
/// selects, read once (improvement-list item 5, Axeyum ADR-2144).
///
/// `None` when the variable is unset: the `SolverConfig` then keeps Axeyum's
/// own default, `DEFAULT_CANONICAL_CACHE` (off) unless the process carries
/// Axeyum's `AXEYUM_CANONICAL_CACHE` lever. When both are set the Glaurung
/// variable wins. A set-but-malformed value panics naming the variable, as the
/// model preference does.
pub(super) fn canonical_cache() -> Option<bool> {
    *CANONICAL_CACHE.get_or_init(|| {
        parse_canonical_cache(std::env::var(CANONICAL_CACHE_ENV).ok().as_deref())
            .unwrap_or_else(|error| panic!("{error}"))
    })
}

/// `on` | `off` (Axeyum's own two spellings; case-insensitive, whitespace
/// trimmed). `None` for an unset variable; `Err` names the variable and the
/// value.
pub(super) fn parse_canonical_cache(value: Option<&str>) -> Result<Option<bool>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "on" => Ok(Some(true)),
        "off" => Ok(Some(false)),
        _ => Err(format!(
            "{CANONICAL_CACHE_ENV}={value:?} is not `on` or `off`; \
             refusing to run the default arm under a lever that was set"
        )),
    }
}

pub(super) fn config() -> SolverConfig {
    config_with_work_budgets(solver_work_budgets())
}

pub(super) fn config_with_work_budgets(work_budgets: SolverWorkBudgets) -> SolverConfig {
    build_config(work_budgets, model_preference(), canonical_cache())
}

/// The `SolverConfig` every Axeyum session this adapter creates is built from:
/// the process check timeout, the AND-flattening lever, the progress-check
/// budget, and -- when the caller names them -- the model preference and the
/// canonical constraint cache. `None` leaves `SolverConfig::new()`'s value in
/// place (see [`model_preference`] and [`canonical_cache`]); the production
/// readers pass the cached levers, and the tests pass values so the settings
/// are checked without touching the process environment.
pub(super) fn build_config(
    work_budgets: SolverWorkBudgets,
    model_preference: Option<ModelPreference>,
    canonical_constraint_cache: Option<bool>,
) -> SolverConfig {
    let internal_and_flattening = std::env::var(INTERNAL_AND_FLATTENING_ENV)
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "on"));
    let config = SolverConfig::new()
        .with_timeout(check_timeout())
        .with_incremental_positive_and_flattening(internal_and_flattening);
    let config = match model_preference {
        Some(preference) => config.with_model_preference(preference),
        None => config,
    };
    let config = match canonical_constraint_cache {
        Some(enabled) => config.with_canonical_constraint_cache(enabled),
        None => config,
    };
    match work_budgets.axeyum_progress_checks {
        Some(limit) => config.with_resource_limit(limit),
        None => config,
    }
}
