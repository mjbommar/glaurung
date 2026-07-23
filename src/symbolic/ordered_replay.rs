//! Exact native replay of a published ordered symbolic trace.
//!
//! This is deliberately narrower than the public SMT-LIB replay route. It
//! reconstructs Glaurung's typed expression DAGs, source-prefix identity, and
//! serial owner leases, then submits every recorded occurrence through the
//! production `solve_for_path_delta` adapter in observation order.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::symbolic::expr::ExprPool;
use crate::symbolic::native_trace::NativeAssertionPack;
use crate::symbolic::solver::axeyum_backend::{
    adaptive_lineage_reuse_stats, close_warm_path, replay_sat_cache_stats,
    serial_sibling_reuse_stats, share_serial_warm_owner_with_children, warm_path_reuse_stats,
    warm_reuse_stats, warm_timeout_cold_retry_stats, warm_timeout_continuation_stats,
};
use crate::symbolic::solver::constraint_cache::{
    process_cache_stats, reset_process_cache, CacheHitKind, EngineCacheLimits, EngineCachePolicy,
    EngineCacheStats, ENGINE_CONSTRAINT_CACHE_ENV,
};
use crate::symbolic::solver::{
    last_engine_cache_check, last_solve_timing, pipe, solve_for_path_delta, Assert,
    AxeyumExecutionClass, SolveResult, WarmAssertionPrefix,
};

const TRACE_SCHEMA: &str = "glaurung-ordered-trace-v1";
const NATIVE_REPLAY_SCHEMA: &str = "glaurung-native-ordered-replay-v1";
const TOPOLOGY: &str = "source-owner-serial-lease-v1";
const AXEYUM_SOURCE_REPO_ENV: &str = "GLAURUNG_AXEYUM_SOURCE_REPO";
const FACTORIAL_MODE_ENV: &str = "GLAURUNG_ENGINE_CACHE_FACTORIAL_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactorialMode {
    ColdOff,
    WarmOff,
    ColdExact,
    WarmExact,
    ColdStructural,
    WarmStructural,
}

impl FactorialMode {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            Some("cold-off") => Ok(Self::ColdOff),
            Some("warm-off") => Ok(Self::WarmOff),
            Some("cold-exact") => Ok(Self::ColdExact),
            Some("warm-exact") => Ok(Self::WarmExact),
            Some("cold-structural") => Ok(Self::ColdStructural),
            Some("warm-structural") => Ok(Self::WarmStructural),
            Some(other) => Err(format!("unsupported {FACTORIAL_MODE_ENV} value {other:?}")),
            None => Err(format!("native replay requires {FACTORIAL_MODE_ENV}")),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ColdOff => "cold-off",
            Self::WarmOff => "warm-off",
            Self::ColdExact => "cold-exact",
            Self::WarmExact => "warm-exact",
            Self::ColdStructural => "cold-structural",
            Self::WarmStructural => "warm-structural",
        }
    }

    const fn warm(self) -> bool {
        matches!(self, Self::WarmOff | Self::WarmExact | Self::WarmStructural)
    }

    const fn cache_policy(self) -> EngineCachePolicy {
        match self {
            Self::ColdOff | Self::WarmOff => EngineCachePolicy::Off,
            Self::ColdExact | Self::WarmExact => EngineCachePolicy::Exact,
            Self::ColdStructural | Self::WarmStructural => EngineCachePolicy::Structural,
        }
    }
}

fn replay_owner_share(mode: FactorialMode, owner: u64, children: u64) {
    if mode.warm() {
        share_serial_warm_owner_with_children(owner, children);
    }
}

fn replay_owner_release(mode: FactorialMode, owner: u64) {
    if mode.warm() {
        close_warm_path(owner);
    }
}

#[derive(Clone)]
struct Scope {
    id: String,
    constraint: String,
    assertion: Assert,
}

#[derive(Clone, Default)]
struct ReplayPath {
    scopes: Vec<Scope>,
    prefixes: Vec<WarmAssertionPrefix>,
}

impl ReplayPath {
    fn root() -> Self {
        Self {
            scopes: Vec::new(),
            prefixes: vec![WarmAssertionPrefix::default()],
        }
    }

    fn push(&mut self, scope: Scope) {
        let mut prefix = self
            .prefixes
            .last()
            .cloned()
            .expect("replay path always retains its empty prefix");
        prefix.push();
        self.scopes.push(scope);
        self.prefixes.push(prefix);
    }

    fn pop(&mut self) -> Result<(), String> {
        self.scopes
            .pop()
            .ok_or_else(|| "native replay scope underflow".to_string())?;
        self.prefixes
            .pop()
            .ok_or_else(|| "native replay prefix underflow".to_string())?;
        Ok(())
    }
}

#[derive(Default)]
struct OutcomeCounts {
    recorded_sat: u64,
    recorded_unsat: u64,
    recorded_unknown: u64,
    recorded_error: u64,
    actual_sat: u64,
    actual_unsat: u64,
    actual_unknown: u64,
    recovered_decisions: u64,
    lost_decisions: u64,
    opposite_decisions: u64,
    synchronized: u64,
    fallback: u64,
    synchronization_mismatches: u64,
    cache_hit_unsynchronized: u64,
    backend_miss_synchronized: u64,
    backend_miss_fallback: u64,
    catch_up_misses: u64,
    catch_up_assertions: u64,
    catch_up_rebuilds: u64,
    closed_lagged_owners: u64,
}

/// Replay one validated trace and atomically write its exact-work report.
///
/// The two supplied hashes bind this solver-only replay to the independently
/// captured finding output and the public SMT-LIB/model-read replay artifact.
pub fn replay_to_report(
    trace_dir: &Path,
    finding_sha256: &str,
    offline_replay_sha256: &str,
    output: &Path,
) -> Result<(), String> {
    validate_hex_hash("finding", finding_sha256)?;
    validate_hex_hash("offline replay", offline_replay_sha256)?;
    let mode = validate_runtime_configuration()?;
    let configured_cache = reset_process_cache()?;
    if configured_cache != mode.cache_policy() {
        return Err(format!(
            "factorial mode {} requires cache {}, got {}",
            mode.as_str(),
            mode.cache_policy().as_str(),
            configured_cache.as_str()
        ));
    }
    let initial_engine_cache = process_cache_stats()?;
    if initial_engine_cache.entries != 0
        || initial_engine_cache.assertion_refs != 0
        || initial_engine_cache.model_values != 0
    {
        return Err("engine cache did not start empty".into());
    }

    let manifest_path = trace_dir.join("trace-manifest-v1.json");
    let events_path = trace_dir.join("events-v1.ndjson");
    let index_path = trace_dir.join("query-index-v1.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    require_eq(&manifest["schema"], TRACE_SCHEMA, "trace schema")?;
    require_eq(
        &manifest["native_replay"]["schema"],
        NATIVE_REPLAY_SCHEMA,
        "native replay schema",
    )?;
    require_eq(
        &manifest["native_replay"]["topology"],
        TOPOLOGY,
        "native replay topology",
    )?;
    if manifest["source"]["dirty"] != false {
        return Err("native replay requires a trace captured from a clean Glaurung tree".into());
    }
    let trace_revision = string(&manifest["source"]["revision"], "source revision")?;
    let replay_revision = git_revision()?;
    if trace_revision != replay_revision && !git_is_ancestor(&trace_revision, &replay_revision)? {
        return Err(format!(
            "trace Glaurung revision {trace_revision} is not the replay revision {replay_revision} or its ancestor"
        ));
    }
    let axeyum_repo = std::env::var(AXEYUM_SOURCE_REPO_ENV)
        .map(PathBuf::from)
        .map_err(|_| format!("native replay requires {AXEYUM_SOURCE_REPO_ENV}"))?;
    let axeyum_source = git_source_identity(&axeyum_repo)?;
    if axeyum_source["tracked_dirty"] != false {
        return Err("native replay requires a tracked-clean Axeyum source tree".into());
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve native replay executable: {error}"))?;
    let executable_sha256 =
        sha256(fs::read(&executable).map_err(|error| {
            format!("read replay executable {}: {error}", executable.display())
        })?);

    let events_bytes = fs::read(&events_path)
        .map_err(|error| format!("read {}: {error}", events_path.display()))?;
    let events_sha256 = sha256(&events_bytes);
    if events_sha256 != string(&manifest["events_sha256"], "events hash")? {
        return Err("ordered event stream hash differs from its manifest".into());
    }
    let index_bytes =
        fs::read(&index_path).map_err(|error| format!("read {}: {error}", index_path.display()))?;
    let index_sha256 = sha256(&index_bytes);
    if index_sha256 != string(&manifest["query_index_sha256"], "query-index hash")? {
        return Err("ordered query index hash differs from its manifest".into());
    }

    let started = Instant::now();
    let mut pool = ExprPool::new();
    let mut native_assertions = BTreeMap::<String, Assert>::new();
    let mut paths = BTreeMap::<String, ReplayPath>::new();
    let mut counts = OutcomeCounts::default();
    let mut event_count = 0_u64;
    let mut check_count = 0_u64;
    let mut owner_shares = 0_u64;
    let mut owner_releases = 0_u64;
    let mut recorded_z3_nanos = 0_u64;
    let mut actual_axeyum_nanos = 0_u64;
    let mut check_rows = Vec::new();
    let mut lagged_owners = BTreeSet::new();

    for (line_index, line) in BufReader::new(events_bytes.as_slice()).lines().enumerate() {
        let line_number = line_index + 1;
        let line = line.map_err(|error| format!("read event line {line_number}: {error}"))?;
        let event: Value = serde_json::from_str(&line)
            .map_err(|error| format!("parse event line {line_number}: {error}"))?;
        let sequence = integer(&event["event_seq"], "event sequence")?;
        if sequence != event_count {
            return Err(format!(
                "non-contiguous event sequence at line {line_number}: {sequence} != {event_count}"
            ));
        }
        event_count = event_count.saturating_add(1);
        let kind = string(&event["event"], "event kind")?;
        let path_id = string(&event["path_id"], "path ID")?;
        match kind.as_str() {
            "analysis_start" | "analysis_end" | "push" | "model_read" | "model_choice" => {}
            "path_start" => {
                let path = match event.get("parent_path_id").filter(|value| !value.is_null()) {
                    Some(parent) => paths
                        .get(&string(parent, "parent path ID")?)
                        .cloned()
                        .ok_or_else(|| format!("path {path_id} has an unknown parent"))?,
                    None => ReplayPath::root(),
                };
                if paths.insert(path_id.clone(), path).is_some() {
                    return Err(format!("duplicate replay path {path_id}"));
                }
            }
            "assert" => {
                let constraint = string(&event["constraint_id"], "constraint ID")?;
                let native_hash =
                    string(&event["native_assertion_sha256"], "native assertion hash")?;
                let assertion = if let Some(assertion) =
                    native_assertions.get(&native_hash).copied()
                {
                    assertion
                } else {
                    let relative =
                        string(&event["native_assertion_path"], "native assertion path")?;
                    if relative != format!("native-assertions/{native_hash}.json") {
                        return Err(format!("non-canonical native assertion path {relative}"));
                    }
                    let native_path = trace_dir.join(relative);
                    let bytes = fs::read(&native_path)
                        .map_err(|error| format!("read {}: {error}", native_path.display()))?;
                    if sha256(&bytes) != native_hash {
                        return Err(format!("native assertion hash mismatch for {constraint}"));
                    }
                    let pack = NativeAssertionPack::from_bytes(&bytes)?;
                    let assertion = pack.import_into(&mut pool)?;
                    let rendered = pipe::assertion_line(&pool, assertion);
                    if sha256(rendered.as_bytes()) != constraint {
                        return Err(format!(
                            "native assertion {constraint} does not render to its public SMT identity"
                        ));
                    }
                    native_assertions.insert(native_hash, assertion);
                    assertion
                };
                let scope = Scope {
                    id: string(&event["scope_id"], "scope ID")?,
                    constraint,
                    assertion,
                };
                paths
                    .get_mut(&path_id)
                    .ok_or_else(|| format!("assert references unknown path {path_id}"))?
                    .push(scope);
            }
            "pop" => paths
                .get_mut(&path_id)
                .ok_or_else(|| format!("pop references unknown path {path_id}"))?
                .pop()?,
            "check" => {
                let path = paths
                    .get(&path_id)
                    .ok_or_else(|| format!("check references unknown path {path_id}"))?;
                let complete = path
                    .scopes
                    .iter()
                    .map(|scope| scope.assertion)
                    .collect::<Vec<_>>();
                let (script, _) = pipe::build_script(&pool, &complete);
                let query_hash = string(&event["query_sha256"], "query hash")?;
                if sha256(script.as_bytes()) != query_hash {
                    return Err(format!(
                        "native query reconstruction mismatch for {query_hash}"
                    ));
                }
                let warm = event
                    .get("warm_replay")
                    .filter(|value| value.is_object())
                    .ok_or_else(|| format!("check {query_hash} omits warm replay metadata"))?;
                let owner = integer(&warm["owner_id"], "owner ID")?;
                let retain = usize_value(
                    &warm["requested_retain_assertions"],
                    "requested retain assertions",
                )?;
                let persistent =
                    usize_value(&warm["persistent_assertions"], "persistent assertions")?;
                let expected_synced = boolean(&warm["synchronized"], "synchronized")?;
                let prefix = path.prefixes.get(persistent).ok_or_else(|| {
                    format!(
                        "persistent prefix {persistent} exceeds {} scopes for {query_hash}",
                        path.scopes.len()
                    )
                })?;
                if scope_digest(&path.scopes[..persistent])
                    != string(&warm["source_prefix_digest"], "source-prefix digest")?
                {
                    return Err(format!("source-prefix digest mismatch for {query_hash}"));
                }
                recorded_z3_nanos = recorded_z3_nanos
                    .saturating_add(event["z3_nanos"].as_u64().unwrap_or_default());
                let warm_before = warm_reuse_stats();
                let (actual, synced) =
                    solve_for_path_delta(&pool, &complete, owner, retain, persistent, prefix);
                let solve_timing = last_solve_timing();
                let engine_cache = last_engine_cache_check();
                let warm_after = warm_reuse_stats();
                actual_axeyum_nanos = actual_axeyum_nanos
                    .saturating_add(solve_timing.axeyum_nanos.unwrap_or_default());
                classify(
                    string(&event["outcome"], "recorded outcome")?.as_str(),
                    &actual,
                    &mut counts,
                )?;
                if engine_cache.policy != mode.cache_policy() {
                    return Err(format!(
                        "check {query_hash} used cache policy {}, expected {}",
                        engine_cache.policy.as_str(),
                        mode.cache_policy().as_str()
                    ));
                }
                let stage_sum = engine_cache
                    .lookup_nanos
                    .saturating_add(engine_cache.model_replay_nanos)
                    .saturating_add(engine_cache.index_update_nanos)
                    .saturating_add(engine_cache.eviction_nanos)
                    .saturating_add(engine_cache.backend_miss_nanos);
                if stage_sum > engine_cache.wrapper_nanos {
                    return Err(format!(
                        "check {query_hash} cache stages exceed wrapper: {stage_sum} > {}",
                        engine_cache.wrapper_nanos
                    ));
                }
                let cache_hit = engine_cache.hit_kind.is_some();
                if cache_hit {
                    if engine_cache.backend_called
                        || engine_cache.backend_miss_nanos != 0
                        || synced
                        || engine_cache.warm_synchronized
                    {
                        return Err(format!(
                            "check {query_hash} cache hit advanced or timed the backend"
                        ));
                    }
                    counts.cache_hit_unsynchronized =
                        counts.cache_hit_unsynchronized.saturating_add(1);
                    if mode.warm() {
                        lagged_owners.insert(owner);
                    }
                } else {
                    if !engine_cache.backend_called {
                        return Err(format!("check {query_hash} miss skipped the backend"));
                    }
                    if synced {
                        counts.backend_miss_synchronized =
                            counts.backend_miss_synchronized.saturating_add(1);
                    } else {
                        counts.backend_miss_fallback =
                            counts.backend_miss_fallback.saturating_add(1);
                    }
                    if mode.warm() && lagged_owners.contains(&owner) {
                        counts.catch_up_misses = counts.catch_up_misses.saturating_add(1);
                        counts.catch_up_assertions = counts.catch_up_assertions.saturating_add(
                            warm_after
                                .assertions_added
                                .saturating_sub(warm_before.assertions_added),
                        );
                        if solve_timing.axeyum_execution.is_some_and(rebuild_execution) {
                            counts.catch_up_rebuilds = counts.catch_up_rebuilds.saturating_add(1);
                        }
                        if synced {
                            lagged_owners.remove(&owner);
                        }
                    }
                }
                if synced {
                    counts.synchronized = counts.synchronized.saturating_add(1);
                } else {
                    counts.fallback = counts.fallback.saturating_add(1);
                }
                let mode_expected_synced = mode.warm() && !cache_hit && expected_synced;
                if synced != mode_expected_synced {
                    counts.synchronization_mismatches =
                        counts.synchronization_mismatches.saturating_add(1);
                }
                check_rows.push(json!({
                    "index": check_count,
                    "query_sha256": query_hash,
                    "recorded_outcome": string(&event["outcome"], "recorded outcome")?,
                    "assertion_count": complete.len(),
                    "owner_id": owner,
                    "cache_class": engine_cache.hit_kind.map(CacheHitKind::as_str).unwrap_or("miss"),
                    "backend_called": engine_cache.backend_called,
                    "warm_synchronized": synced,
                    "axeyum_execution": solve_timing.axeyum_execution.map(AxeyumExecutionClass::as_str),
                    "lookup_nanos": engine_cache.lookup_nanos,
                    "model_replay_nanos": engine_cache.model_replay_nanos,
                    "index_update_nanos": engine_cache.index_update_nanos,
                    "eviction_nanos": engine_cache.eviction_nanos,
                    "backend_miss_nanos": engine_cache.backend_miss_nanos,
                    "wrapper_nanos": engine_cache.wrapper_nanos,
                    "stage_slack_nanos": engine_cache.wrapper_nanos.saturating_sub(stage_sum),
                    "warm_assertions_added": warm_after.assertions_added.saturating_sub(warm_before.assertions_added),
                    "warm_assertions_popped": warm_after.assertions_popped.saturating_sub(warm_before.assertions_popped),
                    "warm_resets_after_error": warm_after.resets_after_error.saturating_sub(warm_before.resets_after_error),
                }));
                check_count = check_count.saturating_add(1);
            }
            "warm_owner_share" => {
                let owner = integer(&event["owner_id"], "owner ID")?;
                let children = integer(&event["children"], "owner children")?;
                replay_owner_share(mode, owner, children);
                owner_shares = owner_shares.saturating_add(1);
            }
            "warm_owner_release" => {
                let owner = integer(&event["owner_id"], "owner ID")?;
                replay_owner_release(mode, owner);
                if lagged_owners.remove(&owner) {
                    counts.closed_lagged_owners = counts.closed_lagged_owners.saturating_add(1);
                }
                owner_releases = owner_releases.saturating_add(1);
            }
            "path_end" => {
                paths
                    .remove(&path_id)
                    .ok_or_else(|| format!("end references unknown path {path_id}"))?;
            }
            other => return Err(format!("unsupported ordered replay event {other}")),
        }
    }

    if !paths.is_empty() {
        return Err(format!(
            "native replay retained {} logical paths",
            paths.len()
        ));
    }
    let expected_events = integer(&manifest["event_count"], "manifest event count")?;
    let expected_checks = integer(
        &manifest["native_replay"]["warm_check_count"],
        "manifest warm-check count",
    )?;
    if event_count != expected_events || check_count != expected_checks {
        return Err(format!(
            "replay count mismatch: events {event_count}/{expected_events}, checks {check_count}/{expected_checks}"
        ));
    }
    if owner_shares
        != integer(
            &manifest["native_replay"]["warm_owner_share_count"],
            "manifest owner-share count",
        )?
        || owner_releases
            != integer(
                &manifest["native_replay"]["warm_owner_release_count"],
                "manifest owner-release count",
            )?
    {
        return Err("native replay owner-lifecycle counts differ from the manifest".into());
    }

    let warm = warm_reuse_stats();
    let ownership = warm_path_reuse_stats();
    let serial = serial_sibling_reuse_stats();
    let adaptive = adaptive_lineage_reuse_stats();
    let continuation = warm_timeout_continuation_stats();
    let cold_retry = warm_timeout_cold_retry_stats();
    let cache = replay_sat_cache_stats();
    let engine_cache = process_cache_stats()?;
    validate_engine_cache_stats(mode, engine_cache, check_count)?;
    if counts.opposite_decisions != 0
        || counts.actual_unknown != 0
        || counts.recovered_decisions != 0
        || counts.lost_decisions != 0
        || counts.synchronization_mismatches != 0
        || warm.resets_after_error != 0
        || ownership.live_paths != 0
        || serial.tracked_owners != 0
        || serial.references != 0
        || cache.cache.replay_failures != 0
        || !lagged_owners.is_empty()
    {
        return Err(format!(
            "native replay gate failed: opposite={}, actual_unknown={}, recovered={}, lost={}, sync_mismatch={}, resets={}, live_paths={}, owners={}, references={}, cache_replay_failures={}, lagged_owners={}",
            counts.opposite_decisions,
            counts.actual_unknown,
            counts.recovered_decisions,
            counts.lost_decisions,
            counts.synchronization_mismatches,
            warm.resets_after_error,
            ownership.live_paths,
            serial.tracked_owners,
            serial.references,
            cache.cache.replay_failures,
            lagged_owners.len(),
        ));
    }

    let report = json!({
        "schema": "glaurung-native-ordered-replay-report-v2",
        "trace": {
            "path": trace_dir.display().to_string(),
            "manifest_sha256": sha256(&manifest_bytes),
            "events_sha256": events_sha256,
            "query_index_sha256": index_sha256,
            "glaurung_revision": trace_revision,
            "event_count": event_count,
            "check_count": check_count,
            "native_assertion_count": native_assertions.len(),
        },
        "bindings": {
            "finding_sha256": finding_sha256,
            "offline_replay_sha256": offline_replay_sha256,
        },
        "implementation": {
            "replay_executable": executable.display().to_string(),
            "replay_executable_sha256": executable_sha256,
            "glaurung_replay_revision": replay_revision,
            "axeyum_source": axeyum_source,
        },
        "configuration": runtime_configuration(mode),
        "outcomes": {
            "recorded_sat": counts.recorded_sat,
            "recorded_unsat": counts.recorded_unsat,
            "recorded_unknown": counts.recorded_unknown,
            "recorded_error": counts.recorded_error,
            "actual_sat": counts.actual_sat,
            "actual_unsat": counts.actual_unsat,
            "actual_unknown": counts.actual_unknown,
            "recovered_decisions": counts.recovered_decisions,
            "lost_decisions": counts.lost_decisions,
            "opposite_decisions": counts.opposite_decisions,
        },
        "timing": {
            "wall_nanos": u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            "recorded_z3_nanos": recorded_z3_nanos,
            "actual_axeyum_nanos": actual_axeyum_nanos,
            "peak_rss_kib": peak_rss_kib()?,
        },
        "exact_work": {
            "owner_share_events": owner_shares,
            "owner_release_events": owner_releases,
            "synchronized_checks": counts.synchronized,
            "unsynchronized_checks": counts.fallback,
            "synchronization_mismatches": counts.synchronization_mismatches,
            "warm_checks": warm.checks,
            "exact_reuses": warm.exact_snapshot_reuses,
            "prefix_assertions_reused": warm.prefix_assertions_reused,
            "assertions_added": warm.assertions_added,
            "assertions_popped": warm.assertions_popped,
            "resets_after_error": warm.resets_after_error,
            "cache_hit_unsynchronized_returns": counts.cache_hit_unsynchronized,
            "backend_miss_synchronized": counts.backend_miss_synchronized,
            "backend_miss_fallback": counts.backend_miss_fallback,
            "catch_up_misses": counts.catch_up_misses,
            "catch_up_assertions": counts.catch_up_assertions,
            "catch_up_rebuilds": counts.catch_up_rebuilds,
            "closed_lagged_owners": counts.closed_lagged_owners,
        },
        "ownership": {
            "paths_created": ownership.paths_created,
            "paths_closed": ownership.paths_closed,
            "live_paths": ownership.live_paths,
            "peak_live_paths": ownership.peak_live_paths,
            "path_limit_fallbacks": ownership.path_limit_fallbacks,
            "assertion_limit_fallbacks": ownership.assertion_limit_fallbacks,
            "adaptive_pressure_events": adaptive.pressure_events,
            "adaptive_expansions": adaptive.expansions,
            "serial_share_events": serial.share_events,
            "serial_tracked_owners": serial.tracked_owners,
            "serial_references": serial.references,
            "serial_peak_references": serial.peak_references,
        },
        "timeout_continuation": {
            "continuations": continuation.continuations,
            "recoveries": continuation.recoveries,
            "unknowns": continuation.unknowns,
            "errors": continuation.errors,
            "cold_retries": cold_retry.retries,
        },
        "replay_sat_cache": {
            "enabled": cache.enabled,
            "hits": cache.cache.hits,
            "misses": cache.cache.misses,
            "insertions": cache.cache.insertions,
            "evictions": cache.cache.evictions,
            "replay_failures": cache.cache.replay_failures,
            "entries": cache.cache.entries,
            "model_values": cache.cache.model_values,
            "model_bits": cache.cache.model_bits,
        },
        "engine_constraint_cache": {
            "policy": mode.cache_policy().as_str(),
            "lookups": engine_cache.lookups,
            "exact_sat_hits": engine_cache.exact_sat_hits,
            "exact_unsat_hits": engine_cache.exact_unsat_hits,
            "sat_superset_hits": engine_cache.sat_superset_hits,
            "unsat_subset_hits": engine_cache.unsat_subset_hits,
            "misses": engine_cache.misses,
            "sat_replay_attempts": engine_cache.sat_replay_attempts,
            "sat_replay_successes": engine_cache.sat_replay_successes,
            "sat_replay_failures": engine_cache.sat_replay_failures,
            "sat_replay_missing_symbols": engine_cache.sat_replay_missing_symbols,
            "insertions": engine_cache.insertions,
            "evictions": engine_cache.evictions,
            "oversize_bypasses": engine_cache.oversize_bypasses,
            "conflicts": engine_cache.conflicts,
            "entries": engine_cache.entries,
            "assertion_refs": engine_cache.assertion_refs,
            "model_values": engine_cache.model_values,
            "peak_entries": engine_cache.peak_entries,
            "peak_assertion_refs": engine_cache.peak_assertion_refs,
            "peak_model_values": engine_cache.peak_model_values,
            "lookup_nanos": engine_cache.lookup_nanos,
            "model_replay_nanos": engine_cache.model_replay_nanos,
            "index_update_nanos": engine_cache.index_update_nanos,
            "eviction_nanos": engine_cache.eviction_nanos,
        },
        "checks": check_rows,
        "gate": "pass",
    });
    write_json_atomically(output, &report)
}

fn classify(
    recorded: &str,
    actual: &SolveResult,
    counts: &mut OutcomeCounts,
) -> Result<(), String> {
    match recorded {
        "sat" => counts.recorded_sat = counts.recorded_sat.saturating_add(1),
        "unsat" => counts.recorded_unsat = counts.recorded_unsat.saturating_add(1),
        "unknown" => counts.recorded_unknown = counts.recorded_unknown.saturating_add(1),
        "error" => counts.recorded_error = counts.recorded_error.saturating_add(1),
        other => return Err(format!("unsupported recorded outcome {other}")),
    }
    let actual_name = match actual {
        SolveResult::Sat(_) => {
            counts.actual_sat = counts.actual_sat.saturating_add(1);
            "sat"
        }
        SolveResult::Unsat => {
            counts.actual_unsat = counts.actual_unsat.saturating_add(1);
            "unsat"
        }
        SolveResult::Unknown(_) => {
            counts.actual_unknown = counts.actual_unknown.saturating_add(1);
            "unknown"
        }
        SolveResult::NoSolver => return Err("native replay reached no-solver".into()),
        SolveResult::Error(error) => return Err(format!("native replay solver error: {error}")),
    };
    if matches!((recorded, actual_name), ("sat", "unsat") | ("unsat", "sat")) {
        counts.opposite_decisions = counts.opposite_decisions.saturating_add(1);
    } else if matches!(recorded, "unknown" | "error") && matches!(actual_name, "sat" | "unsat") {
        counts.recovered_decisions = counts.recovered_decisions.saturating_add(1);
    } else if matches!(recorded, "sat" | "unsat") && actual_name == "unknown" {
        counts.lost_decisions = counts.lost_decisions.saturating_add(1);
    }
    Ok(())
}

fn rebuild_execution(execution: AxeyumExecutionClass) -> bool {
    matches!(
        execution,
        AxeyumExecutionClass::WarmCreated
            | AxeyumExecutionClass::FallbackMissingPath
            | AxeyumExecutionClass::FallbackAutoProbe
            | AxeyumExecutionClass::FallbackPathCap
            | AxeyumExecutionClass::FallbackAssertionCap
            | AxeyumExecutionClass::InvalidDirectDelta
    )
}

fn validate_engine_cache_stats(
    mode: FactorialMode,
    stats: EngineCacheStats,
    checks: u64,
) -> Result<(), String> {
    let hits = stats
        .exact_sat_hits
        .saturating_add(stats.exact_unsat_hits)
        .saturating_add(stats.sat_superset_hits)
        .saturating_add(stats.unsat_subset_hits);
    if mode.cache_policy() == EngineCachePolicy::Off {
        if stats != EngineCacheStats::default() {
            return Err("cache-off mode accumulated engine-cache state or work".into());
        }
        return Ok(());
    }
    if stats.lookups != checks || hits.saturating_add(stats.misses) != checks {
        return Err(format!(
            "engine-cache classification mismatch: lookups={}, hits={}, misses={}, checks={checks}",
            stats.lookups, hits, stats.misses
        ));
    }
    if stats.sat_replay_attempts
        != stats
            .sat_replay_successes
            .saturating_add(stats.sat_replay_failures)
        || stats.sat_replay_successes
            != stats.exact_sat_hits.saturating_add(stats.sat_superset_hits)
    {
        return Err("engine-cache SAT replay accounting differs".into());
    }
    if stats.sat_replay_failures != 0
        || stats.sat_replay_missing_symbols != 0
        || stats.conflicts != 0
    {
        return Err(format!(
            "engine-cache soundness gate failed: replay_failures={}, missing_symbols={}, conflicts={}",
            stats.sat_replay_failures, stats.sat_replay_missing_symbols, stats.conflicts
        ));
    }
    if mode.cache_policy() == EngineCachePolicy::Exact
        && (stats.sat_superset_hits != 0 || stats.unsat_subset_hits != 0)
    {
        return Err("exact cache reported structural implication hits".into());
    }
    let limits = EngineCacheLimits::PREREGISTERED;
    if stats.entries > limits.max_entries as u64
        || stats.assertion_refs > limits.max_assertion_refs as u64
        || stats.model_values > limits.max_model_values as u64
        || stats.peak_entries > limits.max_entries as u64
        || stats.peak_assertion_refs > limits.max_assertion_refs as u64
        || stats.peak_model_values > limits.max_model_values as u64
        || stats.entries > stats.peak_entries
        || stats.assertion_refs > stats.peak_assertion_refs
        || stats.model_values > stats.peak_model_values
    {
        return Err("engine-cache current or peak gauge exceeds its registered bounds".into());
    }
    Ok(())
}

fn peak_rss_kib() -> Result<u64, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read /proc/self/status: {error}"))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or_else(|| "/proc/self/status omits VmHWM".to_string())?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields[0] != "VmHWM:" || fields[2] != "kB" {
        return Err(format!("unexpected VmHWM format: {line}"));
    }
    fields[1]
        .parse::<u64>()
        .map_err(|error| format!("parse VmHWM value: {error}"))
}

fn validate_runtime_configuration() -> Result<FactorialMode, String> {
    #[cfg(feature = "solver-z3")]
    return Err(
        "ordered native replay must be built without solver-z3 so solve_for_path_delta selects Axeyum"
            .into(),
    );

    #[cfg(not(feature = "solver-z3"))]
    {
        let mode = FactorialMode::parse(std::env::var(FACTORIAL_MODE_ENV).ok().as_deref())?;
        let warm_policy = if mode.warm() { "adaptive" } else { "off" };
        let required = [
            ("GLAURUNG_AXEYUM_WARM_REUSE", warm_policy),
            ("GLAURUNG_AXEYUM_DIRECT_DELTA", "1"),
            ("GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE", "1"),
            ("GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER", "0"),
            ("GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY", "0"),
            ("GLAURUNG_AXEYUM_REPLAY_SAT_CACHE", "1"),
            (ENGINE_CONSTRAINT_CACHE_ENV, mode.cache_policy().as_str()),
        ];
        for (name, expected) in required {
            let actual = std::env::var(name).unwrap_or_default();
            if actual != expected {
                return Err(format!(
                    "native replay mode {} requires {name}={expected}, got {actual:?}",
                    mode.as_str()
                ));
            }
        }
        Ok(mode)
    }
}

fn runtime_configuration(mode: FactorialMode) -> Value {
    let names = [
        FACTORIAL_MODE_ENV,
        ENGINE_CONSTRAINT_CACHE_ENV,
        "GLAURUNG_AXEYUM_WARM_REUSE",
        "GLAURUNG_AXEYUM_DIRECT_DELTA",
        "GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE",
        "GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER",
        "GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY",
        "GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE",
        "GLAURUNG_AXEYUM_REPLAY_SAT_CACHE",
        "GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS",
        "GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH",
        AXEYUM_SOURCE_REPO_ENV,
    ];
    let mut configuration = names
        .into_iter()
        .map(|name| {
            (
                name.to_string(),
                Value::String(std::env::var(name).unwrap_or_default()),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    configuration.insert("factorial_mode".into(), json!(mode.as_str()));
    configuration.insert(
        "engine_cache_limits".into(),
        json!({
            "max_entries": EngineCacheLimits::PREREGISTERED.max_entries,
            "max_assertion_refs": EngineCacheLimits::PREREGISTERED.max_assertion_refs,
            "max_model_values": EngineCacheLimits::PREREGISTERED.max_model_values,
            "max_model_values_per_entry": EngineCacheLimits::PREREGISTERED.max_model_values_per_entry,
        }),
    );
    Value::Object(configuration)
}

fn scope_digest(scopes: &[Scope]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"glaurung-scope-digest-v1\0");
    for scope in scopes {
        for value in [&scope.id, &scope.constraint] {
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn git_revision() -> Result<String, String> {
    git_output(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &["rev-parse", "HEAD"],
    )
}

fn git_is_ancestor(ancestor: &str, descendant: &str) -> Result<bool, String> {
    let status = Command::new("git")
        .arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()
        .map_err(|error| format!("run git merge-base: {error}"))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        other => Err(format!("git merge-base failed with status {other:?}")),
    }
}

fn git_source_identity(repo: &Path) -> Result<Value, String> {
    let revision = git_output(repo, &["rev-parse", "HEAD"])?;
    let tracked_status = git_output(repo, &["status", "--porcelain=v1", "--untracked-files=no"])?;
    Ok(json!({
        "repository": repo.display().to_string(),
        "revision": revision,
        "tracked_dirty": !tracked_status.is_empty(),
        "tracked_status_sha256": sha256(tracked_status.as_bytes()),
    }))
}

fn git_output(repo: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .output()
        .map_err(|error| format!("run git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn write_json_atomically(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create report directory {}: {error}", parent.display()))?;
    }
    let temporary = temporary_path(path);
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize native replay report: {error}"))?;
    bytes.push(b'\n');
    let mut file = File::create(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| {
        format!(
            "publish native replay report {} as {}: {error}",
            temporary.display(),
            path.display()
        )
    })
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "native-replay".into(), |name| name.to_os_string());
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

fn validate_hex_hash(name: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{name} hash is not 64 hexadecimal digits"))
    }
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn require_eq(value: &Value, expected: &str, name: &str) -> Result<(), String> {
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(format!("invalid {name}: {value}"))
    }
}

fn string(value: &Value, name: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{name} is not a string"))
}

fn integer(value: &Value, name: &str) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| format!("{name} is not a non-negative integer"))
}

fn usize_value(value: &Value, name: &str) -> Result<usize, String> {
    usize::try_from(integer(value, name)?).map_err(|_| format!("{name} exceeds usize"))
}

fn boolean(value: &Value, name: &str) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("{name} is not a Boolean"))
}

#[cfg(test)]
mod tests {
    use super::{
        peak_rss_kib, replay_owner_release, replay_owner_share, validate_engine_cache_stats,
        EngineCachePolicy, EngineCacheStats, FactorialMode,
    };
    use crate::symbolic::solver::axeyum_backend::serial_sibling_reuse_stats;

    #[test]
    fn factorial_modes_are_exact_and_map_to_one_warm_and_cache_policy() {
        let cases = [
            ("cold-off", false, EngineCachePolicy::Off),
            ("warm-off", true, EngineCachePolicy::Off),
            ("cold-exact", false, EngineCachePolicy::Exact),
            ("warm-exact", true, EngineCachePolicy::Exact),
            ("cold-structural", false, EngineCachePolicy::Structural),
            ("warm-structural", true, EngineCachePolicy::Structural),
        ];
        for (name, warm, cache) in cases {
            let mode = FactorialMode::parse(Some(name)).expect("registered mode");
            assert_eq!(mode.as_str(), name);
            assert_eq!(mode.warm(), warm);
            assert_eq!(mode.cache_policy(), cache);
        }
        for invalid in [None, Some(""), Some("warm"), Some("cold-implication")] {
            assert!(FactorialMode::parse(invalid).is_err());
        }
    }

    #[test]
    fn cold_modes_do_not_mutate_warm_owner_leases() {
        let before = serial_sibling_reuse_stats();
        replay_owner_share(FactorialMode::ColdOff, 0x303, 7);
        replay_owner_release(FactorialMode::ColdOff, 0x303);
        assert_eq!(serial_sibling_reuse_stats(), before);
    }

    #[test]
    fn cache_stat_gate_requires_complete_sound_classification() {
        assert!(validate_engine_cache_stats(
            FactorialMode::ColdOff,
            EngineCacheStats::default(),
            3,
        )
        .is_ok());
        let exact = EngineCacheStats {
            lookups: 3,
            exact_sat_hits: 1,
            exact_unsat_hits: 1,
            misses: 1,
            sat_replay_attempts: 1,
            sat_replay_successes: 1,
            entries: 1,
            assertion_refs: 1,
            model_values: 1,
            peak_entries: 1,
            peak_assertion_refs: 1,
            peak_model_values: 1,
            ..EngineCacheStats::default()
        };
        assert!(validate_engine_cache_stats(FactorialMode::ColdExact, exact, 3).is_ok());

        let mut replay_failure = exact;
        replay_failure.exact_sat_hits = 0;
        replay_failure.misses = 2;
        replay_failure.sat_replay_successes = 0;
        replay_failure.sat_replay_failures = 1;
        assert!(validate_engine_cache_stats(FactorialMode::ColdExact, replay_failure, 3).is_err());

        let mut structural_in_exact = exact;
        structural_in_exact.exact_unsat_hits = 0;
        structural_in_exact.unsat_subset_hits = 1;
        assert!(
            validate_engine_cache_stats(FactorialMode::ColdExact, structural_in_exact, 3).is_err()
        );
    }

    #[test]
    fn linux_peak_rss_source_is_present_and_nonzero() {
        assert!(peak_rss_kib().expect("VmHWM must parse") > 0);
    }
}
