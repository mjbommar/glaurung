//! Exact native replay of a published ordered symbolic trace.
//!
//! This is deliberately narrower than the public SMT-LIB replay route. It
//! reconstructs Glaurung's typed expression DAGs, source-prefix identity, and
//! serial owner leases, then submits every recorded occurrence through the
//! production `solve_for_path_delta` adapter in observation order.

use std::collections::BTreeMap;
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
use crate::symbolic::solver::{
    last_solve_timing, pipe, solve_for_path_delta, Assert, SolveResult, WarmAssertionPrefix,
};

const TRACE_SCHEMA: &str = "glaurung-ordered-trace-v1";
const NATIVE_REPLAY_SCHEMA: &str = "glaurung-native-ordered-replay-v1";
const TOPOLOGY: &str = "source-owner-serial-lease-v1";

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
    validate_runtime_configuration()?;

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
    if trace_revision != replay_revision {
        return Err(format!(
            "trace/replay Glaurung revision mismatch: {trace_revision} != {replay_revision}"
        ));
    }

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
                let (actual, synced) =
                    solve_for_path_delta(&pool, &complete, owner, retain, persistent, prefix);
                actual_axeyum_nanos = actual_axeyum_nanos
                    .saturating_add(last_solve_timing().axeyum_nanos.unwrap_or_default());
                classify(
                    string(&event["outcome"], "recorded outcome")?.as_str(),
                    &actual,
                    &mut counts,
                )?;
                if synced {
                    counts.synchronized = counts.synchronized.saturating_add(1);
                } else {
                    counts.fallback = counts.fallback.saturating_add(1);
                }
                if synced != expected_synced {
                    counts.synchronization_mismatches =
                        counts.synchronization_mismatches.saturating_add(1);
                }
                check_count = check_count.saturating_add(1);
            }
            "warm_owner_share" => {
                let owner = integer(&event["owner_id"], "owner ID")?;
                let children = integer(&event["children"], "owner children")?;
                share_serial_warm_owner_with_children(owner, children);
                owner_shares = owner_shares.saturating_add(1);
            }
            "warm_owner_release" => {
                close_warm_path(integer(&event["owner_id"], "owner ID")?);
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
    if counts.opposite_decisions != 0
        || counts.synchronization_mismatches != 0
        || warm.resets_after_error != 0
        || ownership.live_paths != 0
        || serial.tracked_owners != 0
        || serial.references != 0
        || cache.cache.replay_failures != 0
    {
        return Err(format!(
            "native replay gate failed: opposite={}, sync_mismatch={}, resets={}, live_paths={}, owners={}, references={}, cache_replay_failures={}",
            counts.opposite_decisions,
            counts.synchronization_mismatches,
            warm.resets_after_error,
            ownership.live_paths,
            serial.tracked_owners,
            serial.references,
            cache.cache.replay_failures,
        ));
    }

    let report = json!({
        "schema": "glaurung-native-ordered-replay-report-v1",
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
        "configuration": runtime_configuration(),
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
        },
        "exact_work": {
            "owner_share_events": owner_shares,
            "owner_release_events": owner_releases,
            "synchronized_checks": counts.synchronized,
            "fallback_checks": counts.fallback,
            "synchronization_mismatches": counts.synchronization_mismatches,
            "warm_checks": warm.checks,
            "exact_reuses": warm.exact_snapshot_reuses,
            "prefix_assertions_reused": warm.prefix_assertions_reused,
            "assertions_added": warm.assertions_added,
            "assertions_popped": warm.assertions_popped,
            "resets_after_error": warm.resets_after_error,
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
        SolveResult::Unknown => {
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

fn validate_runtime_configuration() -> Result<(), String> {
    #[cfg(feature = "solver-z3")]
    return Err(
        "ordered native replay must be built without solver-z3 so solve_for_path_delta selects Axeyum"
            .into(),
    );

    #[cfg(not(feature = "solver-z3"))]
    let required = [
        ("GLAURUNG_AXEYUM_WARM_REUSE", "adaptive"),
        ("GLAURUNG_AXEYUM_DIRECT_DELTA", "1"),
        ("GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE", "1"),
        ("GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER", "0"),
        ("GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY", "0"),
        ("GLAURUNG_AXEYUM_REPLAY_SAT_CACHE", "1"),
    ];
    #[cfg(not(feature = "solver-z3"))]
    for (name, expected) in required {
        let actual = std::env::var(name).unwrap_or_default();
        if actual != expected {
            return Err(format!(
                "native replay requires {name}={expected}, got {actual:?}"
            ));
        }
    }
    #[cfg(not(feature = "solver-z3"))]
    Ok(())
}

fn runtime_configuration() -> Value {
    let names = [
        "GLAURUNG_AXEYUM_WARM_REUSE",
        "GLAURUNG_AXEYUM_DIRECT_DELTA",
        "GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE",
        "GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER",
        "GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY",
        "GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE",
        "GLAURUNG_AXEYUM_REPLAY_SAT_CACHE",
        "GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS",
        "GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH",
    ];
    Value::Object(
        names
            .into_iter()
            .map(|name| {
                (
                    name.to_string(),
                    Value::String(std::env::var(name).unwrap_or_default()),
                )
            })
            .collect(),
    )
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
    let output = Command::new("git")
        .arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("run git rev-parse: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse failed: {}",
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
