//! Ordered, lineage-aware symbolic-solver trace capture.
//!
//! The ordinary query dump is intentionally content-deduplicated.  That makes
//! it useful for cold benchmarking, but destroys the path, scope, occurrence,
//! and model-choice facts needed to validate warm incremental solving.  This
//! module supplies the separate, opt-in producer described by Axeyum's
//! `glaurung-ordered-trace-v1.md` contract.
//!
//! Capture is disabled unless [`begin_from_env`] observes
//! `GLAURUNG_ORDERED_TRACE_DIR`.  A producer writes a unique temporary
//! directory and publishes it with one atomic rename only after every path is
//! terminal and all content-addressed query verdicts are conflict-free.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::symbolic::expr::{ExprId, ExprPool};
use crate::symbolic::solver::{pipe, Assert, SolveResult, SolveTiming};

const VERSION: u64 = 1;
const WORKER_ID: &str = "worker-0";
const ANALYSIS_PATH_ID: &str = "analysis";

thread_local! {
    static RECORDER: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

/// RAII owner for one process-local trace.  Call [`Self::finish`] to validate
/// and atomically publish it.  Dropping an unfinished guard leaves no published
/// trace.
#[must_use = "an ordered trace is published only by calling finish"]
pub struct OrderedTraceGuard {
    active: bool,
}

impl OrderedTraceGuard {
    /// Validate and atomically publish this process's trace directory.
    pub fn finish(mut self, terminal_status: &str) -> Result<PathBuf, String> {
        let recorder = RECORDER.with(|slot| slot.borrow_mut().take());
        self.active = false;
        let recorder =
            recorder.ok_or_else(|| "ordered trace recorder is not active".to_string())?;
        recorder.finish(terminal_status)
    }
}

impl Drop for OrderedTraceGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(mut recorder) = RECORDER.with(|slot| slot.borrow_mut().take()) {
            let _ = recorder.events.flush();
            // A temporary directory is intentionally not a published artifact.
            let _ = fs::remove_dir_all(&recorder.temp_dir);
        }
    }
}

/// Start an ordered trace when `GLAURUNG_ORDERED_TRACE_DIR` is set.
///
/// The caller supplies the exact driver bytes so the manifest binds the trace
/// to its analysis input.  Configuration or publication failures are errors,
/// rather than silently falling back to an incomplete artifact.
pub fn begin_from_env(
    driver_path: impl AsRef<Path>,
    driver_bytes: &[u8],
) -> Result<Option<OrderedTraceGuard>, String> {
    let Some(root) = std::env::var_os("GLAURUNG_ORDERED_TRACE_DIR") else {
        return Ok(None);
    };
    begin(Path::new(&root), driver_path.as_ref(), driver_bytes).map(Some)
}

fn begin(
    root: &Path,
    driver_path: &Path,
    driver_bytes: &[u8],
) -> Result<OrderedTraceGuard, String> {
    let already_active = RECORDER.with(|slot| slot.borrow().is_some());
    if already_active {
        return Err("an ordered trace recorder is already active on this thread".into());
    }

    fs::create_dir_all(root)
        .map_err(|e| format!("create ordered trace root {}: {e}", root.display()))?;
    let process_id = format!("process-{}", std::process::id());
    let nonce = Uuid::new_v4().simple().to_string();
    let stem = format!("glaurung-ordered-trace-{}-{nonce}", std::process::id());
    let temp_dir = root.join(format!(".{stem}.tmp"));
    let final_dir = root.join(stem);
    fs::create_dir(&temp_dir)
        .map_err(|e| format!("create temporary trace {}: {e}", temp_dir.display()))?;
    fs::create_dir(temp_dir.join("queries"))
        .map_err(|e| format!("create trace query store: {e}"))?;
    fs::create_dir(temp_dir.join("assertions"))
        .map_err(|e| format!("create trace assertion store: {e}"))?;
    let events_path = temp_dir.join("events-v1.ndjson");
    let events = BufWriter::new(
        File::create(&events_path).map_err(|e| format!("create {}: {e}", events_path.display()))?,
    );

    let driver_hash = sha256(driver_bytes);
    let analysis_id = format!("analysis-{}-{nonce}", &driver_hash[..16]);
    let mut recorder = Recorder {
        temp_dir,
        final_dir,
        events,
        events_hasher: Sha256::new(),
        analysis_id,
        process_id,
        start_instant: Instant::now(),
        start_utc: Utc::now(),
        driver_path: driver_path.to_path_buf(),
        driver_hash,
        event_seq: 0,
        next_path: 0,
        next_scope: 0,
        next_check: 0,
        next_model_read: 0,
        next_model_choice: 0,
        path_seq: BTreeMap::new(),
        started_paths: BTreeSet::new(),
        ended_paths: BTreeSet::new(),
        query_index: BTreeMap::new(),
        assertion_ids: BTreeSet::new(),
        error: None,
    };
    recorder.emit(
        ANALYSIS_PATH_ID,
        None,
        "analysis_start",
        json!({
            "driver_path": driver_path.display().to_string(),
            "driver_sha256": recorder.driver_hash,
        }),
    );
    if let Some(error) = recorder.error.clone() {
        let _ = fs::remove_dir_all(&recorder.temp_dir);
        return Err(error);
    }
    RECORDER.with(|slot| *slot.borrow_mut() = Some(recorder));
    Ok(OrderedTraceGuard { active: true })
}

/// Trace-only state attached to one explorer path.  It is absent when capture
/// is disabled and contains no solver state.
#[derive(Clone, Debug)]
pub(crate) struct TracePath {
    path_id: String,
    scopes: Vec<ScopeRef>,
    last_sat_check: Option<String>,
}

#[derive(Clone, Debug)]
struct ScopeRef {
    scope_id: String,
    constraint_id: String,
}

impl TracePath {
    /// Start a root path when a recorder is active.
    pub(crate) fn root(location: u64) -> Option<Self> {
        RECORDER.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .map(|recorder| recorder.start_path(None, "root", Vec::new(), location))
        })
    }

    /// Start a child path with this path's exact inherited scope stack.
    pub(crate) fn fork(&self, location: u64) -> Self {
        RECORDER.with(|slot| {
            let mut slot = slot.borrow_mut();
            let recorder = slot
                .as_mut()
                .expect("TracePath cannot exist without an active recorder");
            recorder.start_path(
                Some(&self.path_id),
                "symbolic-branch",
                self.scopes.clone(),
                location,
            )
        })
    }

    /// Add a persistent assertion scope to this path.
    pub(crate) fn push_assert(
        &mut self,
        pool: &ExprPool,
        assertion: Assert,
        role: &str,
        location: u64,
    ) {
        RECORDER.with(|slot| {
            if let Some(recorder) = slot.borrow_mut().as_mut() {
                recorder.push_assert(self, pool, assertion, role, location);
            }
        });
    }

    /// Add a temporary assertion scope used by a read-only/probe check.
    pub(crate) fn push_temporary(
        &mut self,
        pool: &ExprPool,
        assertion: Assert,
        role: &str,
        location: u64,
    ) {
        self.push_assert(pool, assertion, role, location);
    }

    /// Pop the most recent temporary scope.
    pub(crate) fn pop(&mut self, location: u64) {
        RECORDER.with(|slot| {
            if let Some(recorder) = slot.borrow_mut().as_mut() {
                recorder.pop(self, location);
            }
        });
    }

    /// Record one exact solver check and return its stable check ID.
    pub(crate) fn check(
        &mut self,
        pool: &ExprPool,
        assertions: &[Assert],
        result: &SolveResult,
        purpose: &str,
        timing: SolveTiming,
        location: u64,
    ) -> Option<String> {
        RECORDER.with(|slot| {
            slot.borrow_mut().as_mut().map(|recorder| {
                recorder.check(self, pool, assertions, result, purpose, timing, location)
            })
        })
    }

    /// Record the evaluated expression and the exploration choice it drove.
    pub(crate) fn model_choice(
        &mut self,
        pool: &ExprPool,
        expression: ExprId,
        value: u128,
        affected_exploration: bool,
        policy: &str,
        location: u64,
    ) {
        RECORDER.with(|slot| {
            if let Some(recorder) = slot.borrow_mut().as_mut() {
                recorder.model_choice(
                    self,
                    pool,
                    expression,
                    value,
                    affected_exploration,
                    policy,
                    location,
                );
            }
        });
    }

    /// End this logical path exactly once.
    pub(crate) fn end(&mut self, reason: &str, location: u64) {
        RECORDER.with(|slot| {
            if let Some(recorder) = slot.borrow_mut().as_mut() {
                recorder.end_path(self, reason, location);
            }
        });
    }
}

#[derive(Debug, Serialize)]
struct QueryIndexEntry {
    content_hash: String,
    path: String,
    outcomes: BTreeSet<String>,
    occurrences: Vec<QueryOccurrence>,
}

#[derive(Debug, Serialize)]
struct QueryOccurrence {
    check_id: String,
    path_id: String,
    event_seq: u64,
}

struct Recorder {
    temp_dir: PathBuf,
    final_dir: PathBuf,
    events: BufWriter<File>,
    events_hasher: Sha256,
    analysis_id: String,
    process_id: String,
    start_instant: Instant,
    start_utc: DateTime<Utc>,
    driver_path: PathBuf,
    driver_hash: String,
    event_seq: u64,
    next_path: u64,
    next_scope: u64,
    next_check: u64,
    next_model_read: u64,
    next_model_choice: u64,
    path_seq: BTreeMap<String, u64>,
    started_paths: BTreeSet<String>,
    ended_paths: BTreeSet<String>,
    query_index: BTreeMap<String, QueryIndexEntry>,
    assertion_ids: BTreeSet<String>,
    error: Option<String>,
}

impl Recorder {
    fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }

    fn start_path(
        &mut self,
        parent_path_id: Option<&str>,
        reason: &str,
        scopes: Vec<ScopeRef>,
        location: u64,
    ) -> TracePath {
        let path_id = format!("path-{}", self.next_path);
        self.next_path += 1;
        if let Some(parent) = parent_path_id {
            if !self.started_paths.contains(parent) || self.ended_paths.contains(parent) {
                self.fail(format!(
                    "path {path_id} references inactive parent {parent}"
                ));
            }
        }
        self.started_paths.insert(path_id.clone());
        self.path_seq.insert(path_id.clone(), 0);
        let digest = scope_digest(&scopes);
        self.emit(
            &path_id,
            Some(location),
            "path_start",
            json!({
                "parent_path_id": parent_path_id,
                "fork_reason": reason,
                "inherited_scope_depth": scopes.len(),
                "scope_digest": digest,
            }),
        );
        TracePath {
            path_id,
            scopes,
            last_sat_check: None,
        }
    }

    fn push_assert(
        &mut self,
        path: &mut TracePath,
        pool: &ExprPool,
        assertion: Assert,
        role: &str,
        location: u64,
    ) {
        if self.ended_paths.contains(&path.path_id) {
            self.fail(format!("push on ended path {}", path.path_id));
            return;
        }
        let prior_depth = path.scopes.len();
        let scope_id = format!("scope-{}", self.next_scope);
        self.next_scope += 1;
        let assertion_bytes = assertion_line(pool, assertion);
        let constraint_id = sha256(assertion_bytes.as_bytes());
        let mut symbols = BTreeMap::new();
        pool.collect_syms(assertion.0, &mut symbols);
        let assertion_symbols = symbols
            .into_iter()
            .map(|(id, symbol_width)| {
                json!({
                    "name": ExprPool::sym_name(id, symbol_width),
                    "width": symbol_width.bits(),
                })
            })
            .collect::<Vec<_>>();
        if self.assertion_ids.insert(constraint_id.clone()) {
            let assertion_path = self
                .temp_dir
                .join("assertions")
                .join(format!("{constraint_id}.smt2"));
            if let Err(error) = fs::write(&assertion_path, assertion_bytes.as_bytes()) {
                self.fail(format!(
                    "write assertion {}: {error}",
                    assertion_path.display()
                ));
            }
        }
        self.emit(
            &path.path_id,
            Some(location),
            "push",
            json!({
                "scope_id": scope_id,
                "prior_depth": prior_depth,
                "resulting_depth": prior_depth + 1,
            }),
        );
        path.scopes.push(ScopeRef {
            scope_id: scope_id.clone(),
            constraint_id: constraint_id.clone(),
        });
        let sort_valid = pool.width_of(assertion.0).bits() == 1;
        if !sort_valid {
            self.fail(format!(
                "assertion {} on {} has width {}, expected 1",
                constraint_id,
                path.path_id,
                pool.width_of(assertion.0).bits()
            ));
        }
        self.emit(
            &path.path_id,
            Some(location),
            "assert",
            json!({
                "scope_id": scope_id,
                "constraint_id": constraint_id,
                "assertion_sha256": sha256(assertion_bytes.as_bytes()),
                "assertion_path": format!("assertions/{constraint_id}.smt2"),
                "assertion_symbols": assertion_symbols,
                "sort_validated": sort_valid,
                "semantic_role": role,
                "scope_digest": scope_digest(&path.scopes),
            }),
        );
    }

    fn pop(&mut self, path: &mut TracePath, location: u64) {
        let prior_depth = path.scopes.len();
        let Some(scope) = path.scopes.pop() else {
            self.fail(format!("scope underflow on {}", path.path_id));
            return;
        };
        self.emit(
            &path.path_id,
            Some(location),
            "pop",
            json!({
                "scope_id": scope.scope_id,
                "prior_depth": prior_depth,
                "resulting_depth": path.scopes.len(),
                "scope_digest": scope_digest(&path.scopes),
            }),
        );
        path.last_sat_check = None;
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        &mut self,
        path: &mut TracePath,
        pool: &ExprPool,
        assertions: &[Assert],
        result: &SolveResult,
        purpose: &str,
        timing: SolveTiming,
        location: u64,
    ) -> String {
        if path.scopes.len() != assertions.len() {
            self.fail(format!(
                "path {} scope/assertion mismatch: {} != {}",
                path.path_id,
                path.scopes.len(),
                assertions.len()
            ));
        }
        let (script, _) = pipe::build_script(pool, assertions);
        let content_hash = sha256(script.as_bytes());
        self.store_query(&content_hash, script.as_bytes());
        let check_id = format!("check-{}", self.next_check);
        self.next_check += 1;
        let (outcome, detail) = outcome(result);
        if let Some(entry) = self.query_index.get(&content_hash) {
            let decided_conflict = (outcome == "sat" && entry.outcomes.contains("unsat"))
                || (outcome == "unsat" && entry.outcomes.contains("sat"));
            if decided_conflict {
                self.fail(format!(
                    "conflicting decided outcomes for query {content_hash}: {:?} vs {outcome}",
                    entry.outcomes
                ));
            }
        }
        let event_seq = self.event_seq;
        let entry = self
            .query_index
            .entry(content_hash.clone())
            .or_insert_with(|| QueryIndexEntry {
                content_hash: content_hash.clone(),
                path: format!("queries/{content_hash}.smt2"),
                outcomes: BTreeSet::new(),
                occurrences: Vec::new(),
            });
        entry.outcomes.insert(outcome.to_string());
        entry.occurrences.push(QueryOccurrence {
            check_id: check_id.clone(),
            path_id: path.path_id.clone(),
            event_seq,
        });
        self.emit(
            &path.path_id,
            Some(location),
            "check",
            json!({
                "check_id": check_id,
                "purpose": purpose,
                "scope_depth": path.scopes.len(),
                "active_constraint_count": assertions.len(),
                "scope_digest": scope_digest(&path.scopes),
                "query_sha256": content_hash,
                "outcome": outcome,
                "outcome_detail": detail,
                "backend_nanos": timing.total_nanos,
                "z3_nanos": timing.z3_nanos,
                "axeyum_nanos": timing.axeyum_nanos,
                "resource_counters": {},
            }),
        );
        if outcome == "sat" {
            path.last_sat_check = Some(check_id.clone());
        } else {
            path.last_sat_check = None;
        }
        check_id
    }

    #[allow(clippy::too_many_arguments)]
    fn model_choice(
        &mut self,
        path: &mut TracePath,
        pool: &ExprPool,
        expression: ExprId,
        value: u128,
        affected_exploration: bool,
        policy: &str,
        location: u64,
    ) {
        let Some(check_id) = path.last_sat_check.clone() else {
            self.fail(format!(
                "model choice on {} did not immediately follow a SAT check",
                path.path_id
            ));
            return;
        };
        let rendered = pool.render_smtlib(expression);
        let width = pool.width_of(expression).bits();
        let expression_id = sha256(format!("{width}\0{rendered}").as_bytes());
        let mut symbols = BTreeMap::new();
        pool.collect_syms(expression, &mut symbols);
        let expression_symbols: Vec<Value> = symbols
            .into_iter()
            .map(|(id, symbol_width)| {
                json!({
                    "name": ExprPool::sym_name(id, symbol_width),
                    "width": symbol_width.bits(),
                })
            })
            .collect();
        let read_id = format!("model-read-{}", self.next_model_read);
        self.next_model_read += 1;
        self.emit(
            &path.path_id,
            Some(location),
            "model_read",
            json!({
                "model_read_id": read_id,
                "check_id": check_id,
                "expression_id": expression_id,
                "expression_smtlib": rendered,
                "expression_symbols": expression_symbols,
                "sort": format!("(_ BitVec {width})"),
                "width": width,
                "returned_value": format!("0x{value:x}"),
                "affected_exploration": affected_exploration,
            }),
        );
        let choice_id = format!("model-choice-{}", self.next_model_choice);
        self.next_model_choice += 1;
        self.emit(
            &path.path_id,
            Some(location),
            "model_choice",
            json!({
                "model_choice_id": choice_id,
                "check_id": check_id,
                "model_read_ids": [read_id],
                "chosen_values": [format!("0x{value:x}")],
                "policy_id": policy,
                "policy_version": 1,
                "downstream_path_ids": [path.path_id],
            }),
        );
        path.last_sat_check = None;
    }

    fn end_path(&mut self, path: &mut TracePath, reason: &str, location: u64) {
        if !self.started_paths.contains(&path.path_id) {
            self.fail(format!("end of unknown path {}", path.path_id));
            return;
        }
        if !self.ended_paths.insert(path.path_id.clone()) {
            self.fail(format!("duplicate end for path {}", path.path_id));
            return;
        }
        self.emit(
            &path.path_id,
            Some(location),
            "path_end",
            json!({
                "reason": reason,
                "terminal_scope_depth": path.scopes.len(),
                "scope_digest": scope_digest(&path.scopes),
            }),
        );
        path.last_sat_check = None;
    }

    fn store_query(&mut self, content_hash: &str, bytes: &[u8]) {
        let path = self
            .temp_dir
            .join("queries")
            .join(format!("{content_hash}.smt2"));
        if path.exists() {
            match fs::read(&path) {
                Ok(existing) if existing == bytes => {}
                Ok(_) => self.fail(format!("content collision at {}", path.display())),
                Err(e) => self.fail(format!("read existing query {}: {e}", path.display())),
            }
            return;
        }
        if let Err(e) = fs::write(&path, bytes) {
            self.fail(format!("write query {}: {e}", path.display()));
        }
    }

    fn emit(&mut self, path_id: &str, location: Option<u64>, event: &str, payload: Value) {
        if self.error.is_some() {
            return;
        }
        let path_seq = self.path_seq.entry(path_id.to_string()).or_insert(0);
        let mut object = Map::new();
        object.insert("version".into(), json!(VERSION));
        object.insert("event_seq".into(), json!(self.event_seq));
        object.insert("event".into(), json!(event));
        object.insert("analysis_id".into(), json!(self.analysis_id));
        object.insert("process_id".into(), json!(self.process_id));
        object.insert("process_seq".into(), json!(self.event_seq));
        object.insert("worker_id".into(), json!(WORKER_ID));
        object.insert("worker_seq".into(), json!(self.event_seq));
        object.insert("path_id".into(), json!(path_id));
        object.insert("path_seq".into(), json!(*path_seq));
        object.insert(
            "location".into(),
            location.map_or(Value::Null, |pc| json!(format!("va:0x{pc:x}"))),
        );
        object.insert(
            "monotonic_ns".into(),
            json!(u64::try_from(self.start_instant.elapsed().as_nanos()).unwrap_or(u64::MAX)),
        );
        if let Value::Object(payload) = payload {
            for (key, value) in payload {
                if object.insert(key.clone(), value).is_some() {
                    self.fail(format!("event payload overwrote envelope field {key}"));
                    return;
                }
            }
        } else {
            self.fail(format!("event {event} payload is not an object"));
            return;
        }
        let mut line = match serde_json::to_vec(&object) {
            Ok(line) => line,
            Err(e) => {
                self.fail(format!("serialize {event} event: {e}"));
                return;
            }
        };
        line.push(b'\n');
        if let Err(e) = self.events.write_all(&line) {
            self.fail(format!("write ordered trace event: {e}"));
            return;
        }
        self.events_hasher.update(&line);
        self.event_seq += 1;
        *path_seq += 1;
    }

    fn finish(mut self, terminal_status: &str) -> Result<PathBuf, String> {
        let open: Vec<_> = self
            .started_paths
            .difference(&self.ended_paths)
            .cloned()
            .collect();
        if !open.is_empty() {
            self.fail(format!("ordered trace has unterminated paths: {open:?}"));
        }
        self.emit(
            ANALYSIS_PATH_ID,
            None,
            "analysis_end",
            json!({
                "terminal_status": terminal_status,
                "paths_started": self.started_paths.len(),
                "queries": self.query_index.len(),
            }),
        );
        if let Some(error) = self.error.clone() {
            let failed = self.temp_dir.with_extension("failed");
            let _ = fs::rename(&self.temp_dir, &failed);
            return Err(format!(
                "{error}; unpublished trace retained at {}",
                failed.display()
            ));
        }

        self.events
            .flush()
            .map_err(|e| format!("flush ordered trace events: {e}"))?;
        self.events
            .get_ref()
            .sync_all()
            .map_err(|e| format!("sync ordered trace events: {e}"))?;
        let events_sha256 = hex::encode(self.events_hasher.finalize());

        let query_index_path = self.temp_dir.join("query-index-v1.json");
        let query_index = json!({
            "version": VERSION,
            "queries": self.query_index.values().collect::<Vec<_>>(),
        });
        let query_index_bytes = pretty_json_bytes(&query_index)?;
        fs::write(&query_index_path, &query_index_bytes)
            .map_err(|e| format!("write {}: {e}", query_index_path.display()))?;
        let query_index_sha256 = sha256(&query_index_bytes);

        let source = source_identity()?;
        let manifest = json!({
            "schema": "glaurung-ordered-trace-v1",
            "version": VERSION,
            "analysis_id": self.analysis_id,
            "process_id": self.process_id,
            "id_allocation": "single-process monotone decimal IDs; event order is observation order",
            "finalizer_merge_order": "single process; no merge performed",
            "terminal_scope_policy": "discard each terminal path's private scope stack",
            "source": source,
            "driver": {
                "path": self.driver_path.display().to_string(),
                "sha256": self.driver_hash,
            },
            "analysis_command": std::env::args().collect::<Vec<_>>(),
            "analysis_configuration": trace_configuration(),
            "solver_features": solver_features(),
            "trusted_oracle": trusted_oracle(),
            "toolchain": command_output("rustc", &["--version"]),
            "host_identity": host_identity(),
            "worker_count": 1,
            "start_time_utc": self.start_utc.to_rfc3339(),
            "end_time_utc": Utc::now().to_rfc3339(),
            "event_count": self.event_seq,
            "path_count": self.started_paths.len(),
            "query_count": self.query_index.len(),
            "assertion_count": self.assertion_ids.len(),
            "events_sha256": events_sha256,
            "query_index_sha256": query_index_sha256,
            "access_classification": "restricted-driver-analysis",
        });
        let manifest_path = self.temp_dir.join("trace-manifest-v1.json");
        fs::write(&manifest_path, pretty_json_bytes(&manifest)?)
            .map_err(|e| format!("write {}: {e}", manifest_path.display()))?;
        sync_dir(&self.temp_dir)?;
        fs::rename(&self.temp_dir, &self.final_dir).map_err(|e| {
            format!(
                "atomically publish {} as {}: {e}",
                self.temp_dir.display(),
                self.final_dir.display()
            )
        })?;
        if let Some(parent) = self.final_dir.parent() {
            sync_dir(parent)?;
        }
        Ok(self.final_dir)
    }
}

fn assertion_line(pool: &ExprPool, assertion: Assert) -> String {
    let bit = if assertion.1 {
        "(_ bv1 1)"
    } else {
        "(_ bv0 1)"
    };
    format!("(assert (= {} {}))\n", pool.render_smtlib(assertion.0), bit)
}

fn scope_digest(scopes: &[ScopeRef]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"glaurung-scope-digest-v1\0");
    for scope in scopes {
        hash_framed(&mut hasher, scope.scope_id.as_bytes());
        hash_framed(&mut hasher, scope.constraint_id.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn outcome(result: &SolveResult) -> (&'static str, Option<String>) {
    match result {
        SolveResult::Sat(_) => ("sat", None),
        SolveResult::Unsat => ("unsat", None),
        SolveResult::Unknown => ("unknown", Some("backend-unknown".into())),
        SolveResult::NoSolver => ("error", Some("no-solver-backend".into())),
        SolveResult::Error(message) => ("error", Some(message.clone())),
    }
}

fn pretty_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("serialize JSON: {e}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn source_identity() -> Result<Value, String> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let revision = git_output(repo, &["rev-parse", "HEAD"])?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid Glaurung revision from git: {revision:?}"));
    }
    let status = git_output(repo, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    Ok(json!({
        "repository": repo.display().to_string(),
        "revision": revision,
        "dirty": !status.is_empty(),
        "status_sha256": sha256(status.as_bytes()),
    }))
}

fn git_output(repo: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("run git {}: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".into())
}

fn host_identity() -> Value {
    json!({
        "hostname": command_output("hostname", &[]),
        "kernel": command_output("uname", &["-srmo"]),
        "architecture": std::env::consts::ARCH,
        "operating_system": std::env::consts::OS,
    })
}

fn trace_configuration() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(key, _)| key.starts_with("GLAURUNG_") || key.starts_with("IOCTLANCE_"))
        .collect()
}

fn solver_features() -> Vec<&'static str> {
    vec![
        "symbolic",
        #[cfg(feature = "solver-z3")]
        "solver-z3",
        #[cfg(feature = "solver-axeyum")]
        "solver-axeyum",
    ]
}

fn trusted_oracle() -> Value {
    #[cfg(feature = "solver-z3")]
    {
        json!({
            "backend": "z3",
            "crate": "z3 0.12.1",
            "runtime_version": std::env::var("GLAURUNG_TRACE_ORACLE_VERSION")
                .unwrap_or_else(|_| "linked-runtime-unreported".into()),
            "authoritative_in_shadow_mode": true,
        })
    }
    #[cfg(not(feature = "solver-z3"))]
    json!({
        "backend": "configured-non-z3",
        "version": "not-authoritative-for-publication",
        "authoritative_in_shadow_mode": false,
    })
}

fn sync_dir(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("sync directory {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CmpOp, Width};
    use crate::symbolic::expr::Expr;
    use crate::symbolic::solver::Model;

    fn shadow_timing(total_nanos: u64) -> SolveTiming {
        SolveTiming {
            total_nanos,
            z3_nanos: Some(total_nanos / 3),
            axeyum_nanos: Some(total_nanos / 2),
        }
    }

    #[test]
    fn publishes_lineage_scopes_repeated_checks_model_choice_and_unsat() {
        let output = tempfile::tempdir().expect("trace output");
        let guard =
            begin(output.path(), Path::new("fixture-driver.sys"), b"driver").expect("start trace");

        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = pool.intern(Expr::Const {
            value: 1,
            width: Width::W8,
        });
        let two = pool.intern(Expr::Const {
            value: 2,
            width: Width::W8,
        });
        let eq_one = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: one,
            width: Width::W8,
        });
        let eq_two = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: two,
            width: Width::W8,
        });

        let mut root = TracePath::root(0x1000).expect("root trace path");
        root.push_assert(&pool, (eq_one, true), "branch", 0x1001);
        let sat = SolveResult::Sat(Model::default());
        root.check(
            &pool,
            &[(eq_one, true)],
            &sat,
            "branch-feasibility",
            shadow_timing(11),
            0x1001,
        );
        root.model_choice(&pool, x, 1, true, "synthetic-model-choice-v1", 0x1001);
        // Exact repeated occurrence: same bytes and verdict, distinct event.
        root.check(
            &pool,
            &[(eq_one, true)],
            &sat,
            "repeated-check",
            shadow_timing(7),
            0x1002,
        );

        let mut child = root.fork(0x2000);
        root.end("forked", 0x1002);
        child.push_temporary(&pool, (eq_two, true), "other", 0x2001);
        child.check(
            &pool,
            &[(eq_one, true), (eq_two, true)],
            &SolveResult::Unsat,
            "value-witness",
            shadow_timing(13),
            0x2001,
        );
        child.pop(0x2001);
        child.end("unsat-prune", 0x2001);

        let published = guard.finish("completed").expect("publish trace");
        assert!(published.join("trace-manifest-v1.json").is_file());
        assert!(published.join("events-v1.ndjson").is_file());
        assert!(published.join("query-index-v1.json").is_file());
        assert_eq!(
            fs::read_dir(published.join("assertions"))
                .expect("read assertion store")
                .count(),
            2
        );

        let events =
            fs::read_to_string(published.join("events-v1.ndjson")).expect("read trace events");
        let rows: Vec<Value> = events
            .lines()
            .map(|line| serde_json::from_str(line).expect("event JSON"))
            .collect();
        for (seq, row) in rows.iter().enumerate() {
            assert_eq!(row["event_seq"], seq as u64);
            assert_eq!(row["process_seq"], seq as u64);
            assert_eq!(row["worker_seq"], seq as u64);
        }
        let kinds: Vec<&str> = rows
            .iter()
            .map(|row| row["event"].as_str().expect("event kind"))
            .collect();
        for required in [
            "analysis_start",
            "path_start",
            "push",
            "assert",
            "check",
            "model_read",
            "model_choice",
            "pop",
            "path_end",
            "analysis_end",
        ] {
            assert!(kinds.contains(&required), "missing {required}: {kinds:?}");
        }
        assert_eq!(kinds.iter().filter(|kind| **kind == "check").count(), 3);
        let checks = rows
            .iter()
            .filter(|row| row["event"] == "check")
            .collect::<Vec<_>>();
        assert!(checks.iter().all(|row| row["z3_nanos"].is_u64()));
        assert!(checks.iter().all(|row| row["axeyum_nanos"].is_u64()));
        let assertions = rows
            .iter()
            .filter(|row| row["event"] == "assert")
            .collect::<Vec<_>>();
        assert!(assertions.iter().all(|row| row["assertion_path"]
            .as_str()
            .is_some_and(|path| path.starts_with("assertions/"))));
        let index: Value = serde_json::from_slice(
            &fs::read(published.join("query-index-v1.json")).expect("read query index"),
        )
        .expect("query-index JSON");
        assert_eq!(index["queries"].as_array().expect("queries").len(), 2);
        assert!(index["queries"]
            .as_array()
            .expect("queries")
            .iter()
            .any(|query| query["occurrences"].as_array().expect("occurrences").len() == 2));

        let validator = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/axeyum-integration/capture/validate_ordered_trace.py");
        let status = Command::new("python3")
            .arg(validator)
            .arg(&published)
            .status()
            .expect("run ordered-trace validator");
        assert!(status.success(), "ordered-trace validator rejected fixture");
    }
}
