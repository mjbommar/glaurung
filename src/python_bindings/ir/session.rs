//! Python-facing reusable decompiler session and exact rendered-artifact cache.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use pyo3::prelude::*;

use super::{decompile_at_session, load_program_session};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RenderKey {
    func_va: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: String,
    max_functions: usize,
}

#[derive(Debug, Default)]
struct RenderCacheState {
    artifacts: HashMap<RenderKey, String>,
    least_recent: VecDeque<RenderKey>,
}

const MAX_RENDER_CACHE_ENTRIES: usize = 256;

#[derive(Debug, Default)]
struct RenderCache {
    state: Mutex<RenderCacheState>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl RenderCache {
    fn state(&self) -> MutexGuard<'_, RenderCacheState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn get(&self, key: &RenderKey) -> Option<String> {
        let mut state = self.state();
        let artifact = state.artifacts.get(key).cloned()?;
        state.least_recent.retain(|candidate| candidate != key);
        state.least_recent.push_back(key.clone());
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(artifact)
    }

    fn install(&self, key: RenderKey, artifact: String) -> String {
        let mut state = self.state();
        if let Some(existing) = state.artifacts.get(&key).cloned() {
            state.least_recent.retain(|candidate| candidate != &key);
            state.least_recent.push_back(key);
            self.hits.fetch_add(1, Ordering::Relaxed);
            return existing;
        }
        if state.artifacts.len() >= MAX_RENDER_CACHE_ENTRIES {
            if let Some(oldest) = state.least_recent.pop_front() {
                state.artifacts.remove(&oldest);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        state.artifacts.insert(key.clone(), artifact.clone());
        state.least_recent.push_back(key);
        self.misses.fetch_add(1, Ordering::Relaxed);
        artifact
    }

    fn clear(&self) {
        let mut state = self.state();
        state.artifacts.clear();
        state.least_recent.clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
    }

    fn stats(&self) -> HashMap<&'static str, u64> {
        let entries = self.state().artifacts.len();
        HashMap::from([
            ("entries", u64::try_from(entries).unwrap_or(u64::MAX)),
            ("evictions", self.evictions.load(Ordering::Relaxed)),
            ("hits", self.hits.load(Ordering::Relaxed)),
            ("misses", self.misses.load(Ordering::Relaxed)),
        ])
    }
}

/// Reusable decompiler state for repeated queries against one immutable image.
#[pyclass(name = "DecompilerSession", module = "glaurung._native.ir")]
pub(super) struct PyDecompilerSession {
    path: String,
    session: crate::program::session::ProgramSession,
    rendered: RenderCache,
}

#[pymethods]
impl PyDecompilerSession {
    #[new]
    fn new(path: String) -> PyResult<Self> {
        let session = load_program_session(&path)?;
        Ok(Self {
            path,
            session,
            rendered: RenderCache::default(),
        })
    }

    /// Exact path whose immutable bytes are owned by this session.
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    /// Session-local exact discovery-cache counters.
    #[getter]
    fn discovery_cache_stats(&self) -> HashMap<&'static str, u64> {
        let stats = self.session.discovery_cache_stats();
        HashMap::from([
            ("entries", u64::try_from(stats.entries).unwrap_or(u64::MAX)),
            ("evictions", stats.evictions),
            ("hits", stats.hits),
            ("misses", stats.misses),
        ])
    }

    /// Session-local exact rendered-artifact cache counters.
    #[getter]
    fn artifact_cache_stats(&self) -> HashMap<&'static str, u64> {
        self.rendered.stats()
    }

    /// Drop all reusable artifacts and reset session-local cache counters.
    fn clear_caches(&self) {
        self.session.clear_caches();
        self.rendered.clear();
    }

    /// Decompile one function through the same pipeline as module-level `decompile_at`.
    #[pyo3(signature = (func_va, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", pdb_cache="", max_functions=1usize))]
    #[allow(clippy::too_many_arguments)]
    fn decompile_at(
        &self,
        py: Python<'_>,
        func_va: u64,
        max_blocks: usize,
        max_instructions: usize,
        timeout_ms: u64,
        types: bool,
        style: &str,
        pdb_cache: &str,
        max_functions: usize,
    ) -> PyResult<String> {
        let key = RenderKey {
            func_va: self.session.image().normalize_function_entry(func_va),
            max_blocks,
            max_instructions,
            timeout_ms,
            types,
            style: style.to_string(),
            max_functions,
        };
        let cacheable = pdb_cache.is_empty() && diagnostics_are_disabled();
        if cacheable {
            if let Some(artifact) = self.rendered.get(&key) {
                return Ok(artifact);
            }
        }

        let artifact = decompile_at_session(
            py,
            &self.session,
            &self.path,
            key.func_va,
            max_blocks,
            max_instructions,
            timeout_ms,
            types,
            style,
            pdb_cache,
            max_functions,
        )?;
        if cacheable {
            return Ok(self.rendered.install(key, artifact));
        }
        Ok(artifact)
    }
}

fn diagnostics_are_disabled() -> bool {
    [
        "GLAURUNG_ACCOUNT_STRUCTURE",
        "GLAURUNG_DUMP_PASSES",
        "GLAURUNG_PASS_HEALTH",
        "GLAURUNG_PIPELINE_PROFILE",
        "GLAURUNG_VERIFY_DEFS",
    ]
    .into_iter()
    .all(|name| std::env::var_os(name).is_none())
}
