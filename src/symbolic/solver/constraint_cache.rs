//! Bounded result caching above the symbolic solver backend.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::exec::{Concrete, Domain};
use crate::ir::types::Width;
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{pipe, Assert, Model, SolveResult};

pub(crate) const ENGINE_CONSTRAINT_CACHE_ENV: &str = "GLAURUNG_ENGINE_CONSTRAINT_CACHE";

thread_local! {
    static PROCESS_CACHE: RefCell<Option<EngineConstraintCache>> = const { RefCell::new(None) };
}

/// Cache behavior selected for one isolated replay process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineCachePolicy {
    /// Bypass cache lookup and insertion.
    Off,
    /// Reuse only byte-identical conjunctions.
    Exact,
    /// Reuse exact results plus sound SAT-superset and UNSAT-subset implications.
    Structural,
}

impl EngineCachePolicy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Exact => "exact",
            Self::Structural => "structural",
        }
    }
}

pub(crate) fn parse_engine_cache_policy(value: Option<&str>) -> Result<EngineCachePolicy, String> {
    match value {
        None | Some("off") => Ok(EngineCachePolicy::Off),
        Some("exact") => Ok(EngineCachePolicy::Exact),
        Some("structural") => Ok(EngineCachePolicy::Structural),
        Some(other) => Err(format!(
            "{ENGINE_CONSTRAINT_CACHE_ENV} must be off, exact, or structural; got {other:?}"
        )),
    }
}

fn configured_policy() -> Result<EngineCachePolicy, String> {
    parse_engine_cache_policy(std::env::var(ENGINE_CONSTRAINT_CACHE_ENV).ok().as_deref())
}

pub(crate) fn reset_process_cache() -> Result<EngineCachePolicy, String> {
    let policy = configured_policy()?;
    PROCESS_CACHE.with(|slot| {
        *slot.borrow_mut() = Some(EngineConstraintCache::new(
            policy,
            EngineCacheLimits::PREREGISTERED,
        ));
    });
    Ok(policy)
}

#[cfg(test)]
pub(crate) fn reset_process_cache_for_test(policy: EngineCachePolicy, limits: EngineCacheLimits) {
    PROCESS_CACHE.with(|slot| {
        *slot.borrow_mut() = Some(EngineConstraintCache::new(policy, limits));
    });
}

pub(crate) fn process_cache_policy() -> Result<EngineCachePolicy, String> {
    with_process_cache(|cache| cache.policy)
}

pub(crate) fn process_cache_stats() -> Result<EngineCacheStats, String> {
    with_process_cache(|cache| cache.stats())
}

pub(crate) fn lookup_process_cache(
    pool: &ExprPool,
    asserts: &[Assert],
) -> Result<CacheLookup, String> {
    with_process_cache(|cache| cache.lookup(pool, asserts))?
}

pub(crate) fn insert_process_cache(
    pool: &ExprPool,
    asserts: &[Assert],
    result: &SolveResult,
) -> Result<(), String> {
    with_process_cache(|cache| cache.insert(pool, asserts, result))?;
    Ok(())
}

fn with_process_cache<T>(
    operation: impl FnOnce(&mut EngineConstraintCache) -> T,
) -> Result<T, String> {
    PROCESS_CACHE.with(|slot| {
        if slot.borrow().is_none() {
            let policy = configured_policy()?;
            *slot.borrow_mut() = Some(EngineConstraintCache::new(
                policy,
                EngineCacheLimits::PREREGISTERED,
            ));
        }
        let mut slot = slot.borrow_mut();
        let cache = slot
            .as_mut()
            .ok_or_else(|| "engine cache initialization failed".to_string())?;
        Ok(operation(cache))
    })
}

/// Simultaneous resource bounds for the engine cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EngineCacheLimits {
    pub(crate) max_entries: usize,
    pub(crate) max_assertion_refs: usize,
    pub(crate) max_model_values: usize,
    pub(crate) max_model_values_per_entry: usize,
}

impl EngineCacheLimits {
    /// The immutable ADR-0303 experiment limits.
    pub(crate) const PREREGISTERED: Self = Self {
        max_entries: 4_096,
        max_assertion_refs: 524_288,
        max_model_values: 262_144,
        max_model_values_per_entry: 256,
    };
}

/// Classification of one successful cache answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheHitKind {
    ExactSat,
    ExactUnsat,
    SatSuperset,
    UnsatSubset,
}

impl CacheHitKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ExactSat => "exact-sat",
            Self::ExactUnsat => "exact-unsat",
            Self::SatSuperset => "sat-superset",
            Self::UnsatSubset => "unsat-subset",
        }
    }

    pub(crate) const fn is_structural(self) -> bool {
        matches!(self, Self::SatSuperset | Self::UnsatSubset)
    }
}

/// Outcome of one cache lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CacheLookup {
    Hit {
        kind: CacheHitKind,
        result: SolveResult,
    },
    Miss,
}

/// Cumulative counters plus current/peak bounded-resource gauges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EngineCacheStats {
    pub(crate) lookups: u64,
    pub(crate) exact_sat_hits: u64,
    pub(crate) exact_unsat_hits: u64,
    pub(crate) sat_superset_hits: u64,
    pub(crate) unsat_subset_hits: u64,
    pub(crate) misses: u64,
    pub(crate) sat_replay_attempts: u64,
    pub(crate) sat_replay_successes: u64,
    pub(crate) sat_replay_failures: u64,
    pub(crate) sat_replay_missing_symbols: u64,
    pub(crate) insertions: u64,
    pub(crate) evictions: u64,
    pub(crate) oversize_bypasses: u64,
    pub(crate) conflicts: u64,
    pub(crate) lookup_nanos: u64,
    pub(crate) model_replay_nanos: u64,
    pub(crate) index_update_nanos: u64,
    pub(crate) eviction_nanos: u64,
    pub(crate) entries: u64,
    pub(crate) assertion_refs: u64,
    pub(crate) model_values: u64,
    pub(crate) peak_entries: u64,
    pub(crate) peak_assertion_refs: u64,
    pub(crate) peak_model_values: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AssertionKey([u8; 32]);

type QueryKey = Vec<AssertionKey>;

#[derive(Debug, Clone)]
enum CachedResult {
    Sat(Model),
    Unsat,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    query: QueryKey,
    result: CachedResult,
    last_used: u64,
}

#[derive(Debug, Default)]
struct UnsatTrieNode {
    terminals: BTreeSet<u64>,
    children: BTreeMap<AssertionKey, UnsatTrieNode>,
}

impl UnsatTrieNode {
    fn insert(&mut self, query: &[AssertionKey], entry_id: u64) {
        let mut node = self;
        for key in query {
            node = node.children.entry(*key).or_default();
        }
        node.terminals.insert(entry_id);
    }

    fn remove(&mut self, query: &[AssertionKey], entry_id: u64) {
        Self::remove_at(self, query, entry_id);
    }

    fn remove_at(node: &mut Self, query: &[AssertionKey], entry_id: u64) -> bool {
        if let Some((first, rest)) = query.split_first() {
            let remove_child = node
                .children
                .get_mut(first)
                .is_some_and(|child| Self::remove_at(child, rest, entry_id));
            if remove_child {
                node.children.remove(first);
            }
        } else {
            node.terminals.remove(&entry_id);
        }
        node.terminals.is_empty() && node.children.is_empty()
    }

    fn find_subset(&self, query: &[AssertionKey]) -> Option<u64> {
        fn search(node: &UnsatTrieNode, query: &[AssertionKey], start: usize) -> Option<u64> {
            let mut best = node.terminals.first().copied();
            for index in start..query.len() {
                if let Some(child) = node.children.get(&query[index]) {
                    if let Some(candidate) = search(child, query, index + 1) {
                        best = Some(best.map_or(candidate, |current| current.min(candidate)));
                    }
                }
            }
            best
        }

        search(self, query, 0)
    }
}

/// Deterministic, bounded cache for complete solver queries.
pub(crate) struct EngineConstraintCache {
    policy: EngineCachePolicy,
    limits: EngineCacheLimits,
    next_entry_id: u64,
    clock: u64,
    entries: BTreeMap<u64, CacheEntry>,
    exact: BTreeMap<QueryKey, u64>,
    sat_entries: BTreeSet<u64>,
    sat_postings: BTreeMap<AssertionKey, BTreeSet<u64>>,
    unsat_trie: UnsatTrieNode,
    stats: EngineCacheStats,
}

impl EngineConstraintCache {
    pub(crate) fn new(policy: EngineCachePolicy, limits: EngineCacheLimits) -> Self {
        Self {
            policy,
            limits,
            next_entry_id: 0,
            clock: 0,
            entries: BTreeMap::new(),
            exact: BTreeMap::new(),
            sat_entries: BTreeSet::new(),
            sat_postings: BTreeMap::new(),
            unsat_trie: UnsatTrieNode::default(),
            stats: EngineCacheStats::default(),
        }
    }

    pub(crate) fn stats(&self) -> EngineCacheStats {
        self.stats
    }

    pub(crate) fn lookup(
        &mut self,
        pool: &ExprPool,
        asserts: &[Assert],
    ) -> Result<CacheLookup, String> {
        let started = Instant::now();
        let replay_before = self.stats.model_replay_nanos;
        let result = self.lookup_inner(pool, asserts);
        let elapsed = nanos(started);
        let replay_elapsed = self.stats.model_replay_nanos.saturating_sub(replay_before);
        self.stats.lookup_nanos = self
            .stats
            .lookup_nanos
            .saturating_add(elapsed.saturating_sub(replay_elapsed));
        result
    }

    fn lookup_inner(&mut self, pool: &ExprPool, asserts: &[Assert]) -> Result<CacheLookup, String> {
        self.stats.lookups = self.stats.lookups.saturating_add(1);
        if self.policy == EngineCachePolicy::Off {
            return Ok(self.record_miss());
        }

        let query = query_key(pool, asserts);
        if let Some(entry_id) = self.exact.get(&query).copied() {
            return self.answer_from_entry(pool, asserts, entry_id, true);
        }
        if self.policy == EngineCachePolicy::Exact {
            return Ok(self.record_miss());
        }

        let unsat_entry = self.unsat_trie.find_subset(&query);
        let sat_entry = self.find_sat_superset(&query);
        match (unsat_entry, sat_entry) {
            (Some(_), Some(_)) => {
                self.stats.conflicts = self.stats.conflicts.saturating_add(1);
                Err("engine cache contains conflicting SAT and UNSAT implications".into())
            }
            (Some(entry_id), None) => self.answer_from_entry(pool, asserts, entry_id, false),
            (None, Some(entry_id)) => self.answer_from_entry(pool, asserts, entry_id, false),
            (None, None) => Ok(self.record_miss()),
        }
    }

    pub(crate) fn insert(&mut self, pool: &ExprPool, asserts: &[Assert], result: &SolveResult) {
        let started = Instant::now();
        let eviction_before = self.stats.eviction_nanos;
        self.insert_inner(pool, asserts, result);
        let elapsed = nanos(started);
        let eviction_elapsed = self.stats.eviction_nanos.saturating_sub(eviction_before);
        self.stats.index_update_nanos = self
            .stats
            .index_update_nanos
            .saturating_add(elapsed.saturating_sub(eviction_elapsed));
    }

    fn insert_inner(&mut self, pool: &ExprPool, asserts: &[Assert], result: &SolveResult) {
        if self.policy == EngineCachePolicy::Off {
            return;
        }
        let cached = match result {
            SolveResult::Sat(model) => CachedResult::Sat(model.clone()),
            SolveResult::Unsat => CachedResult::Unsat,
            SolveResult::Unknown(_) | SolveResult::NoSolver | SolveResult::Error(_) => return,
        };
        let query = query_key(pool, asserts);
        let model_values = match &cached {
            CachedResult::Sat(model) => model.values.len(),
            CachedResult::Unsat => 0,
        };
        if self.limits.max_entries == 0
            || query.len() > self.limits.max_assertion_refs
            || model_values > self.limits.max_model_values
            || model_values > self.limits.max_model_values_per_entry
        {
            self.stats.oversize_bypasses = self.stats.oversize_bypasses.saturating_add(1);
            return;
        }

        if let Some(existing) = self.exact.get(&query).copied() {
            self.remove_entry(existing, false);
        }
        while self.entries.len().saturating_add(1) > self.limits.max_entries
            || self
                .stats
                .assertion_refs
                .try_into()
                .unwrap_or(usize::MAX)
                .saturating_add(query.len())
                > self.limits.max_assertion_refs
            || usize::try_from(self.stats.model_values)
                .unwrap_or(usize::MAX)
                .saturating_add(model_values)
                > self.limits.max_model_values
        {
            let Some(victim) = self.lru_victim() else {
                self.stats.oversize_bypasses = self.stats.oversize_bypasses.saturating_add(1);
                return;
            };
            self.remove_entry(victim, true);
        }

        let entry_id = self.next_entry_id;
        self.next_entry_id = self.next_entry_id.saturating_add(1);
        let last_used = self.tick();
        let entry = CacheEntry {
            query: query.clone(),
            result: cached,
            last_used,
        };
        self.exact.insert(query.clone(), entry_id);
        match &entry.result {
            CachedResult::Sat(_) => {
                self.sat_entries.insert(entry_id);
                for key in &query {
                    self.sat_postings.entry(*key).or_default().insert(entry_id);
                }
            }
            CachedResult::Unsat => self.unsat_trie.insert(&query, entry_id),
        }
        self.entries.insert(entry_id, entry);
        self.stats.insertions = self.stats.insertions.saturating_add(1);
        self.stats.entries = self.stats.entries.saturating_add(1);
        self.stats.assertion_refs = self.stats.assertion_refs.saturating_add(query.len() as u64);
        self.stats.model_values = self.stats.model_values.saturating_add(model_values as u64);
        self.refresh_peak_gauges();
    }

    fn answer_from_entry(
        &mut self,
        pool: &ExprPool,
        asserts: &[Assert],
        entry_id: u64,
        exact: bool,
    ) -> Result<CacheLookup, String> {
        let cached = self
            .entries
            .get(&entry_id)
            .map(|entry| entry.result.clone())
            .ok_or_else(|| format!("engine cache index references missing entry {entry_id}"))?;
        let (kind, result) = match cached {
            CachedResult::Sat(model) => {
                if !self.replay_sat(pool, asserts, &model) {
                    return Ok(self.record_miss());
                }
                let kind = if exact {
                    self.stats.exact_sat_hits = self.stats.exact_sat_hits.saturating_add(1);
                    CacheHitKind::ExactSat
                } else {
                    self.stats.sat_superset_hits = self.stats.sat_superset_hits.saturating_add(1);
                    CacheHitKind::SatSuperset
                };
                (kind, SolveResult::Sat(model))
            }
            CachedResult::Unsat => {
                let kind = if exact {
                    self.stats.exact_unsat_hits = self.stats.exact_unsat_hits.saturating_add(1);
                    CacheHitKind::ExactUnsat
                } else {
                    self.stats.unsat_subset_hits = self.stats.unsat_subset_hits.saturating_add(1);
                    CacheHitKind::UnsatSubset
                };
                (kind, SolveResult::Unsat)
            }
        };
        let last_used = self.tick();
        if let Some(entry) = self.entries.get_mut(&entry_id) {
            entry.last_used = last_used;
        }
        Ok(CacheLookup::Hit { kind, result })
    }

    fn replay_sat(&mut self, pool: &ExprPool, asserts: &[Assert], model: &Model) -> bool {
        let started = Instant::now();
        let result = self.replay_sat_inner(pool, asserts, model);
        self.stats.model_replay_nanos =
            self.stats.model_replay_nanos.saturating_add(nanos(started));
        result
    }

    fn replay_sat_inner(&mut self, pool: &ExprPool, asserts: &[Assert], model: &Model) -> bool {
        self.stats.sat_replay_attempts = self.stats.sat_replay_attempts.saturating_add(1);
        let mut memo = BTreeMap::new();
        for (expression, expected) in asserts {
            match strict_eval(pool, *expression, &model.values, &mut memo) {
                Ok(value) if (value != 0) == *expected => {}
                Ok(_) => {
                    self.stats.sat_replay_failures =
                        self.stats.sat_replay_failures.saturating_add(1);
                    return false;
                }
                Err(ReplayError::MissingSymbol(_)) => {
                    self.stats.sat_replay_failures =
                        self.stats.sat_replay_failures.saturating_add(1);
                    self.stats.sat_replay_missing_symbols =
                        self.stats.sat_replay_missing_symbols.saturating_add(1);
                    return false;
                }
                Err(ReplayError::InvalidWidth) => {
                    self.stats.sat_replay_failures =
                        self.stats.sat_replay_failures.saturating_add(1);
                    return false;
                }
            }
        }
        self.stats.sat_replay_successes = self.stats.sat_replay_successes.saturating_add(1);
        true
    }

    fn find_sat_superset(&self, query: &[AssertionKey]) -> Option<u64> {
        if query.is_empty() {
            return self.sat_entries.first().copied();
        }
        let mut postings = query
            .iter()
            .map(|key| self.sat_postings.get(key))
            .collect::<Option<Vec<_>>>()?;
        postings.sort_by_key(|entries| entries.len());
        let mut candidates = postings.first()?.iter().copied().collect::<BTreeSet<_>>();
        for posting in postings.iter().skip(1) {
            candidates.retain(|entry_id| posting.contains(entry_id));
            if candidates.is_empty() {
                return None;
            }
        }
        candidates.first().copied()
    }

    fn record_miss(&mut self) -> CacheLookup {
        self.stats.misses = self.stats.misses.saturating_add(1);
        CacheLookup::Miss
    }

    fn lru_victim(&self) -> Option<u64> {
        self.entries
            .iter()
            .min_by_key(|(entry_id, entry)| (entry.last_used, **entry_id))
            .map(|(entry_id, _)| *entry_id)
    }

    fn remove_entry(&mut self, entry_id: u64, eviction: bool) {
        let started = eviction.then(Instant::now);
        let Some(entry) = self.entries.remove(&entry_id) else {
            return;
        };
        let assertion_refs = entry.query.len() as u64;
        let model_values = match &entry.result {
            CachedResult::Sat(model) => model.values.len() as u64,
            CachedResult::Unsat => 0,
        };
        if self.exact.get(&entry.query) == Some(&entry_id) {
            self.exact.remove(&entry.query);
        }
        match entry.result {
            CachedResult::Sat(_) => {
                self.sat_entries.remove(&entry_id);
                for key in &entry.query {
                    let remove_posting = self.sat_postings.get_mut(key).is_some_and(|posting| {
                        posting.remove(&entry_id);
                        posting.is_empty()
                    });
                    if remove_posting {
                        self.sat_postings.remove(key);
                    }
                }
            }
            CachedResult::Unsat => self.unsat_trie.remove(&entry.query, entry_id),
        }
        if eviction {
            self.stats.evictions = self.stats.evictions.saturating_add(1);
        }
        self.stats.entries = self.stats.entries.saturating_sub(1);
        self.stats.assertion_refs = self.stats.assertion_refs.saturating_sub(assertion_refs);
        self.stats.model_values = self.stats.model_values.saturating_sub(model_values);
        if let Some(started) = started {
            self.stats.eviction_nanos = self.stats.eviction_nanos.saturating_add(nanos(started));
        }
    }

    fn refresh_peak_gauges(&mut self) {
        self.stats.peak_entries = self.stats.peak_entries.max(self.stats.entries);
        self.stats.peak_assertion_refs = self
            .stats
            .peak_assertion_refs
            .max(self.stats.assertion_refs);
        self.stats.peak_model_values = self.stats.peak_model_values.max(self.stats.model_values);
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }
}

fn query_key(pool: &ExprPool, asserts: &[Assert]) -> QueryKey {
    let mut keys = asserts
        .iter()
        .map(|assertion| {
            let digest = Sha256::digest(pipe::assertion_line(pool, *assertion).as_bytes());
            AssertionKey(digest.into())
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayError {
    MissingSymbol(u32),
    InvalidWidth,
}

fn strict_eval(
    pool: &ExprPool,
    id: ExprId,
    model: &BTreeMap<u32, u128>,
    memo: &mut BTreeMap<ExprId, u128>,
) -> Result<u128, ReplayError> {
    if let Some(value) = memo.get(&id) {
        return Ok(*value);
    }
    let mut concrete = Concrete;
    let value = match *pool.get(id) {
        Expr::Const { value, width } => {
            valid_width(width)?;
            concrete.constant(width, value)
        }
        Expr::Sym { id, width } => {
            valid_width(width)?;
            concrete.constant(
                width,
                *model.get(&id).ok_or(ReplayError::MissingSymbol(id))?,
            )
        }
        Expr::Bin { op, a, b, width } => {
            valid_width(width)?;
            let a = strict_eval(pool, a, model, memo)?;
            let b = strict_eval(pool, b, model, memo)?;
            concrete.binop(op, &a, &b, width)
        }
        Expr::Un { op, a, width } => {
            valid_width(width)?;
            let a = strict_eval(pool, a, model, memo)?;
            concrete.unop(op, &a, width)
        }
        Expr::Cmp { op, a, b, width } => {
            valid_width(width)?;
            let a = strict_eval(pool, a, model, memo)?;
            let b = strict_eval(pool, b, model, memo)?;
            concrete.cmp(op, &a, &b, width)
        }
        Expr::ZExt { a, from, to } => {
            valid_width(from)?;
            valid_width(to)?;
            if to.bits() < from.bits() {
                return Err(ReplayError::InvalidWidth);
            }
            let a = strict_eval(pool, a, model, memo)?;
            concrete.zext(&a, from, to)
        }
        Expr::SExt { a, from, to } => {
            valid_width(from)?;
            valid_width(to)?;
            if to.bits() < from.bits() {
                return Err(ReplayError::InvalidWidth);
            }
            let a = strict_eval(pool, a, model, memo)?;
            concrete.sext(&a, from, to)
        }
        Expr::Trunc { a, to } => {
            valid_width(to)?;
            let a = strict_eval(pool, a, model, memo)?;
            concrete.trunc(&a, to)
        }
        Expr::Extract { a, hi, lo } => {
            if hi <= lo || hi > 128 {
                return Err(ReplayError::InvalidWidth);
            }
            let a = strict_eval(pool, a, model, memo)?;
            concrete.extract(&a, hi, lo)
        }
        Expr::Concat { hi, lo, hi_w, lo_w } => {
            valid_width(hi_w)?;
            valid_width(lo_w)?;
            if hi_w.bits().saturating_add(lo_w.bits()) > 128 {
                return Err(ReplayError::InvalidWidth);
            }
            let hi = strict_eval(pool, hi, model, memo)?;
            let lo = strict_eval(pool, lo, model, memo)?;
            concrete.concat(&hi, &lo, hi_w, lo_w)
        }
        Expr::Ite { c, t, e, width } => {
            valid_width(width)?;
            let condition = strict_eval(pool, c, model, memo)?;
            let then_value = strict_eval(pool, t, model, memo)?;
            let else_value = strict_eval(pool, e, model, memo)?;
            concrete.ite(&condition, &then_value, &else_value, width)
        }
    };
    memo.insert(id, value);
    Ok(value)
}

fn valid_width(width: Width) -> Result<(), ReplayError> {
    if (1..=128).contains(&width.bits()) {
        Ok(())
    } else {
        Err(ReplayError::InvalidWidth)
    }
}

fn nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        parse_engine_cache_policy, CacheHitKind, CacheLookup, EngineCacheLimits, EngineCachePolicy,
        EngineConstraintCache,
    };
    use crate::ir::types::{BinOp, CmpOp, UnOp, Width};
    use crate::symbolic::expr::{Expr, ExprPool};
    use crate::symbolic::solver::{Assert, Model, SolveResult};

    fn limits(entries: usize) -> EngineCacheLimits {
        EngineCacheLimits {
            max_entries: entries,
            max_assertion_refs: 64,
            max_model_values: 64,
            max_model_values_per_entry: 16,
        }
    }

    fn model(values: &[(u32, u128)]) -> Model {
        Model {
            values: values.iter().copied().collect::<BTreeMap<_, _>>(),
        }
    }

    fn expect_hit(lookup: Result<CacheLookup, String>, expected_kind: CacheHitKind) -> SolveResult {
        match lookup.expect("lookup must not conflict") {
            CacheLookup::Hit { kind, result } => {
                assert_eq!(kind, expected_kind);
                result
            }
            CacheLookup::Miss => panic!("expected cache hit"),
        }
    }

    #[test]
    fn exact_sat_and_unsat_hits_are_typed_and_sat_is_replayed() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let sat_query = [(x, true)];
        let unsat_query = [(x, false)];
        let mut cache = EngineConstraintCache::new(EngineCachePolicy::Exact, limits(8));

        cache.insert(&pool, &sat_query, &SolveResult::Sat(model(&[(0, 7)])));
        cache.insert(&pool, &unsat_query, &SolveResult::Unsat);

        assert_eq!(
            expect_hit(cache.lookup(&pool, &sat_query), CacheHitKind::ExactSat),
            SolveResult::Sat(model(&[(0, 7)]))
        );
        assert_eq!(
            expect_hit(cache.lookup(&pool, &unsat_query), CacheHitKind::ExactUnsat),
            SolveResult::Unsat
        );
        let stats = cache.stats();
        assert_eq!(stats.exact_sat_hits, 1);
        assert_eq!(stats.exact_unsat_hits, 1);
        assert_eq!(stats.sat_replay_attempts, 1);
        assert_eq!(stats.sat_replay_successes, 1);
        assert_eq!(stats.sat_replay_failures, 0);
    }

    #[test]
    fn structural_policy_reuses_only_sound_implication_directions() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let y = pool.fresh_symbol(Width::W8);
        let weak = [(x, true)];
        let strong = [(x, true), (y, false)];

        let mut sat_cache = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(8));
        sat_cache.insert(&pool, &strong, &SolveResult::Sat(model(&[(0, 9), (1, 0)])));
        assert_eq!(
            expect_hit(sat_cache.lookup(&pool, &weak), CacheHitKind::SatSuperset),
            SolveResult::Sat(model(&[(0, 9), (1, 0)]))
        );

        let mut unsat_cache = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(8));
        unsat_cache.insert(&pool, &weak, &SolveResult::Unsat);
        assert_eq!(
            expect_hit(
                unsat_cache.lookup(&pool, &strong),
                CacheHitKind::UnsatSubset
            ),
            SolveResult::Unsat
        );

        let mut wrong_sat = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(8));
        wrong_sat.insert(&pool, &weak, &SolveResult::Sat(model(&[(0, 1), (1, 0)])));
        assert_eq!(wrong_sat.lookup(&pool, &strong), Ok(CacheLookup::Miss));

        let mut wrong_unsat = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(8));
        wrong_unsat.insert(&pool, &strong, &SolveResult::Unsat);
        assert_eq!(wrong_unsat.lookup(&pool, &weak), Ok(CacheLookup::Miss));
    }

    #[test]
    fn missing_or_false_sat_models_fall_through_without_becoming_hits() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let query = [(x, true)];

        let mut missing = EngineConstraintCache::new(EngineCachePolicy::Exact, limits(8));
        missing.insert(&pool, &query, &SolveResult::Sat(model(&[])));
        assert_eq!(missing.lookup(&pool, &query), Ok(CacheLookup::Miss));
        let missing_stats = missing.stats();
        assert_eq!(missing_stats.sat_replay_attempts, 1);
        assert_eq!(missing_stats.sat_replay_failures, 1);
        assert_eq!(missing_stats.sat_replay_missing_symbols, 1);
        assert_eq!(missing_stats.exact_sat_hits, 0);

        let mut false_model = EngineConstraintCache::new(EngineCachePolicy::Exact, limits(8));
        false_model.insert(&pool, &query, &SolveResult::Sat(model(&[(0, 0)])));
        assert_eq!(false_model.lookup(&pool, &query), Ok(CacheLookup::Miss));
        let false_stats = false_model.stats();
        assert_eq!(false_stats.sat_replay_attempts, 1);
        assert_eq!(false_stats.sat_replay_failures, 1);
        assert_eq!(false_stats.sat_replay_missing_symbols, 0);
        assert_eq!(false_stats.exact_sat_hits, 0);
    }

    #[test]
    fn query_identity_sorts_and_elides_duplicate_assertions() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let y = pool.fresh_symbol(Width::W8);
        let inserted = [(x, true), (y, false), (x, true)];
        let reordered = [(y, false), (x, true)];
        let mut cache = EngineConstraintCache::new(EngineCachePolicy::Exact, limits(8));
        cache.insert(&pool, &inserted, &SolveResult::Unsat);

        assert_eq!(
            expect_hit(cache.lookup(&pool, &reordered), CacheHitKind::ExactUnsat),
            SolveResult::Unsat
        );
        assert_eq!(cache.stats().assertion_refs, 2);
    }

    #[test]
    fn lru_eviction_is_deterministic_and_removes_every_index() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let y = pool.fresh_symbol(Width::W8);
        let z = pool.fresh_symbol(Width::W8);
        let qx = [(x, true)];
        let qy = [(y, true)];
        let qz = [(z, true)];
        let mut cache = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(2));
        cache.insert(&pool, &qx, &SolveResult::Unsat);
        cache.insert(&pool, &qy, &SolveResult::Unsat);
        expect_hit(cache.lookup(&pool, &qx), CacheHitKind::ExactUnsat);
        cache.insert(&pool, &qz, &SolveResult::Unsat);

        assert_eq!(cache.lookup(&pool, &qy), Ok(CacheLookup::Miss));
        expect_hit(cache.lookup(&pool, &qx), CacheHitKind::ExactUnsat);
        expect_hit(cache.lookup(&pool, &qz), CacheHitKind::ExactUnsat);
        let stats = cache.stats();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.evictions, 1);
        assert_eq!(stats.peak_entries, 2);
    }

    #[test]
    fn individually_oversized_results_are_counted_and_bypassed() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let query: Vec<Assert> = vec![(x, true)];
        let mut cache = EngineConstraintCache::new(
            EngineCachePolicy::Exact,
            EngineCacheLimits {
                max_entries: 8,
                max_assertion_refs: 8,
                max_model_values: 8,
                max_model_values_per_entry: 1,
            },
        );
        cache.insert(&pool, &query, &SolveResult::Sat(model(&[(0, 1), (1, 2)])));

        assert_eq!(cache.lookup(&pool, &query), Ok(CacheLookup::Miss));
        let stats = cache.stats();
        assert_eq!(stats.oversize_bypasses, 1);
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.model_values, 0);
    }

    #[test]
    fn unknown_and_error_results_are_never_cached() {
        use crate::symbolic::solver::SolveUnknownReason;

        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let query = [(x, true)];
        let mut cache = EngineConstraintCache::new(EngineCachePolicy::Exact, limits(8));
        for result in [
            SolveResult::Unknown(SolveUnknownReason::ResourceLimit),
            SolveResult::NoSolver,
            SolveResult::Error("declined".into()),
        ] {
            cache.insert(&pool, &query, &result);
        }

        assert_eq!(cache.lookup(&pool, &query), Ok(CacheLookup::Miss));
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn aggregate_reference_and_model_bounds_evict_before_insertion() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let y = pool.fresh_symbol(Width::W8);
        let z = pool.fresh_symbol(Width::W8);
        let qx = [(x, true)];
        let qyz = [(y, true), (z, false)];
        let mut cache = EngineConstraintCache::new(
            EngineCachePolicy::Structural,
            EngineCacheLimits {
                max_entries: 8,
                max_assertion_refs: 2,
                max_model_values: 2,
                max_model_values_per_entry: 2,
            },
        );
        cache.insert(&pool, &qx, &SolveResult::Sat(model(&[(0, 1)])));
        cache.insert(&pool, &qyz, &SolveResult::Sat(model(&[(1, 1), (2, 0)])));

        assert_eq!(cache.lookup(&pool, &qx), Ok(CacheLookup::Miss));
        expect_hit(cache.lookup(&pool, &qyz), CacheHitKind::ExactSat);
        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.assertion_refs, 2);
        assert_eq!(stats.model_values, 2);
    }

    #[test]
    fn eviction_removes_sat_postings_and_unsat_trie_terminals() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let y = pool.fresh_symbol(Width::W8);
        let weak = [(x, true)];
        let strong = [(x, true), (y, true)];
        let unrelated = [(y, false)];

        let mut sat_cache = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(1));
        sat_cache.insert(&pool, &strong, &SolveResult::Sat(model(&[(0, 1), (1, 1)])));
        sat_cache.insert(&pool, &unrelated, &SolveResult::Unsat);
        assert_eq!(sat_cache.lookup(&pool, &weak), Ok(CacheLookup::Miss));

        let mut unsat_cache = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(1));
        unsat_cache.insert(&pool, &weak, &SolveResult::Unsat);
        unsat_cache.insert(&pool, &unrelated, &SolveResult::Sat(model(&[(1, 0)])));
        assert_eq!(unsat_cache.lookup(&pool, &strong), Ok(CacheLookup::Miss));
    }

    #[test]
    fn conflicting_structural_implications_fail_closed() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let y = pool.fresh_symbol(Width::W8);
        let z = pool.fresh_symbol(Width::W8);
        let unsat_subset = [(x, true)];
        let middle = [(x, true), (y, false)];
        let sat_superset = [(x, true), (y, false), (z, true)];
        let mut cache = EngineConstraintCache::new(EngineCachePolicy::Structural, limits(8));
        cache.insert(&pool, &unsat_subset, &SolveResult::Unsat);
        cache.insert(
            &pool,
            &sat_superset,
            &SolveResult::Sat(model(&[(0, 1), (1, 0), (2, 1)])),
        );

        let error = cache
            .lookup(&pool, &middle)
            .expect_err("inconsistent implication indexes must fail closed");
        assert!(error.contains("conflicting SAT and UNSAT"));
        assert_eq!(cache.stats().conflicts, 1);
    }

    #[test]
    fn strict_replay_covers_the_complete_expression_surface() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = pool.constant(Width::W8, 1);
        let zero = pool.constant(Width::W8, 0);
        let add = pool.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W8,
        });
        let inverted = pool.intern(Expr::Un {
            op: UnOp::Not,
            a: add,
            width: Width::W8,
        });
        let condition = pool.intern(Expr::Cmp {
            op: CmpOp::Ne,
            a: inverted,
            b: zero,
            width: Width::W8,
        });
        let zext = pool.intern(Expr::ZExt {
            a: x,
            from: Width::W8,
            to: Width::W16,
        });
        let sext = pool.intern(Expr::SExt {
            a: x,
            from: Width::W8,
            to: Width::W16,
        });
        let trunc = pool.intern(Expr::Trunc {
            a: sext,
            to: Width::W8,
        });
        let high = pool.intern(Expr::Extract {
            a: zext,
            hi: 8,
            lo: 4,
        });
        let low = pool.intern(Expr::Extract {
            a: trunc,
            hi: 4,
            lo: 0,
        });
        let concat = pool.intern(Expr::Concat {
            hi: high,
            lo: low,
            hi_w: Width(4),
            lo_w: Width(4),
        });
        let selected = pool.intern(Expr::Ite {
            c: condition,
            t: concat,
            e: inverted,
            width: Width::W8,
        });
        let query = [(selected, true)];
        let mut cache = EngineConstraintCache::new(EngineCachePolicy::Exact, limits(8));
        cache.insert(&pool, &query, &SolveResult::Sat(model(&[(0, 0x81)])));

        assert_eq!(
            expect_hit(cache.lookup(&pool, &query), CacheHitKind::ExactSat),
            SolveResult::Sat(model(&[(0, 0x81)]))
        );
    }

    #[test]
    fn policy_parser_defaults_off_and_rejects_unregistered_aliases() {
        assert_eq!(parse_engine_cache_policy(None), Ok(EngineCachePolicy::Off));
        assert_eq!(
            parse_engine_cache_policy(Some("off")),
            Ok(EngineCachePolicy::Off)
        );
        assert_eq!(
            parse_engine_cache_policy(Some("exact")),
            Ok(EngineCachePolicy::Exact)
        );
        assert_eq!(
            parse_engine_cache_policy(Some("structural")),
            Ok(EngineCachePolicy::Structural)
        );
        for invalid in ["", "on", "implication", "green"] {
            assert!(
                parse_engine_cache_policy(Some(invalid)).is_err(),
                "{invalid}"
            );
        }
    }
}
