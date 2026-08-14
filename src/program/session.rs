//! Reusable program-scoped ownership and deterministic analysis caches.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::analysis::cfg::{analyze_functions_image_with_seeds, Budgets};
use crate::core::function::Function;
use crate::ir::call_args::CallConv;
use crate::program::environment::{
    callback_api_identity, recover_program_environment, ProgramEnvironment,
};
use crate::program::image::{ProgramImage, ProgramImageError};
use crate::program::symbols::{SymbolIncompleteness, SymbolStore};
use crate::program::types::TypeStore;

#[derive(Debug)]
struct ProgramTypeArtifacts {
    debug_types: Arc<[crate::debug::dwarf::DwarfType]>,
    store: Arc<TypeStore>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DiscoveryKey {
    max_functions: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    total_timeout_ms: u64,
    seeds: Box<[u64]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EnvironmentKey {
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    calling_convention: u8,
    callback_apis: Box<[(u64, &'static str)]>,
    requested_vas: Box<[u64]>,
}

impl EnvironmentKey {
    fn new(
        image: &ProgramImage,
        budgets: &Budgets,
        calling_convention: CallConv,
        address_names: &HashMap<u64, String>,
        requested_vas: &[u64],
    ) -> Self {
        let calling_convention = match calling_convention {
            CallConv::SysVAmd64 => 0,
            CallConv::Win64 => 1,
            CallConv::Cdecl32 => 2,
            CallConv::Aarch64 => 3,
            CallConv::Arm => 4,
            CallConv::ArmHardFloat => 5,
        };
        let mut requested_vas = requested_vas
            .iter()
            .map(|address| image.normalize_function_entry(*address))
            .collect::<Vec<_>>();
        requested_vas.sort_unstable();
        requested_vas.dedup();
        Self {
            max_blocks: budgets.max_blocks,
            max_instructions: budgets.max_instructions,
            timeout_ms: budgets.timeout_ms,
            calling_convention,
            callback_apis: callback_api_identity(address_names),
            requested_vas: requested_vas.into_boxed_slice(),
        }
    }
}

impl DiscoveryKey {
    fn new(image: &ProgramImage, budgets: &Budgets, requested_vas: &[u64]) -> Self {
        let mut seeds = requested_vas
            .iter()
            .map(|address| image.normalize_function_entry(*address))
            .collect::<Vec<_>>();
        seeds.sort_unstable();
        seeds.dedup();
        Self {
            max_functions: budgets.max_functions,
            max_blocks: budgets.max_blocks,
            max_instructions: budgets.max_instructions,
            timeout_ms: budgets.timeout_ms,
            total_timeout_ms: budgets.total_timeout_ms,
            seeds: seeds.into_boxed_slice(),
        }
    }
}

const MAX_DISCOVERY_CACHE_ENTRIES: usize = 256;
const MAX_ENVIRONMENT_CACHE_ENTRIES: usize = 256;

#[derive(Debug, Default)]
struct DiscoveryCacheState {
    functions: HashMap<DiscoveryKey, Arc<[Function]>>,
    least_recent: VecDeque<DiscoveryKey>,
}

#[derive(Debug, Default)]
struct DiscoveryCache {
    state: Mutex<DiscoveryCacheState>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl DiscoveryCache {
    fn state(&self) -> MutexGuard<'_, DiscoveryCacheState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn get(&self, key: &DiscoveryKey) -> Option<Arc<[Function]>> {
        let mut state = self.state();
        let functions = state.functions.get(key).cloned()?;
        state.least_recent.retain(|candidate| candidate != key);
        state.least_recent.push_back(key.clone());
        Some(functions)
    }

    fn install(&self, key: DiscoveryKey, functions: Arc<[Function]>) -> Arc<[Function]> {
        let mut state = self.state();
        if let Some(existing) = state.functions.get(&key).cloned() {
            state.least_recent.retain(|candidate| candidate != &key);
            state.least_recent.push_back(key);
            self.hits.fetch_add(1, Ordering::Relaxed);
            return existing;
        }
        if state.functions.len() >= MAX_DISCOVERY_CACHE_ENTRIES {
            if let Some(oldest) = state.least_recent.pop_front() {
                state.functions.remove(&oldest);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        state.functions.insert(key.clone(), functions.clone());
        state.least_recent.push_back(key);
        self.misses.fetch_add(1, Ordering::Relaxed);
        functions
    }

    fn clear(&self) {
        let mut state = self.state();
        state.functions.clear();
        state.least_recent.clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
    }
}

/// Observable reuse counters for one [`ProgramSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryCacheStats {
    /// Exact-key queries served from an existing immutable result.
    pub hits: u64,
    /// Exact-key queries that performed discovery and installed a result.
    pub misses: u64,
    /// Distinct discovery artifacts retained by this session.
    pub entries: usize,
    /// Least-recently-used artifacts discarded at the bounded capacity.
    pub evictions: u64,
}

/// One immutable image plus analysis artifacts reusable across function queries.
///
/// Cache keys include every discovery budget and the normalized, sorted seed set.
/// A session never substitutes a result produced under different limits or for a
/// different requested-address set.
#[derive(Debug, Clone)]
pub struct ProgramSession {
    image: ProgramImage,
    discovery: Arc<DiscoveryCache>,
    environments: Arc<Mutex<HashMap<EnvironmentKey, Arc<ProgramEnvironment>>>>,
    type_artifacts: Arc<OnceLock<ProgramTypeArtifacts>>,
    symbol_artifacts: Arc<OnceLock<Arc<SymbolStore>>>,
}

impl ProgramSession {
    /// Read one program image and create an empty analysis session.
    pub fn from_path(path: &Path) -> Result<Self, ProgramImageError> {
        ProgramImage::from_path(path).map(Self::from_image)
    }

    /// Own an already indexed image without parsing it again.
    pub fn from_image(image: ProgramImage) -> Self {
        Self {
            image,
            discovery: Arc::new(DiscoveryCache::default()),
            environments: Arc::new(Mutex::new(HashMap::new())),
            type_artifacts: Arc::new(OnceLock::new()),
            symbol_artifacts: Arc::new(OnceLock::new()),
        }
    }

    /// Canonical program symbol environment imported once from exact object
    /// symbol, import, export, and relocation tables.
    pub fn symbol_store(&self) -> Arc<SymbolStore> {
        self.symbol_artifacts
            .get_or_init(|| {
                let mut store = SymbolStore::default();
                match crate::decompile::profile::parse_object(self.image.bytes()) {
                    Ok(object) => store.import_object(&object, &self.image),
                    Err(_) => store.note_incomplete(SymbolIncompleteness::UnreadableImage),
                }
                Arc::new(store)
            })
            .clone()
    }

    fn type_artifacts(&self) -> &ProgramTypeArtifacts {
        self.type_artifacts.get_or_init(|| {
            let debug_types: Arc<[crate::debug::dwarf::DwarfType]> =
                crate::debug::dwarf::extract_dwarf_types(self.image.bytes()).into();
            let mut store = TypeStore::default();
            let address_size = self
                .image
                .target()
                .address_bits()
                .map_or(8, |bits| u64::from(bits).div_ceil(8));
            store.import_dwarf_types(&debug_types, address_size);
            ProgramTypeArtifacts {
                debug_types,
                store: Arc::new(store),
            }
        })
    }

    /// DWARF types parsed once from this session's immutable image.
    pub fn debug_types(&self) -> Arc<[crate::debug::dwarf::DwarfType]> {
        self.type_artifacts().debug_types.clone()
    }

    /// Canonical program type graph populated from available debug evidence.
    pub fn type_store(&self) -> Arc<TypeStore> {
        self.type_artifacts().store.clone()
    }

    /// The session's single immutable program image.
    pub fn image(&self) -> &ProgramImage {
        &self.image
    }

    /// The image's canonical machine target.
    pub fn target(&self) -> &crate::target::TargetSpec {
        self.image.target()
    }

    /// Discover functions or reuse the exact immutable artifact from this session.
    pub fn discover_functions(&self, budgets: &Budgets, requested_vas: &[u64]) -> Arc<[Function]> {
        let key = DiscoveryKey::new(&self.image, budgets, requested_vas);
        if let Some(functions) = self.discovery.get(&key) {
            self.discovery.hits.fetch_add(1, Ordering::Relaxed);
            return functions;
        }

        let (functions, _call_graph) =
            analyze_functions_image_with_seeds(&self.image, budgets, &key.seeds);
        let functions: Arc<[Function]> = functions.into();
        self.discovery.install(key, functions)
    }

    /// Snapshot the session-local discovery reuse counters.
    pub fn discovery_cache_stats(&self) -> DiscoveryCacheStats {
        let entries = self.discovery.state().functions.len();
        DiscoveryCacheStats {
            hits: self.discovery.hits.load(Ordering::Relaxed),
            misses: self.discovery.misses.load(Ordering::Relaxed),
            entries,
            evictions: self.discovery.evictions.load(Ordering::Relaxed),
        }
    }

    /// Recover or reuse immutable program-level symbol/type/callback facts.
    pub fn environment(
        &self,
        budgets: &Budgets,
        calling_convention: CallConv,
        address_names: &HashMap<u64, String>,
        requested_vas: &[u64],
    ) -> Arc<ProgramEnvironment> {
        let key = EnvironmentKey::new(
            &self.image,
            budgets,
            calling_convention,
            address_names,
            requested_vas,
        );
        if let Some(environment) = self
            .environments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned()
        {
            return environment;
        }
        let environment = Arc::new(recover_program_environment(
            &self.image,
            budgets,
            calling_convention,
            address_names,
            &key.requested_vas,
            self.type_store(),
        ));
        let mut environments = self
            .environments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if environments.len() >= MAX_ENVIRONMENT_CACHE_ENTRIES {
            environments.clear();
        }
        environments
            .entry(key)
            .or_insert_with(|| environment.clone())
            .clone()
    }

    /// Drop budget-dependent analysis artifacts and reset discovery counters.
    /// Immutable image-derived debug/type facts remain shared for the session.
    pub fn clear_caches(&self) {
        self.discovery.clear();
        self.environments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}
