/// Core data types module
pub mod core;

/// Error types and error handling
pub mod error;

/// Logging and tracing infrastructure
pub mod logging;

/// Timeout utilities for analysis operations
pub mod timeout;

/// Triage runtime implementation
pub mod triage;

/// Symbol extraction and analysis
pub mod symbols;

/// Symbol name demangling helpers
pub mod demangle;
/// Similarity and fuzzy hashing (CTPH)
pub mod similarity;
/// Cross-platform string scanning and language detection
pub mod strings;

/// High-performance entropy calculation and analysis
pub mod entropy;

/// Analysis-time program and memory views
pub mod analysis;
/// Disassembly engines and adapters
pub mod disasm;

#[cfg(feature = "python-ext")]
use pyo3::{prelude::*, wrap_pyfunction};

// Python-callable analysis helpers (module-level)
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "imphash")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn imphash_py(path: String, max_read_bytes: u64, max_file_size: u64) -> PyResult<Option<String>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::symbols::analysis::imphash::pe_imphash(&data))
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_exports")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn analyze_exports_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<(u32, u32, u32)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    if let Some(ec) = crate::symbols::analysis::export::analyze_pe_exports(&data) {
        Ok(Some((ec.direct, ec.forwarded, ec.ordinal_only)))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_env")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn analyze_env_py(
    py: Python<'_>,
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Py<PyAny>> {
    use object::read::Object;
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let obj = object::read::File::parse(&*data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("object parse error: {e}")))?;
    let dict = pyo3::types::PyDict::new(py);
    // Common: libraries from imports
    if let Ok(imps) = obj.imports() {
        let mut libs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for imp in imps {
            let lib = String::from_utf8_lossy(imp.library()).to_string();
            if !lib.is_empty() {
                libs.insert(lib);
            }
        }
        dict.set_item("libs", libs.into_iter().collect::<Vec<_>>())?;
    }
    // ELF specifics: rpaths/runpaths via our summarizer (fast header check)
    let is_elf = data.len() >= 4 && &data[0..4] == b"\x7FELF";
    if is_elf {
        let caps = crate::symbols::types::BudgetCaps::default();
        let sum = crate::symbols::elf::summarize_elf(&data, &caps);
        if let Some(v) = sum.rpaths.clone() {
            dict.set_item("rpaths", v)?;
        }
        if let Some(v) = sum.runpaths.clone() {
            dict.set_item("runpaths", v)?;
        }
    }
    // PE specifics: pdb path, tls callbacks, entry section, relocations
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        if let Some(env) = crate::symbols::analysis::pe_env::analyze_pe_env(&data) {
            if let Some(pdb) = env.pdb_path {
                dict.set_item("pdb_path", pdb)?;
            }
            dict.set_item("tls_callbacks", env.tls_callbacks as u32)?;
            if let Some(es) = env.entry_section {
                dict.set_item("entry_section", es)?;
            }
            dict.set_item("relocations_present", env.relocations_present)?;
        }
    }
    // Mach-O specifics: rpaths, minOS, code signature bit
    if let Some(env) = crate::symbols::analysis::macho_env::analyze_macho_env(&data) {
        if !env.rpaths.is_empty() {
            dict.set_item("rpaths", env.rpaths)?;
        }
        if let Some(minos) = env.minos {
            dict.set_item("minos", minos)?;
        }
        dict.set_item("code_signature", env.code_signature)?;
    }
    Ok(dict.into_any().unbind())
}

/// A Python module implemented in Rust.
#[cfg(feature = "python-ext")]
#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register core types
    m.add_class::<crate::core::address::AddressKind>()?;
    m.add_class::<crate::core::address::Address>()?;
    m.add_class::<crate::core::address_range::AddressRange>()?;
    m.add_class::<crate::core::address_space::AddressSpaceKind>()?;
    m.add_class::<crate::core::address_space::AddressSpace>()?;
    m.add_class::<crate::core::artifact::Artifact>()?;
    m.add_class::<crate::core::binary::Format>()?;
    m.add_class::<crate::core::binary::Arch>()?;
    m.add_class::<crate::core::binary::Endianness>()?;
    m.add_class::<crate::core::binary::Hashes>()?;
    m.add_class::<crate::core::binary::Binary>()?;
    m.add_class::<crate::core::id::IdKind>()?;
    m.add_class::<crate::core::id::Id>()?;
    m.add_class::<crate::core::id::IdGenerator>()?;
    m.add_class::<crate::core::section::SectionPerms>()?;
    m.add_class::<crate::core::section::Section>()?;
    m.add_class::<crate::core::segment::Perms>()?;
    m.add_class::<crate::core::segment::Segment>()?;
    m.add_class::<crate::core::string_literal::StringEncoding>()?;
    m.add_class::<crate::core::string_literal::StringClassification>()?;
    m.add_class::<crate::core::string_literal::StringLiteral>()?;
    m.add_class::<crate::core::symbol::SymbolKind>()?;
    m.add_class::<crate::core::symbol::SymbolBinding>()?;
    m.add_class::<crate::core::symbol::SymbolVisibility>()?;
    m.add_class::<crate::core::symbol::SymbolSource>()?;
    m.add_class::<crate::core::symbol::Symbol>()?;
    m.add_class::<crate::core::instruction::OperandKind>()?;
    m.add_class::<crate::core::instruction::Access>()?;
    m.add_class::<crate::core::instruction::SideEffect>()?;
    m.add_class::<crate::core::instruction::Operand>()?;
    m.add_class::<crate::core::instruction::Instruction>()?;
    m.add_class::<crate::core::register::RegisterKind>()?;
    m.add_class::<crate::core::register::Register>()?;
    m.add_class::<crate::core::disassembler::DisassemblerError>()?;
    m.add_class::<crate::core::disassembler::Architecture>()?;
    // Endianness is exported from core::binary to avoid name collisions
    m.add_class::<crate::core::disassembler::DisassemblerConfig>()?;
    m.add_class::<crate::core::basic_block::BasicBlock>()?;
    m.add_class::<crate::core::pattern::MetadataValue>()?;
    m.add_class::<crate::core::pattern::PatternType>()?;
    m.add_class::<crate::core::pattern::YaraMatch>()?;
    m.add_class::<crate::core::pattern::PatternDefinition>()?;
    m.add_class::<crate::core::pattern::Pattern>()?;
    m.add_class::<crate::core::relocation::RelocationType>()?;
    m.add_class::<crate::core::relocation::Relocation>()?;
    m.add_class::<crate::core::tool_metadata::SourceKind>()?;
    m.add_class::<crate::core::tool_metadata::ToolMetadata>()?;

    // Data types and variables
    m.add_class::<crate::core::data_type::DataTypeKind>()?;
    m.add_class::<crate::core::data_type::Field>()?;
    m.add_class::<crate::core::data_type::EnumMember>()?;
    m.add_class::<crate::core::data_type::TypeData>()?;
    m.add_class::<crate::core::data_type::DataType>()?;
    m.add_class::<crate::core::variable::StorageLocation>()?;
    m.add_class::<crate::core::variable::Variable>()?;
    m.add_class::<crate::core::function::FunctionKind>()?;
    m.add_class::<crate::core::function::FunctionFlagsPy>()?;
    m.add_class::<crate::core::function::Function>()?;
    m.add_class::<crate::core::reference::UnresolvedReferenceKind>()?;
    m.add_class::<crate::core::reference::ReferenceTarget>()?;
    m.add_class::<crate::core::reference::ReferenceKind>()?;
    m.add_class::<crate::core::reference::Reference>()?;

    // Graphs: ControlFlowGraph and CallGraph
    m.add_class::<crate::core::control_flow_graph::ControlFlowEdgeKind>()?;
    m.add_class::<crate::core::control_flow_graph::ControlFlowEdge>()?;
    m.add_class::<crate::core::control_flow_graph::ControlFlowGraph>()?;
    m.add_class::<crate::core::control_flow_graph::ControlFlowGraphStats>()?;
    m.add_class::<crate::core::call_graph::CallType>()?;
    m.add_class::<crate::core::call_graph::CallGraphEdge>()?;
    m.add_class::<crate::core::call_graph::CallGraph>()?;
    m.add_class::<crate::core::call_graph::CallGraphStats>()?;

    // Submodule: triage
    let triage = pyo3::types::PyModule::new(py, "triage")?;
    triage.add_class::<crate::core::triage::SnifferSource>()?;
    triage.add_class::<crate::core::triage::TriageHint>()?;
    triage.add_class::<crate::core::triage::TriageErrorKind>()?;
    triage.add_class::<crate::core::triage::TriageError>()?;
    triage.add_class::<crate::core::triage::ConfidenceSignal>()?;
    triage.add_class::<crate::core::triage::ParserKind>()?;
    triage.add_class::<crate::core::triage::ParserResult>()?;
    triage.add_class::<crate::core::triage::EntropySummary>()?;
    triage.add_class::<crate::core::triage::EntropyAnalysis>()?;
    triage.add_class::<crate::core::triage::EntropyClass>()?;
    triage.add_class::<crate::core::triage::PackedIndicators>()?;
    triage.add_class::<crate::core::triage::EntropyAnomaly>()?;
    triage.add_class::<crate::core::triage::DetectedString>()?;
    triage.add_class::<crate::core::triage::StringsSummary>()?;
    triage.add_class::<crate::core::triage::IocSample>()?;
    triage.add_class::<crate::symbols::SymbolSummary>()?;
    triage.add_class::<crate::core::triage::SimilaritySummary>()?;
    triage.add_class::<crate::triage::signing::SigningSummary>()?;
    triage.add_class::<crate::core::triage::PackerMatch>()?;
    triage.add_class::<crate::core::triage::ContainerChild>()?;
    triage.add_class::<crate::core::triage::ContainerMetadata>()?;
    triage.add_class::<crate::triage::recurse::RecursionSummary>()?;
    // Overlay analysis classes
    triage.add_class::<crate::triage::overlay::OverlayAnalysis>()?;
    triage.add_class::<crate::triage::overlay::OverlayFormat>()?;
    triage.add_class::<crate::core::triage::Budgets>()?;
    triage.add_class::<crate::core::triage::TriageVerdict>()?;
    triage.add_class::<crate::core::triage::TriagedArtifact>()?;
    // Triage configuration classes
    triage.add_class::<crate::triage::config::TriageConfig>()?;
    triage.add_class::<crate::triage::config::IOConfig>()?;
    triage.add_class::<crate::triage::config::EntropyConfig>()?;
    triage.add_class::<crate::triage::config::EntropyThresholds>()?;
    triage.add_class::<crate::triage::config::EntropyWeights>()?;
    triage.add_class::<crate::triage::config::HeuristicsConfig>()?;
    triage.add_class::<crate::triage::config::ScoringConfig>()?;
    triage.add_class::<crate::triage::config::PackerConfig>()?;
    triage.add_class::<crate::triage::config::SimilarityConfig>()?;
    triage.add_class::<crate::triage::config::HeaderConfig>()?;
    triage.add_class::<crate::triage::config::ParserConfig>()?;
    // Triage API functions
    triage.add_function(wrap_pyfunction!(
        crate::triage::api::analyze_path_py,
        &triage
    )?)?;
    triage.add_function(wrap_pyfunction!(
        crate::triage::api::analyze_bytes_py,
        &triage
    )?)?;
    // Back-compat: symbols helpers under triage
    triage.add_function(wrap_pyfunction!(crate::symbols::list_symbols_py, &triage)?)?;
    triage.add_function(wrap_pyfunction!(
        crate::symbols::list_symbols_demangled_py,
        &triage
    )?)?;
    // Entropy convenience functions
    triage.add_function(wrap_pyfunction!(
        crate::triage::entropy::entropy_of_bytes_py,
        &triage
    )?)?;
    triage.add_function(wrap_pyfunction!(
        crate::triage::entropy::compute_entropy_bytes_py,
        &triage
    )?)?;
    triage.add_function(wrap_pyfunction!(
        crate::triage::entropy::analyze_entropy_bytes_py,
        &triage
    )?)?;
    // Language detection helper for debugging
    #[pyfunction]
    #[pyo3(name = "detect_language")]
    #[pyo3(signature = (text, min_size=4, min_conf=0.5, agree_conf=0.4))]
    fn detect_language_py(
        text: &str,
        min_size: usize,
        min_conf: f64,
        agree_conf: f64,
    ) -> (Option<String>, Option<String>, Option<f64>) {
        // Use the redesigned router with supplied floors where possible
        let cfg = {
            let mut c = crate::strings::StringsConfig::default();
            c.min_len_for_detect = min_size;
            c.min_lang_confidence = min_conf;
            c.min_lang_confidence_agree = agree_conf;
            c
        };
        let router = crate::strings::detect::LanguageRouter::from_cfg(&cfg);
        router.detect(text).tuple()
    }
    triage.add_function(wrap_pyfunction!(detect_language_py, &triage)?)?;
    // Raw engine accessors for experiments
    #[pyfunction]
    #[pyo3(name = "detect_language_whatlang")]
    #[pyo3(signature = (text))]
    fn detect_language_whatlang_py(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
        crate::strings::detect::detect_with_whatlang(text)
    }
    triage.add_function(wrap_pyfunction!(detect_language_whatlang_py, &triage)?)?;

    #[pyfunction]
    #[pyo3(name = "detect_language_lingua")]
    #[pyo3(signature = (text))]
    fn detect_language_lingua_py(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
        crate::strings::detect::detect_with_lingua(text)
    }
    triage.add_function(wrap_pyfunction!(detect_language_lingua_py, &triage)?)?;

    // Batch ensemble detection with Rayon
    #[pyfunction]
    #[pyo3(name = "detect_languages")]
    #[pyo3(signature = (texts, min_size=4, min_conf=0.5, agree_conf=0.4))]
    fn detect_languages_py(
        texts: Vec<String>,
        min_size: usize,
        min_conf: f64,
        agree_conf: f64,
    ) -> Vec<(Option<String>, Option<String>, Option<f64>)> {
        use rayon::prelude::*;
        let cfg = {
            let mut c = crate::strings::StringsConfig::default();
            c.min_len_for_detect = min_size;
            c.min_lang_confidence = min_conf;
            c.min_lang_confidence_agree = agree_conf;
            c
        };
        let router = crate::strings::detect::LanguageRouter::from_cfg(&cfg);
        texts.par_iter().map(|s| router.detect(s).tuple()).collect()
    }
    triage.add_function(wrap_pyfunction!(detect_languages_py, &triage)?)?;
    // Add triage submodule
    m.add_submodule(&triage)?;

    // Top-level submodule: strings (search, similarity, normalization)
    let strings_mod = pyo3::types::PyModule::new(py, "strings")?;
    // Python-visible match object
    #[pyclass]
    #[derive(Clone)]
    struct SearchMatch {
        #[pyo3(get)]
        kind: String,
        #[pyo3(get)]
        text: String,
        #[pyo3(get)]
        start: u32,
        #[pyo3(get)]
        end: u32,
        #[pyo3(get)]
        offset: Option<u64>,
    }

    fn to_kind_str(k: crate::strings::search::MatchKind) -> &'static str {
        use crate::strings::search::MatchKind::*;
        match k {
            Url => "url",
            Email => "email",
            Hostname => "hostname",
            Domain => "domain",
            Ipv4 => "ipv4",
            Ipv6 => "ipv6",
            PathWindows => "path_windows",
            PathUNC => "path_unc",
            PathPosix => "path_posix",
            Registry => "registry",
            JavaPath => "java_path",
            CIdentifier => "c_identifier",
            ItaniumMangled => "itanium_mangled",
            MsvcMangled => "msvc_mangled",
        }
    }

    #[pyfunction]
    #[pyo3(name = "defang")]
    #[pyo3(signature = (text, max_len=4096))]
    fn defang_py(text: &str, max_len: usize) -> String {
        crate::strings::normalize::normalize_defanged(text, max_len).into_owned()
    }

    #[pyfunction]
    #[pyo3(name = "search_text")]
    #[pyo3(signature = (text, defang_normalize=true, max_matches_total=10_000, max_matches_per_kind=1_000, time_guard_ms=25))]
    fn search_text_py(
        text: &str,
        defang_normalize: bool,
        max_matches_total: usize,
        max_matches_per_kind: usize,
        time_guard_ms: u64,
    ) -> Vec<SearchMatch> {
        let t = if defang_normalize {
            crate::strings::normalize::normalize_defanged(text, 64 * 1024).into_owned()
        } else {
            text.to_string()
        };
        let budget = crate::strings::search::SearchBudget {
            max_matches_total,
            max_matches_per_kind,
            time_guard_ms,
        };
        crate::strings::search::scan_text(&t, &budget)
            .into_iter()
            .map(|m| SearchMatch {
                kind: to_kind_str(m.kind).to_string(),
                text: m.text,
                start: m.start as u32,
                end: m.end as u32,
                offset: m.abs_offset.map(|o| o as u64),
            })
            .collect()
    }

    #[pyfunction]
    #[pyo3(name = "search_bytes")]
    #[pyo3(signature = (data, min_length=4, max_samples=40, max_scan_bytes=1_048_576, time_guard_ms=10, defang_normalize=true, max_matches_total=10_000, max_matches_per_kind=1_000))]
    fn search_bytes_py(
        data: &[u8],
        min_length: usize,
        max_samples: usize,
        max_scan_bytes: usize,
        time_guard_ms: u64,
        defang_normalize: bool,
        max_matches_total: usize,
        max_matches_per_kind: usize,
    ) -> Vec<SearchMatch> {
        let mut cfg = crate::strings::StringsConfig::default();
        cfg.min_length = min_length;
        cfg.max_samples = max_samples;
        cfg.max_scan_bytes = max_scan_bytes;
        cfg.time_guard_ms = time_guard_ms;
        cfg.enable_language = false;
        cfg.enable_classification = false;
        let budget = crate::strings::search::SearchBudget {
            max_matches_total,
            max_matches_per_kind,
            time_guard_ms,
        };
        let mut matches = crate::strings::search::scan_bytes(data, &cfg, &budget);
        if defang_normalize {
            // Re-run normalization on extracted text where practical
            for m in matches.iter_mut() {
                let n = crate::strings::normalize::normalize_defanged(&m.text, 64 * 1024);
                if let std::borrow::Cow::Owned(s) = n {
                    m.text = s;
                }
            }
        }
        matches
            .into_iter()
            .map(|m| SearchMatch {
                kind: to_kind_str(m.kind).to_string(),
                text: m.text,
                start: m.start as u32,
                end: m.end as u32,
                offset: m.abs_offset.map(|o| o as u64),
            })
            .collect()
    }

    #[pyfunction]
    #[pyo3(name = "similarity_score")]
    #[pyo3(signature = (a, b, algo="jaro_winkler"))]
    fn similarity_score_py(a: &str, b: &str, algo: &str) -> f64 {
        let algo = match algo.to_ascii_lowercase().as_str() {
            "jaro" => crate::strings::similarity::SimilarityAlgo::Jaro,
            "damerau" | "dl" => {
                crate::strings::similarity::SimilarityAlgo::NormalizedDamerauLevenshtein
            }
            "sorensen" | "dice" => crate::strings::similarity::SimilarityAlgo::SorensenDice,
            _ => crate::strings::similarity::SimilarityAlgo::JaroWinkler,
        };
        crate::strings::similarity::score(algo, a, b)
    }

    #[pyfunction]
    #[pyo3(name = "similarity_best_match")]
    #[pyo3(signature = (query, candidates, algo="jaro_winkler", min_score=0.85, max_candidates=10000, max_len=128))]
    fn similarity_best_match_py(
        query: &str,
        candidates: Vec<String>,
        algo: &str,
        min_score: f64,
        max_candidates: usize,
        max_len: usize,
    ) -> Option<(String, f64)> {
        let algo = match algo.to_ascii_lowercase().as_str() {
            "jaro" => crate::strings::similarity::SimilarityAlgo::Jaro,
            "damerau" | "dl" => {
                crate::strings::similarity::SimilarityAlgo::NormalizedDamerauLevenshtein
            }
            "sorensen" | "dice" => crate::strings::similarity::SimilarityAlgo::SorensenDice,
            _ => crate::strings::similarity::SimilarityAlgo::JaroWinkler,
        };
        crate::strings::similarity::best_match(
            query,
            candidates.iter().map(|s| s.as_str()),
            algo,
            min_score,
            max_candidates,
            max_len,
        )
        .map(|(s, sc)| (s.to_string(), sc))
    }

    #[pyfunction]
    #[pyo3(name = "similarity_top_k")]
    #[pyo3(signature = (query, candidates, k=5, algo="jaro_winkler", min_score=0.6, max_candidates=10000, max_len=128))]
    fn similarity_top_k_py(
        query: &str,
        candidates: Vec<String>,
        k: usize,
        algo: &str,
        min_score: f64,
        max_candidates: usize,
        max_len: usize,
    ) -> Vec<(String, f64)> {
        let algo = match algo.to_ascii_lowercase().as_str() {
            "jaro" => crate::strings::similarity::SimilarityAlgo::Jaro,
            "damerau" | "dl" => {
                crate::strings::similarity::SimilarityAlgo::NormalizedDamerauLevenshtein
            }
            "sorensen" | "dice" => crate::strings::similarity::SimilarityAlgo::SorensenDice,
            _ => crate::strings::similarity::SimilarityAlgo::JaroWinkler,
        };
        crate::strings::similarity::top_k(
            query,
            candidates.iter().map(|s| s.as_str()),
            algo,
            min_score,
            k,
            max_candidates,
            max_len,
        )
        .into_iter()
        .map(|(s, sc)| (s.to_string(), sc))
        .collect()
    }

    strings_mod.add_class::<SearchMatch>()?;
    strings_mod.add_function(wrap_pyfunction!(defang_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(search_text_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(search_bytes_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(similarity_score_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(similarity_best_match_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(similarity_top_k_py, &strings_mod)?)?;
    // Demangling helpers
    #[pyfunction]
    #[pyo3(name = "demangle_text")]
    fn demangle_text_py(text: &str) -> Option<(String, String)> {
        crate::demangle::demangle_one(text).map(|r| {
            let flavor = match r.flavor {
                crate::demangle::SymbolFlavor::Rust => "rust",
                crate::demangle::SymbolFlavor::Itanium => "itanium",
                crate::demangle::SymbolFlavor::Msvc => "msvc",
                crate::demangle::SymbolFlavor::Unknown => "unknown",
            };
            (r.demangled, flavor.to_string())
        })
    }
    #[pyfunction]
    #[pyo3(name = "demangle_list")]
    #[pyo3(signature = (names, max=10000))]
    fn demangle_list_py(names: Vec<String>, max: usize) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        let mut count = 0usize;
        for n in names {
            if count >= max {
                break;
            }
            if let Some(r) = crate::demangle::demangle_one(&n) {
                let flavor = match r.flavor {
                    crate::demangle::SymbolFlavor::Rust => "rust",
                    crate::demangle::SymbolFlavor::Itanium => "itanium",
                    crate::demangle::SymbolFlavor::Msvc => "msvc",
                    crate::demangle::SymbolFlavor::Unknown => "unknown",
                };
                out.push((n, r.demangled, flavor.to_string()));
                count += 1;
            }
        }
        out
    }
    strings_mod.add_function(wrap_pyfunction!(demangle_text_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(demangle_list_py, &strings_mod)?)?;
    m.add_submodule(&strings_mod)?;

    // Top-level submodule: disasm
    let disasm_mod = pyo3::types::PyModule::new(py, "disasm")?;
    disasm_mod.add_class::<crate::disasm::py_api::PyDisassembler>()?;
    disasm_mod.add_function(wrap_pyfunction!(
        crate::disasm::py_api::disassembler_for_path_py,
        &disasm_mod
    )?)?;
    disasm_mod.add_function(wrap_pyfunction!(
        crate::disasm::py_api::disassemble_window_py,
        &disasm_mod
    )?)?;
    disasm_mod.add_function(wrap_pyfunction!(
        crate::disasm::py_api::disassemble_window_at_py,
        &disasm_mod
    )?)?;
    m.add_submodule(&disasm_mod)?;

    // Top-level submodule: symbols
    let sym_mod = pyo3::types::PyModule::new(py, "symbols")?;
    sym_mod.add_function(wrap_pyfunction!(crate::symbols::list_symbols_py, &sym_mod)?)?;
    sym_mod.add_class::<crate::symbols::SymbolSummary>()?;
    sym_mod.add_function(wrap_pyfunction!(imphash_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(analyze_exports_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(analyze_env_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(
        crate::symbols::list_symbols_demangled_py,
        &sym_mod
    )?)?;
    // Suspicious import utilities
    #[pyfunction]
    #[pyo3(name = "detect_suspicious_imports")]
    #[pyo3(signature = (names, max_out=128))]
    fn detect_suspicious_imports_py(names: Vec<String>, max_out: usize) -> Vec<String> {
        crate::symbols::analysis::suspicious::detect_suspicious_imports(&names, max_out)
    }
    #[pyfunction]
    #[pyo3(name = "set_suspicious_imports")]
    #[pyo3(signature = (names, clear=true))]
    fn set_suspicious_imports_py(names: Vec<String>, clear: bool) -> usize {
        crate::symbols::analysis::suspicious::set_extra_apis(names.into_iter(), clear)
    }
    #[pyfunction]
    #[pyo3(name = "load_capa_apis")]
    #[pyo3(signature = (path, clear=false, limit=5000))]
    fn load_capa_apis_py(path: String, clear: bool, limit: usize) -> PyResult<usize> {
        let p = std::path::Path::new(&path);
        crate::symbols::analysis::suspicious::load_capa_apis_from_path(p, limit, clear)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{e}")))
    }
    sym_mod.add_function(wrap_pyfunction!(detect_suspicious_imports_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(set_suspicious_imports_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(load_capa_apis_py, &sym_mod)?)?;
    m.add_submodule(&sym_mod)?;

    // Top-level submodule: analysis (function discovery, CFG)
    let analysis_mod = pyo3::types::PyModule::new(py, "analysis")?;
    // Entry detection helpers
    #[pyfunction]
    #[pyo3(name = "detect_entry_bytes")]
    fn detect_entry_bytes_py(data: &[u8]) -> Option<(String, String, String, u64, Option<usize>)> {
        if let Some(info) = crate::analysis::entry::detect_entry(data) {
            let fmt = format!("{}", info.format);
            let arch = format!("{}", info.arch);
            let end = format!("{}", info.endianness);
            return Some((fmt, arch, end, info.entry_va, info.file_offset));
        }
        None
    }
    #[pyfunction]
    #[pyo3(name = "detect_entry_path")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
    fn detect_entry_path_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
    ) -> PyResult<Option<(String, String, String, u64, Option<usize>)>> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        Ok(detect_entry_bytes_py(&data))
    }
    #[pyfunction]
    #[pyo3(name = "analyze_functions_bytes")]
    #[pyo3(signature = (data, max_functions=16usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=100u64))]
    fn analyze_functions_bytes_py(
        data: &[u8],
        max_functions: usize,
        max_blocks: usize,
        max_instructions: usize,
        timeout_ms: u64,
    ) -> (
        Vec<crate::core::function::Function>,
        crate::core::call_graph::CallGraph,
    ) {
        let budgets = crate::analysis::cfg::Budgets {
            max_functions,
            max_blocks,
            max_instructions,
            timeout_ms,
        };
        crate::analysis::cfg::analyze_functions_bytes(data, &budgets)
    }
    #[pyfunction]
    #[pyo3(name = "analyze_functions_path")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64, max_functions=16usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=100u64))]
    fn analyze_functions_path_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
        max_functions: usize,
        max_blocks: usize,
        max_instructions: usize,
        timeout_ms: u64,
    ) -> PyResult<(
        Vec<crate::core::function::Function>,
        crate::core::call_graph::CallGraph,
    )> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        let budgets = crate::analysis::cfg::Budgets {
            max_functions,
            max_blocks,
            max_instructions,
            timeout_ms,
        };
        Ok(crate::analysis::cfg::analyze_functions_bytes(
            &data, &budgets,
        ))
    }
    analysis_mod.add_function(wrap_pyfunction!(detect_entry_bytes_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(detect_entry_path_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(analyze_functions_bytes_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(analyze_functions_path_py, &analysis_mod)?)?;
    // Map VA to file offset for a given file
    // Map VA to file offset for a given file
    #[pyfunction]
    #[pyo3(name = "va_to_file_offset_path")]
    #[pyo3(signature = (path, va, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
    fn va_to_file_offset_path_py(
        path: String,
        va: u64,
        max_read_bytes: u64,
        max_file_size: u64,
    ) -> PyResult<Option<usize>> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        Ok(crate::analysis::entry::va_to_file_offset(&data, va))
    }
    analysis_mod.add_function(wrap_pyfunction!(va_to_file_offset_path_py, &analysis_mod)?)?;
    // ELF PLT map helper
    #[pyfunction]
    #[pyo3(name = "elf_plt_map_path")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
    fn elf_plt_map_path_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
    ) -> PyResult<Vec<(u64, String)>> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        Ok(crate::analysis::elf_plt::elf_plt_map(&data))
    }
    analysis_mod.add_function(wrap_pyfunction!(elf_plt_map_path_py, &analysis_mod)?)?;
    // ELF GOT map helper
    #[pyfunction]
    #[pyo3(name = "elf_got_map_path")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
    fn elf_got_map_path_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
    ) -> PyResult<Vec<(u64, String)>> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        Ok(crate::analysis::elf_got::elf_got_map(&data))
    }
    analysis_mod.add_function(wrap_pyfunction!(elf_got_map_path_py, &analysis_mod)?)?;
    // PE IAT map helper
    #[pyfunction]
    #[pyo3(name = "pe_iat_map_path")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
    fn pe_iat_map_path_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
    ) -> PyResult<Vec<(u64, String)>> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        Ok(crate::analysis::pe_iat::pe_iat_map(&data))
    }
    analysis_mod.add_function(wrap_pyfunction!(pe_iat_map_path_py, &analysis_mod)?)?;
    m.add_submodule(&analysis_mod)?;

    // Top-level helper: symbol address map for a file
    #[pyfunction]
    #[pyo3(name = "symbol_address_map")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
    fn symbol_address_map_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
    ) -> PyResult<Vec<(u64, String)>> {
        use object::read::Object;
        use object::ObjectSymbol;
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        let mut out: Vec<(u64, String)> = Vec::new();
        if let Ok(obj) = object::read::File::parse(&data[..]) {
            for sym in obj.symbols() {
                if sym.is_definition() {
                    if let (Ok(name), addr) = (sym.name(), sym.address()) {
                        let s = name.to_string();
                        if !s.is_empty() {
                            out.push((addr, s));
                        }
                    }
                }
            }
            for sym in obj.dynamic_symbols() {
                if sym.is_definition() {
                    if let (Ok(name), addr) = (sym.name(), sym.address()) {
                        let s = name.to_string();
                        if !s.is_empty() {
                            out.push((addr, s));
                        }
                    }
                }
            }
        }
        // Dedup by address, keep first name
        out.sort_by_key(|(a, _)| *a);
        out.dedup_by_key(|(a, _)| *a);
        Ok(out)
    }
    m.add_function(wrap_pyfunction!(symbol_address_map_py, m)?)?;

    // Top-level submodule: similarity (CTPH fuzzy hashing)
    let similarity_mod = pyo3::types::PyModule::new(py, "similarity")?;
    // CTPH wrappers
    #[pyfunction]
    #[pyo3(name = "ctph_hash_bytes")]
    #[pyo3(signature = (data, window_size=8, digest_size=4, precision=8))]
    fn ctph_hash_bytes_py(
        data: &[u8],
        window_size: usize,
        digest_size: usize,
        precision: u8,
    ) -> String {
        let cfg = crate::similarity::CtphConfig {
            window_size,
            digest_size,
            precision,
        };
        crate::similarity::ctph_hash(data, &cfg)
    }

    #[pyfunction]
    #[pyo3(name = "ctph_hash_path")]
    #[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600, window_size=8, digest_size=4, precision=8))]
    fn ctph_hash_path_py(
        path: String,
        max_read_bytes: u64,
        max_file_size: u64,
        window_size: usize,
        digest_size: usize,
        precision: u8,
    ) -> PyResult<String> {
        let limit = std::cmp::min(max_read_bytes, max_file_size);
        let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
        let cfg = crate::similarity::CtphConfig {
            window_size,
            digest_size,
            precision,
        };
        Ok(crate::similarity::ctph_hash(&data, &cfg))
    }

    #[pyfunction]
    #[pyo3(name = "ctph_similarity")]
    fn ctph_similarity_py(a: &str, b: &str) -> f64 {
        crate::similarity::ctph_similarity(a, b)
    }

    #[pyfunction]
    #[pyo3(name = "ctph_recommended_params")]
    fn ctph_recommended_params_py(length: usize) -> (usize, usize, u8) {
        // Simple heuristic tuned for typical binary sizes
        if length < 16 * 1024 {
            (8, 4, 8)
        } else if length < 1 * 1024 * 1024 {
            (16, 5, 16)
        } else {
            (32, 6, 16)
        }
    }

    #[pyfunction]
    #[pyo3(name = "ctph_pairwise_matrix")]
    #[pyo3(signature = (digests, max_pairs=250_000))]
    fn ctph_pairwise_matrix_py(digests: Vec<String>, max_pairs: usize) -> Vec<(usize, usize, f64)> {
        let n = digests.len();
        let mut out = Vec::new();
        let mut count = 0usize;
        for i in 0..n {
            for j in (i + 1)..n {
                if count >= max_pairs {
                    return out;
                }
                let s = crate::similarity::ctph_similarity(&digests[i], &digests[j]);
                out.push((i, j, s));
                count += 1;
            }
        }
        out
    }

    #[pyfunction]
    #[pyo3(name = "ctph_top_k")]
    #[pyo3(signature = (query_digest, candidates, k=5, min_score=0.6, max_candidates=10000))]
    fn ctph_top_k_py(
        query_digest: &str,
        candidates: Vec<String>,
        k: usize,
        min_score: f64,
        max_candidates: usize,
    ) -> Vec<(String, f64)> {
        let mut scored: Vec<(String, f64)> = Vec::new();
        for (idx, c) in candidates.into_iter().enumerate() {
            if idx >= max_candidates {
                break;
            }
            let s = crate::similarity::ctph_similarity(query_digest, &c);
            if s >= min_score {
                scored.push((c, s));
            }
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        scored
    }

    similarity_mod.add_function(wrap_pyfunction!(ctph_hash_bytes_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_hash_path_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_similarity_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(
        ctph_recommended_params_py,
        &similarity_mod
    )?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_pairwise_matrix_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_top_k_py, &similarity_mod)?)?;
    m.add_submodule(&similarity_mod)?;

    // Register logging functions
    m.add_function(wrap_pyfunction!(crate::logging::init_logging, m)?)?;
    m.add_function(wrap_pyfunction!(crate::logging::log_message, m)?)?;
    m.add_class::<crate::logging::LogLevel>()?;

    Ok(())
}
