//! Python bindings for string processing functionality.
//!
//! This module contains all Python bindings related to string extraction,
//! normalization, similarity, and language detection.

use pyo3::prelude::*;

/// Python-visible match object for string searches.
#[pyclass]
#[derive(Clone)]
pub struct SearchMatch {
    #[pyo3(get)]
    pub kind: String,
    #[pyo3(get)]
    pub text: String,
    #[pyo3(get)]
    pub start: u32,
    #[pyo3(get)]
    pub end: u32,
    #[pyo3(get)]
    pub offset: Option<u64>,
}

/// Register string-related Python bindings.
pub fn register_strings_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create strings submodule
    let strings_mod = pyo3::types::PyModule::new(py, "strings")?;

    // Register the SearchMatch class
    strings_mod.add_class::<SearchMatch>()?;

    // Register string processing functions
    strings_mod.add_function(wrap_pyfunction!(defang_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(search_text_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(search_bytes_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(similarity_score_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(similarity_best_match_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(similarity_top_k_py, &strings_mod)?)?;

    // Demangling helpers
    strings_mod.add_function(wrap_pyfunction!(demangle_text_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(demangle_list_py, &strings_mod)?)?;

    // Byte-level metrics (entropy, base64-likeness, char-class hist,
    // unicode script frequencies). Used by the embedded-content
    // extraction tools to identify what an unknown blob looks like.
    strings_mod.add_function(wrap_pyfunction!(shannon_entropy_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(printable_ascii_ratio_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(is_base64_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(character_class_histogram_py, &strings_mod)?)?;
    strings_mod.add_function(wrap_pyfunction!(unicode_script_frequencies_py, &strings_mod)?)?;
    // Reuse the existing triage `infer`-based content sniffer to
    // identify embedded blobs (jpeg / png / pdf / zip / executable
    // formats) — we already build the table once for triage; this
    // makes it callable per-bytes from Python.
    strings_mod.add_function(wrap_pyfunction!(sniff_bytes_py, &strings_mod)?)?;

    // Add strings submodule to main module
    m.add_submodule(&strings_mod)?;

    Ok(())
}

/// Convert internal MatchKind to string representation.
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

/// Defang text by normalizing suspicious patterns.
#[pyfunction]
#[pyo3(name = "defang")]
#[pyo3(signature = (text, max_len=4096))]
fn defang_py(text: &str, max_len: usize) -> String {
    crate::strings::normalize::normalize_defanged(text, max_len).into_owned()
}

/// Search for patterns in text.
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

/// Search for patterns in binary data.
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

/// Calculate similarity score between two strings.
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

/// Find best matching string from candidates.
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

/// Find top-k matching strings from candidates.
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

/// Demangle a single symbol.
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

/// Demangle a list of symbols.
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

// ----------------------------------------------------------------------------
// Byte-level metric bindings — see src/strings/metrics.rs for the underlying
// implementations.
// ----------------------------------------------------------------------------

/// Shannon entropy of a byte slice in bits/byte.
#[pyfunction]
#[pyo3(name = "shannon_entropy")]
fn shannon_entropy_py(data: &[u8]) -> f64 {
    crate::strings::metrics::shannon_entropy(data)
}

/// Fraction of bytes that are printable ASCII or common whitespace.
#[pyfunction]
#[pyo3(name = "printable_ascii_ratio")]
fn printable_ascii_ratio_py(data: &[u8]) -> f64 {
    crate::strings::metrics::printable_ascii_ratio(data)
}

/// Quick "does this look like base64?" verdict. Returns a dict with
/// keys `is_base64`, `alphabet_fraction`, `length_aligned`, `padded`,
/// `decoded_size_estimate`.
#[pyfunction]
#[pyo3(name = "is_base64")]
fn is_base64_py(py: Python<'_>, data: &[u8]) -> PyResult<PyObject> {
    let v = crate::strings::metrics::is_base64(data);
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("is_base64", v.is_base64)?;
    dict.set_item("alphabet_fraction", v.alphabet_fraction)?;
    dict.set_item("length_aligned", v.length_aligned)?;
    dict.set_item("padded", v.padded)?;
    dict.set_item("decoded_size_estimate", v.decoded_size_estimate)?;
    Ok(dict.into())
}

/// Character-class histogram. Returns a dict with keys `total`,
/// `alpha`, `digit`, `punct`, `whitespace`, `control`, `high_bit`,
/// `null`. Useful for fingerprinting unknown buffers.
#[pyfunction]
#[pyo3(name = "character_class_histogram")]
fn character_class_histogram_py(py: Python<'_>, data: &[u8]) -> PyResult<PyObject> {
    let h = crate::strings::metrics::character_class_histogram(data);
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("total", h.total)?;
    dict.set_item("alpha", h.alpha)?;
    dict.set_item("digit", h.digit)?;
    dict.set_item("punct", h.punct)?;
    dict.set_item("whitespace", h.whitespace)?;
    dict.set_item("control", h.control)?;
    dict.set_item("high_bit", h.high_bit)?;
    dict.set_item("null", h.null)?;
    Ok(dict.into())
}

/// Unicode script frequencies for valid UTF-8 input. Empty dict on
/// invalid UTF-8 — caller should treat that as "this isn't text".
/// Keys are script names (`Latin`, `Cyrillic`, `Han`, …).
#[pyfunction]
#[pyo3(name = "unicode_script_frequencies")]
fn unicode_script_frequencies_py(
    py: Python<'_>,
    data: &[u8],
) -> PyResult<PyObject> {
    let m = crate::strings::metrics::unicode_script_frequencies(data);
    let dict = pyo3::types::PyDict::new(py);
    for (k, v) in m {
        dict.set_item(k, v)?;
    }
    Ok(dict.into())
}

/// Identify the file-type of a byte slice using the same `infer`-based
/// content sniffer that the triage pipeline uses for top-level files.
/// Returns ``(mime, extension, label)`` or ``None`` when no signature
/// matches. Either of the strings may be empty when the sniffer found
/// only one of the three.
#[pyfunction]
#[pyo3(name = "sniff_bytes")]
fn sniff_bytes_py(data: &[u8]) -> Option<(String, String, String)> {
    if let Some(hint) = crate::triage::sniffers::ContentSniffer::sniff_bytes(data) {
        let mime = hint.mime.unwrap_or_default();
        let ext = hint.extension.unwrap_or_default();
        let label = hint.label.unwrap_or_default();
        if mime.is_empty() && ext.is_empty() && label.is_empty() {
            return None;
        }
        return Some((mime, ext, label));
    }
    None
}
