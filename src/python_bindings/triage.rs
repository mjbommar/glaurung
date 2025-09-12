//! Python bindings for triage functionality.
//!
//! This module contains all Python bindings related to binary triage,
//! including analysis functions and configuration types.

use pyo3::prelude::*;

/// Register triage-related Python bindings.
pub fn register_triage_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create triage submodule
    let triage = pyo3::types::PyModule::new(py, "triage")?;

    // Register triage core types
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
    triage.add_function(wrap_pyfunction!(language_detection_py, &triage)?)?;

    // Raw engine accessors for experiments
    triage.add_function(wrap_pyfunction!(detect_language_whatlang_py, &triage)?)?;
    triage.add_function(wrap_pyfunction!(detect_language_lingua_py, &triage)?)?;

    // Batch ensemble detection with Rayon
    triage.add_function(wrap_pyfunction!(detect_languages_py, &triage)?)?;

    // Add triage submodule to main module
    m.add_submodule(&triage)?;

    Ok(())
}

/// Language detection helper for debugging.
#[pyfunction]
#[pyo3(name = "detect_language")]
#[pyo3(signature = (text, min_size=4, min_conf=0.5, agree_conf=0.4))]
fn language_detection_py(
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

/// Raw engine accessors for experiments.
#[pyfunction]
#[pyo3(name = "detect_language_whatlang")]
#[pyo3(signature = (text))]
fn detect_language_whatlang_py(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    crate::strings::detect::detect_with_whatlang(text)
}

#[pyfunction]
#[pyo3(name = "detect_language_lingua")]
#[pyo3(signature = (text))]
fn detect_language_lingua_py(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    crate::strings::detect::detect_with_lingua(text)
}

/// Batch ensemble detection with Rayon.
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
