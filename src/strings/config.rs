//! Configuration for bounded string extraction and detection.

#[derive(Debug, Clone)]
pub struct StringsConfig {
    /// Minimum length for a string candidate (in characters)
    pub min_length: usize,
    /// Maximum number of sampled strings to include in the summary
    pub max_samples: usize,
    /// Maximum number of bytes scanned from input
    pub max_scan_bytes: usize,
    /// Time guard for scanning/detection (milliseconds)
    pub time_guard_ms: u64,
    /// Whether to perform language detection
    pub enable_language: bool,
    /// Maximum number of strings to run language detection on
    pub max_lang_detect: usize,
    /// Minimum string length required to attempt language detection
    pub min_len_for_detect: usize,
    /// Maximum string length (in characters) to use lingua; longer strings use whatlang
    pub max_len_for_lingua: usize,
    /// Minimum confidence required to accept a language prediction
    pub min_lang_confidence: f64,
    /// Minimum confidence when both engines agree; below this keep script only
    pub min_lang_confidence_agree: f64,
    /// Apply stricter heuristic filtering for language eligibility
    pub texty_strict: bool,
    /// Use fast language detection mode optimized for malware analysis
    pub use_fast_detection: bool,
    /// Whether to perform IOC classification
    pub enable_classification: bool,
    /// Maximum number of strings to classify
    pub max_classify: usize,
    /// Maximum number of IOC matches to count per string per category
    pub max_ioc_per_string: usize,
    /// Maximum number of IOC match samples to include in summary
    pub max_ioc_samples: usize,
}

impl Default for StringsConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_samples: 40,
            max_scan_bytes: 1_048_576, // 1 MiB
            time_guard_ms: 10,
            enable_language: true,
            max_lang_detect: 100,
            min_len_for_detect: 4,
            max_len_for_lingua: 32,
            min_lang_confidence: 0.65,
            min_lang_confidence_agree: 0.55,
            texty_strict: false,
            use_fast_detection: true, // Default to fast mode for performance
            enable_classification: true,
            max_classify: 200,
            max_ioc_per_string: 16,
            max_ioc_samples: 50,
        }
    }
}
