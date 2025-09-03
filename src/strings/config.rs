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
            min_len_for_detect: 10,
            enable_classification: true,
            max_classify: 200,
            max_ioc_per_string: 16,
            max_ioc_samples: 50,
        }
    }
}
