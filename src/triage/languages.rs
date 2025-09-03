//! Compatibility wrappers that forward to the top-level `crate::strings` module.

use crate::core::triage::StringsSummary;

/// Detect language for a single string (for legacy callers).
pub fn detect_string_language(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    // Use the shared detector (no local min-length check; caller can decide)
    crate::strings::detect::detect_string_language(text)
}

/// Extract strings with language detection (legacy call site).
pub fn extract_with_languages(
    data: &[u8],
    min_string_length: usize,
    max_samples: usize,
) -> StringsSummary {
    let cfg = crate::strings::StringsConfig {
        min_length: min_string_length,
        max_samples,
        ..Default::default()
    };
    crate::strings::extract_summary(data, &cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_with_languages_wrapper() {
        let data = b"This is a longer English string for language detection testing. Another test string here.";
        let summary = extract_with_languages(data, 4, 10);
        assert!(summary.ascii_count > 0);
    }
}
