//! Fast language detection optimized for malware analysis.

use crate::strings::detect::detect_with_whatlang_cached;
use rayon::prelude::*;

// Limited language set handled explicitly in acceptance below.

// Optimized thresholds for binary analysis
const MIN_STRING_LENGTH: usize = 6; // Shorter strings unreliable
const MAX_STRING_LENGTH: usize = 400; // Allow longer sentences
const MIN_ENTROPY: f64 = 1.6; // Below this is repetitive
const MAX_ENTROPY: f64 = 7.5; // Above this is likely encrypted/compressed
const MIN_VOWEL_RATIO: f32 = 0.17; // Natural language heuristic (Latin-like)

/// Calculate Shannon entropy of a string
fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts = std::collections::HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for count in char_counts.values() {
        let probability = (*count as f64) / len;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Fast pre-filter to determine if string should be analyzed
pub fn should_detect_language(s: &str) -> bool {
    // Length filter
    let char_count = s.chars().count();
    if char_count < MIN_STRING_LENGTH || char_count > MAX_STRING_LENGTH {
        return false;
    }

    // Calculate metrics in single pass for efficiency
    let mut letter_count = 0;
    let mut letter_ascii = 0;
    let mut vowel_count = 0;
    let mut has_underscore = false;
    let mut has_digit = false;
    let mut has_space = false;
    let mut has_lowercase = false;
    let mut _printable_count = 0;

    for c in s.chars() {
        if !c.is_control() {
            _printable_count += 1;
        }
        if c.is_alphabetic() {
            letter_count += 1;
            if c.is_ascii() && c.is_ascii_alphabetic() {
                letter_ascii += 1;
            }
            if c.is_lowercase() {
                has_lowercase = true;
            }
            let lower_c = c.to_ascii_lowercase();
            if matches!(lower_c, 'a' | 'e' | 'i' | 'o' | 'u') {
                vowel_count += 1;
            }
        }
        if c == '_' {
            has_underscore = true;
        }
        if c.is_ascii_digit() {
            has_digit = true;
        }
        if c == ' ' {
            has_space = true;
        }
    }

    // Skip likely code identifiers
    if has_underscore || (has_digit && !has_space) {
        return false;
    }

    // Skip all-caps constants without spaces
    if !has_space && !has_lowercase && char_count >= 6 {
        return false;
    }

    // Vowel ratio check for Latin-like texts only (avoid penalizing non-Latin)
    if letter_ascii > 0 && (letter_ascii as f32) / (letter_count as f32).max(1.0) >= 0.7 {
        let vowel_ratio = vowel_count as f32 / letter_ascii as f32;
        if vowel_ratio < MIN_VOWEL_RATIO {
            return false;
        }
    }

    // Entropy check (do this last as it's more expensive)
    let entropy = calculate_shannon_entropy(s);
    if entropy < MIN_ENTROPY || entropy > MAX_ENTROPY {
        return false;
    }

    true
}

/// Fast single-string language detection using whatlang only
pub fn detect_language_fast(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    if !should_detect_language(text) {
        return (None, None, None);
    }
    // Length-aware acceptance thresholds
    let len = text.chars().count();
    let min_conf = if len < 12 {
        0.90
    } else if len < 32 {
        0.85
    } else if len > 96 {
        0.75
    } else {
        0.80
    };

    let (lang, script, conf) = detect_with_whatlang_cached(text);
    if let Some(l) = &lang {
        let info_conf = conf.unwrap_or(0.0);
        // Accept only target languages unless extremely confident
        let allowed = match l.as_str() {
            "eng" => true,
            "cmn" => true,
            "rus" => true,
            "spa" => true,
            "ara" => true,
            _ => info_conf > 0.97,
        };
        if allowed && info_conf >= min_conf {
            return (lang, script, conf);
        }
        return (None, script, conf);
    }
    (None, None, None)
}

/// Batch language detection result
#[derive(Debug, Clone)]
pub struct BatchLangResult {
    pub lang: Option<String>,
    pub script: Option<String>,
    pub confidence: Option<f64>,
    pub string_index: usize,
}

/// Parallel batch processing of strings
pub fn detect_languages_batch(strings: &[String]) -> Vec<BatchLangResult> {
    strings
        .par_iter()
        .enumerate()
        .map(|(idx, s)| {
            let (lang, script, conf) = detect_language_fast(s);
            BatchLangResult {
                lang,
                script,
                confidence: conf,
                string_index: idx,
            }
        })
        .collect()
}

/// Smart sampling strategy for large string sets
pub fn detect_languages_smart_sample(
    strings: &[String],
    max_sample: usize,
) -> Vec<BatchLangResult> {
    // Sample diverse strings based on length distribution
    let mut sampled_indices = Vec::new();

    if strings.len() <= max_sample {
        // Process all if under limit
        return detect_languages_batch(strings);
    }

    // Group strings by length buckets
    let mut length_buckets: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();

    for (idx, s) in strings.iter().enumerate() {
        let bucket = (s.len() / 10) * 10; // 10-char buckets
        length_buckets
            .entry(bucket)
            .or_insert_with(Vec::new)
            .push(idx);
    }

    // Sample proportionally from each bucket
    let samples_per_bucket = max_sample / length_buckets.len().max(1);

    for (_, indices) in length_buckets.iter() {
        let take_count = samples_per_bucket.min(indices.len());
        // Take first N from each bucket (could randomize)
        sampled_indices.extend(&indices[..take_count]);

        if sampled_indices.len() >= max_sample {
            break;
        }
    }

    // Process sampled strings in parallel
    sampled_indices
        .par_iter()
        .map(|&idx| {
            let s: &String = &strings[idx];
            let (lang, script, conf) = detect_language_fast(s.as_str());
            BatchLangResult {
                lang,
                script,
                confidence: conf,
                string_index: idx,
            }
        })
        .collect()
}

/// Language statistics for quick consensus
#[derive(Debug, Clone)]
pub struct LangStats {
    pub dominant_language: Option<String>,
    pub dominant_script: Option<String>,
    pub confidence: f64,
    pub language_counts: std::collections::HashMap<String, usize>,
    pub total_detected: usize,
}

/// Analyze batch results for consensus
pub fn analyze_language_consensus(results: &[BatchLangResult]) -> LangStats {
    let mut lang_counts = std::collections::HashMap::new();
    let mut script_counts = std::collections::HashMap::new();
    let mut total_confidence = 0.0;
    let mut detected_count = 0;

    for result in results {
        if let Some(ref lang) = result.lang {
            *lang_counts.entry(lang.clone()).or_insert(0) += 1;
            detected_count += 1;
        }
        if let Some(ref script) = result.script {
            *script_counts.entry(script.clone()).or_insert(0) += 1;
        }
        if let Some(conf) = result.confidence {
            total_confidence += conf;
        }
    }

    // Find dominant language
    let dominant_language = lang_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(lang, _)| lang.clone());

    // Find dominant script
    let dominant_script = script_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(script, _)| script.clone());

    LangStats {
        dominant_language,
        dominant_script,
        confidence: if detected_count > 0 {
            total_confidence / detected_count as f64
        } else {
            0.0
        },
        language_counts: lang_counts,
        total_detected: detected_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        assert!(calculate_shannon_entropy("AAAAAAAA") < 1.0); // Low entropy
        assert!(calculate_shannon_entropy("abcdefgh") > 2.0); // Higher entropy
        assert!(calculate_shannon_entropy("a1b2c3d4") > 2.5); // Mixed entropy
    }

    #[test]
    fn test_should_detect_language() {
        // Should pass
        assert!(should_detect_language("This is a normal English sentence"));
        assert!(should_detect_language("Error loading configuration file"));

        // Should fail - too short
        assert!(!should_detect_language("abc"));

        // Should fail - no vowels
        assert!(!should_detect_language("bcdfghjklmnpqrstvwxyz"));

        // Should fail - looks like code
        assert!(!should_detect_language("get_user_data"));
        assert!(!should_detect_language("CONSTANT_VALUE"));

        // Should fail - high entropy (likely encrypted)
        assert!(!should_detect_language("a9$k2@p5#m8&q3"));
    }

    #[test]
    fn test_fast_detection() {
        let text = "This is definitely an English sentence with high confidence";
        let (lang, script, conf) = detect_language_fast(text);
        assert_eq!(lang, Some("eng".to_string()));
        assert_eq!(script, Some("Latin".to_string()));
        assert!(conf.unwrap() > 0.8);
    }

    #[test]
    fn test_batch_processing() {
        let strings = vec![
            "This is English text".to_string(),
            "Another English sentence".to_string(),
            "get_data_from_server".to_string(), // Should be filtered
            "ABC123".to_string(),               // Should be filtered
        ];

        let results = detect_languages_batch(&strings);
        assert_eq!(results.len(), 4);

        // Check that code-like strings were filtered
        assert!(results[2].lang.is_none());
        assert!(results[3].lang.is_none());
    }
}
