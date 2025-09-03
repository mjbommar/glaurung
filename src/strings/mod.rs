//! Top-level string extraction and analysis utilities.
//!
//! This module provides bounded, configurable string scanning, optional
//! language detection, and hooks for IOC-focused classification. It is
//! designed for reuse across early triage and deeper analyses.

mod classify;
mod config;
pub mod detect;
pub mod normalize;
pub mod patterns;
mod scan;
pub mod search;
pub mod similarity;

pub use config::StringsConfig;

use crate::core::triage::{DetectedString, IocSample, StringsSummary};
use crate::strings::search::{MatchKind, SearchBudget};
use std::collections::HashMap;

/// Extract strings summary from raw bytes using the provided configuration.
///
/// Produces counts, sampled strings (encoding + offsets), and aggregated
/// language/script histograms when enabled.
pub fn extract_summary(data: &[u8], cfg: &StringsConfig) -> StringsSummary {
    let start = std::time::Instant::now();

    // Phase 1: scan encodings under byte/time limits
    let scanned = scan::scan_strings(data, cfg, start);

    // Phase 2: assemble sampled DetectedString set (bounded by max_samples)
    let mut detected_strings: Vec<DetectedString> = Vec::new();
    let mut language_counts: HashMap<String, u32> = HashMap::new();
    let mut script_counts: HashMap<String, u32> = HashMap::new();

    // Helper closure: annotate with language when enabled and within budget
    let mut lang_budget_remaining = cfg.max_lang_detect;
    let mut annotate = |text: &str| -> (Option<String>, Option<String>, Option<f64>) {
        if cfg.enable_language
            && lang_budget_remaining > 0
            && text.len() >= cfg.min_len_for_detect
            && detect::is_texty_for_lang(text)
        {
            lang_budget_remaining = lang_budget_remaining.saturating_sub(1);
            let (l, s, c) = detect::detect_string_language(text);
            if let Some(conf) = c {
                if conf >= 0.5 {
                    return (l, s, Some(conf));
                }
            }
            (None, None, None)
        } else {
            (None, None, None)
        }
    };

    // Select ASCII first
    for (text, offset) in scanned
        .ascii_strings
        .iter()
        .take(cfg.max_samples.saturating_sub(detected_strings.len()))
    {
        let (language, script, confidence) = annotate(text);
        if let Some(ref l) = language {
            *language_counts.entry(l.clone()).or_insert(0) += 1;
        }
        if let Some(ref s) = script {
            *script_counts.entry(s.clone()).or_insert(0) += 1;
        }
        detected_strings.push(DetectedString::new(
            text.clone(),
            "ascii".to_string(),
            language,
            script,
            confidence,
            Some(*offset as u64),
        ));
    }

    // Then UTF-16LE
    for (text, offset) in scanned
        .utf16le_strings
        .iter()
        .take(cfg.max_samples.saturating_sub(detected_strings.len()))
    {
        let (language, script, confidence) = annotate(text);
        if let Some(ref l) = language {
            *language_counts.entry(l.clone()).or_insert(0) += 1;
        }
        if let Some(ref s) = script {
            *script_counts.entry(s.clone()).or_insert(0) += 1;
        }
        detected_strings.push(DetectedString::new(
            text.clone(),
            "utf16le".to_string(),
            language,
            script,
            confidence,
            Some(*offset as u64),
        ));
    }

    // Finally UTF-16BE
    for (text, offset) in scanned
        .utf16be_strings
        .iter()
        .take(cfg.max_samples.saturating_sub(detected_strings.len()))
    {
        let (language, script, confidence) = annotate(text);
        if let Some(ref l) = language {
            *language_counts.entry(l.clone()).or_insert(0) += 1;
        }
        if let Some(ref s) = script {
            *script_counts.entry(s.clone()).or_insert(0) += 1;
        }
        detected_strings.push(DetectedString::new(
            text.clone(),
            "utf16be".to_string(),
            language,
            script,
            confidence,
            Some(*offset as u64),
        ));
    }

    // Optional: classify IOCs across detected strings under budget
    let (ioc_counts, ioc_samples) = if cfg.enable_classification {
        let mut texts: Vec<&str> = Vec::new();
        for (t, _) in &scanned.ascii_strings {
            if texts.len() >= cfg.max_classify {
                break;
            }
            texts.push(t);
        }
        for (t, _) in &scanned.utf16le_strings {
            if texts.len() >= cfg.max_classify {
                break;
            }
            texts.push(t);
        }
        for (t, _) in &scanned.utf16be_strings {
            if texts.len() >= cfg.max_classify {
                break;
            }
            texts.push(t);
        }
        let counts = classify::classify_texts(texts, cfg.max_ioc_per_string);
        let counts_opt = if counts.is_empty() {
            None
        } else {
            Some(counts)
        };

        // Gather a few IOC samples with offsets for downstream tooling
        let budget = SearchBudget {
            max_matches_total: cfg.max_ioc_samples,
            max_matches_per_kind: cfg.max_ioc_per_string,
            time_guard_ms: cfg.time_guard_ms,
        };
        let mut samples: Vec<IocSample> = Vec::new();
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for m in search::scan_bytes(data, cfg, &budget) {
            let kind = match m.kind {
                MatchKind::Url => "url",
                MatchKind::Email => "email",
                MatchKind::Hostname => "hostname",
                MatchKind::Domain => "domain",
                MatchKind::Ipv4 => "ipv4",
                MatchKind::Ipv6 => "ipv6",
                MatchKind::PathWindows => "path_windows",
                MatchKind::PathUNC => "path_unc",
                MatchKind::PathPosix => "path_posix",
                MatchKind::Registry => "registry",
                MatchKind::JavaPath => "java_path",
                MatchKind::CIdentifier => "c_identifier",
                MatchKind::ItaniumMangled => "itanium_mangled",
                MatchKind::MsvcMangled => "msvc_mangled",
            };
            let key = (kind.to_string(), m.text.clone());
            if seen.insert(key) {
                let off = m.abs_offset.map(|x| x as u64);
                let text = if m.text.len() > 512 {
                    m.text[..512].to_string()
                } else {
                    m.text
                };
                samples.push(IocSample::new(kind.to_string(), text, off));
                if samples.len() >= cfg.max_ioc_samples {
                    break;
                }
            }
        }
        let samples_opt = if samples.is_empty() {
            None
        } else {
            Some(samples)
        };
        (counts_opt, samples_opt)
    } else {
        (None, None)
    };

    // Build summary with new fields
    StringsSummary {
        ascii_count: scanned.ascii_count,
        utf8_count: scanned.utf8_count,
        utf16le_count: scanned.utf16le_count,
        utf16be_count: scanned.utf16be_count,
        strings: if detected_strings.is_empty() {
            None
        } else {
            Some(detected_strings)
        },
        language_counts: if language_counts.is_empty() {
            None
        } else {
            Some(language_counts)
        },
        script_counts: if script_counts.is_empty() {
            None
        } else {
            Some(script_counts)
        },
        ioc_counts,
        ioc_samples,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_summary_defaults_includes_language_counts_under_budget() {
        let data = b"This is an English sentence.\x00Bonjour le monde.";
        let cfg = StringsConfig {
            min_length: 6,
            max_samples: 10,
            max_lang_detect: 1, // only annotate the first string
            ..StringsConfig::default()
        };
        let summary = extract_summary(data, &cfg);
        assert!(summary.ascii_count >= 1);
        let counts = summary.language_counts.as_ref().unwrap();
        // Only one detection should be counted due to budget
        let total: u32 = counts.values().copied().sum();
        assert_eq!(total, 1);
    }
}
