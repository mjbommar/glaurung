//! Top-level string extraction and analysis utilities.
//!
//! This module provides bounded, configurable string scanning, optional
//! language detection, and hooks for IOC-focused classification. It is
//! designed for reuse across early triage and deeper analyses.

mod classify;
mod config;
pub mod detect;
pub mod detect_fast;
pub mod normalize;
pub mod patterns;
mod scan;
pub mod search;
pub mod similarity;

pub use config::StringsConfig;

use crate::core::triage::{DetectedString, IocSample, StringsSummary};
use crate::strings::detect::LanguageRouter;
use crate::strings::search::{MatchKind, SearchBudget};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

    // Parallelize language detection with a shared atomic budget.
    const PAR_THRESHOLD: usize = 128;
    let budget = Arc::new(AtomicUsize::new(cfg.max_lang_detect));

    // Language router derived from config
    let router = LanguageRouter::from_cfg(cfg);

    // Helper to process a batch for a given encoding label
    let mut process_batch = |label: &str,
                             items: &[(String, usize)]|
     -> (
        Vec<DetectedString>,
        HashMap<String, u32>,
        HashMap<String, u32>,
    ) {
        if items.is_empty() {
            return (Vec::new(), HashMap::new(), HashMap::new());
        }
        let results: Vec<(Option<String>, Option<String>, Option<f64>)> =
            if items.len() >= PAR_THRESHOLD {
                items
                    .par_iter()
                    .map(|(text, _off)| {
                        if cfg.enable_language
                            && text.len() >= cfg.min_len_for_detect
                            && detect::is_texty_for_lang_with_policy(text, cfg.texty_strict)
                        {
                            // Attempt budget decrement
                            let mut ok = false;
                            loop {
                                let cur = budget.load(Ordering::Relaxed);
                                if cur == 0 {
                                    break;
                                }
                                if budget
                                    .compare_exchange_weak(
                                        cur,
                                        cur - 1,
                                        Ordering::SeqCst,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                                {
                                    ok = true;
                                    break;
                                }
                            }
                            if ok {
                                router.detect(text).tuple()
                            } else {
                                (None, None, None)
                            }
                        } else {
                            (None, None, None)
                        }
                    })
                    .collect()
            } else {
                items
                    .iter()
                    .map(|(text, _off)| {
                        if cfg.enable_language
                            && budget.load(Ordering::Relaxed) > 0
                            && text.len() >= cfg.min_len_for_detect
                            && detect::is_texty_for_lang_with_policy(text, cfg.texty_strict)
                        {
                            let mut ok = false;
                            loop {
                                let cur = budget.load(Ordering::Relaxed);
                                if cur == 0 {
                                    break;
                                }
                                if budget
                                    .compare_exchange_weak(
                                        cur,
                                        cur - 1,
                                        Ordering::SeqCst,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                                {
                                    ok = true;
                                    break;
                                }
                            }
                            if ok {
                                router.detect(text).tuple()
                            } else {
                                (None, None, None)
                            }
                        } else {
                            (None, None, None)
                        }
                    })
                    .collect()
            };

        let mut batch_ds: Vec<DetectedString> = Vec::with_capacity(items.len());
        let mut lang_local: HashMap<String, u32> = HashMap::new();
        let mut script_local: HashMap<String, u32> = HashMap::new();
        for ((text, off), (language, script, confidence)) in items.iter().zip(results.into_iter()) {
            if let Some(ref l) = language {
                *lang_local.entry(l.clone()).or_insert(0) += 1;
            }
            if let Some(ref s) = script {
                *script_local.entry(s.clone()).or_insert(0) += 1;
            }
            batch_ds.push(DetectedString::new(
                text.clone(),
                label.to_string(),
                language,
                script,
                confidence,
                Some(*off as u64),
            ));
        }
        (batch_ds, lang_local, script_local)
    };

    // Prepare capped batches and process in order (ASCII, UTF-16LE, UTF-16BE)
    let cap_ascii = cfg.max_samples.saturating_sub(detected_strings.len());
    let ascii_items: Vec<(String, usize)> = scanned
        .ascii_strings
        .iter()
        .take(cap_ascii)
        .cloned()
        .collect();
    {
        let (mut v, lc, sc) = process_batch("ascii", &ascii_items);
        detected_strings.append(&mut v);
        for (k, v) in lc {
            *language_counts.entry(k).or_insert(0) += v;
        }
        for (k, v) in sc {
            *script_counts.entry(k).or_insert(0) += v;
        }
    }

    let cap_u16le = cfg.max_samples.saturating_sub(detected_strings.len());
    let u16le_items: Vec<(String, usize)> = scanned
        .utf16le_strings
        .iter()
        .take(cap_u16le)
        .cloned()
        .collect();
    {
        let (mut v, lc, sc) = process_batch("utf16le", &u16le_items);
        detected_strings.append(&mut v);
        for (k, v) in lc {
            *language_counts.entry(k).or_insert(0) += v;
        }
        for (k, v) in sc {
            *script_counts.entry(k).or_insert(0) += v;
        }
    }

    let cap_u16be = cfg.max_samples.saturating_sub(detected_strings.len());
    let u16be_items: Vec<(String, usize)> = scanned
        .utf16be_strings
        .iter()
        .take(cap_u16be)
        .cloned()
        .collect();
    {
        let (mut v, lc, sc) = process_batch("utf16be", &u16be_items);
        detected_strings.append(&mut v);
        for (k, v) in lc {
            *language_counts.entry(k).or_insert(0) += v;
        }
        for (k, v) in sc {
            *script_counts.entry(k).or_insert(0) += v;
        }
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
            // Convert to BTreeMap for stable serialization order
            let mut bt: BTreeMap<String, u32> = BTreeMap::new();
            for (k, v) in counts.into_iter() {
                bt.insert(k, v);
            }
            Some(bt)
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
    // Convert language/script counters into deterministic order maps
    let lang_counts_bt = if language_counts.is_empty() {
        None
    } else {
        let mut bt: BTreeMap<String, u32> = BTreeMap::new();
        for (k, v) in language_counts.into_iter() {
            bt.insert(k, v);
        }
        Some(bt)
    };
    let script_counts_bt = if script_counts.is_empty() {
        None
    } else {
        let mut bt: BTreeMap<String, u32> = BTreeMap::new();
        for (k, v) in script_counts.into_iter() {
            bt.insert(k, v);
        }
        Some(bt)
    };

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
        language_counts: lang_counts_bt,
        script_counts: script_counts_bt,
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
