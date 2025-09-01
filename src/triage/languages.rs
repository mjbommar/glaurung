//! Language detection for extracted strings using whatlang.

use crate::core::triage::{DetectedString, StringsSummary};
use std::collections::HashMap;
use whatlang::{detect, Lang, Script};

/// Minimum string length for language detection (whatlang needs reasonable text)
const MIN_LANG_DETECT_LENGTH: usize = 10;

/// Maximum number of strings to detect language for (performance)
const MAX_LANG_DETECT_STRINGS: usize = 100;

/// Convert whatlang Lang to string representation
fn lang_to_string(lang: Lang) -> String {
    format!("{:?}", lang).to_lowercase()
}

/// Convert whatlang Script to string representation
fn script_to_string(script: Script) -> String {
    format!("{:?}", script)
}

/// Detect language for a single string
pub fn detect_string_language(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    if text.len() < MIN_LANG_DETECT_LENGTH {
        return (None, None, None);
    }

    match detect(text) {
        Some(info) => {
            let lang = lang_to_string(info.lang());
            let script = script_to_string(info.script());
            let confidence = info.confidence();
            (Some(lang), Some(script), Some(confidence))
        }
        None => (None, None, None),
    }
}

/// Extract strings with language detection
pub fn extract_with_languages(
    data: &[u8],
    min_string_length: usize,
    max_samples: usize,
) -> StringsSummary {
    const MAX_SCAN: usize = 1_048_576; // 1 MiB cap
    let scan = &data[..data.len().min(MAX_SCAN)];

    let mut detected_strings: Vec<DetectedString> = Vec::new();
    let mut ascii_count: u32 = 0;
    let mut utf16le_count: u32 = 0;
    let mut utf16be_count: u32 = 0;
    let mut language_counts: HashMap<String, u32> = HashMap::new();
    let mut script_counts: HashMap<String, u32> = HashMap::new();

    // Extract ASCII strings with language detection
    let mut cur: Vec<u8> = Vec::new();
    let mut cur_offset: usize = 0;

    for (i, &b) in scan.iter().enumerate() {
        if (b.is_ascii_graphic() || b == b'\t' || b == b' ') && b != b'\x7f' {
            if cur.is_empty() {
                cur_offset = i;
            }
            cur.push(b);
        } else {
            if cur.len() >= min_string_length {
                ascii_count = ascii_count.saturating_add(1);

                if detected_strings.len() < max_samples {
                    if let Ok(text) = String::from_utf8(cur.clone()) {
                        let (language, script, confidence) =
                            if detected_strings.len() < MAX_LANG_DETECT_STRINGS {
                                detect_string_language(&text)
                            } else {
                                (None, None, None)
                            };

                        // Update counts
                        if let Some(ref lang) = language {
                            *language_counts.entry(lang.clone()).or_insert(0) += 1;
                        }
                        if let Some(ref scr) = script {
                            *script_counts.entry(scr.clone()).or_insert(0) += 1;
                        }

                        detected_strings.push(DetectedString::new(
                            text,
                            "ascii".to_string(),
                            language,
                            script,
                            confidence,
                            Some(cur_offset as u64),
                        ));
                    }
                }
            }
            cur.clear();
        }
    }

    // Handle final string
    if cur.len() >= min_string_length {
        ascii_count = ascii_count.saturating_add(1);
        if detected_strings.len() < max_samples {
            if let Ok(text) = String::from_utf8(cur.clone()) {
                let (language, script, confidence) =
                    if detected_strings.len() < MAX_LANG_DETECT_STRINGS {
                        detect_string_language(&text)
                    } else {
                        (None, None, None)
                    };

                if let Some(ref lang) = language {
                    *language_counts.entry(lang.clone()).or_insert(0) += 1;
                }
                if let Some(ref scr) = script {
                    *script_counts.entry(scr.clone()).or_insert(0) += 1;
                }

                detected_strings.push(DetectedString::new(
                    text,
                    "ascii".to_string(),
                    language,
                    script,
                    confidence,
                    Some(cur_offset as u64),
                ));
            }
        }
    }

    // UTF-16LE extraction with language detection
    let mut utf16le_strings: Vec<(String, usize)> = Vec::new();
    let mut run_le: Vec<u16> = Vec::new();
    let mut run_le_offset: usize = 0;

    for (i, chunk) in scan.chunks_exact(2).enumerate() {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        if ch == 0 {
            if run_le.len() >= min_string_length {
                if let Ok(text) = String::from_utf16(&run_le) {
                    utf16le_strings.push((text, run_le_offset));
                    utf16le_count = utf16le_count.saturating_add(1);
                }
            }
            run_le.clear();
        } else if ch < 128 && (ch as u8).is_ascii_graphic() {
            if run_le.is_empty() {
                run_le_offset = i * 2;
            }
            run_le.push(ch);
        } else {
            if run_le.len() >= min_string_length {
                if let Ok(text) = String::from_utf16(&run_le) {
                    utf16le_strings.push((text, run_le_offset));
                    utf16le_count = utf16le_count.saturating_add(1);
                }
            }
            run_le.clear();
        }
    }

    // Add UTF-16LE strings to detected_strings
    for (text, offset) in utf16le_strings
        .iter()
        .take(max_samples.saturating_sub(detected_strings.len()))
    {
        let (language, script, confidence) = if detected_strings.len() < MAX_LANG_DETECT_STRINGS {
            detect_string_language(text)
        } else {
            (None, None, None)
        };

        if let Some(ref lang) = language {
            *language_counts.entry(lang.clone()).or_insert(0) += 1;
        }
        if let Some(ref scr) = script {
            *script_counts.entry(scr.clone()).or_insert(0) += 1;
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

    // UTF-16BE extraction with language detection
    let mut utf16be_strings: Vec<(String, usize)> = Vec::new();
    let mut run_be: Vec<u16> = Vec::new();
    let mut run_be_offset: usize = 0;

    for (i, chunk) in scan.chunks_exact(2).enumerate() {
        let ch = u16::from_be_bytes([chunk[0], chunk[1]]);
        if ch == 0 {
            if run_be.len() >= min_string_length {
                if let Ok(text) = String::from_utf16(&run_be) {
                    utf16be_strings.push((text, run_be_offset));
                    utf16be_count = utf16be_count.saturating_add(1);
                }
            }
            run_be.clear();
        } else if ch < 128 && (ch as u8).is_ascii_graphic() {
            if run_be.is_empty() {
                run_be_offset = i * 2;
            }
            run_be.push(ch);
        } else {
            if run_be.len() >= min_string_length {
                if let Ok(text) = String::from_utf16(&run_be) {
                    utf16be_strings.push((text, run_be_offset));
                    utf16be_count = utf16be_count.saturating_add(1);
                }
            }
            run_be.clear();
        }
    }

    // Add UTF-16BE strings to detected_strings
    for (text, offset) in utf16be_strings
        .iter()
        .take(max_samples.saturating_sub(detected_strings.len()))
    {
        let (language, script, confidence) = if detected_strings.len() < MAX_LANG_DETECT_STRINGS {
            detect_string_language(text)
        } else {
            (None, None, None)
        };

        if let Some(ref lang) = language {
            *language_counts.entry(lang.clone()).or_insert(0) += 1;
        }
        if let Some(ref scr) = script {
            *script_counts.entry(scr.clone()).or_insert(0) += 1;
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

    StringsSummary::new(
        ascii_count,
        utf16le_count,
        utf16be_count,
        if detected_strings.is_empty() {
            None
        } else {
            Some(detected_strings)
        },
        if language_counts.is_empty() {
            None
        } else {
            Some(language_counts)
        },
        if script_counts.is_empty() {
            None
        } else {
            Some(script_counts)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_english() {
        let text = "This is a test string in English language for detection.";
        let (lang, script, conf) = detect_string_language(text);
        assert!(lang.is_some());
        assert_eq!(lang.unwrap(), "eng");
        assert_eq!(script.unwrap(), "Latin");
        assert!(conf.unwrap() > 0.8);
    }

    #[test]
    fn test_detect_short_string() {
        let text = "Hello";
        let (lang, script, conf) = detect_string_language(text);
        assert!(lang.is_none());
        assert!(script.is_none());
        assert!(conf.is_none());
    }

    #[test]
    fn test_extract_with_languages() {
        let data = b"This is a longer English string for language detection testing. Another test string here.";
        let summary = extract_with_languages(data, 4, 10);

        assert!(summary.ascii_count > 0);
        assert!(summary.strings.is_some());

        let strings = summary.strings.unwrap();
        assert!(!strings.is_empty());

        // Check that at least one string has language detected
        let has_lang = strings.iter().any(|s| s.language.is_some());
        assert!(has_lang);
    }

    #[test]
    fn test_language_counts() {
        let data = b"This is English text. This is another English sentence. Ceci est du texte en francais.";
        let summary = extract_with_languages(data, 10, 10);

        assert!(summary.language_counts.is_some());
        let counts = summary.language_counts.unwrap();
        assert!(counts.contains_key("eng") || counts.contains_key("fra"));
    }
}
