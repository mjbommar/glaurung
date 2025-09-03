//! Language detection helpers.

use whatlang::{detect, Lang, Script};

/// Convert whatlang Lang to string representation (lowercase debug name)
fn lang_to_string(lang: Lang) -> String {
    format!("{:?}", lang).to_lowercase()
}

/// Convert whatlang Script to string representation
fn script_to_string(script: Script) -> String {
    format!("{:?}", script)
}

/// Detect language for a single string.
/// Returns (lang_iso639_3, script, confidence)
pub fn detect_string_language(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
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

/// Heuristic filter: treat only "texty" strings as eligible for language detection.
/// Skips tokens that look like code/class descriptors or are rich in punctuation typical of code.
pub fn is_texty_for_lang(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    // Common code-ish punctuation and JVM descriptors
    let bad_punct = ['/', '\\', ';', '$', ':', '<', '>', '[', ']', '(', ')'];
    if s.chars().any(|c| bad_punct.contains(&c)) {
        return false;
    }
    // Skip obvious JVM descriptors
    if s.starts_with('L') && s.contains("java/") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_english_for_long_text() {
        let text = "This is a reasonably long English sentence for detection to work properly.";
        let (lang, script, conf) = detect_string_language(text);
        assert!(lang.is_some());
        assert_eq!(lang.unwrap(), "eng");
        assert_eq!(script.unwrap(), "Latin");
        assert!(conf.unwrap() >= 0.5);
    }
}
