//! Language detection helpers.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use whatlang::{detect, Lang, Script};

// Optional lingua detector for short texts
static LINGUA_DETECTOR: Lazy<lingua::LanguageDetector> = Lazy::new(|| {
    lingua::LanguageDetectorBuilder::from_all_languages()
        .with_preloaded_language_models()
        .build()
});

// Defaults; the configurable version is exposed via
// detect_string_language_with_thresholds. This fallback keeps
// compatibility for legacy callers (e.g., src/triage/languages.rs).
const MIN_SIZE: usize = 4;
const MAX_LINGUA_LEN: usize = 32;
const LRU_CAPACITY_PER_ENGINE: usize = 8192;

type DetectTuple = (Option<String>, Option<String>, Option<f64>);

struct SimpleLru<V: Clone> {
    cap: usize,
    tick: u64,
    map: HashMap<u64, (V, u64)>,
}

impl<V: Clone> SimpleLru<V> {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            tick: 0,
            map: HashMap::with_capacity(cap),
        }
    }
    fn get(&mut self, k: &u64) -> Option<V> {
        if let Some((v, t)) = self.map.get_mut(k) {
            self.tick = self.tick.wrapping_add(1);
            *t = self.tick;
            Some(v.clone())
        } else {
            None
        }
    }
    fn put(&mut self, k: u64, v: V) {
        self.tick = self.tick.wrapping_add(1);
        if self.map.len() >= self.cap && !self.map.contains_key(&k) {
            // Evict least-recently-used (min tick)
            if let Some((&old_k, _)) = self
                .map
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, v)| (k, v))
            {
                self.map.remove(&old_k);
            }
        }
        self.map.insert(k, (v, self.tick));
    }
}

static WHATLANG_CACHE: Lazy<Mutex<SimpleLru<DetectTuple>>> =
    Lazy::new(|| Mutex::new(SimpleLru::new(LRU_CAPACITY_PER_ENGINE)));

static LINGUA_CACHE: Lazy<Mutex<SimpleLru<DetectTuple>>> =
    Lazy::new(|| Mutex::new(SimpleLru::new(LRU_CAPACITY_PER_ENGINE)));

fn text_hash(s: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Structured detection result used by the refactored API.
#[derive(Debug, Clone)]
pub struct Detection {
    pub language: Option<String>,
    pub script: Option<String>,
    pub confidence: Option<f64>,
}

impl Detection {
    pub fn none() -> Self {
        Self {
            language: None,
            script: None,
            confidence: None,
        }
    }
    pub fn tuple(self) -> (Option<String>, Option<String>, Option<f64>) {
        (self.language, self.script, self.confidence)
    }
}

/// Unified router controlling engine selection and thresholds.
#[derive(Debug, Clone)]
pub struct LanguageRouter {
    pub min_size: usize,
    pub max_lingua_len: usize,
    pub min_conf_disagree: f64,
    pub min_conf_agree: f64,
    pub strict_texty: bool,
    pub fast_mode: bool,
}

impl LanguageRouter {
    pub fn from_cfg(cfg: &crate::strings::config::StringsConfig) -> Self {
        Self {
            min_size: cfg.min_len_for_detect,
            max_lingua_len: cfg.max_len_for_lingua,
            min_conf_disagree: cfg.min_lang_confidence,
            min_conf_agree: cfg.min_lang_confidence_agree,
            strict_texty: cfg.texty_strict,
            fast_mode: cfg.use_fast_detection,
        }
    }

    pub fn detect(&self, text: &str) -> Detection {
        if !is_texty_for_lang_with_policy(text, self.strict_texty) {
            return Detection::none();
        }
        if self.fast_mode {
            let (l, s, c) = crate::strings::detect_fast::detect_language_fast(text);
            return Detection {
                language: l,
                script: s,
                confidence: c,
            };
        }
        let (l, s, c) =
            detect_string_language_with_thresholds(text, self.min_size, self.max_lingua_len);
        Detection {
            language: l,
            script: s,
            confidence: c,
        }
    }
}

/// Pluggable engine interface for language detection.
pub trait LanguageEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, text: &str) -> Detection;
}

pub struct WhatlangEngine;
impl LanguageEngine for WhatlangEngine {
    fn name(&self) -> &'static str {
        "whatlang"
    }
    fn detect(&self, text: &str) -> Detection {
        let (l, s, c) = detect_with_whatlang_cached(text);
        Detection {
            language: l,
            script: s,
            confidence: c,
        }
    }
}

pub struct LinguaEngine;
impl LanguageEngine for LinguaEngine {
    fn name(&self) -> &'static str {
        "lingua"
    }
    fn detect(&self, text: &str) -> Detection {
        let (l, s, c) = detect_with_lingua_cached(text);
        Detection {
            language: l,
            script: s,
            confidence: c,
        }
    }
}

/// Convert whatlang Lang to string representation (lowercase debug name)
fn lang_to_string(lang: Lang) -> String {
    format!("{:?}", lang).to_lowercase()
}

/// Convert whatlang Script to string representation
fn script_to_string(script: Script) -> String {
    format!("{:?}", script)
}

fn lingua_lang_to_iso639_3_lower(lang: &lingua::Language) -> String {
    // Lingua returns uppercase codes; normalize to lowercase
    lang.iso_code_639_3().to_string().to_lowercase()
}

fn lingua_script_for(lang: &lingua::Language) -> Option<String> {
    // Only report script if language uniquely maps to one script to avoid misleading info
    use lingua::Language as L;
    let single = L::all_with_single_unique_script();
    if !single.contains(lang) {
        return None;
    }
    if L::all_with_latin_script().contains(lang) {
        return Some("Latin".to_string());
    }
    if L::all_with_cyrillic_script().contains(lang) {
        return Some("Cyrillic".to_string());
    }
    if L::all_with_devanagari_script().contains(lang) {
        return Some("Devanagari".to_string());
    }
    if L::all_with_arabic_script().contains(lang) {
        return Some("Arabic".to_string());
    }
    None
}

/// Detect language for a single string.
/// Returns (lang_iso639_3, script, confidence)
pub fn detect_string_language(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    detect_string_language_with_thresholds(text, MIN_SIZE, MAX_LINGUA_LEN)
}

/// Configurable version used by the triage pipeline, wired via StringsConfig.
pub fn detect_string_language_with_thresholds(
    text: &str,
    min_size: usize,
    max_lingua_len: usize,
) -> (Option<String>, Option<String>, Option<f64>) {
    // Route engines by length: lingua for short text, whatlang for long text,
    // and fall back to ensemble for medium where it helps precision.
    let len = text.chars().count();
    if len < min_size {
        return (None, None, None);
    }
    if len <= max_lingua_len {
        // Short: ensemble helps most
        return detect_string_language_ensemble(text, min_size, 0.65, 0.55);
    }
    if len > max_lingua_len * 2 {
        // Long: whatlang only with moderate floor
        let (l, s, c) = detect_with_whatlang_cached(text);
        if c.unwrap_or(0.0) >= 0.60 {
            return (l, s, c);
        }
        return (None, s, c);
    }
    // Medium: prefer whatlang, accept if high confidence, else run ensemble
    let (wl, ws, wc) = detect_with_whatlang_cached(text);
    if wc.unwrap_or(0.0) >= 0.75 {
        return (wl, ws, wc);
    }
    detect_string_language_ensemble(text, min_size, 0.65, 0.55)
}

/// Ensemble strategy: run both engines. If both agree, accept; if they differ,
/// accept the one above `min_conf` (pick the higher if both exceed threshold);
/// otherwise return None.
pub fn detect_string_language_ensemble(
    text: &str,
    min_size: usize,
    min_conf_disagree: f64,
    min_conf_agree: f64,
) -> (Option<String>, Option<String>, Option<f64>) {
    let len = text.chars().count();
    if len < min_size {
        return (None, None, None);
    }

    // Length-aware routing: skip lingua for long strings to save time
    let (l_lang, l_script, l_conf) = if len <= MAX_LINGUA_LEN {
        detect_with_lingua_cached(text)
    } else {
        (None, None, None)
    };
    let (w_lang, w_script, w_conf) = detect_with_whatlang_cached(text);

    match (l_lang.clone(), w_lang.clone()) {
        (Some(ll), Some(wl)) if ll == wl => {
            let script = w_script.or(l_script);
            let conf = match (l_conf, w_conf) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            if conf.unwrap_or(0.0) >= min_conf_agree {
                return (Some(ll), script, conf);
            } else {
                // Keep script only when agreement confidence is low
                return (None, script, conf);
            }
        }
        _ => {
            let lc = l_conf.unwrap_or(0.0);
            let wc = w_conf.unwrap_or(0.0);
            // Prefer lingua on very short strings; prefer whatlang on medium/long
            if len <= 12 {
                if lc.max(wc) < min_conf_disagree {
                    return (None, l_script.or(w_script), l_conf.or(w_conf));
                }
                if lc >= 0.65 && lc >= wc {
                    return (l_lang, l_script, l_conf);
                }
                if wc >= 0.90 {
                    return (w_lang, w_script, w_conf);
                }
            } else if len > MAX_LINGUA_LEN {
                if wc >= min_conf_disagree {
                    return (w_lang, w_script, w_conf);
                }
            } else {
                // Medium length: choose higher if passes floor, slightly higher floor for whatlang
                if lc >= wc && lc >= min_conf_disagree {
                    return (l_lang, l_script, l_conf);
                }
                if wc >= (min_conf_disagree + 0.05) {
                    return (w_lang, w_script, w_conf);
                }
            }
        }
    }
    (None, None, None)
}

/// Strict textiness predicate variant; applies additional heuristics to reduce false positives
pub fn is_texty_for_lang_with_policy(s: &str, strict: bool) -> bool {
    // Basic checks first
    if !is_texty_for_lang(s) {
        return false;
    }
    if !strict {
        return true;
    }
    let len = s.chars().count();
    if len == 0 {
        return false;
    }
    let letters = s.chars().filter(|c| c.is_alphabetic()).count();
    let spaces = s.chars().filter(|&c| c == ' ').count();
    // Skip identifiers or tokens with underscores and digits mixed
    if s.contains('_') || (s.chars().any(|c| c.is_ascii_digit()) && s.find(' ').is_none()) {
        return false;
    }
    // Skip all-caps long tokens without spaces
    if s.find(' ').is_none() && s.chars().all(|c| !c.is_lowercase()) && len >= 6 {
        return false;
    }
    // Alpha+space ratio threshold for Latin-like text
    let alpha_space = letters + spaces;
    if alpha_space < (len as usize * 7 / 10) {
        // < 70%
        return false;
    }
    // Vowel ratio (simple heuristic for Latin)
    if len >= 8 {
        let vowels = s
            .to_lowercase()
            .chars()
            .filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
            .count();
        if letters > 0 && (vowels as f64) / (letters as f64) < 0.20 {
            return false;
        }
    }
    true
}

/// Direct whatlang detection (no thresholds). Returns (iso639_3_lower, script, confidence).
pub fn detect_with_whatlang(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
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

/// Cached whatlang detection
pub fn detect_with_whatlang_cached(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    let key = text_hash(text);
    if let Some(v) = WHATLANG_CACHE.lock().unwrap().get(&key) {
        return v;
    }
    let v = detect_with_whatlang(text);
    WHATLANG_CACHE.lock().unwrap().put(key, v.clone());
    v
}

/// Direct lingua detection (no thresholds). Returns (iso639_3_lower, script_if_unambiguous, confidence).
pub fn detect_with_lingua(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    if let Some(lang) = LINGUA_DETECTOR.detect_language_of(text) {
        let code = lingua_lang_to_iso639_3_lower(&lang);
        let script = lingua_script_for(&lang);
        let conf = LINGUA_DETECTOR.compute_language_confidence(text, lang);
        (Some(code), script, Some(conf))
    } else {
        (None, None, None)
    }
}

/// Cached lingua detection
pub fn detect_with_lingua_cached(text: &str) -> (Option<String>, Option<String>, Option<f64>) {
    let key = text_hash(text);
    if let Some(v) = LINGUA_CACHE.lock().unwrap().get(&key) {
        return v;
    }
    let v = detect_with_lingua(text);
    LINGUA_CACHE.lock().unwrap().put(key, v.clone());
    v
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

    #[test]
    fn router_detects_with_defaults() {
        let cfg = crate::strings::config::StringsConfig::default();
        let router = LanguageRouter::from_cfg(&cfg);
        let det = router.detect("Hello world this is a test of English detection.");
        assert!(det.language.is_some());
        assert_eq!(det.language.unwrap(), "eng");
    }
}
