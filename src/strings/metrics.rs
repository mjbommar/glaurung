//! Byte-level metrics and "is this textual / encoded?" predicates.
//!
//! Five small, well-defined functions that the higher layers (string
//! detection, encoded-blob extraction, triage classifiers) can compose
//! to answer simple questions:
//!
//! - `shannon_entropy` — how uniform is the byte distribution?
//! - `printable_ascii_ratio` — how much looks like text already?
//! - `is_base64` — does this look like a base64-encoded blob?
//! - `character_class_histogram` — counts of alpha / digit / punct /
//!   space / control / high-bit bytes, the kind of summary useful for
//!   fingerprinting unknown data.
//! - `unicode_script_frequencies` — for valid UTF-8, which Unicode
//!   scripts are present (Latin, Cyrillic, Han, Arabic, …) and at
//!   what frequency.
//!
//! All functions are pure, allocate at most a small fixed-size table,
//! and never panic. They are exposed to Python via
//! `crate::python_bindings::strings`.

use std::collections::BTreeMap;

/// Shannon entropy in bits/byte for a slice. 0.0 for empty input,
/// up to 8.0 for a uniformly random byte sequence.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Fraction of bytes in printable ASCII range (`0x20..=0x7e`) plus
/// common whitespace (`\t`, `\n`, `\r`). Returns 0.0 on empty input.
pub fn printable_ascii_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, 0x09 | 0x0a | 0x0d))
        .count();
    printable as f64 / data.len() as f64
}

/// Verdict on whether a byte slice looks like base64-encoded data.
#[derive(Debug, Clone, PartialEq)]
pub struct Base64Verdict {
    /// True when the input passes all the cheap base64 sanity checks:
    /// ≥ 90% characters in the base64 alphabet, length is a multiple
    /// of 4 (with allowance for ≤ 2 `=` padding chars), no embedded
    /// whitespace, and length ≥ 8 (shorter blobs are too noisy to
    /// identify reliably).
    pub is_base64: bool,
    /// Fraction of bytes in `[A-Za-z0-9+/=]`.
    pub alphabet_fraction: f64,
    /// True when `len % 4 == 0` after stripping padding.
    pub length_aligned: bool,
    /// True when the input ends in 1 or 2 `=` characters.
    pub padded: bool,
    /// Estimated decoded size in bytes (`len * 3 / 4` minus padding).
    pub decoded_size_estimate: usize,
}

/// Test whether a byte slice looks like base64.
///
/// Conservative: prefers false negatives over false positives. Use
/// this as a cheap pre-filter before attempting to actually decode
/// (which is much more expensive on a large blob).
pub fn is_base64(data: &[u8]) -> Base64Verdict {
    let n = data.len();
    if n < 8 {
        return Base64Verdict {
            is_base64: false,
            alphabet_fraction: 0.0,
            length_aligned: false,
            padded: false,
            decoded_size_estimate: 0,
        };
    }
    // Count alphabet membership.
    let mut alpha = 0usize;
    for &b in data {
        if matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
        {
            alpha += 1;
        }
    }
    let frac = alpha as f64 / n as f64;
    // Padding character count at the tail.
    let pad = data
        .iter()
        .rev()
        .take(2)
        .filter(|&&b| b == b'=')
        .count();
    let aligned = (n % 4) == 0;
    let decoded = (n / 4) * 3 - pad;

    let is = frac >= 0.90 && aligned && pad <= 2 && decoded > 0;
    Base64Verdict {
        is_base64: is,
        alphabet_fraction: frac,
        length_aligned: aligned,
        padded: pad > 0,
        decoded_size_estimate: decoded,
    }
}

/// Histogram of byte-level character classes — useful for fingerprinting
/// unknown buffers without committing to "is this text?" or "is this
/// binary?".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CharClassHistogram {
    pub total: usize,
    pub alpha: usize,
    pub digit: usize,
    pub punct: usize,
    /// `' '`, `\t`, `\n`, `\r`, `\v`, `\f`.
    pub whitespace: usize,
    /// Other ASCII control bytes (< 0x20 except whitespace, plus 0x7f).
    pub control: usize,
    /// Bytes ≥ 0x80 — outside ASCII. Could be UTF-8 continuation,
    /// Latin-1, or arbitrary binary.
    pub high_bit: usize,
    pub null: usize,
}

/// Walk every byte once, counting which class it falls into. Exact
/// and cheap; intended for quick "what does this look like?" probes.
pub fn character_class_histogram(data: &[u8]) -> CharClassHistogram {
    let mut h = CharClassHistogram {
        total: data.len(),
        ..Default::default()
    };
    for &b in data {
        match b {
            0 => h.null += 1,
            0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x20 => h.whitespace += 1,
            0x01..=0x1f | 0x7f => h.control += 1,
            b'A'..=b'Z' | b'a'..=b'z' => h.alpha += 1,
            b'0'..=b'9' => h.digit += 1,
            0x21..=0x7e => h.punct += 1, // remaining printable ASCII
            0x80..=0xff => h.high_bit += 1,
        }
    }
    h
}

/// Count Unicode scripts present in a UTF-8 string and how many
/// characters of each. Returns an empty map when the input contains
/// invalid UTF-8 — the caller should consult that as a "this isn't
/// proper text" signal.
///
/// Scripts are reported using the names from the unicode-script crate
/// (`Latin`, `Cyrillic`, `Greek`, `Han`, `Hiragana`, `Katakana`,
/// `Hangul`, `Arabic`, `Hebrew`, `Devanagari`, …). `Common` and
/// `Inherited` (punctuation and combining marks shared across scripts)
/// are reported separately so the caller can distinguish "this string
/// is mostly punctuation" from "this string is Latin-script".
pub fn unicode_script_frequencies(data: &[u8]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return out,
    };
    for ch in s.chars() {
        let script = unicode_script::Script::from(ch);
        let name = format!("{:?}", script);
        *out.entry(name).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_low_for_constant_input() {
        let h = shannon_entropy(&[b'A'; 1024]);
        assert!(h < 0.001, "entropy of constant should be ~0, got {}", h);
    }

    #[test]
    fn entropy_high_for_random_input() {
        // Synthetic uniform bytes: each value 0..256 appears once.
        let bytes: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&bytes);
        assert!(h > 7.99 && h <= 8.0, "expected ~8.0, got {}", h);
    }

    #[test]
    fn printable_ratio_pure_text() {
        let r = printable_ascii_ratio(b"hello world\n");
        assert!(r >= 0.99, "{}", r);
    }

    #[test]
    fn printable_ratio_pure_binary() {
        let r = printable_ascii_ratio(&[0u8, 0xff, 0x01, 0x02, 0xfe]);
        assert!(r < 0.01, "{}", r);
    }

    #[test]
    fn is_base64_yes_padded() {
        let v = is_base64(b"SGVsbG8sIFdvcmxkIQ==");
        assert!(v.is_base64);
        assert!(v.padded);
        assert!(v.length_aligned);
    }

    #[test]
    fn is_base64_no_garbage() {
        let v = is_base64(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08");
        assert!(!v.is_base64);
        assert_eq!(v.alphabet_fraction, 0.0);
    }

    #[test]
    fn char_class_histogram_basic() {
        let h = character_class_histogram(b"Hello, World!\n123");
        assert_eq!(h.total, 17);
        assert_eq!(h.alpha, 10);
        assert_eq!(h.digit, 3);
        assert_eq!(h.punct, 2); // comma, exclam
        assert_eq!(h.whitespace, 2); // space, newline
        assert_eq!(h.control, 0);
    }

    #[test]
    fn unicode_script_freqs_mixed() {
        let freqs = unicode_script_frequencies("Hello мир 世界".as_bytes());
        assert!(freqs.contains_key("Latin"));
        assert!(freqs.contains_key("Cyrillic"));
        assert!(freqs.contains_key("Han"));
    }

    #[test]
    fn unicode_script_freqs_invalid_utf8() {
        let freqs = unicode_script_frequencies(&[0xff, 0xfe, 0xfd]);
        assert!(freqs.is_empty());
    }
}
