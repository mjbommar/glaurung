//! Identifier scanning.
//!
//! `scan_identifier` is the shortest and most shared sublanguage in `scan`:
//! `super::number::scan_number` reuses it to measure a numeric suffix, and a
//! front end's own lexer reuses it again for keyword lookup. Kept to a
//! single function because there is nothing else language-neutral left to
//! say about an identifier once `super::ScanConfig`'s two knobs are
//! applied.

use super::{is_ident_continue, is_ident_start, utf8_len, ScanConfig};

/// The length of the identifier at `at`, or 0 if none starts there:
/// `[A-Za-z_]` then `[A-Za-z0-9_]`, plus `$` and non-ASCII characters under the
/// [`ScanConfig`] knobs that admit them. A length rather than a struct because
/// there is nothing else to report --- the text is the front end's to intern,
/// and whether it is a keyword is a language question this module must not
/// answer (`REQ-SYN-1`). The length always lands on a character boundary, so
/// `&text[at..at + len]` is safe for any `at` that was one.
pub fn scan_identifier(text: &str, at: usize, cfg: ScanConfig) -> usize {
    let bytes = text.as_bytes();
    let end = bytes.len();
    let start = at.min(end);
    let Some(&first) = bytes.get(start) else {
        return 0;
    };
    if !is_ident_start(first, cfg) {
        return 0;
    }
    let mut index = (start + utf8_len(first)).min(end);
    while let Some(&b) = bytes.get(index) {
        if !is_ident_continue(b, cfg) {
            break;
        }
        index = (index + utf8_len(b)).min(end);
    }
    index - start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_at_the_end_of_input_is_measured_to_the_end() {
        let cfg = ScanConfig::C;
        assert_eq!(scan_identifier("abc", 0, cfg), 3);
        assert_eq!(scan_identifier("x", 0, cfg), 1);
        assert_eq!(scan_identifier("_a9", 0, cfg), 3);
        assert_eq!(scan_identifier("9a", 0, cfg), 0);
        assert_eq!(scan_identifier("a b", 0, cfg), 1);
        assert_eq!(scan_identifier("", 0, cfg), 0);
    }

    #[test]
    fn a_dollar_sign_and_a_non_ascii_byte_join_an_identifier_only_when_configured() {
        let cfg = ScanConfig::C;
        assert_eq!(scan_identifier("a$b", 0, cfg), 1);
        let gnu = ScanConfig {
            dollar_in_identifiers: true,
            ..ScanConfig::C
        };
        assert_eq!(scan_identifier("a$b", 0, gnu), 3);
        assert_eq!(scan_identifier("$x", 0, gnu), 2);
        assert_eq!(
            scan_identifier("café", 0, cfg),
            3,
            "ASCII stops at the accent"
        );
        assert_eq!(scan_identifier("café", 0, ScanConfig::RUST), 5);
    }
}
