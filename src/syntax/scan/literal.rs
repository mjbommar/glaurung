//! String and character literal scanning, and escape decoding.
//!
//! `scan_string` and `scan_char` both bottom out in `scan_quoted`, whose loop
//! calls `scan_escape` for every backslash it meets; `decode_escapes` walks
//! the same escape grammar a second time to turn a reported extent into a
//! value. Escapes are kept in this file rather than split out again because
//! that call relationship is the whole reason the module doc gives for
//! decoding lazily (see the parent module doc) --- a literal and its escapes
//! are one sublanguage, not two.

use std::ops::Range;

use super::{digit_value, issue, newline_len, utf8_len, IssueKind, ScanConfig, ScanIssue};

/// The encoding prefix a literal carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LiteralPrefix {
    /// No prefix: an ordinary narrow literal.
    None,
    /// `L` --- `wchar_t`, whose width is a target property, not a lexical one.
    Wide,
    /// `u` --- UTF-16 in C11 and C++11.
    Utf16,
    /// `U` --- UTF-32.
    Utf32,
    /// `u8` --- UTF-8.
    Utf8,
    /// `b` --- Rust's byte literal, under [`ScanConfig::byte_prefix`] only.
    Byte,
}

/// Whether a literal was quoted with `"` or with `'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LiteralKind {
    /// A `"..."` string literal.
    String,
    /// A `'...'` character literal.
    Char,
}

/// A string or character literal's extent, prefix and content. The value is
/// deliberately absent: see the module documentation on lazy decoding, and
/// [`decode_escapes`] for the call that produces one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    /// Bytes occupied from the start offset, prefix and both quotes included.
    pub len: usize,
    /// The encoding prefix seen, if any.
    pub prefix: LiteralPrefix,
    /// String or character.
    pub kind: LiteralKind,
    /// Absolute byte range of the content between the quotes, exclusive of
    /// both. For an unterminated literal it ends where the scan stopped, so it
    /// is always a slicable range on character boundaries.
    pub content: Range<usize>,
    /// How many source characters and escapes the content holds --- the count a
    /// front end needs to reject `''` or to notice C's implementation-defined
    /// multi-character constant `'ab'`. **Not** the encoded length.
    pub elements: usize,
    /// Whether any escape appeared, so a front end can take the content
    /// verbatim when none did.
    pub has_escape: bool,
    /// Whether the closing quote was found.
    pub terminated: bool,
    /// Problems found. Empty --- and unallocated --- for a well-formed literal.
    pub issues: Vec<ScanIssue>,
}

/// Scan a string literal at `at`, with any of the prefixes `L`, `u`, `U`, `u8`
/// and (under [`ScanConfig::byte_prefix`]) `b`, or return `None` if none starts
/// there. Raw strings are not handled; see the module documentation.
pub fn scan_string(text: &str, at: usize, cfg: ScanConfig) -> Option<Literal> {
    scan_quoted(text, at, cfg, b'"', LiteralKind::String)
}

/// Scan a character literal at `at`, with the prefixes [`scan_string`] accepts,
/// or return `None` if none starts there. An empty `''` is reported rather than
/// rejected: whether it is an error is a language rule, and the lexer still
/// needs an extent so the parse continues.
pub fn scan_char(text: &str, at: usize, cfg: ScanConfig) -> Option<Literal> {
    scan_quoted(text, at, cfg, b'\'', LiteralKind::Char)
}

/// The prefix at `at` and its length, if it is followed by `quote`.
fn literal_prefix(
    bytes: &[u8],
    at: usize,
    cfg: ScanConfig,
    quote: u8,
) -> Option<(LiteralPrefix, usize)> {
    let candidates: [(LiteralPrefix, &[u8]); 5] = [
        (LiteralPrefix::Utf8, b"u8"),
        (LiteralPrefix::Wide, b"L"),
        (LiteralPrefix::Utf16, b"u"),
        (LiteralPrefix::Utf32, b"U"),
        (LiteralPrefix::Byte, b"b"),
    ];
    if bytes.get(at) == Some(&quote) {
        return Some((LiteralPrefix::None, 0));
    }
    for (prefix, spelling) in candidates {
        if prefix == LiteralPrefix::Byte && !cfg.byte_prefix {
            continue;
        }
        let width = spelling.len();
        if bytes.get(at..at + width) == Some(spelling) && bytes.get(at + width) == Some(&quote) {
            return Some((prefix, width));
        }
    }
    None
}

/// The shared body of [`scan_string`] and [`scan_char`], which differ only in
/// their delimiter and their empty-content rule. An escape never closes the
/// literal; a raw newline and the end of the input both stop it. Stopping at
/// the newline keeps one missing quote from swallowing the rest of the file.
fn scan_quoted(
    text: &str,
    at: usize,
    cfg: ScanConfig,
    quote: u8,
    kind: LiteralKind,
) -> Option<Literal> {
    let bytes = text.as_bytes();
    let (prefix, prefix_len) = literal_prefix(bytes, at, cfg, quote)?;
    let end = bytes.len();
    let content_start = at + prefix_len + 1;
    let mut index = content_start;
    let mut issues = Vec::new();
    let mut elements = 0usize;
    let mut has_escape = false;
    let mut terminated = false;
    let mut content_end = end;
    while index < end {
        let b = bytes[index];
        if b == quote {
            content_end = index;
            index += 1;
            terminated = true;
            break;
        }
        if b == b'\\' {
            let escape = scan_escape(text, index).unwrap_or(Escape {
                len: 1,
                kind: EscapeKind::Unknown,
                value: None,
                issue: None,
            });
            if let Some(found) = escape.issue {
                issues.push(found);
            }
            if escape.kind != EscapeKind::LineContinuation {
                elements += 1;
                has_escape = true;
            }
            index += escape.len.max(1);
            continue;
        }
        if let Some(width) = newline_len(bytes, index) {
            content_end = index;
            issues.push(issue(IssueKind::NewlineInLiteral, index, index + width));
            break;
        }
        elements += 1;
        index += utf8_len(b);
    }
    let stop = index.min(end);
    let content_end = content_end.min(end);
    if !terminated {
        issues.push(issue(IssueKind::UnterminatedLiteral, at, stop));
    }
    if kind == LiteralKind::Char && terminated && elements == 0 {
        issues.push(issue(IssueKind::EmptyCharLiteral, at, stop));
    }
    Some(Literal {
        len: stop - at,
        prefix,
        kind,
        content: content_start.min(content_end)..content_end,
        elements,
        has_escape,
        terminated,
        issues,
    })
}

/// Which escape form was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EscapeKind {
    /// One of `\n \t \r \\ \' \" \a \b \f \v \?`.
    Simple,
    /// `\NNN`, one to three octal digits. `\0` is this form, not a special case.
    Octal,
    /// `\xHH...`, whose digit count is **unbounded** in C.
    Hex,
    /// `\uXXXX`, a universal character name with exactly four digits.
    UniversalShort,
    /// `\UXXXXXXXX`, a universal character name with exactly eight digits.
    UniversalLong,
    /// A backslash immediately before a newline: no character at all.
    LineContinuation,
    /// A backslash before something that is not an escape.
    Unknown,
}

/// One escape sequence's extent and numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Escape {
    /// Bytes occupied, backslash included. Never zero, so a caller's loop
    /// always advances.
    pub len: usize,
    /// Which form it took.
    pub kind: EscapeKind,
    /// The numeric value where the form has one; `None` for a line
    /// continuation, an unknown escape and a value past 32 bits. A raw `u32`
    /// rather than a `char` because `\xff` is the byte 255 and `\uD800` is a
    /// surrogate --- neither is a Rust `char`, and whether either is legal is
    /// the front end's call.
    pub value: Option<u32>,
    /// The problem found, if any.
    pub issue: Option<ScanIssue>,
}

/// Scan the escape sequence at `at`, or return `None` if no backslash is there.
/// The hex case is the one worth stating: C's `\x` consumes **every** following
/// hexadecimal digit with no two-digit limit, so `"\x41BCDEF"` is one escape
/// worth `0x41BCDEF` and not `'A'` followed by `BCDEF` --- a scanner stopping
/// at two digits gets both the length and the value silently wrong. Universal
/// character names are the opposite rule: exactly four digits, or eight.
pub fn scan_escape(text: &str, at: usize) -> Option<Escape> {
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'\\') {
        return None;
    }
    let plain = |len: usize, kind: EscapeKind, value: Option<u32>| Escape {
        len,
        kind,
        value,
        issue: None,
    };
    let Some(&marker) = bytes.get(at + 1) else {
        return Some(Escape {
            len: 1,
            kind: EscapeKind::Unknown,
            value: None,
            issue: Some(issue(IssueKind::IncompleteEscape, at, at + 1)),
        });
    };
    if let Some(width) = newline_len(bytes, at + 1) {
        return Some(plain(1 + width, EscapeKind::LineContinuation, None));
    }
    let simple = match marker {
        b'n' => Some(0x0a),
        b't' => Some(0x09),
        b'r' => Some(0x0d),
        b'a' => Some(0x07),
        b'b' => Some(0x08),
        b'f' => Some(0x0c),
        b'v' => Some(0x0b),
        b'\\' => Some(0x5c),
        b'\'' => Some(0x27),
        b'"' => Some(0x22),
        b'?' => Some(0x3f),
        _ => None,
    };
    if let Some(value) = simple {
        return Some(plain(2, EscapeKind::Simple, Some(value)));
    }
    if marker.is_ascii_digit() && marker < b'8' {
        let mut value = 0u32;
        let mut index = at + 1;
        while index < at + 4 {
            match bytes.get(index) {
                Some(&b) if (b'0'..b'8').contains(&b) => {
                    value = value * 8 + (b - b'0') as u32;
                    index += 1;
                }
                _ => break,
            }
        }
        return Some(plain(index - at, EscapeKind::Octal, Some(value)));
    }
    if marker == b'x' {
        return Some(scan_hex_escape(bytes, at));
    }
    if marker == b'u' || marker == b'U' {
        let wanted = if marker == b'u' { 4 } else { 8 };
        let kind = if marker == b'u' {
            EscapeKind::UniversalShort
        } else {
            EscapeKind::UniversalLong
        };
        let mut value = 0u32;
        let mut seen = 0usize;
        let mut index = at + 2;
        while seen < wanted {
            match bytes.get(index).copied().and_then(digit_value) {
                Some(digit) => {
                    value = value * 16 + digit;
                    seen += 1;
                    index += 1;
                }
                None => break,
            }
        }
        let short = seen < wanted;
        return Some(Escape {
            len: index - at,
            kind,
            value: (!short).then_some(value),
            issue: short.then(|| issue(IssueKind::IncompleteEscape, at, index)),
        });
    }
    Some(Escape {
        len: 1 + utf8_len(marker),
        kind: EscapeKind::Unknown,
        value: None,
        issue: Some(issue(
            IssueKind::UnknownEscape,
            at,
            at + 1 + utf8_len(marker),
        )),
    })
}

/// The unbounded `\xHH...` case, split out to keep [`scan_escape`] readable.
/// Every hexadecimal digit is consumed even once the value has overflowed, so
/// the length is still the one C gives the escape; only the value is dropped.
fn scan_hex_escape(bytes: &[u8], at: usize) -> Escape {
    let mut value: Option<u32> = Some(0);
    let mut index = at + 2;
    let mut seen = 0usize;
    while let Some(digit) = bytes.get(index).copied().and_then(digit_value) {
        value = value
            .and_then(|current| current.checked_mul(16))
            .and_then(|current| current.checked_add(digit));
        seen += 1;
        index += 1;
    }
    let problem = if seen == 0 {
        Some(issue(IssueKind::IncompleteEscape, at, index))
    } else if value.is_none() {
        Some(issue(IssueKind::EscapeValueOutOfRange, at, index))
    } else {
        None
    };
    Escape {
        len: index - at,
        kind: EscapeKind::Hex,
        value: if seen == 0 { None } else { value },
        issue: problem,
    }
}

/// The decoded content of a literal: one unit per source character or escape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded {
    /// The units, in order: an escape's numeric value, or a source character's
    /// Unicode scalar value. Mapping either onto an execution character set,
    /// and choosing whether a unit is a byte, a `wchar_t` or a `char32_t`, is
    /// the front end's decision --- which is why nothing here narrows them.
    pub units: Vec<u32>,
    /// Problems found while decoding.
    pub issues: Vec<ScanIssue>,
}

/// Decode a literal's content, given the range [`Literal::content`] reported:
/// the deliberately separate second half of literal handling, where scanning
/// answers "how long is it" and decoding answers "what does it say". A range
/// out of bounds or off a character boundary yields an empty result, not a
/// panic, so a stale range degrades instead of aborting.
pub fn decode_escapes(text: &str, content: Range<usize>) -> Decoded {
    let mut decoded = Decoded::default();
    let Some(slice) = text.get(content.clone()) else {
        return decoded;
    };
    let base = content.start;
    let bytes = slice.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let b = bytes[index];
        if b == b'\\' {
            let escape = scan_escape(slice, index).unwrap_or(Escape {
                len: 1,
                kind: EscapeKind::Unknown,
                value: None,
                issue: None,
            });
            if let Some(found) = escape.issue {
                decoded.issues.push(issue(
                    found.kind,
                    base + index,
                    base + index + escape.len.max(1),
                ));
            }
            if escape.kind != EscapeKind::LineContinuation {
                decoded.units.push(escape.value.unwrap_or(0));
            }
            index += escape.len.max(1);
            continue;
        }
        let width = utf8_len(b);
        let unit = slice
            .get(index..index + width)
            .and_then(|piece| piece.chars().next())
            .map_or(b as u32, |c| c as u32);
        decoded.units.push(unit);
        index += width;
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_reports_which_prefix_it_carried() {
        let cfg = ScanConfig::C;
        assert_eq!(
            scan_string("u8\"x\"", 0, cfg).expect("a string").prefix,
            LiteralPrefix::Utf8
        );
        assert_eq!(
            scan_string("u\"x\"", 0, cfg).expect("a string").prefix,
            LiteralPrefix::Utf16
        );
        assert_eq!(
            scan_string("U\"x\"", 0, cfg).expect("a string").prefix,
            LiteralPrefix::Utf32
        );
        assert_eq!(
            scan_char("L'x'", 0, cfg).expect("a char").prefix,
            LiteralPrefix::Wide
        );
        assert_eq!(
            scan_string("\"x\"", 0, cfg).expect("a string").prefix,
            LiteralPrefix::None
        );
        assert!(
            scan_string("b\"x\"", 0, cfg).is_none(),
            "b is not a C prefix"
        );
        assert_eq!(
            scan_string("b\"x\"", 0, ScanConfig::RUST)
                .expect("a string")
                .prefix,
            LiteralPrefix::Byte
        );
    }

    #[test]
    fn an_escaped_backslash_does_not_escape_the_closing_quote() {
        let text = "\"\\\\\"";
        assert_eq!(
            text.len(),
            4,
            "the source is a quote, two backslashes, a quote"
        );
        let found = scan_string(text, 0, ScanConfig::C).expect("a string");
        assert_eq!(found.len, 4);
        assert!(found.terminated);
        assert_eq!(found.elements, 1);
        assert!(found.has_escape);
        assert!(found.issues.is_empty());
        assert_eq!(decode_escapes(text, found.content).units, vec![0x5c]);
    }

    #[test]
    fn an_escaped_quote_does_not_close_a_character_literal() {
        let text = "'\\''";
        let found = scan_char(text, 0, ScanConfig::C).expect("a char");
        assert_eq!(found.len, 4);
        assert!(found.terminated);
        assert_eq!(found.elements, 1);
        assert_eq!(decode_escapes(text, found.content).units, vec![0x27]);
    }

    #[test]
    fn a_hex_escape_consumes_every_following_hexadecimal_digit() {
        let text = "\"\\x41BCDEF\"";
        let found = scan_string(text, 0, ScanConfig::C).expect("a string");
        assert_eq!(found.len, text.len());
        assert_eq!(
            found.elements, 1,
            "one escape, not an escape and five letters"
        );
        let escape = scan_escape(text, 1).expect("an escape");
        assert_eq!(escape.kind, EscapeKind::Hex);
        assert_eq!(escape.len, 9);
        assert_eq!(escape.value, Some(0x41B_CDEF));
        let overflowing = scan_escape("\\x1234567890", 0).expect("an escape");
        assert_eq!(overflowing.value, None);
        assert_eq!(
            overflowing.issue.expect("an issue").kind,
            IssueKind::EscapeValueOutOfRange
        );
        assert_eq!(
            scan_escape("\\xz", 0)
                .expect("an escape")
                .issue
                .expect("an issue")
                .kind,
            IssueKind::IncompleteEscape
        );
    }

    #[test]
    fn an_unterminated_string_stops_at_the_end_of_input_and_is_reported() {
        let text = "\"abc";
        let found = scan_string(text, 0, ScanConfig::C).expect("a string");
        assert_eq!(found.len, 4);
        assert!(!found.terminated);
        assert_eq!(&text[found.content.clone()], "abc");
        assert_eq!(found.issues[0].kind, IssueKind::UnterminatedLiteral);
        let dangling = scan_string("\"a\\", 0, ScanConfig::C).expect("a string");
        assert!(!dangling.terminated);
        assert!(dangling
            .issues
            .iter()
            .any(|found| found.kind == IssueKind::IncompleteEscape));
    }

    #[test]
    fn a_raw_newline_ends_a_literal_rather_than_running_past_it() {
        let text = "\"abc\nnext line\"";
        let found = scan_string(text, 0, ScanConfig::C).expect("a string");
        assert_eq!(found.len, 4, "the newline is not consumed");
        assert!(!found.terminated);
        let kinds: Vec<IssueKind> = found.issues.iter().map(|found| found.kind).collect();
        assert!(kinds.contains(&IssueKind::NewlineInLiteral));
        assert!(kinds.contains(&IssueKind::UnterminatedLiteral));
        let continued = scan_string("\"a\\\nb\"", 0, ScanConfig::C).expect("a string");
        assert!(
            continued.terminated,
            "a backslash-newline continues a literal"
        );
        assert!(continued.issues.is_empty());
    }

    #[test]
    fn an_empty_character_literal_is_reported_but_still_measured() {
        let found = scan_char("''", 0, ScanConfig::C).expect("a char");
        assert_eq!(found.len, 2);
        assert!(found.terminated);
        assert_eq!(found.issues[0].kind, IssueKind::EmptyCharLiteral);
        let multi = scan_char("'ab'", 0, ScanConfig::C).expect("a char");
        assert_eq!(
            multi.elements, 2,
            "a multi-character constant is the front end's call"
        );
        assert!(multi.issues.is_empty());
    }

    #[test]
    fn each_escape_form_decodes_to_the_value_its_grammar_gives_it() {
        let cases = [
            ("\\n", EscapeKind::Simple, 2, Some(0x0a)),
            ("\\?", EscapeKind::Simple, 2, Some(0x3f)),
            ("\\0", EscapeKind::Octal, 2, Some(0)),
            ("\\101", EscapeKind::Octal, 4, Some(65)),
            ("\\1012", EscapeKind::Octal, 4, Some(65)),
            ("\\u00e9", EscapeKind::UniversalShort, 6, Some(0xe9)),
            ("\\U0001F600", EscapeKind::UniversalLong, 10, Some(0x1_f600)),
        ];
        for (text, kind, len, value) in cases {
            let found = scan_escape(text, 0).unwrap_or_else(|| panic!("an escape in {text:?}"));
            assert_eq!(
                (found.kind, found.len, found.value),
                (kind, len, value),
                "{text:?}"
            );
            assert!(found.issue.is_none(), "{text:?}");
        }
        let short = scan_escape("\\u12", 0).expect("an escape");
        assert_eq!(short.value, None);
        assert_eq!(
            short.issue.expect("an issue").kind,
            IssueKind::IncompleteEscape
        );
        let unknown = scan_escape("\\q", 0).expect("an escape");
        assert_eq!(unknown.kind, EscapeKind::Unknown);
        assert_eq!(
            unknown.issue.expect("an issue").kind,
            IssueKind::UnknownEscape
        );
        let trailing = scan_escape("\\", 0).expect("an escape");
        assert_eq!(trailing.len, 1);
        assert_eq!(
            trailing.issue.expect("an issue").kind,
            IssueKind::IncompleteEscape
        );
        assert_eq!(
            scan_escape("\\\r\n", 0).expect("an escape").kind,
            EscapeKind::LineContinuation
        );
    }

    #[test]
    fn decoding_yields_one_unit_per_source_character_or_escape() {
        let text = "\"a\\n\\x41\\\ncafé\"";
        let found = scan_string(text, 0, ScanConfig::C).expect("a string");
        assert!(found.terminated);
        let decoded = decode_escapes(text, found.content);
        assert_eq!(decoded.units, vec![97, 10, 65, 99, 97, 102, 0xe9]);
        assert!(decoded.issues.is_empty());
    }
}
