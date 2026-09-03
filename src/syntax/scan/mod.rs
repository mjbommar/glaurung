//! `SB-4` --- shared lexical sublanguages: numbers, strings, comments.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` section 7, row `SB-4`.
//!
//! C, C++ and Rust disagree about almost everything above the token and agree
//! about nearly everything below it. Each shared construct is a place a
//! hand-written lexer gets the edge case wrong: C's hex escape has no length
//! limit, C99 hex floats spell their exponent `p` because `e` is a hex digit,
//! and an unterminated block comment must consume the rest of the file without
//! panicking or looping. Where the languages genuinely differ the difference is
//! a [`ScanConfig`] knob, never baked in (`REQ-SYN-1`); two are too large for a
//! knob and are not handled at all --- Rust's raw strings (`r#"..."#`) and
//! C++11's `R"delim(...)delim"` are a separate grammar.
//!
//! **Position-based, not stateful.** Every scanner takes `(text, at)`, returns
//! how many bytes the construct occupies plus what was found, owns no cursor
//! and allocates nothing on the success path --- so one scanner serves a lexer,
//! a preprocessor and a "what is under the caret" query. `at` may be anything
//! at all, past the end of the input or inside a multi-byte character included:
//! every entry point returns either "nothing starts here" or a length, none
//! panics (`REQ-SYN-2`), every loop advances at least one byte so work is
//! bounded by the remaining input (`REQ-SYN-4`), and nesting is a counter
//! rather than recursion (`REQ-SYN-3`).
//!
//! **Byte offsets, never character indices.** The scanners read
//! `text.as_bytes()` and compare only ASCII, so a multi-byte character is
//! stepped over and never sliced --- the defence against the one failure mode
//! this file invites, since slicing a `&str` off a character boundary panics.
//! Every byte position returned lands on a character boundary, because a scan
//! stops only at an ASCII delimiter or at the end of the input. A truncated
//! UTF-8 sequence cannot reach here at all (a `&str` is validated at
//! construction), so bytes off disk go through `String::from_utf8_lossy` first.
//!
//! **Escapes are decoded lazily.** [`scan_string`] and [`scan_char`] report a
//! literal's extent, prefix, content range and whether it held an escape, but
//! not its value; [`decode_escapes`] is the separate call that produces one.
//! Three reasons, in order of weight: most literals are never asked for their
//! value, and eager decoding would allocate per literal in the hot loop; the
//! result *type* is a language decision, because `\xff` in a narrow C string is
//! a byte rather than a scalar value and `L'\x1234'` depends on the width of
//! `wchar_t`; and a scanner that decoded eagerly could not serve a
//! preprocessor, which must re-emit a literal's spelling untouched.
//!
//! # Layout
//!
//! This module doc, `ScanConfig`, the shared problem-reporting types
//! (`IssueKind`, `ScanIssue`) and the byte-level helpers every scanner needs
//! live here because all four submodules depend on them; splitting them out
//! further would only turn a private dependency into a public one between
//! files that always change together. Each scanner family below is a
//! separate file, re-exported so a caller sees one flat `syntax::scan` API
//! and cannot tell the split happened:
//!
//!   - `trivia` --- whitespace, line comments, block comments.
//!   - `literal` --- string and char literals, prefixes, escape decoding.
//!   - `number` --- integer and float literals, radix, suffixes.
//!   - `ident` --- identifiers.

use crate::syntax::diag::Diagnostic;
use crate::syntax::ids::Span;

/// The lexical rules that genuinely differ between the languages this substrate
/// serves. A knob exists only where two real languages disagree on the *shape*
/// of a construct; what a language merely *interprets* differently --- which
/// suffixes are legal, whether a multi-character constant is an error, what
/// `wchar_t` is --- is deliberately absent, because the scanners report spans
/// and let the front end judge them. [`ScanConfig::C`] is the [`Default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanConfig {
    /// Whether `/* /* */ */` is one comment (Rust) or two tokens and a syntax
    /// error (C and C++). C's block comments do **not** nest, so the first `*/`
    /// closes the outermost `/*` --- the reason commenting out a region that
    /// contains a comment is a known C hazard --- and a Rust front end that
    /// inherits the C rule truncates every doc comment containing `/*`.
    pub nested_block_comments: bool,

    /// The character that may sit between digits without being part of the
    /// number: `'` in C++14, `_` in Rust, absent in C through C17. Consumed
    /// only when the next byte is a digit of the current radix, which keeps
    /// `1'000` a number while leaving `x'a'` an identifier followed by a
    /// character literal, and makes Rust's `0x_ff` work. Placement is *not*
    /// validated: C++14 requires the separator between digits while Rust
    /// permits a trailing `1_000_`, so that judgement is the front end's.
    pub digit_separator: Option<char>,

    /// Whether `$` is an identifier character. A GNU extension GCC and Clang
    /// both accept by default, so it appears in real preprocessed sources; off
    /// by default because it is not standard C.
    pub dollar_in_identifiers: bool,

    /// Whether a byte at or above `0x80` may appear in an identifier. A correct
    /// answer needs Unicode `XID_Start`/`XID_Continue` tables and `REQ-SYN-6`
    /// forbids the dependency that would supply them, so the default is
    /// ASCII-only and this knob turns on a deliberate over-approximation
    /// accepting any non-ASCII character in either position. Over-accepting is
    /// the safe direction: a front end can re-validate the reported span,
    /// whereas a scanner stopping mid-identifier hands it a broken token. C11's
    /// alternative spelling as a universal character name is covered by
    /// neither setting; it scans as the escape it looks like.
    pub non_ascii_identifiers: bool,

    /// Whether a `.` may be followed by an identifier character and still
    /// belong to the number: true in C, where `1.f` is a float with an `f`
    /// suffix and `1.e+10` is an exponent; false in Rust, where both are field
    /// accesses on an integer. Independent of this knob, a `.` followed by
    /// another `.` is never consumed, so Rust's `1..2` is a number and a range
    /// operator rather than `1.` and `.2`.
    pub dot_may_precede_identifier: bool,

    /// Whether a backslash immediately before a newline splices the two lines.
    /// C does this in translation phase 2 everywhere, including inside a `//`
    /// comment, so a `//` line ending in a backslash swallows the line after it
    /// --- a genuine and much-reported C surprise. Rust has no line splicing.
    /// The knob governs comments only: a backslash-newline inside a string is
    /// accepted unconditionally, because both languages allow it there.
    pub line_splicing: bool,

    /// Whether `b` is a literal prefix, as in Rust's `b"bytes"`. Off for C,
    /// where `b"x"` is an identifier followed by a string literal and treating
    /// it as a prefix would merge two tokens into one.
    pub byte_prefix: bool,
}

impl ScanConfig {
    /// C through C23: no nesting, no separator, no `b` prefix, line splicing,
    /// and a `.` that may be followed by a suffix or an exponent.
    pub const C: Self = Self {
        nested_block_comments: false,
        digit_separator: None,
        dollar_in_identifiers: false,
        non_ascii_identifiers: false,
        dot_may_precede_identifier: true,
        line_splicing: true,
        byte_prefix: false,
    };

    /// C++14 and later: C, plus `'` as the digit separator.
    pub const CPP: Self = Self {
        digit_separator: Some('\''),
        ..Self::C
    };

    /// Rust: nested block comments, `_` as the digit separator, no line
    /// splicing, a `b` prefix, and a `.` that stops before an identifier.
    /// Provided so this module's neutrality is demonstrable rather than
    /// asserted; raw and byte-raw strings still need a front end's own scanner.
    pub const RUST: Self = Self {
        nested_block_comments: true,
        digit_separator: Some('_'),
        dollar_in_identifiers: false,
        non_ascii_identifiers: true,
        dot_may_precede_identifier: false,
        line_splicing: false,
        byte_prefix: true,
    };

    /// The digit separator as a byte, or `None` if unset or non-ASCII.
    const fn separator_byte(self) -> Option<u8> {
        match self.digit_separator {
            Some(c) if (c as u32) < 0x80 => Some(c as u8),
            _ => None,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self::C
    }
}

/// What a scanner found wrong with the construct it just measured. An issue
/// never stops a scan --- the scanner still reports an extent, so one bad
/// literal cannot void a file (`REQ-SYN-2`) --- and it becomes a substrate
/// diagnostic through [`ScanIssue::to_diagnostic`], not a second channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssueKind {
    /// A `/*` with no `*/` before the end of the input.
    UnterminatedBlockComment,
    /// A string or character literal with no closing quote.
    UnterminatedLiteral,
    /// A raw newline inside a string or character literal.
    NewlineInLiteral,
    /// `''` --- a character literal with nothing in it.
    EmptyCharLiteral,
    /// A backslash followed by a character that is not an escape.
    UnknownEscape,
    /// An escape out of input or digits: `\x` with no digit, `\u12`, a trailing
    /// backslash.
    IncompleteEscape,
    /// An escape whose numeric value does not fit in 32 bits.
    EscapeValueOutOfRange,
    /// A radix prefix with no digits after it, such as `0x` alone.
    MissingDigits,
    /// An exponent marker with no digits after it, such as `1e+`.
    MissingExponentDigits,
    /// A hexadecimal float with no `p` exponent, which C99 requires precisely
    /// because `e` is itself a hex digit.
    MissingHexExponent,
    /// A digit outside the radix, such as `09` or `0b12`.
    DigitOutsideRadix,
}

impl IssueKind {
    /// The message for this kind, fixed rather than formatted so a diagnostic
    /// costs no allocation beyond the one `Diagnostic` makes and identical
    /// input yields byte-identical text (`REQ-SYN-5`).
    pub const fn message(self) -> &'static str {
        match self {
            IssueKind::UnterminatedBlockComment => "unterminated block comment",
            IssueKind::UnterminatedLiteral => "unterminated literal",
            IssueKind::NewlineInLiteral => "newline in literal",
            IssueKind::EmptyCharLiteral => "empty character literal",
            IssueKind::UnknownEscape => "unknown escape sequence",
            IssueKind::IncompleteEscape => "incomplete escape sequence",
            IssueKind::EscapeValueOutOfRange => "escape value does not fit in 32 bits",
            IssueKind::MissingDigits => "numeric literal has no digits",
            IssueKind::MissingExponentDigits => "exponent has no digits",
            IssueKind::MissingHexExponent => "hexadecimal float has no exponent",
            IssueKind::DigitOutsideRadix => "digit outside the literal's radix",
        }
    }
}

/// One problem, with the source range it applies to. Kept separate from
/// `Diagnostic` so scanning allocates nothing on the success path: an issue is
/// `Copy`, and only a caller that reports something pays for a `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanIssue {
    /// What went wrong.
    pub kind: IssueKind,
    /// The source range the problem covers.
    pub span: Span,
}

impl ScanIssue {
    /// This issue as a substrate [`Diagnostic`], for a caller collecting them
    /// into a `Diagnostics` list alongside its product (`REQ-SYN-2`).
    pub fn to_diagnostic(self) -> Diagnostic {
        Diagnostic::error(self.span, self.kind.message())
    }
}

/// Build an issue over `[lo, hi)`, clamping offsets that do not fit a `u32` so
/// a span can never wrap to the front of the file. A translation unit above
/// 4 GiB is not an accepted input, as `syntax::ids` records.
fn issue(kind: IssueKind, lo: usize, hi: usize) -> ScanIssue {
    let clamp = |value: usize| value.min(u32::MAX as usize) as u32;
    ScanIssue {
        kind,
        span: Span::new(clamp(lo), clamp(hi)),
    }
}

/// The length of a newline at `at`, or `None` if one does not start there;
/// `\r\n` is one newline of two bytes, so nothing stops between them.
fn newline_len(bytes: &[u8], at: usize) -> Option<usize> {
    match bytes.get(at).copied() {
        Some(b'\r') if bytes.get(at + 1) == Some(&b'\n') => Some(2),
        Some(b'\r') | Some(b'\n') => Some(1),
        _ => None,
    }
}

/// The byte length of the UTF-8 sequence led by `first`, used only to step over
/// a character without slicing it; an invalid lead byte reports 1, which cannot
/// happen inside a validated `&str` but keeps this total.
const fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Whether `b` may start an identifier under `cfg`.
fn is_ident_start(b: u8, cfg: ScanConfig) -> bool {
    b.is_ascii_alphabetic()
        || b == b'_'
        || (cfg.dollar_in_identifiers && b == b'$')
        || (cfg.non_ascii_identifiers && b >= 0x80)
}

/// Whether `b` may continue an identifier under `cfg`.
fn is_ident_continue(b: u8, cfg: ScanConfig) -> bool {
    b.is_ascii_digit() || is_ident_start(b, cfg)
}

/// The value of `b` as a hexadecimal digit, or `None` if it is not one.
const fn digit_value(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u32),
        b'a'..=b'f' => Some((b - b'a') as u32 + 10),
        b'A'..=b'F' => Some((b - b'A') as u32 + 10),
        _ => None,
    }
}

mod ident;
mod literal;
mod number;
mod trivia;

pub use ident::scan_identifier;
pub use literal::{
    decode_escapes, scan_char, scan_escape, scan_string, Decoded, Escape, EscapeKind, Literal,
    LiteralKind, LiteralPrefix,
};
pub use number::{scan_number, Number, Radix};
pub use trivia::{scan_block_comment, scan_line_comment, scan_whitespace, Comment, CommentKind};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scanner_reports_nothing_for_an_offset_past_the_end() {
        let text = "int x = 1;";
        let cfg = ScanConfig::C;
        assert_eq!(scan_whitespace(text, 9_999), 0);
        assert_eq!(scan_identifier(text, 9_999, cfg), 0);
        assert!(scan_number(text, 9_999, cfg).is_none());
        assert!(scan_string(text, 9_999, cfg).is_none());
        assert!(scan_char(text, 9_999, cfg).is_none());
        assert!(scan_escape(text, 9_999).is_none());
        assert!(scan_line_comment(text, 9_999, cfg).is_none());
        assert!(scan_block_comment(text, 9_999, cfg).is_none());
        assert!(decode_escapes(text, 9_999..10_005).units.is_empty());
    }

    #[test]
    fn every_scanner_survives_the_empty_string() {
        let cfg = ScanConfig::C;
        assert_eq!(scan_whitespace("", 0), 0);
        assert_eq!(scan_identifier("", 0, cfg), 0);
        assert!(scan_number("", 0, cfg).is_none());
        assert!(scan_string("", 0, cfg).is_none());
        assert!(scan_escape("", 0).is_none());
        assert!(scan_block_comment("", 0, cfg).is_none());
        assert!(decode_escapes("", 0..0).units.is_empty());
    }

    #[test]
    fn a_multibyte_character_is_stepped_over_rather_than_sliced() {
        let text = "\"héllo";
        let found = scan_string(text, 0, ScanConfig::C).expect("a string");
        assert!(!found.terminated);
        assert_eq!(found.elements, 5, "five characters, seven bytes");
        assert_eq!(
            &text[found.content.clone()],
            "héllo",
            "the range is slicable"
        );
        assert_eq!(found.len, text.len());
        // An offset landing inside a multi-byte sequence must not panic, and
        // must not report a length that runs past the end of the input.
        let inside = 3;
        assert!(!text.is_char_boundary(inside));
        assert_eq!(scan_whitespace(text, inside), 0);
        assert!(scan_number(text, inside, ScanConfig::C).is_none());
        assert!(scan_string(text, inside, ScanConfig::C).is_none());
        assert!(scan_escape(text, inside).is_none());
        assert!(scan_identifier(text, inside, ScanConfig::RUST) <= text.len() - inside);
        let comment = scan_block_comment("/* é", 0, ScanConfig::C).expect("a comment");
        assert_eq!(comment.len, 5);
    }

    #[test]
    fn the_default_configuration_is_the_c_one() {
        assert_eq!(ScanConfig::default(), ScanConfig::C);
        assert_eq!(ScanConfig::CPP.digit_separator, Some('\''));
        assert!(ScanConfig::RUST.nested_block_comments);
    }

    #[test]
    fn scanning_the_same_input_twice_yields_the_same_answer() {
        let text = "0x1p3 \"a\\x41\" /* c */ ident";
        for _ in 0..2 {
            assert_eq!(
                scan_number(text, 0, ScanConfig::C),
                scan_number(text, 0, ScanConfig::C)
            );
            assert_eq!(
                scan_string(text, 6, ScanConfig::C),
                scan_string(text, 6, ScanConfig::C)
            );
        }
    }
}
