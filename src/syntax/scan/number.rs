//! Numeric literal scanning.
//!
//! `scan_number` and its `Radix` classification, plus the digit-run and
//! exponent helpers this file owns alone. The one thing it borrows from
//! elsewhere in `scan` is `super::ident::scan_identifier`: a number's suffix
//! (`ULL`, `f32`) is lexically an identifier, so `scan_number` reuses the
//! identifier scanner for it rather than duplicating its character classes.

use std::ops::Range;

use super::ident::scan_identifier;
use super::{digit_value, is_ident_start, issue, IssueKind, ScanConfig, ScanIssue};

/// The base a numeric literal is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Radix {
    /// No prefix. A bare `0` is reported here rather than as [`Radix::Octal`]:
    /// the C grammar calls it octal, but no consumer can tell the difference.
    Decimal,
    /// A leading `0` followed by more digits.
    Octal,
    /// `0x` or `0X`.
    Hex,
    /// `0b` or `0B` --- a GNU extension standardised in C23, accepted
    /// unconditionally because it appears in real preprocessed input.
    Binary,
}

impl Radix {
    /// The base as a number, for a front end parsing the digits.
    pub const fn value(self) -> u32 {
        match self {
            Radix::Decimal => 10,
            Radix::Octal => 8,
            Radix::Hex => 16,
            Radix::Binary => 2,
        }
    }
}

/// A numeric literal's extent, classification and parts. No value is computed:
/// whether `0xffffffffffffffff` overflows, and into what type, depends on the
/// target's integer widths and on what the suffix means --- both language
/// decisions, and both wrong to make in the substrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    /// Bytes occupied from the start offset, suffix included.
    pub len: usize,
    /// The base the digits are written in.
    pub radix: Radix,
    /// Whether this is a floating literal: it has a fraction, an exponent, or
    /// both.
    pub is_float: bool,
    /// Absolute byte range of the numeric body: radix prefix removed, suffix
    /// excluded. It still holds any `.`, exponent marker, exponent sign and
    /// digit separators, because removing those is part of computing a value
    /// and this scanner computes none.
    pub digits: Range<usize>,
    /// Absolute byte range of the suffix, empty when there is none. Reported,
    /// never validated: `u`, `ull`, `f`, `L` and Rust's `f32` are all just the
    /// identifier run after the body, and which are legal is a language rule.
    pub suffix: Range<usize>,
    /// Problems found. Empty --- and unallocated --- for a well-formed literal.
    pub issues: Vec<ScanIssue>,
}

/// Consume a run of digits and separators, reporting how many digits were seen
/// and how many fell outside `check`. `consume` is the set the run swallows and
/// `check` the radix they must belong to; the two differ for octal and binary,
/// where `09` and `0b12` are one bad literal rather than two numbers.
fn digit_run(
    bytes: &[u8],
    from: usize,
    consume: u32,
    check: u32,
    separator: Option<u8>,
) -> (usize, usize, usize) {
    let mut index = from;
    let mut digits = 0usize;
    let mut outside = 0usize;
    loop {
        match bytes.get(index).copied() {
            Some(b) if matches!(digit_value(b), Some(value) if value < consume) => {
                if digit_value(b).unwrap_or(0) >= check {
                    outside += 1;
                }
                digits += 1;
                index += 1;
            }
            Some(b)
                if Some(b) == separator
                    && matches!(
                        bytes.get(index + 1).copied().and_then(digit_value),
                        Some(value) if value < consume
                    ) =>
            {
                index += 1;
            }
            _ => break,
        }
    }
    (index, digits, outside)
}

/// Whether the `.` at `at` belongs to the number being scanned: never when
/// another `.` follows, so Rust's `1..2` is a number and a range rather than
/// `1.` and `.2`; and, with [`ScanConfig::dot_may_precede_identifier`] off,
/// never when an identifier character follows, so `1.max(2)` is a method call.
fn dot_joins_number(bytes: &[u8], at: usize, cfg: ScanConfig) -> bool {
    if bytes.get(at) != Some(&b'.') {
        return false;
    }
    match bytes.get(at + 1).copied() {
        None => true,
        Some(b'.') => false,
        Some(b) => cfg.dot_may_precede_identifier || !is_ident_start(b, cfg),
    }
}

/// Consume an exponent whose marker sits at `at`, recording a diagnostic if it
/// carries no digits.
fn scan_exponent(
    bytes: &[u8],
    at: usize,
    separator: Option<u8>,
    start: usize,
    issues: &mut Vec<ScanIssue>,
) -> usize {
    let mut index = at + 1;
    if matches!(bytes.get(index).copied(), Some(b'+') | Some(b'-')) {
        index += 1;
    }
    let (next, digits, _) = digit_run(bytes, index, 10, 10, separator);
    if digits == 0 {
        issues.push(issue(IssueKind::MissingExponentDigits, start, next));
    }
    next
}

/// Scan the numeric literal at `at`, or return `None` if none starts there. A
/// number starts at a digit, or at a `.` followed by a digit --- which is what
/// makes `.5f` a literal rather than a member access. The forms are the C
/// family's: decimal, octal, `0x`, `0b`, an optional fraction, a decimal `e`
/// exponent, a hexadecimal `p` exponent, and a trailing suffix. That `p` is no
/// stylistic choice of C99's: `e` is a hex digit, so a hex float has no other
/// letter available, and `0x1p3` is real in preprocessed output.
pub fn scan_number(text: &str, at: usize, cfg: ScanConfig) -> Option<Number> {
    let bytes = text.as_bytes();
    let first = bytes.get(at).copied()?;
    let leads_with_dot =
        first == b'.' && matches!(bytes.get(at + 1).copied(), Some(b) if b.is_ascii_digit());
    if !first.is_ascii_digit() && !leads_with_dot {
        return None;
    }
    let separator = cfg.separator_byte();
    let mut issues: Vec<ScanIssue> = Vec::new();
    let mut is_float = false;
    let mut radix = Radix::Decimal;
    let mut index = at;
    if first == b'0' {
        match bytes.get(at + 1).copied() {
            Some(b'x') | Some(b'X') => {
                radix = Radix::Hex;
                index = at + 2;
            }
            Some(b'b') | Some(b'B') => {
                radix = Radix::Binary;
                index = at + 2;
            }
            _ => {}
        }
    }
    let digits_start = index;
    match radix {
        Radix::Hex => {
            let (next, whole, _) = digit_run(bytes, index, 16, 16, separator);
            index = next;
            let mut seen = whole;
            if dot_joins_number(bytes, index, cfg) {
                is_float = true;
                let (next, fraction, _) = digit_run(bytes, index + 1, 16, 16, separator);
                index = next;
                seen += fraction;
            }
            if matches!(bytes.get(index).copied(), Some(b'p') | Some(b'P')) {
                is_float = true;
                index = scan_exponent(bytes, index, separator, at, &mut issues);
            } else if is_float {
                issues.push(issue(IssueKind::MissingHexExponent, at, index));
            }
            if seen == 0 {
                issues.push(issue(IssueKind::MissingDigits, at, index));
            }
        }
        Radix::Binary => {
            let (next, seen, outside) = digit_run(bytes, index, 10, 2, separator);
            index = next;
            if seen == 0 {
                issues.push(issue(IssueKind::MissingDigits, at, index));
            } else if outside > 0 {
                issues.push(issue(IssueKind::DigitOutsideRadix, at, index));
            }
        }
        _ => {
            let (next, whole, non_octal) = digit_run(bytes, index, 10, 8, separator);
            index = next;
            if dot_joins_number(bytes, index, cfg) {
                is_float = true;
                let (next, _, _) = digit_run(bytes, index + 1, 10, 10, separator);
                index = next;
            }
            if matches!(bytes.get(index).copied(), Some(b'e') | Some(b'E'))
                && matches!(
                    bytes.get(index + 1).copied(),
                    Some(b'+') | Some(b'-') | Some(b'0'..=b'9')
                )
            {
                is_float = true;
                index = scan_exponent(bytes, index, separator, at, &mut issues);
            }
            if !is_float && first == b'0' && whole > 1 {
                radix = Radix::Octal;
                if non_octal > 0 {
                    issues.push(issue(IssueKind::DigitOutsideRadix, at, index));
                }
            }
        }
    }
    let body_end = index;
    let suffix_len = scan_identifier(text, body_end, cfg);
    Some(Number {
        len: body_end + suffix_len - at,
        radix,
        is_float,
        digits: digits_start.min(body_end)..body_end,
        suffix: body_end..body_end + suffix_len,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hexadecimal_float_spells_its_exponent_with_a_p() {
        let found = scan_number("0x1p3", 0, ScanConfig::C).expect("a number");
        assert_eq!(found.len, 5);
        assert_eq!(found.radix, Radix::Hex);
        assert!(found.is_float);
        assert_eq!(found.digits, 2..5);
        assert!(found.suffix.is_empty());
        assert!(found.issues.is_empty());
        let with_fraction = scan_number("0x1.8p-2f", 0, ScanConfig::C).expect("a number");
        assert_eq!(with_fraction.len, 9);
        assert_eq!(with_fraction.suffix, 8..9);
        assert!(with_fraction.issues.is_empty());
        let missing = scan_number("0x1.8", 0, ScanConfig::C).expect("a number");
        assert_eq!(missing.issues[0].kind, IssueKind::MissingHexExponent);
    }

    #[test]
    fn a_number_may_begin_with_a_dot_and_end_with_a_suffix() {
        let found = scan_number(".5f", 0, ScanConfig::C).expect("a number");
        assert_eq!(found.len, 3);
        assert_eq!(found.radix, Radix::Decimal);
        assert!(found.is_float);
        assert_eq!(found.digits, 0..2);
        assert_eq!(found.suffix, 2..3);
        assert!(scan_number(".x", 0, ScanConfig::C).is_none());
    }

    #[test]
    fn a_trailing_dot_may_still_carry_an_exponent() {
        let found = scan_number("1.e+10", 0, ScanConfig::C).expect("a number");
        assert_eq!(found.len, 6);
        assert!(found.is_float);
        assert!(found.issues.is_empty());
        assert_eq!(
            scan_number("1.", 0, ScanConfig::C).expect("a number").len,
            2
        );
        let empty_exponent = scan_number("1e+", 0, ScanConfig::C).expect("a number");
        assert_eq!(
            empty_exponent.issues[0].kind,
            IssueKind::MissingExponentDigits
        );
    }

    #[test]
    fn a_binary_literal_reports_its_radix_and_its_suffix_span() {
        let found = scan_number("0b1010ull", 0, ScanConfig::C).expect("a number");
        assert_eq!(found.len, 9);
        assert_eq!(found.radix, Radix::Binary);
        assert!(!found.is_float);
        assert_eq!(found.digits, 2..6);
        assert_eq!(found.suffix, 6..9);
        assert!(found.issues.is_empty());
        assert_eq!(
            scan_number("0b12", 0, ScanConfig::C)
                .expect("a number")
                .issues[0]
                .kind,
            IssueKind::DigitOutsideRadix
        );
        assert_eq!(
            scan_number("0x", 0, ScanConfig::C)
                .expect("a number")
                .issues[0]
                .kind,
            IssueKind::MissingDigits
        );
    }

    #[test]
    fn an_octal_literal_is_distinguished_from_a_decimal_one() {
        let octal = scan_number("0755", 0, ScanConfig::C).expect("a number");
        assert_eq!(octal.radix, Radix::Octal);
        assert_eq!(octal.radix.value(), 8);
        let zero = scan_number("0", 0, ScanConfig::C).expect("a number");
        assert_eq!(zero.radix, Radix::Decimal);
        let bad = scan_number("09", 0, ScanConfig::C).expect("a number");
        assert_eq!(bad.issues[0].kind, IssueKind::DigitOutsideRadix);
        let float = scan_number("08.5", 0, ScanConfig::C).expect("a number");
        assert_eq!(
            float.radix,
            Radix::Decimal,
            "a leading zero float is decimal"
        );
        assert!(float.issues.is_empty());
        let suffixed = scan_number("42ULL", 0, ScanConfig::C).expect("a number");
        assert_eq!(suffixed.suffix, 2..5);
    }

    #[test]
    fn a_digit_separator_is_consumed_only_when_a_digit_follows_it() {
        let grouped = scan_number("1'000'000", 0, ScanConfig::CPP).expect("a number");
        assert_eq!(grouped.len, 9);
        assert_eq!(grouped.digits, 0..9);
        let quoted_next = scan_number("1'a'", 0, ScanConfig::CPP).expect("a number");
        assert_eq!(
            quoted_next.len, 1,
            "an apostrophe before a letter starts a literal"
        );
        let underscored = scan_number("0x_ff", 0, ScanConfig::RUST).expect("a number");
        assert_eq!(underscored.len, 5);
        assert_eq!(underscored.radix, Radix::Hex);
        let unseparated = scan_number("1'000", 0, ScanConfig::C).expect("a number");
        assert_eq!(unseparated.len, 1, "C through C17 has no separator");
    }

    #[test]
    fn a_dot_after_a_number_is_a_fraction_in_c_and_a_member_access_in_rust() {
        let c_float = scan_number("1.f", 0, ScanConfig::C).expect("a number");
        assert_eq!(c_float.len, 3);
        assert!(c_float.is_float);
        let rust_access = scan_number("1.f", 0, ScanConfig::RUST).expect("a number");
        assert_eq!(rust_access.len, 1);
        assert!(!rust_access.is_float);
        let range = scan_number("1..2", 0, ScanConfig::C).expect("a number");
        assert_eq!(range.len, 1, "two dots are never a fraction");
    }
}
