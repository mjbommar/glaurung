//! Integer and character constants: their value and their C type.
//!
//! Split out of [`super::expr`] because it is a self-contained reading of C17
//! 6.4.4 with no dependency on the emitter --- and because keeping it there put
//! that file over the 1,000-LOC line the large-module review draws.

use super::ctype::IntType;

/// The canonical 64-bit bits and C type of an integer or character constant.
///
/// Returns `None` for a floating constant, a string, and any spelling this
/// model does not resolve --- the caller reports it by name rather than
/// guessing a value.
pub(crate) fn parse_literal(text: &str) -> Option<(i64, IntType)> {
    if text.starts_with('"') || text.starts_with('L') && text.contains('"') {
        return None;
    }
    if text.starts_with('\'') {
        return char_literal(text);
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains('.')
        || (!lower.starts_with("0x") && lower.contains('e'))
        || (lower.starts_with("0x") && lower.contains('p'))
    {
        return None; // floating constant
    }
    let digits: String = lower
        .chars()
        .take_while(|c| !matches!(c, 'u' | 'l'))
        .collect();
    let suffix = &lower[digits.len()..];
    if !suffix.chars().all(|c| matches!(c, 'u' | 'l')) {
        return None;
    }
    let unsigned = suffix.contains('u');
    let long = suffix.contains('l');
    let (radix, body) = if let Some(rest) = digits.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = digits.strip_prefix("0b") {
        (2, rest)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits.as_str())
    };
    let body: String = body.chars().filter(|c| *c != '\'').collect();
    if body.is_empty() {
        return None;
    }
    let value = u64::from_str_radix(&body, radix).ok()?;

    // C17 6.4.4.1: the first type in the list for the constant's base and
    // suffix that can represent it.
    let candidates: &[IntType] = match (unsigned, long, radix == 10) {
        (false, false, true) => &[IntType::INT, IntType::LONG],
        (false, false, false) => &[IntType::INT, IntType::UINT, IntType::LONG, IntType::ULONG],
        (true, false, _) => &[IntType::UINT, IntType::ULONG],
        (false, true, true) => &[IntType::LONG],
        (false, true, false) => &[IntType::LONG, IntType::ULONG],
        (true, true, _) => &[IntType::ULONG],
    };
    for ty in candidates {
        if fits(value, *ty) {
            return Some((value as i64, *ty));
        }
    }
    Some((value as i64, IntType::ULONG))
}

fn fits(value: u64, ty: IntType) -> bool {
    let bits = ty.width.bits();
    if bits >= 64 {
        return !ty.signed || value <= i64::MAX as u64;
    }
    let limit = if ty.signed {
        (1u64 << (bits - 1)) - 1
    } else {
        (1u64 << bits) - 1
    };
    value <= limit
}

/// A character constant. Its type is `int`; its value is the (signed, on
/// x86-64 Linux) `char` the escape denotes.
fn char_literal(text: &str) -> Option<(i64, IntType)> {
    let body = text.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = body.chars();
    let value: i64 = match chars.next()? {
        '\\' => match chars.next()? {
            'n' => 10,
            't' => 9,
            'r' => 13,
            '0' => 0,
            'a' => 7,
            'b' => 8,
            'f' => 12,
            'v' => 11,
            '\\' => 92,
            '\'' => 39,
            '"' => 34,
            '?' => 63,
            'x' => {
                let hex: String = chars.by_ref().collect();
                i64::from(u8::from_str_radix(&hex, 16).ok()? as i8)
            }
            octal if octal.is_digit(8) => {
                let mut digits = String::from(octal);
                digits.extend(chars.by_ref());
                i64::from(u8::from_str_radix(&digits, 8).ok()? as i8)
            }
            _ => return None,
        },
        one if one.is_ascii() => i64::from(one as u8 as i8),
        _ => return None,
    };
    // A multi-character constant is implementation-defined; refuse it.
    if !matches!(text.chars().nth(1), Some('\\')) && body.chars().count() > 1 {
        return None;
    }
    Some((value, IntType::INT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_constants_take_the_first_type_that_fits() {
        assert_eq!(parse_literal("0"), Some((0, IntType::INT)));
        assert_eq!(
            parse_literal("2147483647"),
            Some((2147483647, IntType::INT))
        );
        assert_eq!(
            parse_literal("2147483648"),
            Some((2147483648, IntType::LONG)),
            "a decimal constant never becomes unsigned int"
        );
        assert_eq!(parse_literal("1u"), Some((1, IntType::UINT)));
        assert_eq!(parse_literal("1L"), Some((1, IntType::LONG)));
        assert_eq!(parse_literal("1UL"), Some((1, IntType::ULONG)));
    }

    #[test]
    fn hex_constants_may_become_unsigned_int_where_decimal_may_not() {
        assert_eq!(
            parse_literal("0xffffffff"),
            Some((0xffff_ffff, IntType::UINT))
        );
        assert_eq!(
            parse_literal("0x7fffffff"),
            Some((0x7fff_ffff, IntType::INT))
        );
        assert_eq!(parse_literal("010"), Some((8, IntType::INT)));
        assert_eq!(parse_literal("0b101"), Some((5, IntType::INT)));
    }

    #[test]
    fn character_constants_are_int_and_signed_on_this_abi() {
        assert_eq!(parse_literal("'A'"), Some((65, IntType::INT)));
        assert_eq!(parse_literal("'\\n'"), Some((10, IntType::INT)));
        assert_eq!(parse_literal("'\\0'"), Some((0, IntType::INT)));
        assert_eq!(parse_literal("'\\xff'"), Some((-1, IntType::INT)));
    }

    #[test]
    fn floating_and_string_literals_are_refused_rather_than_guessed() {
        assert_eq!(parse_literal("1.5"), None);
        assert_eq!(parse_literal("1e9"), None);
        assert_eq!(parse_literal("\"hi\""), None);
    }
}
