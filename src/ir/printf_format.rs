//! Fail-closed parsing of `printf`-family format strings.
//!
//! The parser is shared by program-wide type evidence and per-call argument
//! reconstruction. Unsupported positional, dynamic-width, wide-string, or
//! otherwise ambiguous conversions decline the whole format rather than
//! inventing an arity or type.

use crate::ir::types_recover::TypeHint;

/// Parse one ordinary `printf` format into the types consumed by its
/// conversions, in source order.
pub(crate) fn parse_printf_hints(format: &str, pointer_width: u8) -> Option<Vec<TypeHint>> {
    let bytes = format.as_bytes();
    let mut hints = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'%' {
            cursor += 1;
            continue;
        }
        cursor += 1;
        if bytes.get(cursor) == Some(&b'%') {
            cursor += 1;
            continue;
        }
        while bytes
            .get(cursor)
            .is_some_and(|byte| b"-+ #0'".contains(byte))
        {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'*') {
            return None;
        }
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'$') {
            return None;
        }
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            if bytes.get(cursor) == Some(&b'*') {
                return None;
            }
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
        }
        let length_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| b"hljztL".contains(byte))
        {
            cursor += 1;
        }
        let length = std::str::from_utf8(&bytes[length_start..cursor]).ok()?;
        let conversion = char::from(*bytes.get(cursor)?);
        cursor += 1;
        let integer_width = match length {
            "hh" => 1,
            "h" => 2,
            "l" | "z" | "t" => pointer_width,
            "ll" | "j" => 8,
            "" => 4,
            _ => return None,
        };
        let hint = match conversion {
            's' if length.is_empty() => TypeHint::Pointer { pointee_width: 1 },
            'c' if length.is_empty() => TypeHint::Int {
                signed: true,
                width: 4,
            },
            'd' | 'i' => TypeHint::Int {
                signed: true,
                width: integer_width,
            },
            'o' | 'u' | 'x' | 'X' => TypeHint::Int {
                signed: false,
                width: integer_width,
            },
            'p' if length.is_empty() => TypeHint::Pointer { pointee_width: 0 },
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' if length.is_empty() || length == "l" => {
                TypeHint::Float { width: 8 }
            }
            _ => return None,
        };
        hints.push(hint);
    }
    Some(hints)
}

#[cfg(test)]
mod tests {
    use super::parse_printf_hints;
    use crate::ir::types_recover::TypeHint;

    #[test]
    fn parser_is_typed_and_fail_closed() {
        assert_eq!(
            parse_printf_hints("name '%s': %ld%%", 8),
            Some(vec![
                TypeHint::Pointer { pointee_width: 1 },
                TypeHint::Int {
                    signed: true,
                    width: 8,
                },
            ])
        );
        for unsupported in ["%2$s", "%*s", "%ls", "%hf"] {
            assert_eq!(parse_printf_hints(unsupported, 8), None);
        }
    }
}
