//! LEB128 and Modified UTF-8 (MUTF-8) decoding for DEX.
//!
//! DEX stores unsigned sizes as ULEB128 and strings as Java "Modified UTF-8":
//! the same as UTF-8 except (a) the NUL character is encoded as the two bytes
//! `0xC0 0x80` so real NULs can terminate the string, and (b) code points above
//! the BMP are stored as a *pair* of three-byte UTF-8 surrogate sequences (CESU-8)
//! rather than a single four-byte sequence.

use super::types::{DexError, Result};

/// Read an unsigned LEB128 value starting at `off`, returning the value and the
/// number of bytes consumed.
pub fn read_uleb128(data: &[u8], off: usize) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        let byte = *data.get(off + i).ok_or(DexError::Truncated {
            offset: off + i,
            needed: 1,
        })?;
        if shift >= 32 {
            return Err(DexError::MalformedHeader("ULEB128 exceeds 32 bits".into()));
        }
        result |= ((byte & 0x7f) as u32) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok((result, i))
}

/// Decode a MUTF-8 string whose UTF-16 code-unit length is `utf16_len`,
/// starting at `off`. Stops at the terminating NUL byte.
///
/// Returns a lossless Rust `String`. Invalid sequences are rejected rather than
/// silently replaced, so callers can trust the bytes actually parsed as a valid
/// DEX string.
pub fn decode_mutf8(data: &[u8], off: usize, utf16_len: usize) -> Result<String> {
    // Collect UTF-16 code units, then convert. `utf16_len` counts UTF-16 units,
    // not bytes and not Unicode scalar values, so a surrogate pair counts as 2.
    let mut units: Vec<u16> = Vec::with_capacity(utf16_len);
    let mut i = off;
    while units.len() < utf16_len {
        let b0 = *data.get(i).ok_or(DexError::Truncated {
            offset: i,
            needed: 1,
        })?;
        if b0 == 0 {
            // Premature NUL: string shorter than advertised. Accept what we have.
            break;
        } else if b0 < 0x80 {
            units.push(b0 as u16);
            i += 1;
        } else if b0 & 0xe0 == 0xc0 {
            // Two-byte sequence (also encodes NUL as 0xC0 0x80).
            let b1 = byte(data, i + 1)?;
            if b1 & 0xc0 != 0x80 {
                return Err(DexError::InvalidString);
            }
            let cp = (((b0 & 0x1f) as u16) << 6) | ((b1 & 0x3f) as u16);
            units.push(cp);
            i += 2;
        } else if b0 & 0xf0 == 0xe0 {
            // Three-byte sequence. In MUTF-8/CESU-8 astral characters appear as
            // two of these forming a surrogate pair; each is one UTF-16 unit.
            let b1 = byte(data, i + 1)?;
            let b2 = byte(data, i + 2)?;
            if b1 & 0xc0 != 0x80 || b2 & 0xc0 != 0x80 {
                return Err(DexError::InvalidString);
            }
            let cp = (((b0 & 0x0f) as u16) << 12)
                | (((b1 & 0x3f) as u16) << 6)
                | ((b2 & 0x3f) as u16);
            units.push(cp);
            i += 3;
        } else {
            return Err(DexError::InvalidString);
        }
    }

    String::from_utf16(&units).map_err(|_| DexError::InvalidString)
}

#[inline]
fn byte(data: &[u8], i: usize) -> Result<u8> {
    data.get(i).copied().ok_or(DexError::Truncated {
        offset: i,
        needed: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_values() {
        assert_eq!(read_uleb128(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(read_uleb128(&[0x7f], 0).unwrap(), (127, 1));
        assert_eq!(read_uleb128(&[0x80, 0x01], 0).unwrap(), (128, 2));
        assert_eq!(read_uleb128(&[0xff, 0x7f], 0).unwrap(), (16383, 2));
    }

    #[test]
    fn mutf8_ascii_and_null() {
        // "Hi" then NUL terminator.
        let data = b"Hi\0";
        assert_eq!(decode_mutf8(data, 0, 2).unwrap(), "Hi");
        // Embedded NUL encoded as C0 80.
        let data2 = [b'A', 0xc0, 0x80, b'B', 0x00];
        assert_eq!(decode_mutf8(&data2, 0, 3).unwrap(), "A\0B");
    }

    #[test]
    fn mutf8_bmp_multibyte() {
        // U+00E9 'é' -> C3 A9 in two-byte form.
        let data = [0xc3, 0xa9, 0x00];
        assert_eq!(decode_mutf8(&data, 0, 1).unwrap(), "é");
    }

    #[test]
    fn mutf8_surrogate_pair() {
        // U+1F600 GRINNING FACE as CESU-8 surrogate pair:
        // high D83D -> ED A0 BD, low DE00 -> ED B8 80. Two UTF-16 units.
        let data = [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0x00];
        assert_eq!(decode_mutf8(&data, 0, 2).unwrap(), "\u{1F600}");
    }
}
