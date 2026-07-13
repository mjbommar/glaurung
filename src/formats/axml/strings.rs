//! `ResStringPool` decoding (both UTF-8 and UTF-16 variants).

use super::types::{AxmlError, Result, UTF8_FLAG};

/// A decoded Android resource string pool.
pub struct StringPool {
    strings: Vec<String>,
}

impl StringPool {
    /// Parse a string-pool chunk. `chunk` is the whole chunk (starting at its
    /// `ResChunk_header`), `header_size` its declared header size.
    pub fn parse(chunk: &[u8]) -> Result<Self> {
        // ResStringPool_header layout (after the 8-byte ResChunk_header):
        //   u32 stringCount, u32 styleCount, u32 flags,
        //   u32 stringsStart, u32 stylesStart
        if chunk.len() < 28 {
            return Err(AxmlError::Truncated {
                offset: 0,
                needed: 28,
            });
        }
        let string_count = u32(chunk, 8)? as usize;
        let flags = u32(chunk, 16)?;
        let strings_start = u32(chunk, 20)? as usize;
        let is_utf8 = flags & UTF8_FLAG != 0;

        // The string offset array immediately follows the 28-byte header.
        let mut strings = Vec::with_capacity(string_count.min(1 << 16));
        for i in 0..string_count {
            let off_pos = 28 + i * 4;
            let rel = u32(chunk, off_pos)? as usize;
            let abs = strings_start
                .checked_add(rel)
                .ok_or_else(|| AxmlError::MalformedChunk("string offset overflow".into()))?;
            let s = if is_utf8 {
                decode_utf8_entry(chunk, abs)?
            } else {
                decode_utf16_entry(chunk, abs)?
            };
            strings.push(s);
        }

        Ok(Self { strings })
    }

    /// Resolve a string by index. A `0xFFFFFFFF` sentinel yields `None`.
    pub fn get(&self, index: u32) -> Option<&str> {
        if index == 0xffff_ffff {
            return None;
        }
        self.strings.get(index as usize).map(|s| s.as_str())
    }

    /// Number of strings in the pool.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

fn u32(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or(AxmlError::Truncated {
        offset: off,
        needed: 4,
    })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode one UTF-8 string-pool entry: `[u16-ish char len][u16-ish byte len]
/// bytes NUL`. Both lengths use the "high bit of the first byte means a second
/// byte follows" varint scheme.
fn decode_utf8_entry(data: &[u8], mut off: usize) -> Result<String> {
    // Skip the character-count field (we trust the byte count instead).
    let (_char_len, adv) = varint_u8(data, off)?;
    off += adv;
    let (byte_len, adv) = varint_u8(data, off)?;
    off += adv;
    let bytes = data.get(off..off + byte_len).ok_or(AxmlError::Truncated {
        offset: off,
        needed: byte_len,
    })?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Decode one UTF-16 string-pool entry: `[u16-ish unit len] units NUL16`.
fn decode_utf16_entry(data: &[u8], mut off: usize) -> Result<String> {
    let (unit_len, adv) = varint_u16(data, off)?;
    off += adv;
    let byte_len = unit_len * 2;
    let bytes = data.get(off..off + byte_len).ok_or(AxmlError::Truncated {
        offset: off,
        needed: byte_len,
    })?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Read the AXML 1-or-2-byte length prefix for UTF-8 pools (values counted in
/// bytes/chars). If the high bit of the first byte is set, the low 7 bits are
/// the high byte of a 15-bit length.
fn varint_u8(data: &[u8], off: usize) -> Result<(usize, usize)> {
    let b0 = *data.get(off).ok_or(AxmlError::Truncated {
        offset: off,
        needed: 1,
    })?;
    if b0 & 0x80 != 0 {
        let b1 = *data.get(off + 1).ok_or(AxmlError::Truncated {
            offset: off + 1,
            needed: 1,
        })?;
        Ok(((((b0 & 0x7f) as usize) << 8) | b1 as usize, 2))
    } else {
        Ok((b0 as usize, 1))
    }
}

/// Read the AXML 1-or-2-unit length prefix for UTF-16 pools (values counted in
/// 16-bit units). If the high bit of the first unit is set, it is a 31-bit
/// length across two units.
fn varint_u16(data: &[u8], off: usize) -> Result<(usize, usize)> {
    let lo = read_u16(data, off)?;
    if lo & 0x8000 != 0 {
        let hi = read_u16(data, off + 2)?;
        Ok(((((lo & 0x7fff) as usize) << 16) | hi as usize, 4))
    } else {
        Ok((lo as usize, 2))
    }
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let b = data.get(off..off + 2).ok_or(AxmlError::Truncated {
        offset: off,
        needed: 2,
    })?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal UTF-8 string pool chunk with two strings.
    fn utf8_pool(strings: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(body.len() as u32);
            let bytes = s.as_bytes();
            body.push(s.chars().count() as u8); // char len
            body.push(bytes.len() as u8); // byte len
            body.extend_from_slice(bytes);
            body.push(0); // NUL
        }
        let header_size = 28u32;
        let strings_start = header_size + (strings.len() as u32) * 4;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&super::super::types::RES_STRING_POOL_TYPE.to_le_bytes());
        chunk.extend_from_slice(&(header_size as u16).to_le_bytes());
        let total = strings_start + body.len() as u32;
        chunk.extend_from_slice(&total.to_le_bytes());
        chunk.extend_from_slice(&(strings.len() as u32).to_le_bytes()); // stringCount
        chunk.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        chunk.extend_from_slice(&super::super::types::UTF8_FLAG.to_le_bytes()); // flags
        chunk.extend_from_slice(&strings_start.to_le_bytes()); // stringsStart
        chunk.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for o in &offsets {
            chunk.extend_from_slice(&o.to_le_bytes());
        }
        chunk.extend_from_slice(&body);
        chunk
    }

    #[test]
    fn parses_utf8_pool() {
        let chunk = utf8_pool(&["manifest", "exported", "com.example.app"]);
        let pool = StringPool::parse(&chunk).unwrap();
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.get(0), Some("manifest"));
        assert_eq!(pool.get(1), Some("exported"));
        assert_eq!(pool.get(2), Some("com.example.app"));
        assert_eq!(pool.get(0xffff_ffff), None);
        assert_eq!(pool.get(9), None);
    }
}
