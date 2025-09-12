//! Utility functions for PE parsing

use crate::formats::pe::types::{PeError, Result};

/// Extension trait for reading primitive types from byte slices
pub trait ReadExt {
    fn read_u8_at(&self, offset: usize) -> Option<u8>;
    fn read_u16_le_at(&self, offset: usize) -> Option<u16>;
    fn read_u32_le_at(&self, offset: usize) -> Option<u32>;
    fn read_u64_le_at(&self, offset: usize) -> Option<u64>;
    fn read_cstring_at(&self, offset: usize, max_len: usize) -> Option<&str>;
    fn read_slice_at(&self, offset: usize, len: usize) -> Option<&[u8]>;
}

impl ReadExt for [u8] {
    #[inline(always)]
    fn read_u8_at(&self, offset: usize) -> Option<u8> {
        self.get(offset).copied()
    }

    #[inline(always)]
    fn read_u16_le_at(&self, offset: usize) -> Option<u16> {
        self.get(offset..offset + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes)
    }

    #[inline(always)]
    fn read_u32_le_at(&self, offset: usize) -> Option<u32> {
        self.get(offset..offset + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    }

    #[inline(always)]
    fn read_u64_le_at(&self, offset: usize) -> Option<u64> {
        self.get(offset..offset + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    }

    fn read_cstring_at(&self, offset: usize, max_len: usize) -> Option<&str> {
        let start = offset;
        let end = (offset + max_len).min(self.len());
        let slice = self.get(start..end)?;

        // Find null terminator
        let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..len]).ok()
    }

    #[inline(always)]
    fn read_slice_at(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset + len > self.len() {
            None
        } else {
            Some(&self[offset..offset + len])
        }
    }
}

/// Helper to read a null-terminated string from a buffer
pub fn read_cstring(data: &[u8], offset: usize, max_len: usize) -> Result<&str> {
    data.read_cstring_at(offset, max_len)
        .ok_or(PeError::InvalidString)
}

/// Helper to read a UTF-16LE string from a buffer
pub fn read_utf16le_string(data: &[u8], offset: usize, max_len: usize) -> Result<String> {
    let end = (offset + max_len * 2).min(data.len());
    if offset >= end {
        return Err(PeError::InvalidOffset { offset });
    }

    let slice = &data[offset..end];
    let mut words = Vec::new();
    let mut i = 0;

    while i + 1 < slice.len() {
        let word = u16::from_le_bytes([slice[i], slice[i + 1]]);
        if word == 0 {
            break;
        }
        words.push(word);
        i += 2;
    }

    String::from_utf16(&words).map_err(|_| PeError::InvalidString)
}

/// Calculate entropy of a byte slice
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Align a value up to the specified alignment
#[inline(always)]
pub fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        value
    } else {
        (value + alignment - 1) & !(alignment - 1)
    }
}

/// Check if a range is within bounds
#[inline(always)]
pub fn check_bounds(offset: usize, size: usize, data_len: usize) -> Result<()> {
    if offset > data_len || size > data_len || offset + size > data_len {
        Err(PeError::InvalidOffset { offset })
    } else {
        Ok(())
    }
}

/// Convert a section name array to a string
pub fn section_name_to_string(name: &[u8; 8]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&name[..end]).to_string()
}

/// Check if data looks like it might be packed/compressed
pub fn is_high_entropy(data: &[u8]) -> bool {
    calculate_entropy(data) > 7.0
}

/// Simple checksum validation helper
pub fn calculate_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum = 0u64;
    let mut i = 0;

    // Sum all 16-bit words
    while i < data.len() {
        // Skip the checksum field itself
        if i == checksum_offset || i == checksum_offset + 1 {
            i += 2;
            continue;
        }

        let word = if i + 1 < data.len() {
            u16::from_le_bytes([data[i], data[i + 1]]) as u64
        } else {
            data[i] as u64
        };

        sum = sum.wrapping_add(word);
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }

    // Add file size
    sum = sum.wrapping_add(data.len() as u64);

    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_ext() {
        let data = b"Hello, World!\0Extra";

        assert_eq!(data.read_u8_at(0), Some(b'H'));
        assert_eq!(data.read_u8_at(100), None);

        let data = b"\x34\x12\x78\x56\x00\x00\x00\x00";
        assert_eq!(data.read_u16_le_at(0), Some(0x1234));
        assert_eq!(data.read_u32_le_at(0), Some(0x56781234));

        let data = b"test\0string";
        assert_eq!(data.read_cstring_at(0, 10), Some("test"));
    }

    #[test]
    fn test_read_cstring() {
        let data = b"Hello\0World";
        assert_eq!(read_cstring(data, 0, 10).unwrap(), "Hello");
        assert_eq!(read_cstring(data, 6, 10).unwrap(), "World");

        // Test without null terminator
        let data = b"NoNull";
        assert_eq!(read_cstring(data, 0, 6).unwrap(), "NoNull");
    }

    #[test]
    fn test_read_utf16le_string() {
        let data = b"H\0e\0l\0l\0o\0\0\0";
        assert_eq!(read_utf16le_string(data, 0, 10).unwrap(), "Hello");

        // Test empty string
        let data = b"\0\0";
        assert_eq!(read_utf16le_string(data, 0, 10).unwrap(), "");
    }

    #[test]
    fn test_calculate_entropy() {
        // All same bytes = 0 entropy
        let data = vec![0x41; 100];
        assert_eq!(calculate_entropy(&data), 0.0);

        // Random-looking data = high entropy
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0);

        // Empty data
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0x1234, 0x200), 0x1400);

        // Zero alignment
        assert_eq!(align_up(0x1234, 0), 0x1234);
    }

    #[test]
    fn test_check_bounds() {
        assert!(check_bounds(0, 10, 100).is_ok());
        assert!(check_bounds(90, 10, 100).is_ok());
        assert!(check_bounds(0, 100, 100).is_ok());

        assert!(check_bounds(95, 10, 100).is_err());
        assert!(check_bounds(101, 0, 100).is_err());
        assert!(check_bounds(0, 101, 100).is_err());
    }

    #[test]
    fn test_section_name_to_string() {
        let mut name = [0u8; 8];
        name[0..5].copy_from_slice(b".text");
        assert_eq!(section_name_to_string(&name), ".text");

        name.copy_from_slice(b".textbss");
        assert_eq!(section_name_to_string(&name), ".textbss");

        name = [0u8; 8];
        assert_eq!(section_name_to_string(&name), "");
    }

    #[test]
    fn test_is_high_entropy() {
        // Low entropy data
        let data = vec![0x41; 1000];
        assert!(!is_high_entropy(&data));

        // High entropy data (pseudo-random)
        let mut data = Vec::new();
        for i in 0..1000 {
            data.push((i * 7 + 13) as u8);
        }
        // This should have moderate entropy, not necessarily > 7.0
        // Let's create truly random-looking data
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(is_high_entropy(&data));
    }
}
