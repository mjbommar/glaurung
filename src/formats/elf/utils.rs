//! Utility functions for ELF parsing

use crate::formats::elf::types::{ElfClass, ElfData, ElfError, Result};

/// Trait for reading values with endianness support
pub trait EndianRead {
    fn read_u16(&self, offset: usize, data: ElfData) -> Result<u16>;
    fn read_u32(&self, offset: usize, data: ElfData) -> Result<u32>;
    fn read_u64(&self, offset: usize, data: ElfData) -> Result<u64>;
    fn read_i32(&self, offset: usize, data: ElfData) -> Result<i32>;
    fn read_i64(&self, offset: usize, data: ElfData) -> Result<i64>;
}

impl EndianRead for [u8] {
    fn read_u16(&self, offset: usize, data: ElfData) -> Result<u16> {
        if offset + 2 > self.len() {
            return Err(ElfError::Truncated { offset, needed: 2 });
        }
        let bytes: [u8; 2] = self[offset..offset + 2].try_into().unwrap();
        Ok(match data {
            ElfData::Little => u16::from_le_bytes(bytes),
            ElfData::Big => u16::from_be_bytes(bytes),
        })
    }

    fn read_u32(&self, offset: usize, data: ElfData) -> Result<u32> {
        if offset + 4 > self.len() {
            return Err(ElfError::Truncated { offset, needed: 4 });
        }
        let bytes: [u8; 4] = self[offset..offset + 4].try_into().unwrap();
        Ok(match data {
            ElfData::Little => u32::from_le_bytes(bytes),
            ElfData::Big => u32::from_be_bytes(bytes),
        })
    }

    fn read_u64(&self, offset: usize, data: ElfData) -> Result<u64> {
        if offset + 8 > self.len() {
            return Err(ElfError::Truncated { offset, needed: 8 });
        }
        let bytes: [u8; 8] = self[offset..offset + 8].try_into().unwrap();
        Ok(match data {
            ElfData::Little => u64::from_le_bytes(bytes),
            ElfData::Big => u64::from_be_bytes(bytes),
        })
    }

    fn read_i32(&self, offset: usize, data: ElfData) -> Result<i32> {
        if offset + 4 > self.len() {
            return Err(ElfError::Truncated { offset, needed: 4 });
        }
        let bytes: [u8; 4] = self[offset..offset + 4].try_into().unwrap();
        Ok(match data {
            ElfData::Little => i32::from_le_bytes(bytes),
            ElfData::Big => i32::from_be_bytes(bytes),
        })
    }

    fn read_i64(&self, offset: usize, data: ElfData) -> Result<i64> {
        if offset + 8 > self.len() {
            return Err(ElfError::Truncated { offset, needed: 8 });
        }
        let bytes: [u8; 8] = self[offset..offset + 8].try_into().unwrap();
        Ok(match data {
            ElfData::Little => i64::from_le_bytes(bytes),
            ElfData::Big => i64::from_be_bytes(bytes),
        })
    }
}

/// Read an address based on ELF class
pub fn read_addr(data: &[u8], offset: usize, class: ElfClass, endian: ElfData) -> Result<u64> {
    match class {
        ElfClass::Elf32 => data.read_u32(offset, endian).map(|v| v as u64),
        ElfClass::Elf64 => data.read_u64(offset, endian),
    }
}

/// Read a null-terminated string from data
pub fn read_cstring(data: &[u8], offset: usize) -> Result<&str> {
    if offset >= data.len() {
        return Err(ElfError::InvalidOffset { offset });
    }

    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());

    std::str::from_utf8(&slice[..end]).map_err(|_| ElfError::InvalidString)
}

/// Align a value up to the specified alignment
pub fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 || alignment == 1 {
        value
    } else {
        (value + alignment - 1) & !(alignment - 1)
    }
}

/// Check if a range is within bounds
pub fn check_bounds(offset: usize, size: usize, data_len: usize) -> Result<()> {
    if offset > data_len || size > data_len || offset + size > data_len {
        Err(ElfError::InvalidOffset { offset })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_read() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

        // Little endian
        assert_eq!(data.read_u16(0, ElfData::Little).unwrap(), 0x3412);
        assert_eq!(data.read_u32(0, ElfData::Little).unwrap(), 0x78563412);
        assert_eq!(
            data.read_u64(0, ElfData::Little).unwrap(),
            0xf0debc9a78563412
        );

        // Big endian
        assert_eq!(data.read_u16(0, ElfData::Big).unwrap(), 0x1234);
        assert_eq!(data.read_u32(0, ElfData::Big).unwrap(), 0x12345678);
        assert_eq!(data.read_u64(0, ElfData::Big).unwrap(), 0x123456789abcdef0);
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstring(data, 0).unwrap(), "hello");
        assert_eq!(read_cstring(data, 6).unwrap(), "world");

        let data = b"no_null_terminator";
        assert_eq!(read_cstring(data, 0).unwrap(), "no_null_terminator");
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(0x1234, 0x1000), 0x2000);
        assert_eq!(align_up(0x2000, 0x1000), 0x2000);
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
}
