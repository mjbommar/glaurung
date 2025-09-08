//! MemoryView: safe, bounded reads by Address with simple translation.
//!
//! This trait and helpers allow analysis code to read bytes using
//! `core::address::Address` values. Implementations should be deterministic
//! and enforce bounds to avoid panics.

use crate::core::address::{Address, AddressKind};
use crate::core::binary::Endianness;

/// Errors that can occur during memory reads.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemoryError {
    #[error("unsupported address kind: {0:?}")]
    Unsupported(AddressKind),
    #[error("address out of range: {0}")]
    OutOfRange(String),
    #[error("translation failed: {0}")]
    Translation(String),
}

/// Bounded memory reads by Address.
pub trait MemoryView {
    /// Read `len` bytes starting at `addr`.
    fn read_bytes(&self, addr: &Address, len: usize) -> Result<Vec<u8>, MemoryError>;

    /// Convenience: read a little/big-endian u16.
    fn read_u16(&self, addr: &Address, endian: Endianness) -> Result<u16, MemoryError> {
        let b = self.read_bytes(addr, 2)?;
        Ok(match endian {
            Endianness::Little => u16::from_le_bytes([b[0], b[1]]),
            Endianness::Big => u16::from_be_bytes([b[0], b[1]]),
        })
    }

    /// Convenience: read a little/big-endian u32.
    fn read_u32(&self, addr: &Address, endian: Endianness) -> Result<u32, MemoryError> {
        let b = self.read_bytes(addr, 4)?;
        Ok(match endian {
            Endianness::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endianness::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        })
    }

    /// Convenience: read a little/big-endian u64.
    fn read_u64(&self, addr: &Address, endian: Endianness) -> Result<u64, MemoryError> {
        let b = self.read_bytes(addr, 8)?;
        Ok(match endian {
            Endianness::Little => {
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
            Endianness::Big => u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        })
    }
}

/// A simple memory view over a byte slice that supports FileOffset reads
/// and VA/RVA reads via a user-provided translator function.
pub struct SliceMemoryView<'a> {
    data: &'a [u8],
    /// Translate VA/RVA addresses to FileOffset values when possible.
    /// Returns a FileOffset `Address` on success.
    translator: Option<Box<dyn Fn(&Address) -> Option<Address> + Send + Sync + 'a>>,
}

impl<'a> SliceMemoryView<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            translator: None,
        }
    }

    pub fn with_translator<F>(mut self, f: F) -> Self
    where
        F: Fn(&Address) -> Option<Address> + Send + Sync + 'a,
    {
        self.translator = Some(Box::new(f));
        self
    }
}

impl<'a> MemoryView for SliceMemoryView<'a> {
    fn read_bytes(&self, addr: &Address, len: usize) -> Result<Vec<u8>, MemoryError> {
        if len == 0 {
            return Ok(Vec::new());
        }

        // Normalize address to FileOffset when needed
        let fo_addr = match addr.kind {
            AddressKind::FileOffset => addr.clone(),
            AddressKind::VA | AddressKind::RVA => {
                if let Some(tr) = &self.translator {
                    tr(addr).ok_or_else(|| {
                        MemoryError::Translation(format!("no mapping for {}", addr))
                    })?
                } else {
                    return Err(MemoryError::Unsupported(addr.kind));
                }
            }
            _ => return Err(MemoryError::Unsupported(addr.kind)),
        };

        let start = fo_addr.value as usize;
        let end = start.saturating_add(len);
        if start >= self.data.len() || end > self.data.len() || end < start {
            return Err(MemoryError::OutOfRange(format!(
                "FO:{:#x}..{:#x} (len={}) not within [0,{:#x})",
                start,
                end,
                len,
                self.data.len()
            )));
        }

        Ok(self.data[start..end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn slice_memory_read_file_offset() {
        let data = (0u8..=255u8).collect::<Vec<_>>();
        let mv = SliceMemoryView::new(&data);
        let addr = Address::new(AddressKind::FileOffset, 10, 64, None, None).unwrap();
        let bytes = mv.read_bytes(&addr, 4).unwrap();
        assert_eq!(bytes, vec![10, 11, 12, 13]);
    }

    #[test]
    fn slice_memory_read_va_via_translator() {
        let data = (0u8..=255u8).collect::<Vec<_>>();
        // Simple mapping: VA 0x400000 -> FO 0
        let base = 0x400000u64;
        let mv =
            SliceMemoryView::new(&data).with_translator(move |addr: &Address| match addr.kind {
                AddressKind::VA => {
                    if addr.value < base {
                        return None;
                    }
                    let off = addr.value - base;
                    Address::new(AddressKind::FileOffset, off, addr.bits, None, None).ok()
                }
                AddressKind::RVA => {
                    Address::new(AddressKind::FileOffset, addr.value, addr.bits, None, None).ok()
                }
                _ => None,
            });

        let va = Address::new(AddressKind::VA, base + 5, 64, None, None).unwrap();
        let bytes = mv.read_bytes(&va, 3).unwrap();
        assert_eq!(bytes, vec![5, 6, 7]);
    }
}
