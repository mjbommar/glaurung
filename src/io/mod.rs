//! Bounded and safe I/O utilities for file analysis.
//!
//! This module provides a `SafeReader` for accessing file contents in a safe,
//! efficient, and ergonomic way. It uses memory-mapping for performance and
//! enforces strict resource limits to prevent DoS from malicious files.

pub mod error;

use crate::io::error::{IoError, Result};
use bytes::Bytes;
use memmap2::Mmap;
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing::{debug, trace, warn};

/// Maximum size to read for initial sniffing (4KB).
pub const MAX_SNIFF_SIZE: u64 = 4096;
/// Maximum size for header validation (64KB).
pub const MAX_HEADER_SIZE: u64 = 65536;
/// Maximum size for entropy calculation and other heuristics (1MB).
pub const MAX_HEURISTICS_SIZE: u64 = 1024 * 1024;

/// Defines the resource limits for I/O operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IOLimits {
    /// The absolute maximum file size that can be opened.
    pub max_file_size: u64,
    /// The maximum total number of bytes that can be read from the file across all operations.
    pub max_read_bytes: u64,
}

impl Default for IOLimits {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_read_bytes: 10 * 1024 * 1024,  // 10MB
        }
    }
}

/// A safe, bounded file reader that uses memory-mapping for efficient access.
///
/// It ensures that file access is constrained by the provided `IOLimits`,
/// preventing excessive memory usage and protecting against denial-of-service vectors.
pub struct SafeReader {
    path: PathBuf,
    // None when the file size is zero; memmap cannot map empty files.
    mmap: Option<Mmap>,
    limits: IOLimits,
    bytes_read: u64,
    file_size: u64,
}

impl SafeReader {
    /// Opens a file, memory-maps it, and wraps it in a `SafeReader`.
    ///
    /// This function will fail if the file size exceeds `limits.max_file_size`.
    pub fn open<P: AsRef<Path>>(path: P, limits: IOLimits) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        debug!(
            path = %path.display(),
            size = file_size,
            limits.max_file_size = limits.max_file_size,
            "Opening file for safe reading"
        );

        if file_size > limits.max_file_size {
            warn!(
                path = %path.display(),
                size = file_size,
                limit = limits.max_file_size,
                "File is too large"
            );
            return Err(IoError::FileTooLarge {
                limit: limits.max_file_size,
                found: file_size,
            });
        }

        // For zero-length files, do not attempt to mmap (unsupported); keep None.
        // For non-empty files, map read-only.
        let mmap = if file_size == 0 {
            None
        } else {
            // Safety: The file is backed by a real file on disk and we only request a read-only map.
            Some(unsafe { Mmap::map(&file)? })
        };

        Ok(Self { path: path.to_path_buf(), mmap, limits, bytes_read: 0, file_size })
    }

    /// Returns the total size of the underlying file in bytes.
    pub fn size(&self) -> u64 { self.file_size }

    /// Returns the total number of bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Returns the `IOLimits` enforced by this reader.
    pub fn limits(&self) -> &IOLimits {
        &self.limits
    }

    /// Reads a slice of the file at a given offset.
    ///
    /// Returns a `Bytes` object, which is a cheap, reference-counted slice of the
    /// underlying memory map.
    ///
    /// # Errors
    ///
    /// Returns `IoError::ReadLimitExceeded` if the requested read would cause the
    /// total number of bytes read to exceed `limits.max_read_bytes`.
    pub fn read_at(&mut self, offset: u64, len: u64) -> Result<Bytes> {
        let requested_len = len as usize;
        let offset = offset as usize;

        // Check if the read would exceed the total read budget.
        if self.bytes_read.saturating_add(len) > self.limits.max_read_bytes {
            warn!(
                path = %self.path.display(),
                current_read = self.bytes_read,
                requested = len,
                limit = self.limits.max_read_bytes,
                "Read limit exceeded"
            );
            return Err(IoError::ReadLimitExceeded {
                limit: self.limits.max_read_bytes,
                current: self.bytes_read,
            });
        }

        // If the file is empty or offset is beyond EOF, return empty without changing state.
        if self.file_size == 0 {
            return Ok(Bytes::new());
        }

        let map = match &self.mmap {
            Some(m) => m,
            None => return Ok(Bytes::new()),
        };

        // Ensure the read is within the file's bounds.
        let end = offset.saturating_add(requested_len);
        if offset >= map.len() {
            return Ok(Bytes::new()); // Read starts past EOF.
        }
        let bounded_end = std::cmp::min(end, map.len());
        let actual_len = bounded_end - offset;

        // Copy out a Bytes buffer referencing owned data (avoid invalid from_static).
        let slice = &map[offset..bounded_end];
        let out = Bytes::copy_from_slice(slice);
        self.bytes_read += actual_len as u64;

        trace!(
            path = %self.path.display(),
            offset = offset,
            len = actual_len,
            total_read = self.bytes_read,
            "Performed read"
        );

        Ok(out)
    }

    /// A convenience method to read a prefix of the file.
    ///
    /// Equivalent to `read_at(0, len)`.
    pub fn read_prefix(&mut self, len: u64) -> Result<Bytes> {
        self.read_at(0, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file(content: &[u8]) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content).unwrap();
        temp_file
    }

    #[test]
    fn open_file_successfully() {
        let file = create_temp_file(b"hello world");
        let limits = IOLimits::default();
        let reader = SafeReader::open(file.path(), limits).unwrap();
        assert_eq!(reader.size(), 11);
    }

    #[test]
    fn open_file_too_large() {
        let file = create_temp_file(&[0; 100]);
        let limits = IOLimits {
            max_file_size: 50,
            max_read_bytes: 1000,
        };
        let result = SafeReader::open(file.path(), limits);
        assert!(matches!(result, Err(IoError::FileTooLarge { .. })));
    }

    #[test]
    fn read_prefix_correctly() {
        let file = create_temp_file(b"hello world");
        let limits = IOLimits::default();
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        let data = reader.read_prefix(5).unwrap();
        assert_eq!(data, &b"hello"[..]);
        assert_eq!(reader.bytes_read(), 5);
    }

    #[test]
    fn read_at_offset_correctly() {
        let file = create_temp_file(b"hello world");
        let limits = IOLimits::default();
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        let data = reader.read_at(6, 5).unwrap();
        assert_eq!(data, &b"world"[..]);
        assert_eq!(reader.bytes_read(), 5);
    }

    #[test]
    fn read_past_eof_returns_partial() {
        let file = create_temp_file(b"hello");
        let limits = IOLimits::default();
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        let data = reader.read_at(3, 10).unwrap();
        assert_eq!(data, &b"lo"[..]);
        assert_eq!(reader.bytes_read(), 2);
    }

    #[test]
    fn read_at_eof_returns_empty() {
        let file = create_temp_file(b"hello");
        let limits = IOLimits::default();
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        let data = reader.read_at(5, 10).unwrap();
        assert!(data.is_empty());
        assert_eq!(reader.bytes_read(), 0);
    }

    #[test]
    fn enforce_read_limit_single_read() {
        let file = create_temp_file(&[0; 100]);
        let limits = IOLimits {
            max_file_size: 1000,
            max_read_bytes: 50,
        };
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        let result = reader.read_prefix(60);
        assert!(matches!(result, Err(IoError::ReadLimitExceeded { .. })));
    }

    #[test]
    fn enforce_read_limit_multiple_reads() {
        let file = create_temp_file(&[0; 100]);
        let limits = IOLimits {
            max_file_size: 1000,
            max_read_bytes: 50,
        };
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        
        // First read, should succeed
        let data1 = reader.read_prefix(30).unwrap();
        assert_eq!(data1.len(), 30);
        assert_eq!(reader.bytes_read(), 30);

        // Second read, should fail
        let result = reader.read_at(30, 30);
        assert!(matches!(result, Err(IoError::ReadLimitExceeded { .. })));
        
        // State should not have changed
        assert_eq!(reader.bytes_read(), 30);
    }
    
    #[test]
    fn read_up_to_exact_limit() {
        let file = create_temp_file(&[0; 100]);
        let limits = IOLimits {
            max_file_size: 1000,
            max_read_bytes: 50,
        };
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        
        let data1 = reader.read_prefix(30).unwrap();
        assert_eq!(data1.len(), 30);

        let data2 = reader.read_at(30, 20).unwrap();
        assert_eq!(data2.len(), 20);
        
        assert_eq!(reader.bytes_read(), 50);

        // Next read should return empty without error, as we request 0 bytes effectively
        let result = reader.read_at(50, 10);
        assert!(matches!(result, Err(IoError::ReadLimitExceeded { .. })));
    }

    #[test]
    fn open_empty_file() {
        let file = create_temp_file(b"");
        let limits = IOLimits::default();
        let mut reader = SafeReader::open(file.path(), limits).unwrap();
        assert_eq!(reader.size(), 0);
        let data = reader.read_prefix(10).unwrap();
        assert!(data.is_empty());
        assert_eq!(reader.bytes_read(), 0);
    }
}
