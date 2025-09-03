//! Shared test utilities for creating temporary files and common test operations.
//!
//! This module consolidates common test helper functions to avoid duplication
//! across test modules.

use glaurung::triage::io::{IOLimits, SafeFileReader};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

/// Creates a temporary file with the given content.
///
/// This is a shared utility function that creates a `NamedTempFile` and writes
/// the provided content to it. The file will be automatically cleaned up when
/// the returned `NamedTempFile` is dropped.
///
/// # Arguments
///
/// * `content` - The content to write to the temporary file
///
/// # Returns
///
/// A `NamedTempFile` with the content written to it
///
/// # Panics
///
/// Panics if the temporary file cannot be created or if writing to it fails
pub fn create_temp_file(content: &[u8]) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content).unwrap();
    temp_file
}

/// Creates a temporary file with a specific size filled with a repeating byte pattern.
///
/// This is useful for testing I/O limits and buffer handling.
///
/// # Arguments
///
/// * `size` - The size of the file to create in bytes
/// * `pattern` - The byte value to fill the file with
///
/// # Returns
///
/// A `NamedTempFile` with the specified size and pattern
pub fn create_temp_file_with_size(size: usize, pattern: u8) -> NamedTempFile {
    let content = vec![pattern; size];
    create_temp_file(&content)
}

/// Opens a file with SafeFileReader and default IOLimits, unwrapping any errors.
///
/// This consolidates the common pattern of opening files in tests with error handling.
///
/// # Arguments
///
/// * `path` - Path to the file to open
///
/// # Returns
///
/// A `SafeFileReader` instance
///
/// # Panics
///
/// Panics if the file cannot be opened
pub fn open_safe_reader<P: AsRef<Path>>(path: P) -> SafeFileReader {
    SafeFileReader::open(path, IOLimits::default()).unwrap()
}

/// Opens a file with SafeFileReader using custom IOLimits, unwrapping any errors.
///
/// # Arguments
///
/// * `path` - Path to the file to open
/// * `limits` - Custom I/O limits to apply
///
/// # Returns
///
/// A `SafeFileReader` instance
///
/// # Panics
///
/// Panics if the file cannot be opened
pub fn open_safe_reader_with_limits<P: AsRef<Path>>(path: P, limits: IOLimits) -> SafeFileReader {
    SafeFileReader::open(path, limits).unwrap()
}

/// Reads a prefix from a file using SafeFileReader, unwrapping any errors.
///
/// This consolidates the common pattern of reading file prefixes in tests.
///
/// # Arguments
///
/// * `path` - Path to the file to read
/// * `size` - Number of bytes to read from the beginning
///
/// # Returns
///
/// A vector containing the requested bytes
///
/// # Panics
///
/// Panics if the file cannot be opened or read
pub fn read_file_prefix<P: AsRef<Path>>(path: P, size: u64) -> Vec<u8> {
    let mut reader = open_safe_reader(path);
    reader.read_prefix(size).unwrap()
}

/// Reads a prefix from a file using SafeFileReader with custom limits, unwrapping any errors.
///
/// # Arguments
///
/// * `path` - Path to the file to read
/// * `size` - Number of bytes to read from the beginning
/// * `limits` - Custom I/O limits to apply
///
/// # Returns
///
/// A vector containing the requested bytes
///
/// # Panics
///
/// Panics if the file cannot be opened or read
pub fn read_file_prefix_with_limits<P: AsRef<Path>>(
    path: P,
    size: u64,
    limits: IOLimits,
) -> Vec<u8> {
    let mut reader = open_safe_reader_with_limits(path, limits);
    reader.read_prefix(size).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_create_temp_file() {
        let content = b"hello world";
        let temp_file = create_temp_file(content);

        // Verify file exists and has correct content
        let path = temp_file.path();
        assert!(path.exists());

        let read_content = fs::read(path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_create_temp_file_with_size() {
        let size = 1024;
        let pattern = 0xAA;
        let temp_file = create_temp_file_with_size(size, pattern);

        let path = temp_file.path();
        let read_content = fs::read(path).unwrap();

        assert_eq!(read_content.len(), size);
        assert!(read_content.iter().all(|&b| b == pattern));
    }

    #[test]
    fn test_empty_file() {
        let temp_file = create_temp_file(b"");
        let path = temp_file.path();
        let read_content = fs::read(path).unwrap();
        assert_eq!(read_content.len(), 0);
    }

    #[test]
    fn test_open_safe_reader() {
        let content = b"test content for safe reader";
        let temp_file = create_temp_file(content);

        let reader = open_safe_reader(temp_file.path());
        assert_eq!(reader.size(), content.len() as u64);
    }

    #[test]
    fn test_read_file_prefix() {
        let content = b"hello world test data";
        let temp_file = create_temp_file(content);

        let prefix = read_file_prefix(temp_file.path(), 5);
        assert_eq!(prefix, b"hello");

        let prefix = read_file_prefix(temp_file.path(), 11);
        assert_eq!(prefix, b"hello world");
    }

    #[test]
    fn test_read_file_prefix_with_limits() {
        let content = vec![0xAB; 1000];
        let temp_file = create_temp_file(&content);

        let limits = IOLimits {
            max_read_bytes: 100,
            max_file_size: u64::MAX,
        };

        let prefix = read_file_prefix_with_limits(temp_file.path(), 50, limits);
        assert_eq!(prefix.len(), 50);
        assert!(prefix.iter().all(|&b| b == 0xAB));
    }
}
