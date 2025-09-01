//! Bounded I/O utilities for safe file reading.
//!
//! Provides prefix caching, bounded readers, and safe file access
//! with resource limits to prevent DoS attacks.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use tracing::{debug, info, warn};

/// Maximum size to read for initial sniffing (4KB)
pub const MAX_SNIFF_SIZE: u64 = 4096;

/// Maximum size for header validation (64KB)
pub const MAX_HEADER_SIZE: u64 = 65536;

/// Maximum size for entropy calculation (1MB)
pub const MAX_ENTROPY_SIZE: u64 = 1024 * 1024;

/// Resource limits for I/O operations.
#[derive(Debug, Clone)]
pub struct IOLimits {
    pub max_read_bytes: u64,
    pub max_file_size: u64,
}

impl Default for IOLimits {
    fn default() -> Self {
        Self {
            max_read_bytes: 10 * 1024 * 1024, // 10MB
            max_file_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// A bounded reader that limits the amount of data read.
pub struct BoundedReader<R> {
    inner: R,
    bytes_read: u64,
    limit: u64,
}

impl<R: Read> BoundedReader<R> {
    pub fn new(reader: R, limit: u64) -> Self {
        Self {
            inner: reader,
            bytes_read: 0,
            limit,
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.bytes_read >= self.limit {
            debug!("BoundedReader reached limit of {} bytes", self.limit);
            return Ok(0); // EOF
        }

        let remaining = self.limit - self.bytes_read;
        let max_to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let read_buf = &mut buf[..max_to_read];

        let n = self.inner.read(read_buf)?;
        self.bytes_read += n as u64;

        if self.bytes_read >= self.limit {
            warn!(
                "BoundedReader limit reached after reading {} bytes",
                self.bytes_read
            );
        }

        Ok(n)
    }
}

/// Cached prefix data for efficient re-reading.
#[derive(Debug, Clone)]
pub struct PrefixCache {
    data: Vec<u8>,
    capacity: usize,
}

impl PrefixCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn with_data(data: Vec<u8>, capacity: usize) -> Self {
        Self { data, capacity }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Read up to capacity bytes from a reader into the cache.
    pub fn fill_from_reader<R: Read>(&mut self, reader: &mut R) -> io::Result<usize> {
        self.data.clear();
        let mut chunk = vec![0u8; self.capacity];
        let n = reader.read(&mut chunk)?;
        self.data.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// Get a sub-slice of the cached data.
    pub fn slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        if start + len <= self.data.len() {
            Some(&self.data[start..start + len])
        } else {
            None
        }
    }
}

/// Safe file reader with resource limits.
pub struct SafeFileReader {
    file: File,
    size: u64,
    limits: IOLimits,
}

impl SafeFileReader {
    /// Open a file with safety limits.
    pub fn open<P: AsRef<Path>>(path: P, limits: IOLimits) -> io::Result<Self> {
        let path = path.as_ref();
        info!("Opening file for safe reading: {:?}", path);

        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        debug!(
            "File size: {} bytes, limits: max_file={}, max_read={}",
            size, limits.max_file_size, limits.max_read_bytes
        );

        // Check file size limit
        if size > limits.max_file_size {
            warn!(
                "File too large: {} bytes (limit: {})",
                size, limits.max_file_size
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "File too large: {} bytes (limit: {})",
                    size, limits.max_file_size
                ),
            ));
        }

        info!("Successfully opened file: {:?} ({} bytes)", path, size);
        Ok(Self { file, size, limits })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn limits(&self) -> &IOLimits {
        &self.limits
    }

    /// Read the entire file with bounds checking.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut reader = BoundedReader::new(&mut self.file, self.limits.max_read_bytes);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(data)
    }

    /// Read a prefix of the file.
    pub fn read_prefix(&mut self, size: u64) -> io::Result<Vec<u8>> {
        let read_size = std::cmp::min(size, self.limits.max_read_bytes);
        self.file.seek(SeekFrom::Start(0))?;
        let mut reader = BoundedReader::new(&mut self.file, read_size);
        let mut data = vec![0u8; read_size as usize];
        let n = reader.read(&mut data)?;
        data.truncate(n);
        Ok(data)
    }

    /// Create a bounded reader from the current position.
    pub fn bounded_reader(&mut self, limit: u64) -> BoundedReader<&mut File> {
        let effective_limit = std::cmp::min(limit, self.limits.max_read_bytes);
        BoundedReader::new(&mut self.file, effective_limit)
    }

    /// Fill a prefix cache from the file.
    pub fn fill_cache(&mut self, cache: &mut PrefixCache) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut reader = self.bounded_reader(cache.capacity as u64);
        cache.fill_from_reader(&mut reader)
    }
}

/// Utility functions for safe I/O operations.
pub struct IOUtils;

impl IOUtils {
    /// Safely read a file to a vector with size limits.
    pub fn read_file_with_limit<P: AsRef<Path>>(path: P, max_size: u64) -> io::Result<Vec<u8>> {
        // Only limit how much we read; allow larger files but cap read size
        let mut reader = SafeFileReader::open(
            path,
            IOLimits {
                max_read_bytes: max_size,
                max_file_size: u64::MAX,
            },
        )?;
        reader.read_all()
    }

    /// Read just the prefix of a file.
    pub fn read_file_prefix<P: AsRef<Path>>(
        path: P,
        prefix_size: u64,
        max_file_size: u64,
    ) -> io::Result<Vec<u8>> {
        let mut reader = SafeFileReader::open(
            path,
            IOLimits {
                max_read_bytes: prefix_size,
                max_file_size,
            },
        )?;
        reader.read_prefix(prefix_size)
    }

    /// Check if a path exists and is a regular file.
    pub fn is_regular_file<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref()
            .metadata()
            .map(|m| m.is_file())
            .unwrap_or(false)
    }

    /// Get file size without opening it.
    pub fn file_size<P: AsRef<Path>>(path: P) -> io::Result<u64> {
        let metadata = std::fs::metadata(path)?;
        Ok(metadata.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_bounded_reader() {
        let data = b"Hello, World! This is a test.";
        let mut reader = BoundedReader::new(Cursor::new(data), 10);

        let mut buf = [0u8; 20];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], &data[..10]);
        assert_eq!(reader.bytes_read(), 10);

        // Try to read more - should get 0 (EOF due to limit)
        let n2 = reader.read(&mut buf).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_prefix_cache() {
        let data = b"Hello, World!";
        let mut cache = PrefixCache::new(20);

        let mut reader = Cursor::new(data);
        let n = cache.fill_from_reader(&mut reader).unwrap();

        assert_eq!(n, data.len());
        assert_eq!(cache.data(), data);
        assert_eq!(cache.len(), data.len());

        // Test slicing
        let slice = cache.slice(0, 5).unwrap();
        assert_eq!(slice, b"Hello");

        let slice2 = cache.slice(7, 5).unwrap();
        assert_eq!(slice2, b"World");
    }

    #[test]
    fn test_safe_file_reader() {
        let test_data = b"Hello, World! This is test data for the file reader.";
        let temp_file = NamedTempFile::new().unwrap();
        temp_file.as_file().write_all(test_data).unwrap();

        let limits = IOLimits {
            max_read_bytes: 1000,
            max_file_size: 10000,
        };

        let mut reader = SafeFileReader::open(temp_file.path(), limits.clone()).unwrap();
        assert_eq!(reader.size(), test_data.len() as u64);

        // Test reading all
        let data = reader.read_all().unwrap();
        assert_eq!(data, test_data);

        // Test reading prefix
        let limits2 = IOLimits {
            max_read_bytes: 1000,
            max_file_size: 10000,
        };
        let mut reader2 = SafeFileReader::open(temp_file.path(), limits2).unwrap();
        let prefix = reader2.read_prefix(10).unwrap();
        assert_eq!(prefix, &test_data[..10]);
    }

    #[test]
    fn test_file_size_limit() {
        let test_data = vec![0u8; 100]; // 100 bytes
        let temp_file = NamedTempFile::new().unwrap();
        temp_file.as_file().write_all(&test_data).unwrap();

        let limits = IOLimits {
            max_read_bytes: 1000,
            max_file_size: 50, // Smaller than file
        };

        let result = SafeFileReader::open(temp_file.path(), limits);
        assert!(result.is_err());
    }

    #[test]
    fn test_io_utils() {
        let test_data = b"Hello, World!";
        let temp_file = NamedTempFile::new().unwrap();
        temp_file.as_file().write_all(test_data).unwrap();

        // Test reading with limit
        let data = IOUtils::read_file_with_limit(temp_file.path(), 100).unwrap();
        assert_eq!(data, test_data);

        // Test reading prefix
        let prefix = IOUtils::read_file_prefix(temp_file.path(), 5, 1000).unwrap();
        assert_eq!(prefix, &test_data[..5]);

        // Test file size
        let size = IOUtils::file_size(temp_file.path()).unwrap();
        assert_eq!(size, test_data.len() as u64);

        // Test is_regular_file
        assert!(IOUtils::is_regular_file(temp_file.path()));
    }
}
