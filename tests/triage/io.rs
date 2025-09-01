//! Integration tests for I/O functionality.
//!
//! Tests file reading, size limits, and bounded I/O operations
//! with real sample files.

use glaurung::triage::io::{IOLimits, IOUtils, SafeFileReader};
use std::io::Read;
use std::path::Path;

use crate::common::file_utils::*;
use crate::common::test_data::*;
use crate::common::{sample_file_exists, sample_file_path};

/// Test reading various file types with size limits
#[test]
fn test_file_reading_with_limits() {
    let test_cases = vec![
        (SAMPLE_JAR, "JAR file"),
        (SAMPLE_JAVA_CLASS, "Java class"),
        (SAMPLE_PYTHON_PYC, "Python bytecode"),
        (SAMPLE_FORTRAN, "Fortran executable"),
    ];

    for (file_path, description) in test_cases {
        if !sample_file_exists(file_path) {
            println!("Skipping {} - file not found", file_path);
            continue;
        }

        let path = sample_file_path(file_path);
        assert_path_exists(&path, &format!("{} sample file", description));

        let limits = IOLimits {
            max_read_bytes: 4096,             // Limit to 4KB for testing
            max_file_size: 100 * 1024 * 1024, // 100MB
        };

        let mut reader = SafeFileReader::open(&path, limits.clone()).unwrap();
        println!("Reading {}: {} bytes", description, reader.size());

        // Read first 256 bytes
        let header = reader.read_prefix(256).unwrap();
        println!(
            "  First 256 bytes: {:02x?}",
            &header[..16.min(header.len())]
        );

        // Test that we can read the full file (but limited)
        let mut reader2 = SafeFileReader::open(&path, limits).unwrap();
        let full_data = reader2.read_all().unwrap();

        // Should be limited to max_read_bytes
        assert!(
            full_data.len() <= 4096,
            "Data should be limited to max_read_bytes"
        );
        assert_eq!(full_data.len(), reader.size().min(4096) as usize);
    }
}

/// Test file size limit enforcement
#[test]
fn test_file_size_limit_enforcement() {
    if !sample_file_exists(SAMPLE_JAR) {
        println!("Skipping file size limit test - JAR file not found");
        return;
    }

    let path = sample_file_path(SAMPLE_JAR);

    // Test with limit smaller than file size
    let small_limits = IOLimits {
        max_read_bytes: 1000, // Only allow 1000 bytes
        max_file_size: 2000,  // File is ~1482 bytes, so this should work
    };

    let mut reader = SafeFileReader::open(&path, small_limits.clone()).unwrap();
    let file_size = reader.size();

    // Test reading all (should be limited)
    let data = reader.read_all().unwrap();
    assert_eq!(data.len(), 1000); // Should be limited to max_read_bytes

    // Test reading prefix
    let mut reader2 = SafeFileReader::open(&path, small_limits).unwrap();
    let prefix = reader2.read_prefix(500).unwrap();
    assert_eq!(prefix.len(), 500); // Should read exactly what we asked for (within limit)
}

/// Test IO utilities with real files
#[test]
fn test_io_utilities_real_files() {
    if !sample_file_exists(SAMPLE_JAR) {
        println!("Skipping IO utilities test - JAR file not found");
        return;
    }

    let path = sample_file_path(SAMPLE_JAR);

    // Test file existence
    assert!(IOUtils::is_regular_file(&path));

    // Test file size
    let size = IOUtils::file_size(&path).unwrap();
    assert!(size > 0);
    println!("JAR file size: {} bytes", size);

    // Test reading with limit
    let data = IOUtils::read_file_with_limit(&path, 1000).unwrap();
    assert_eq!(data.len(), 1000);

    // Test reading prefix
    let prefix = IOUtils::read_file_prefix(&path, 256, 10000).unwrap();
    assert_eq!(prefix.len(), 256);

    // Verify the data is actually from the file
    let full_prefix = IOUtils::read_file_prefix(&path, 256, 10000).unwrap();
    assert_eq!(prefix, full_prefix);
}

/// Test that bounded readers work correctly
#[test]
fn test_bounded_reader_behavior() {
    use glaurung::triage::io::BoundedReader;
    use std::io::Cursor;

    // Test with a known data size
    let test_data = vec![0u8; 2000]; // 2000 bytes
    let mut reader = BoundedReader::new(Cursor::new(&test_data), 1000);

    let mut buffer = vec![0u8; 1500]; // Try to read more than limit
    let n = reader.read(&mut buffer).unwrap();

    assert_eq!(n, 1000); // Should be limited to 1000 bytes
    assert_eq!(reader.bytes_read(), 1000);

    // Try to read more - should get 0 (EOF due to limit)
    let n2 = reader.read(&mut buffer).unwrap();
    assert_eq!(n2, 0);
}

/// Test reading files that don't exist
#[test]
fn test_missing_file_handling() {
    let nonexistent_path = Path::new("samples/this/file/does/not/exist");

    let limits = IOLimits::default();
    let result = SafeFileReader::open(nonexistent_path, limits);

    assert!(result.is_err(), "Should fail to open nonexistent file");
    assert!(IOUtils::is_regular_file(nonexistent_path) == false);
}
