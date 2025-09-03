//! Integration tests using real sample files.
//!
//! Comprehensive tests that validate the triage system works correctly
//! with actual binary files from the samples directory.

use glaurung::triage::io::{IOLimits, SafeFileReader};
use glaurung::triage::sniffers::CombinedSniffer;
use std::path::Path;

use crate::common::test_data::*;
use crate::common::{sample_file_exists, sample_file_path};

/// Comprehensive test of file type detection
#[test]
fn test_comprehensive_file_type_detection() {
    let test_cases = vec![
        (SAMPLE_ELF_GCC, "GCC ELF", vec!["elf"]),
        (SAMPLE_ELF_CLANG, "Clang ELF", vec!["elf"]),
        (SAMPLE_PE_EXE, "Windows PE", vec!["exe"]),
        (SAMPLE_JAR, "Java JAR", vec!["zip", "jar"]),
        (SAMPLE_JAVA_CLASS, "Java class", vec!["class"]),
        (SAMPLE_FORTRAN, "Fortran ELF", vec!["elf"]),
    ];

    for (file_path, description, expected_labels) in test_cases {
        if !sample_file_exists(file_path) {
            println!("Skipping {} - file not found", file_path);
            continue;
        }

        let path = sample_file_path(file_path);
        let limits = IOLimits::default();
        let mut reader = SafeFileReader::open(&path, limits).unwrap();
        let data = reader.read_prefix(4096).unwrap();

        let result = CombinedSniffer::sniff(&data, Some(&path));

        println!("=== {} ===", description);
        println!("File: {}", file_path);
        println!("Size: {} bytes", reader.size());
        println!("Hints found: {}", result.hints.len());
        println!("Errors: {}", result.errors.len());

        for hint in &result.hints {
            println!(
                "  - {} ({:?}): {}",
                hint.label.as_deref().unwrap_or("unknown"),
                hint.source,
                hint.mime.as_deref().unwrap_or("no mime")
            );
        }

        // Should have at least one hint
        assert!(
            !result.hints.is_empty(),
            "No hints found for {}",
            description
        );

        // Check that we got expected labels
        let found_labels: Vec<&str> = result
            .hints
            .iter()
            .filter_map(|h| h.label.as_deref())
            .collect();

        let has_expected = expected_labels
            .iter()
            .any(|expected| found_labels.contains(expected));

        assert!(
            has_expected,
            "Expected one of {:?} in {:?} for {}",
            expected_labels, found_labels, description
        );
    }
}

/// Test file size validation and limits
#[test]
fn test_file_size_validation() {
    let test_files = vec![
        (SAMPLE_JAR, "JAR file"),
        (SAMPLE_ELF_GCC, "GCC ELF"),
        (SAMPLE_PE_EXE, "PE executable"),
    ];

    for (file_path, description) in test_files {
        if !sample_file_exists(file_path) {
            println!("Skipping {} size test - file not found", file_path);
            continue;
        }

        let path = sample_file_path(file_path);
        let limits = IOLimits::default();

        let reader = SafeFileReader::open(&path, limits).unwrap();
        let file_size = reader.size();

        println!("{} size: {} bytes", description, file_size);
        assert!(file_size > 0, "File should not be empty: {}", description);

        // Test with very restrictive limits
        let restrictive_limits = IOLimits {
            max_read_bytes: 100,
            max_file_size: file_size + 1000, // Allow the file but limit reading
        };

        let mut restrictive_reader = SafeFileReader::open(&path, restrictive_limits).unwrap();
        let limited_data = restrictive_reader.read_all().unwrap();

        assert_eq!(
            limited_data.len(),
            100,
            "Should be limited to 100 bytes for {}",
            description
        );
    }
}

/// Test reading different sections of files
#[test]
fn test_file_section_reading() {
    if !sample_file_exists(SAMPLE_ELF_GCC) {
        println!("Skipping section reading test - ELF file not found");
        return;
    }

    let path = sample_file_path(SAMPLE_ELF_GCC);
    let limits = IOLimits::default();
    let mut reader = SafeFileReader::open(&path, limits.clone()).unwrap();

    // Read ELF header (first 64 bytes)
    let elf_header = reader.read_prefix(64).unwrap();
    println!("ELF header (64 bytes): {:02x?}", &elf_header[..16]);

    // Verify ELF magic
    assert_eq!(
        &elf_header[0..4],
        &[0x7f, 0x45, 0x4c, 0x46],
        "Should be ELF magic"
    );

    // Read more data
    let mut reader2 = SafeFileReader::open(&path, limits).unwrap();
    let more_data = reader2.read_prefix(256).unwrap();
    println!("First 256 bytes: {:02x?}", &more_data[..32]);

    // Verify the additional data is consistent
    assert_eq!(
        &more_data[0..64],
        &elf_header[..],
        "First 64 bytes should match"
    );
}

/// Test error handling with malformed or missing files
#[test]
fn test_error_handling() {
    // Test with non-existent file
    let nonexistent = Path::new("samples/does/not/exist");
    let limits = IOLimits::default();

    let result = SafeFileReader::open(nonexistent, limits);
    assert!(result.is_err(), "Should fail to open non-existent file");

    // Test with file that's too large (if we had one)
    // This would test the max_file_size limit

    println!("Error handling tests completed successfully");
}

/// Test that our sniffers handle edge cases gracefully
#[test]
fn test_sniffer_edge_cases() {
    // Test with empty file (if we had one)
    // Test with very small files
    // Test with files that have unusual extensions

    let test_cases = vec![
        (SAMPLE_PYTHON_PYC, "Python bytecode (may not be detected)"),
        (SAMPLE_JAVA_CLASS, "Java class file"),
    ];

    for (file_path, description) in test_cases {
        if !sample_file_exists(file_path) {
            println!("Skipping {} - file not found", file_path);
            continue;
        }

        let path = sample_file_path(file_path);
        let limits = IOLimits::default();
        let mut reader = SafeFileReader::open(&path, limits).unwrap();
        let data = reader.read_prefix(4096).unwrap();

        let result = CombinedSniffer::sniff(&data, Some(&path));

        println!(
            "{}: {} hints, {} errors",
            description,
            result.hints.len(),
            result.errors.len()
        );

        // Should not have errors (even if no hints)
        assert!(
            result.errors.is_empty(),
            "Should not have errors for {}",
            description
        );

        // Print what we found (for debugging)
        for hint in &result.hints {
            println!("  Found: {:?} ({:?})", hint.label, hint.source);
        }
    }
}
