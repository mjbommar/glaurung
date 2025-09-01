//! Integration tests for sniffer functionality.
//!
//! Tests the interaction between content and extension sniffers
//! using real sample files.

use glaurung::triage::io::{IOLimits, SafeFileReader};
use glaurung::triage::sniffers::{CombinedSniffer, ContentSniffer, ExtensionSniffer};

use crate::common::file_utils::*;
use crate::common::test_data::*;
use crate::common::{sample_file_exists, sample_file_path};

/// Test content sniffer with real ELF files
#[test]
fn test_content_sniffer_real_files() {
    let test_cases = vec![(SAMPLE_ELF_GCC, "GCC ELF"), (SAMPLE_ELF_CLANG, "Clang ELF")];

    for (file_path, description) in test_cases {
        if !sample_file_exists(file_path) {
            println!("Skipping {} - file not found", file_path);
            continue;
        }

        let path = sample_file_path(file_path);
        assert_path_exists(&path, &format!("{} sample file", description));

        let limits = IOLimits::default();
        let mut reader = SafeFileReader::open(&path, limits).unwrap();
        let data = reader.read_prefix(4096).unwrap();

        let hint = ContentSniffer::sniff_bytes(&data);
        if let Some(hint) = hint {
            println!("{}: detected as {:?}", description, hint.label);
            assert!(hint.mime.is_some());
        }
    }
}

/// Test extension sniffer with real files
#[test]
fn test_extension_sniffer_real_files() {
    let test_cases = vec![
        (SAMPLE_PE_EXE, "exe"),
        (SAMPLE_JAR, "jar"),
        (SAMPLE_JAVA_CLASS, "class"),
    ];

    for (file_path, expected_ext) in test_cases {
        if !sample_file_exists(file_path) {
            println!("Skipping {} - file not found", file_path);
            continue;
        }

        let path = sample_file_path(file_path);
        let hint = ExtensionSniffer::sniff_path(&path);

        if let Some(hint) = hint {
            println!("{}: extension detected as {:?}", file_path, hint.extension);
            assert_eq!(hint.extension.as_deref(), Some(expected_ext));
        } else {
            panic!("Expected extension hint for {}", file_path);
        }
    }
}

/// Test combined sniffer with real files
#[test]
fn test_combined_sniffer_real_files() {
    let test_cases = vec![
        (SAMPLE_ELF_GCC, "GCC ELF executable"),
        (SAMPLE_PE_EXE, "Windows PE executable"),
        (SAMPLE_JAR, "Java JAR archive"),
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
            "{}: found {} hints, {} errors",
            description,
            result.hints.len(),
            result.errors.len()
        );

        // Print detailed results for debugging
        for hint in &result.hints {
            println!(
                "  Hint: {:?} ({:?}) - {:?}",
                hint.label, hint.source, hint.mime
            );
        }

        // Should have at least one hint
        assert!(
            !result.hints.is_empty(),
            "No hints found for {}",
            description
        );
    }
}

/// Test sniffer behavior with Python bytecode (expected to have no hints)
#[test]
fn test_sniffer_python_bytecode() {
    if !sample_file_exists(SAMPLE_PYTHON_PYC) {
        println!("Skipping Python bytecode test - file not found");
        return;
    }

    let path = sample_file_path(SAMPLE_PYTHON_PYC);
    let limits = IOLimits::default();
    let mut reader = SafeFileReader::open(&path, limits).unwrap();
    let data = reader.read_prefix(4096).unwrap();

    let result = CombinedSniffer::sniff(&data, Some(&path));
    println!(
        "Python bytecode: found {} hints, {} errors",
        result.hints.len(),
        result.errors.len()
    );

    // Python bytecode might not be detected by our current sniffers
    // This is expected - we're testing that the system doesn't crash
    // and handles unknown formats gracefully
    assert!(
        result.errors.is_empty(),
        "Should not have errors for unknown format"
    );
}
