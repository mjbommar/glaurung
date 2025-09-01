//! Integration tests for packer detection with real samples.

use glaurung::triage::packers::detect_packers;
use glaurung::triage::api::{analyze_path, analyze_bytes};
use glaurung::triage::io::IOLimits;
use std::fs;
use std::path::Path;

/// Test UPX detection on packed binaries
#[test]
fn test_upx_detection_real_binaries() {
    // Try to find UPX-packed samples
    let test_files = vec![
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0.upx9",
        "samples/binaries/platforms/linux/amd64/export/native/clang/O0/hello-c-clang-O0.upx9",
        "samples/binaries/platforms/linux/amd64/export/go/hello-go.upx9",
        "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release.upx9",
    ];
    
    let mut found_any = false;
    
    for file_path in test_files {
        if !Path::new(file_path).exists() {
            continue;
        }
        
        found_any = true;
        let data = fs::read(file_path).expect("Failed to read packed file");
        let packers = detect_packers(&data);
        
        println!("Testing {}", file_path);
        println!("  File size: {} bytes", data.len());
        println!("  Detected packers: {:?}", packers);
        
        // Should detect UPX
        assert!(!packers.is_empty(), "Failed to detect UPX in {}", file_path);
        
        let upx_match = packers.iter().find(|p| p.name == "UPX");
        assert!(upx_match.is_some(), "UPX not detected in {}", file_path);
        
        let confidence = upx_match.unwrap().confidence;
        println!("  UPX confidence: {:.2}", confidence);
        
        // Should have reasonable confidence
        assert!(confidence > 0.5, "UPX confidence too low: {}", confidence);
    }
    
    if !found_any {
        eprintln!("No UPX-packed samples found. Run: cd samples && ./build-packed.sh");
    }
}

/// Test that unpacked binaries don't trigger false positives
#[test]
fn test_no_false_positives_unpacked() {
    let test_files = vec![
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0",
        "samples/binaries/platforms/linux/amd64/export/python/hello.pyc",
        "samples/binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.class",
    ];
    
    for file_path in test_files {
        if !Path::new(file_path).exists() {
            continue;
        }
        
        let data = fs::read(file_path).expect("Failed to read file");
        let packers = detect_packers(&data);
        
        println!("Testing {} for false positives", file_path);
        println!("  Detected packers: {:?}", packers);
        
        // Should not detect UPX in unpacked files
        let upx_match = packers.iter().find(|p| p.name == "UPX");
        assert!(upx_match.is_none(), "False positive UPX detection in {}", file_path);
    }
}

/// Test packer detection through the full triage API
#[test]
fn test_packer_detection_via_triage_api() {
    let packed_file = "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0.upx9";
    
    if !Path::new(packed_file).exists() {
        eprintln!("Skipping API test - packed file not found");
        return;
    }
    
    let limits = IOLimits::default();
    let artifact = analyze_path(packed_file, &limits).expect("Failed to analyze packed file");
    
    println!("Triage result for packed binary:");
    println!("  Verdicts: {:?}", artifact.verdicts);
    println!("  Packers: {:?}", artifact.packers);
    
    // Should detect packer
    assert!(artifact.packers.is_some(), "No packers field in result");
    
    let packers = artifact.packers.unwrap();
    assert!(!packers.is_empty(), "No packers detected");
    
    // Check confidence signals for packer
    if !artifact.verdicts.is_empty() {
        let verdict = &artifact.verdicts[0];
        if let Some(signals) = &verdict.signals {
            let packer_signal = signals.iter().find(|s| s.name.contains("packer"));
            println!("  Packer signal: {:?}", packer_signal);
        }
    }
}

/// Test comparison of packed vs unpacked entropy
#[test]
fn test_packed_vs_unpacked_entropy() {
    use glaurung::triage::entropy::entropy_of_slice;
    
    let pairs = vec![
        (
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0",
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0.upx9"
        ),
    ];
    
    for (orig_path, packed_path) in pairs {
        if !Path::new(orig_path).exists() || !Path::new(packed_path).exists() {
            continue;
        }
        
        let orig_data = fs::read(orig_path).expect("Failed to read original");
        let packed_data = fs::read(packed_path).expect("Failed to read packed");
        
        let orig_entropy = entropy_of_slice(&orig_data);
        let packed_entropy = entropy_of_slice(&packed_data);
        
        println!("Entropy comparison:");
        println!("  Original: {} bytes, entropy: {:.4}", orig_data.len(), orig_entropy);
        println!("  Packed:   {} bytes, entropy: {:.4}", packed_data.len(), packed_entropy);
        println!("  Compression ratio: {:.2}x", orig_data.len() as f64 / packed_data.len() as f64);
        
        // UPX-packed files should have higher entropy due to compression
        assert!(packed_entropy > orig_entropy, 
                "Packed entropy ({:.4}) should be higher than original ({:.4})", 
                packed_entropy, orig_entropy);
    }
}

/// Test UPX version detection
#[test]
fn test_upx_version_detection() {
    // Create a test binary with known UPX version string
    let test_data_with_version = b"UPX!\x00\x00\x00\x00$Id: UPX 4.2.4 Copyright";
    
    let packers = detect_packers(test_data_with_version);
    assert!(!packers.is_empty(), "Failed to detect UPX with version string");
    
    let upx = &packers[0];
    assert_eq!(upx.name, "UPX");
    
    // Should have higher confidence with version string
    println!("UPX confidence with version: {:.2}", upx.confidence);
    assert!(upx.confidence > 0.7, "Version detection should increase confidence");
}

/// Test scanning limits for packer detection
#[test]
fn test_packer_scan_limits() {
    use std::time::Instant;
    
    // Create large test data with UPX signature at different positions
    let positions = vec![0, 1024, 16384, 524288 - 4];
    
    for pos in positions {
        let mut data = vec![0u8; 524288];
        data[pos..pos + 4].copy_from_slice(b"UPX!");
        
        let start = Instant::now();
        let packers = detect_packers(&data);
        let duration = start.elapsed();
        
        println!("Scan with UPX at position {}: {:?}", pos, duration);
        assert!(!packers.is_empty(), "Failed to find UPX at position {}", pos);
        
        // Should complete quickly even for large files
        assert!(duration.as_millis() < 100, "Scan took too long: {:?}", duration);
    }
}

/// Test packed Python bytecode (if possible with UPX)
#[test]
fn test_packed_python_bytecode() {
    // Note: Python .pyc files typically can't be UPX-packed directly,
    // but we can test our packer detection doesn't interfere with
    // Python bytecode detection
    
    let pyc_file = "samples/binaries/platforms/linux/amd64/export/python/hello.pyc";
    
    if !Path::new(pyc_file).exists() {
        return;
    }
    
    let data = fs::read(pyc_file).expect("Failed to read Python bytecode");
    let packers = detect_packers(&data);
    
    // Should not detect packers in regular Python bytecode
    assert!(packers.is_empty(), "False positive packer detection in .pyc file");
    
    // Verify through full triage that it's still detected as Python
    let limits = IOLimits::default();
    let artifact = analyze_bytes(&data, &limits).expect("Failed to analyze");
    
    if !artifact.verdicts.is_empty() {
        use glaurung::core::binary::Format;
        assert_eq!(artifact.verdicts[0].format, Format::PythonBytecode, 
                   "Python bytecode not properly detected");
    }
}

/// Benchmark packer detection performance
#[test]
#[ignore] // Run with --ignored for benchmarks
fn bench_packer_detection() {
    use std::time::Instant;
    
    let test_files = vec![
        ("Small binary", "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0"),
        ("Large binary", "samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-debug"),
        ("Packed binary", "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0.upx9"),
    ];
    
    for (desc, file_path) in test_files {
        if !Path::new(file_path).exists() {
            continue;
        }
        
        let data = fs::read(file_path).expect("Failed to read file");
        let iterations = 1000;
        
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = detect_packers(&data);
        }
        let duration = start.elapsed();
        
        let per_scan = duration / iterations;
        let throughput = (data.len() as f64 * iterations as f64) / duration.as_secs_f64() / 1_000_000.0;
        
        println!("{}: {} bytes", desc, data.len());
        println!("  Time per scan: {:?}", per_scan);
        println!("  Throughput: {:.2} MB/s", throughput);
    }
}