//! Integration tests for entropy analysis with real samples.

use glaurung::triage::entropy::{analyze_entropy, compute_entropy, entropy_of_slice};
use glaurung::core::triage::EntropyClass;
use std::fs;

/// Test entropy on real Python bytecode files
#[test]
fn test_python_bytecode_entropy() {
    let pyc_files = vec![
        "samples/binaries/platforms/linux/amd64/export/python/hello-py3.8.pyc",
        "samples/binaries/platforms/linux/amd64/export/python/hello-py3.13.pyc",
    ];

    for file_path in pyc_files {
        if !std::path::Path::new(file_path).exists() {
            eprintln!("Skipping {} - not found", file_path);
            continue;
        }

        let data = fs::read(file_path).expect("Failed to read file");
        let cfg = glaurung::triage::config::EntropyConfig::default();
        let analysis = analyze_entropy(&data, &cfg);

        println!("=== {} ===", file_path);
        println!("Overall entropy: {:.2}", analysis.summary.overall.unwrap_or(0.0));
        println!("Classification: {:?}", analysis.classification);
        println!("Has packed indicators: {}", analysis.packed_indicators.verdict > 0.5);

        // Python bytecode should have moderate entropy (compiled code)
        match analysis.classification {
            EntropyClass::Code(_) | EntropyClass::Compressed(_) => {
                // Expected for bytecode
            }
            _ => panic!("Unexpected classification for Python bytecode: {:?}", analysis.classification),
        }
    }
}

/// Test entropy on ELF binaries with different optimization levels
#[test]
fn test_elf_entropy_by_optimization() {
    let elf_files = vec![
        ("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0", "O0"),
        ("samples/binaries/platforms/linux/amd64/export/native/gcc/O3/hello-gcc-O3", "O3"),
    ];

    let mut entropies = Vec::new();
    
    for (file_path, opt_level) in elf_files {
        if !std::path::Path::new(file_path).exists() {
            eprintln!("Skipping {} - not found", file_path);
            continue;
        }

        let data = fs::read(file_path).expect("Failed to read file");
        let entropy = entropy_of_slice(&data);
        entropies.push((opt_level, entropy));

        println!("ELF {} entropy: {:.4}", opt_level, entropy);
        
        // ELF binaries should have moderate entropy
        assert!(entropy > 2.0, "ELF entropy too low");
        assert!(entropy < 7.0, "ELF entropy too high");
    }
}

/// Test entropy cliff detection in mixed content
#[test]
fn test_entropy_cliff_detection() {
    // Create synthetic data with entropy cliff
    let mut data = Vec::new();
    
    // Low entropy section (text-like)
    // Use a simple pseudo-random generator instead of rand crate
    let mut rng = 42u64;
    for _ in 0..8192 {
        rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push(b'A' + ((rng >> 32) as u8 % 26));
    }
    
    // Sudden jump to high entropy (compressed/encrypted-like)
    for _ in 0..8192 {
        rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((rng >> 24) as u8);
    }
    
    let cfg = glaurung::triage::config::EntropyConfig::default();
    let analysis = analyze_entropy(&data, &cfg);
    
    // Should detect entropy cliff
    assert!(analysis.anomalies.len() > 0, "Failed to detect entropy cliff");
    assert!(analysis.packed_indicators.entropy_cliff.is_some(), "No cliff index recorded");
    
    println!("Detected {} anomalies", analysis.anomalies.len());
    for anomaly in &analysis.anomalies {
        println!("  Anomaly at window {}: {:.2} -> {:.2} (delta: {:.2})", 
                 anomaly.index, anomaly.from, anomaly.to, anomaly.delta);
    }
}

/// Test entropy on Java class files
#[test]
fn test_java_class_entropy() {
    let class_file = "samples/binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.class";
    
    if !std::path::Path::new(class_file).exists() {
        eprintln!("Skipping Java class test - file not found");
        return;
    }
    
    let data = fs::read(class_file).expect("Failed to read class file");
    let cfg = glaurung::triage::config::EntropyConfig::default();
    let analysis = analyze_entropy(&data, &cfg);
    
    println!("Java class file entropy: {:.2}", analysis.summary.overall.unwrap_or(0.0));
    
    // Class files have structured binary format with moderate entropy
    match analysis.classification {
        EntropyClass::Code(_) | EntropyClass::Compressed(_) => {
            // Expected for class files
        }
        _ => panic!("Unexpected classification for Java class: {:?}", analysis.classification),
    }
}

/// Test sliding window entropy on large binary
#[test]
fn test_sliding_window_large_file() {
    // Use the largest available sample
    let large_file = "samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-debug";
    
    if !std::path::Path::new(large_file).exists() {
        eprintln!("Skipping large file test - file not found");
        return;
    }
    
    let data = fs::read(large_file).expect("Failed to read file");
    let cfg = glaurung::triage::config::EntropyConfig {
        window_size: 4096,
        step: 2048,  // Overlapping windows
        max_windows: 64,
        ..Default::default()
    };
    
    let summary = compute_entropy(&data, &cfg);
    
    if let Some(windows) = &summary.windows {
        println!("Computed {} entropy windows", windows.len());
        
        // Analyze variance in entropy across the file
        let mean: f64 = windows.iter().sum::<f64>() / windows.len() as f64;
        let variance: f64 = windows.iter()
            .map(|&x| (x - mean) * (x - mean))
            .sum::<f64>() / windows.len() as f64;
        let std_dev = variance.sqrt();
        
        println!("Window entropy stats:");
        println!("  Mean: {:.4}", mean);
        println!("  Std Dev: {:.4}", std_dev);
        println!("  Min: {:.4}", windows.iter().fold(f64::INFINITY, |a, &b| a.min(b)));
        println!("  Max: {:.4}", windows.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b)));
        
        // Binary files should have some variance in entropy
        assert!(std_dev > 0.1, "Entropy too uniform across file");
    }
}

/// Test entropy on different file formats
#[test]
fn test_cross_format_entropy_comparison() {
    let test_files = vec![
        ("samples/binaries/platforms/linux/amd64/export/python/hello.pyc", "Python"),
        ("samples/binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.jar", "JAR"),
        ("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0", "ELF"),
        ("samples/binaries/platforms/linux/amd64/export/go/hello-go", "Go"),
        ("samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release", "Rust"),
    ];
    
    let cfg = glaurung::triage::config::EntropyConfig::default();
    let mut results = Vec::new();
    
    for (file_path, format) in test_files {
        if !std::path::Path::new(file_path).exists() {
            eprintln!("Skipping {} - not found", file_path);
            continue;
        }
        
        let data = fs::read(file_path).expect("Failed to read file");
        let analysis = analyze_entropy(&data, &cfg);
        let entropy = analysis.summary.overall.unwrap_or(0.0);
        
        results.push((format, entropy, analysis.classification.clone()));
        println!("{}: entropy={:.4}, class={:?}", format, entropy, analysis.classification);
    }
    
    // JAR files (ZIP) should have higher entropy than native binaries
    let jar_entropy = results.iter()
        .find(|(fmt, _, _)| *fmt == "JAR")
        .map(|(_, e, _)| *e);
    let elf_entropy = results.iter()
        .find(|(fmt, _, _)| *fmt == "ELF")
        .map(|(_, e, _)| *e);
    
    if let (Some(jar), Some(elf)) = (jar_entropy, elf_entropy) {
        assert!(jar > elf, "JAR should have higher entropy than uncompressed ELF");
    }
}

/// Benchmark entropy calculation performance
#[test]
#[ignore] // Run with --ignored for benchmarks
fn bench_entropy_performance() {
    use std::time::Instant;
    
    let sizes = vec![1024, 16384, 65536, 262144, 1048576];
    
    for size in sizes {
        // Create pseudo-random data without external crate
        let mut rng = 12345u64;
        let data: Vec<u8> = (0..size).map(|_| {
            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            (rng >> 24) as u8
        }).collect();
        
        let start = Instant::now();
        let _ = entropy_of_slice(&data);
        let duration = start.elapsed();
        
        let throughput = (size as f64) / duration.as_secs_f64() / 1_000_000.0;
        println!("Size: {:7} bytes, Time: {:?}, Throughput: {:.2} MB/s", 
                 size, duration, throughput);
    }
}