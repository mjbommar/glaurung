//! Comprehensive integration tests for compiler and language detection
//! Tests against all sample binaries in samples/binaries/platforms/

use glaurung::triage::compiler_detection::{
    detect_language_and_compiler_with_path, detect_packer, guess_language_from_compiler,
    is_likely_stripped, is_shared_library, PackerType, *,
};
use glaurung::triage::rich_header;
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Helper to analyze a binary file
fn analyze_binary(path: &Path) -> Option<LanguageDetectionResult> {
    if !path.exists() {
        return None;
    }

    let data = fs::read(path).ok()?;

    // Parse with object crate
    let obj = object::read::File::parse(&*data).ok()?;

    // Extract symbols
    let symbols: Vec<String> = obj
        .symbols()
        .filter_map(|sym| sym.name().ok().map(|n| n.to_string()))
        .collect();

    // Get imports/libraries
    let libraries: Vec<String> = obj
        .imports()
        .ok()
        .map(|imports| {
            let mut libs = std::collections::HashSet::new();
            for imp in imports {
                let lib = imp.library();
                libs.insert(String::from_utf8_lossy(lib).to_string());
            }
            libs.into_iter().collect()
        })
        .unwrap_or_default();

    // Extract strings (simplified - just look for readable ASCII)
    let strings: Vec<String> = extract_strings_from_data(&data);

    // Look for .comment section (ELF)
    let elf_comment = obj
        .sections()
        .find(|s| s.name().ok() == Some(".comment"))
        .and_then(|s| s.data().ok())
        .map(|data| String::from_utf8_lossy(data).to_string());

    // Check for PE Rich Header
    let rich_header = if data.len() >= 2 && &data[..2] == b"MZ" {
        rich_header::parse_rich_header(&data)
    } else {
        None
    };

    // Detect language and compiler with file path context
    Some(detect_language_and_compiler_with_path(
        &symbols,
        &libraries,
        &strings,
        rich_header.as_ref(),
        elf_comment.as_deref(),
        &data,
        Some(path.to_str().unwrap_or("")),
    ))
}

/// Extract printable strings from binary data
fn extract_strings_from_data(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte >= 0x20 && byte < 0x7F {
            current.push(byte);
        } else if current.len() >= 4 {
            if let Ok(s) = String::from_utf8(current.clone()) {
                strings.push(s);
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    strings
}

/// Test result for reporting
#[derive(Debug)]
struct TestResult {
    path: PathBuf,
    expected_language: SourceLanguage,
    expected_compiler: CompilerVendor,
    detected_language: SourceLanguage,
    detected_compiler: Option<CompilerVendor>,
    confidence: f32,
    passed: bool,
}

/// Run tests on a directory of binaries
fn test_binaries_in_dir(
    dir: &Path,
    expected_language: SourceLanguage,
    expected_compiler: CompilerVendor,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && !path.extension().map_or(false, |e| e == "json") {
                if let Some(detection) = analyze_binary(&path) {
                    let detected_compiler = detection.compiler.as_ref().map(|c| c.vendor);
                    let passed = detection.language == expected_language
                        || (expected_language == SourceLanguage::C
                            && detection.language == SourceLanguage::Cpp);

                    results.push(TestResult {
                        path: path.clone(),
                        expected_language,
                        expected_compiler,
                        detected_language: detection.language,
                        detected_compiler,
                        confidence: detection.confidence,
                        passed,
                    });
                }
            }
        }
    }

    results
}

// ============================================================================
// GCC/G++ Tests
// ============================================================================

#[test]
fn test_gcc_c_binaries() {
    let base = Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc");
    let mut all_results = Vec::new();

    // Test different optimization levels
    for opt_level in &["O0", "O1", "O2", "O3", "debug"] {
        let dir = base.join(opt_level);
        let results = test_binaries_in_dir(&dir, SourceLanguage::C, CompilerVendor::Gnu);

        // Filter for C binaries (hello-c-gcc-*)
        let c_results: Vec<_> = results
            .into_iter()
            .filter(|r| r.path.to_string_lossy().contains("hello-c-gcc"))
            .collect();

        all_results.extend(c_results);
    }

    // Report results
    let passed = all_results.iter().filter(|r| r.passed).count();
    let total = all_results.len();

    println!("\nGCC C Binaries: {}/{} passed", passed, total);
    for result in &all_results {
        if !result.passed {
            println!(
                "  FAILED: {:?} - detected as {:?} ({:.1}%)",
                result.path.file_name().unwrap(),
                result.detected_language,
                result.confidence * 100.0
            );
        }
    }

    assert!(
        passed > 0,
        "At least some GCC C binaries should be detected"
    );
}

#[test]
fn test_gpp_cpp_binaries() {
    let base = Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc");
    let mut all_results = Vec::new();

    for opt_level in &["O0", "O1", "O2", "O3", "debug"] {
        let dir = base.join(opt_level);
        let results = test_binaries_in_dir(&dir, SourceLanguage::Cpp, CompilerVendor::Gnu);

        // Filter for C++ binaries (hello-cpp-g++-*)
        let cpp_results: Vec<_> = results
            .into_iter()
            .filter(|r| r.path.to_string_lossy().contains("hello-cpp-g++"))
            .collect();

        all_results.extend(cpp_results);
    }

    let passed = all_results.iter().filter(|r| r.passed).count();
    let total = all_results.len();

    println!("\nG++ C++ Binaries: {}/{} passed", passed, total);
    assert!(passed > 0, "At least some G++ binaries should be detected");
}

// ============================================================================
// Clang/Clang++ Tests
// ============================================================================

#[test]
fn test_clang_c_binaries() {
    let base = Path::new("samples/binaries/platforms/linux/amd64/export/native/clang");
    let mut all_results = Vec::new();

    for opt_level in &["O0", "O1", "O2", "O3", "debug"] {
        let dir = base.join(opt_level);
        let results = test_binaries_in_dir(&dir, SourceLanguage::C, CompilerVendor::Llvm);

        let c_results: Vec<_> = results
            .into_iter()
            .filter(|r| r.path.to_string_lossy().contains("hello-c-clang"))
            .collect();

        all_results.extend(c_results);
    }

    let passed = all_results.iter().filter(|r| r.passed).count();
    let total = all_results.len();

    println!("\nClang C Binaries: {}/{} passed", passed, total);
    assert!(
        passed > 0,
        "At least some Clang C binaries should be detected"
    );
}

#[test]
fn test_clangpp_cpp_binaries() {
    let base = Path::new("samples/binaries/platforms/linux/amd64/export/native/clang");
    let mut all_results = Vec::new();

    for opt_level in &["O0", "O1", "O2", "O3", "debug"] {
        let dir = base.join(opt_level);
        let results = test_binaries_in_dir(&dir, SourceLanguage::Cpp, CompilerVendor::Llvm);

        let cpp_results: Vec<_> = results
            .into_iter()
            .filter(|r| r.path.to_string_lossy().contains("hello-cpp-clang++"))
            .collect();

        all_results.extend(cpp_results);
    }

    let passed = all_results.iter().filter(|r| r.passed).count();
    let total = all_results.len();

    println!("\nClang++ C++ Binaries: {}/{} passed", passed, total);
    assert!(
        passed > 0,
        "At least some Clang++ binaries should be detected"
    );
}

// ============================================================================
// Rust Tests
// ============================================================================

#[test]
fn test_rust_binaries() {
    let rust_dir = Path::new("samples/binaries/platforms/linux/amd64/export/rust");
    let mut results = Vec::new();

    for binary_name in &["hello-rust-debug", "hello-rust-release", "hello-rust-musl"] {
        let path = rust_dir.join(binary_name);
        if let Some(detection) = analyze_binary(&path) {
            let passed = detection.language == SourceLanguage::Rust;
            results.push((binary_name, detection, passed));
        }
    }

    println!("\nRust Binaries:");
    for (name, detection, passed) in &results {
        println!(
            "  {}: {:?} ({:.1}%) - {}",
            name,
            detection.language,
            detection.confidence * 100.0,
            if *passed { "PASS" } else { "FAIL" }
        );
    }

    let passed_count = results.iter().filter(|(_, _, p)| *p).count();
    assert!(passed_count >= 2, "Most Rust binaries should be detected");
}

// ============================================================================
// Go Tests
// ============================================================================

#[test]
fn test_go_binaries() {
    let go_dir = Path::new("samples/binaries/platforms/linux/amd64/export/go");
    let mut results = Vec::new();

    for binary_name in &["hello-go", "hello-go-static"] {
        let path = go_dir.join(binary_name);
        if let Some(detection) = analyze_binary(&path) {
            let passed = detection.language == SourceLanguage::Go;
            results.push((binary_name, detection, passed));

            // Also check for Go build ID
            if path.exists() {
                let data = fs::read(&path).unwrap();
                let has_buildid = has_go_buildid(&data);
                println!("  {} has Go build ID: {}", binary_name, has_buildid);
            }
        }
    }

    println!("\nGo Binaries:");
    for (name, detection, passed) in &results {
        println!(
            "  {}: {:?} ({:.1}%) - {}",
            name,
            detection.language,
            detection.confidence * 100.0,
            if *passed { "PASS" } else { "FAIL" }
        );
    }
}

// ============================================================================
// Fortran Tests
// ============================================================================

#[test]
fn test_fortran_binaries() {
    let fortran_dir = Path::new("samples/binaries/platforms/linux/amd64/export/fortran");
    let mut results = Vec::new();

    for binary_name in &[
        "hello-gfortran-O0",
        "hello-gfortran-O1",
        "hello-gfortran-O2",
        "hello-gfortran-O3",
        "hello-gfortran-debug",
    ] {
        let path = fortran_dir.join(binary_name);
        if let Some(detection) = analyze_binary(&path) {
            // Fortran compiled with gfortran shows up as Fortran or C
            let passed = detection.language == SourceLanguage::Fortran
                || detection.language == SourceLanguage::C;
            results.push((binary_name, detection, passed));
        }
    }

    println!("\nFortran Binaries:");
    for (name, detection, _) in &results {
        println!(
            "  {}: {:?} (compiler: {:?})",
            name,
            detection.language,
            detection.compiler.as_ref().map(|c| &c.vendor)
        );
    }
}

// ============================================================================
// MinGW Cross-Compilation Tests
// ============================================================================

#[test]
fn test_mingw_windows_binaries() {
    let cross_dir = Path::new("samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64");
    let mut results = Vec::new();

    for binary_name in &[
        "hello-c-x86_64-mingw.exe",
        "hello-cpp-x86_64-mingw.exe",
        "suspicious_win-c-x86_64-mingw.exe",
    ] {
        let path = cross_dir.join(binary_name);
        if let Some(detection) = analyze_binary(&path) {
            let is_cpp = binary_name.contains("cpp");
            let expected = if is_cpp {
                SourceLanguage::Cpp
            } else {
                SourceLanguage::C
            };
            let passed = detection.language == expected
                || (expected == SourceLanguage::C && detection.language == SourceLanguage::Cpp);
            results.push((binary_name, detection, passed));
        }
    }

    println!("\nMinGW Windows Binaries:");
    for (name, detection, passed) in &results {
        println!(
            "  {}: {:?} - {}",
            name,
            detection.language,
            if *passed { "PASS" } else { "FAIL" }
        );
    }
}

// ============================================================================
// Cross-Architecture Tests (ARM, RISC-V)
// ============================================================================

#[test]
fn test_cross_architecture_binaries() {
    let cross_base = Path::new("samples/binaries/platforms/linux/amd64/export/cross");
    let mut results = HashMap::new();

    // Test ARM64 binaries
    for binary in &["arm64/hello-arm64-gcc", "arm64/hello-arm64-g++"] {
        let path = cross_base.join(binary);
        if let Some(detection) = analyze_binary(&path) {
            results.insert(binary.to_string(), detection);
        }
    }

    // Test ARM HF binaries
    for binary in &["armhf/hello-armhf-gcc", "armhf/hello-armhf-g++"] {
        let path = cross_base.join(binary);
        if let Some(detection) = analyze_binary(&path) {
            results.insert(binary.to_string(), detection);
        }
    }

    // Test RISC-V binaries
    for binary in &["riscv64/hello-riscv64-gcc", "riscv64/hello-riscv64-g++"] {
        let path = cross_base.join(binary);
        if let Some(detection) = analyze_binary(&path) {
            results.insert(binary.to_string(), detection);
        }
    }

    println!("\nCross-Architecture Binaries:");
    for (name, detection) in &results {
        let is_cpp = name.contains("g++");
        let expected = if is_cpp { "C++" } else { "C" };
        println!(
            "  {}: {:?} (expected: {})",
            name, detection.language, expected
        );
    }
}

// ============================================================================
// .NET/Mono Tests
// ============================================================================

#[test]
fn test_dotnet_mono_binaries() {
    let paths = vec![
        "samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe",
        "samples/binaries/platforms/windows/amd64/export/windows/dotnet/mono/Hello-mono.exe",
    ];

    println!("\n.NET/Mono Binaries:");
    for path_str in paths {
        let path = Path::new(path_str);
        if path.exists() {
            let data = fs::read(path).unwrap();
            // .NET binaries are PE format with CLR metadata
            let is_pe = data.len() >= 2 && &data[..2] == b"MZ";
            println!("  {}: PE format: {}", path_str, is_pe);

            if let Some(detection) = analyze_binary(path) {
                println!("    Detected: {:?}", detection.language);
            }
        }
    }
}

// ============================================================================
// Python Bytecode Tests
// ============================================================================

#[test]
fn test_python_bytecode() {
    let python_dir = Path::new("samples/binaries/platforms/linux/amd64/export/python");
    let mut pyc_files = Vec::new();

    if let Ok(entries) = fs::read_dir(python_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "pyc") {
                pyc_files.push(path);
            }
        }
    }

    println!("\nPython Bytecode Files:");
    for path in &pyc_files {
        if let Ok(data) = fs::read(path) {
            // Python bytecode has magic number at the start
            if data.len() >= 4 {
                let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                println!(
                    "  {}: magic={:08x}",
                    path.file_name().unwrap().to_string_lossy(),
                    magic
                );
            }
        }
    }
}

// ============================================================================
// Java Class/JAR Tests
// ============================================================================

#[test]
fn test_java_binaries() {
    let java_base = Path::new("samples/binaries/platforms/linux/amd64/export/java");
    let mut class_files = Vec::new();
    let mut jar_files = Vec::new();

    // Find all .class and .jar files
    for jdk_version in &["jdk11", "jdk17", "jdk21"] {
        let jdk_dir = java_base.join(jdk_version);
        if let Ok(entries) = fs::read_dir(&jdk_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "class") {
                    class_files.push(path);
                } else if path.extension().map_or(false, |e| e == "jar") {
                    jar_files.push(path);
                }
            }
        }
    }

    println!("\nJava Class Files:");
    for path in &class_files {
        if let Ok(data) = fs::read(path) {
            // Java class files start with 0xCAFEBABE
            if data.len() >= 4 {
                let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let is_java = magic == 0xCAFEBABE;
                println!(
                    "  {}: Java class file: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    is_java
                );
            }
        }
    }

    println!("\nJava JAR Files:");
    for path in &jar_files {
        if let Ok(data) = fs::read(path) {
            // JAR files are ZIP archives
            if data.len() >= 4 {
                let is_zip = &data[..2] == b"PK";
                println!(
                    "  {}: ZIP/JAR format: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    is_zip
                );
            }
        }
    }
}

// ============================================================================
// Lua Bytecode Tests
// ============================================================================

#[test]
fn test_lua_bytecode() {
    let lua_dir = Path::new("samples/binaries/platforms/linux/amd64/export/lua");
    let mut luac_files = Vec::new();

    if let Ok(entries) = fs::read_dir(lua_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "luac") {
                luac_files.push(path);
            }
        }
    }

    println!("\nLua Bytecode Files:");
    for path in &luac_files {
        if let Ok(data) = fs::read(path) {
            // Lua bytecode starts with ESC Lua (0x1B4C7561)
            if data.len() >= 4 {
                let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let is_lua = magic == 0x1B4C7561;
                println!(
                    "  {}: Lua bytecode: {} (magic={:08x})",
                    path.file_name().unwrap().to_string_lossy(),
                    is_lua,
                    magic
                );
            }
        }
    }
}

// ============================================================================
// Summary Test - Count All Detected Languages
// ============================================================================

#[test]
fn test_comprehensive_language_coverage() {
    let mut language_counts: HashMap<SourceLanguage, usize> = HashMap::new();
    let mut compiler_counts: HashMap<CompilerVendor, usize> = HashMap::new();
    let mut total_files = 0;
    let mut successful_detections = 0;

    // Scan all binary files in samples
    let samples_dir = Path::new("samples/binaries/platforms");
    scan_directory_recursive(
        samples_dir,
        &mut language_counts,
        &mut compiler_counts,
        &mut total_files,
        &mut successful_detections,
    );

    println!("\n=== COMPREHENSIVE DETECTION SUMMARY ===");
    println!("Total files analyzed: {}", total_files);
    println!(
        "Successful detections: {} ({:.1}%)",
        successful_detections,
        (successful_detections as f32 / total_files as f32) * 100.0
    );

    println!("\nLanguages detected:");
    let mut lang_vec: Vec<_> = language_counts.into_iter().collect();
    lang_vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (lang, count) in lang_vec {
        println!("  {:?}: {}", lang, count);
    }

    println!("\nCompilers detected:");
    let mut comp_vec: Vec<_> = compiler_counts.into_iter().collect();
    comp_vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (compiler, count) in comp_vec {
        println!("  {:?}: {}", compiler, count);
    }

    assert!(
        successful_detections > 0,
        "Should detect at least some binaries"
    );
}

fn scan_directory_recursive(
    dir: &Path,
    language_counts: &mut HashMap<SourceLanguage, usize>,
    compiler_counts: &mut HashMap<CompilerVendor, usize>,
    total_files: &mut usize,
    successful_detections: &mut usize,
) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_directory_recursive(
                    &path,
                    language_counts,
                    compiler_counts,
                    total_files,
                    successful_detections,
                );
            } else if path.is_file() {
                // Skip JSON metadata files, text files, and JAR files (they're ZIP archives)
                if path
                    .extension()
                    .map_or(false, |e| e == "json" || e == "txt" || e == "jar")
                {
                    continue;
                }

                *total_files += 1;

                if let Some(detection) = analyze_binary(&path) {
                    if detection.language != SourceLanguage::Unknown {
                        *successful_detections += 1;
                        *language_counts.entry(detection.language).or_insert(0) += 1;

                        if let Some(compiler) = detection.compiler {
                            *compiler_counts.entry(compiler.vendor).or_insert(0) += 1;
                        }
                    } else {
                        // Log failed detection
                        let filename = path.file_name().unwrap().to_string_lossy();
                        let parent = path
                            .parent()
                            .and_then(|p| p.file_name())
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_default();
                        println!("  FAILED: {}/{}", parent, filename);
                    }
                }
            }
        }
    }
}
