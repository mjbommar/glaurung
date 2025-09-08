//! Integration tests for compiler and language detection

use glaurung::triage::compiler_detection::*;
use object::{Object, ObjectSection, ObjectSymbol};
use std::path::Path;

#[test]
fn test_detect_gcc_compiled_binary() {
    let gcc_binary =
        Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0");
    if !gcc_binary.exists() {
        eprintln!("Skipping test: GCC sample binary not found");
        return;
    }

    // Read the binary
    let data = std::fs::read(gcc_binary).unwrap();

    // Parse with object crate to get symbols
    if let Ok(obj) = object::read::File::parse(&*data) {
        // Extract symbols
        let symbols: Vec<String> = obj
            .symbols()
            .filter_map(|sym| sym.name().ok().map(|n| n.to_string()))
            .collect();

        // Get imports
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

        // Extract strings (simplified)
        let strings: Vec<String> = data
            .windows(4)
            .filter_map(|window| {
                if window.iter().all(|&b| b >= 0x20 && b < 0x7F) {
                    Some(String::from_utf8_lossy(window).to_string())
                } else {
                    None
                }
            })
            .collect();

        // Look for .comment section
        let elf_comment = obj
            .sections()
            .find(|s| s.name().ok() == Some(".comment"))
            .and_then(|s| s.data().ok())
            .map(|data| String::from_utf8_lossy(data).to_string());

        // Detect language and compiler
        let result = detect_language_and_compiler(
            &symbols,
            &libraries,
            &strings,
            None, // No Rich Header for ELF
            elf_comment.as_deref(),
            &data,
        );

        println!("GCC Binary Detection:");
        println!("  Language: {:?}", result.language);
        println!("  Compiler: {:?}", result.compiler);
        println!("  Confidence: {:.2}%", result.confidence * 100.0);
        println!("  Evidence: {}", result.evidence_summary);

        // Assertions
        assert!(matches!(
            result.language,
            SourceLanguage::C | SourceLanguage::Cpp
        ));
        if let Some(compiler) = result.compiler {
            assert_eq!(compiler.vendor, CompilerVendor::Gnu);
        }
    }
}

#[test]
fn test_detect_clang_compiled_binary() {
    let clang_binary =
        Path::new("samples/binaries/platforms/linux/amd64/export/native/clang/O0/hello-clang-O0");
    if !clang_binary.exists() {
        eprintln!("Skipping test: Clang sample binary not found");
        return;
    }

    let data = std::fs::read(clang_binary).unwrap();

    if let Ok(obj) = object::read::File::parse(&*data) {
        let symbols: Vec<String> = obj
            .symbols()
            .filter_map(|sym| sym.name().ok().map(|n| n.to_string()))
            .collect();

        let elf_comment = obj
            .sections()
            .find(|s| s.name().ok() == Some(".comment"))
            .and_then(|s| s.data().ok())
            .map(|data| String::from_utf8_lossy(data).to_string());

        let result = detect_language_and_compiler(
            &symbols,
            &Vec::new(),
            &Vec::new(),
            None,
            elf_comment.as_deref(),
            &data,
        );

        println!("Clang Binary Detection:");
        println!("  Language: {:?}", result.language);
        println!("  Compiler: {:?}", result.compiler);
        println!("  Evidence: {}", result.evidence_summary);

        if let Some(compiler) = result.compiler {
            assert_eq!(compiler.vendor, CompilerVendor::Llvm);
        }
    }
}

#[test]
fn test_detect_go_binary() {
    let go_binary = Path::new("samples/binaries/platforms/linux/amd64/export/go/hello-go");
    if !go_binary.exists() {
        eprintln!("Skipping test: Go sample binary not found");
        return;
    }

    let data = std::fs::read(go_binary).unwrap();

    if let Ok(obj) = object::read::File::parse(&*data) {
        let symbols: Vec<String> = obj
            .symbols()
            .filter_map(|sym| sym.name().ok().map(|n| n.to_string()))
            .collect();

        // Check for Go symbols
        let has_go_symbols = symbols
            .iter()
            .any(|s| s.starts_with("main.") || s.starts_with("runtime.") || s.contains("golang"));

        // Check for Go build ID
        let has_go_buildid = has_go_buildid(&data);

        let result =
            detect_language_and_compiler(&symbols, &Vec::new(), &Vec::new(), None, None, &data);

        println!("Go Binary Detection:");
        println!("  Language: {:?}", result.language);
        println!("  Has Go symbols: {}", has_go_symbols);
        println!("  Has Go build ID: {}", has_go_buildid);
        println!("  Evidence: {}", result.evidence_summary);

        if has_go_symbols || has_go_buildid {
            assert_eq!(result.language, SourceLanguage::Go);
        }
    }
}

#[test]
fn test_detect_rust_binary() {
    let rust_binary =
        Path::new("samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release");
    if !rust_binary.exists() {
        eprintln!("Skipping test: Rust sample binary not found");
        return;
    }

    let data = std::fs::read(rust_binary).unwrap();

    if let Ok(obj) = object::read::File::parse(&*data) {
        let symbols: Vec<String> = obj
            .symbols()
            .filter_map(|sym| sym.name().ok().map(|n| n.to_string()))
            .collect();

        // Look for Rust symbols
        let rust_symbol_count = symbols
            .iter()
            .filter(|s| rustc_demangle::try_demangle(s).is_ok())
            .count();

        let result =
            detect_language_and_compiler(&symbols, &Vec::new(), &Vec::new(), None, None, &data);

        println!("Rust Binary Detection:");
        println!("  Language: {:?}", result.language);
        println!("  Rust symbols found: {}", rust_symbol_count);
        println!("  Evidence: {}", result.evidence_summary);

        if rust_symbol_count > 0 {
            assert_eq!(result.language, SourceLanguage::Rust);
        }
    }
}

#[test]
fn test_detect_cpp_symbols() {
    // Test C++ mangled symbols
    let cpp_symbols = vec![
        "_ZN3std6vectorIiSaIiEE9push_backERKi".to_string(),
        "_ZNSt8ios_base4InitC1Ev".to_string(),
        "_ZNKSt6vectorIiSaIiEE4sizeEv".to_string(),
    ];

    let evidence = detect_language_from_symbols(&cpp_symbols);
    assert!(evidence.cpp_itanium_symbols > 0);

    // Test with libraries
    let cpp_libs = vec!["libstdc++.so.6".to_string(), "libgcc_s.so.1".to_string()];

    let lib_evidence = detect_runtime_libraries(&cpp_libs);
    assert!(lib_evidence.libstdcpp_imports > 0);
}

#[test]
fn test_packer_detection() {
    // Test UPX detection
    let upx_data = b"some data UPX! more data";
    assert_eq!(detect_packer(upx_data), Some(PackerType::UPX));

    // Test no packer
    let clean_data = b"just a normal binary without packers";
    assert_eq!(detect_packer(clean_data), None);
}

#[test]
fn test_stripped_binary_detection() {
    // Test empty symbols
    let empty_symbols: Vec<String> = vec![];
    assert!(is_likely_stripped(&empty_symbols));

    // Test minimal symbols (typical of stripped binary)
    let minimal_symbols = vec![
        "_start".to_string(),
        "_DYNAMIC".to_string(),
        "__libc_start_main@GLIBC_2.2.5".to_string(),
    ];
    assert!(is_likely_stripped(&minimal_symbols));

    // Test normal binary with many symbols
    let normal_symbols = vec![
        "main".to_string(),
        "foo".to_string(),
        "bar".to_string(),
        "baz".to_string(),
        "calculate".to_string(),
        "process_data".to_string(),
        "handle_error".to_string(),
        "init_system".to_string(),
        "cleanup".to_string(),
        "validate_input".to_string(),
        "write_output".to_string(),
    ];
    assert!(!is_likely_stripped(&normal_symbols));
}

#[test]
fn test_language_guessing_from_compiler() {
    use glaurung::triage::compiler_detection::{CompilerInfo, CompilerVendor};

    // Test g++ -> C++
    let gpp_compiler = CompilerInfo {
        vendor: CompilerVendor::Gnu,
        product_name: "g++".to_string(),
        version_major: Some(11),
        version_minor: Some(4),
        version_patch: Some(0),
        build_number: None,
        target_triple: None,
    };
    assert_eq!(
        guess_language_from_compiler(&gpp_compiler),
        SourceLanguage::Cpp
    );

    // Test gcc -> C
    let gcc_compiler = CompilerInfo {
        vendor: CompilerVendor::Gnu,
        product_name: "GCC".to_string(),
        version_major: Some(11),
        version_minor: Some(4),
        version_patch: Some(0),
        build_number: None,
        target_triple: None,
    };
    assert_eq!(
        guess_language_from_compiler(&gcc_compiler),
        SourceLanguage::C
    );

    // Test clang++ -> C++
    let clangpp_compiler = CompilerInfo {
        vendor: CompilerVendor::Llvm,
        product_name: "clang++".to_string(),
        version_major: Some(14),
        version_minor: Some(0),
        version_patch: Some(0),
        build_number: None,
        target_triple: None,
    };
    assert_eq!(
        guess_language_from_compiler(&clangpp_compiler),
        SourceLanguage::Cpp
    );
}

#[test]
fn test_shared_library_detection() {
    assert!(is_shared_library("libfoo.so"));
    assert!(is_shared_library("libbar.so.1"));
    assert!(is_shared_library("library.dll"));
    assert!(is_shared_library("framework.dylib"));
    assert!(!is_shared_library("program.exe"));
    assert!(!is_shared_library("binary"));
}

#[test]
fn test_detect_msvc_binary() {
    // Simulate MSVC-compiled binary evidence
    let msvc_symbols = vec![
        "?foo@@YAHXZ".to_string(),
        "??0exception@std@@QAE@ABQBD@Z".to_string(),
        "??_7type_info@@6B@".to_string(),
    ];

    let msvc_libs = vec![
        "MSVCP140.dll".to_string(),
        "VCRUNTIME140.dll".to_string(),
        "KERNEL32.dll".to_string(),
    ];

    let evidence_symbols = detect_language_from_symbols(&msvc_symbols);
    let evidence_libs = detect_runtime_libraries(&msvc_libs);

    assert!(evidence_symbols.cpp_msvc_symbols > 0);
    assert!(evidence_libs.msvcrt_imports > 0);
}
