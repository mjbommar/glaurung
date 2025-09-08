//! Compiler and programming language detection from binary analysis.
//!
//! This module identifies the original programming language and compiler toolchain
//! used to create binaries through multiple detection strategies:
//! - Symbol name mangling schemes
//! - Runtime library signatures
//! - Compiler-specific metadata (Rich Headers, ELF notes)
//! - Code generation patterns
//! - String and error message analysis

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Programming languages that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub enum SourceLanguage {
    C,
    Cpp,
    Rust,
    Go,
    Swift,
    ObjectiveC,
    D,
    Fortran,
    Pascal,
    Ada,
    Zig,
    Nim,
    Crystal,
    CSharp,
    Java,
    Python,
    JavaScript,
    TypeScript,
    Kotlin,
    Scala,
    Unknown,
}

/// Compiler vendors/families
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub enum CompilerVendor {
    Gnu,       // GCC, G++
    Llvm,      // Clang, Clang++
    Microsoft, // MSVC, Visual Studio
    Intel,     // ICC, ICX
    Rustc,     // Rust compiler
    Go,        // Go compiler (gc)
    Swift,     // Swift compiler
    MinGW,     // MinGW-w64
    Borland,   // Legacy Borland C++
    Watcom,    // OpenWatcom
    Tcc,       // Tiny C Compiler
    Pcc,       // Portable C Compiler
    Unknown,
}

/// Detailed compiler information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct CompilerInfo {
    pub vendor: CompilerVendor,
    pub product_name: String,
    pub version_major: Option<u32>,
    pub version_minor: Option<u32>,
    pub version_patch: Option<u32>,
    pub build_number: Option<u32>,
    pub target_triple: Option<String>, // e.g., "x86_64-pc-linux-gnu"
}

/// Evidence collected during detection
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LanguageEvidence {
    // Symbol-based evidence
    pub cpp_itanium_symbols: u32,
    pub cpp_msvc_symbols: u32,
    pub rust_symbols: u32,
    pub go_symbols: u32,
    pub swift_symbols: u32,
    pub objc_symbols: u32,
    pub plain_c_symbols: u32,

    // Runtime library evidence
    pub libstdcpp_imports: u32,
    pub libcpp_imports: u32,
    pub msvcrt_imports: u32,
    pub rust_std_imports: u32,
    pub go_runtime_refs: u32,

    // String content evidence
    pub cpp_error_strings: u32,
    pub rust_panic_strings: u32,
    pub go_error_strings: u32,

    // Metadata evidence
    pub has_rich_header: bool,
    pub has_go_buildid: bool,
    pub has_rust_metadata: bool,
    pub has_dwarf_info: bool,
    pub has_pdb_reference: bool,
}

/// Final detection result with confidence scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct LanguageDetectionResult {
    pub language: SourceLanguage,
    pub compiler: Option<CompilerInfo>,
    pub confidence: f32, // 0.0 to 1.0
    pub alternative_languages: Vec<(SourceLanguage, f32)>,
    pub evidence_summary: String,
}

/// Detect language from symbol name patterns
pub fn detect_language_from_symbols(symbols: &[String]) -> LanguageEvidence {
    let mut evidence = LanguageEvidence::default();

    for symbol in symbols {
        // Rust symbols often have specific patterns even when using legacy mangling
        // Check for Rust-specific patterns first
        if symbol.starts_with("_R") || // New Rust mangling
           (symbol.starts_with("_ZN") && symbol.contains("17h")) || // Legacy Rust with hash
           symbol.contains("$LT$") || symbol.contains("$GT$") || // Rust's < and > encoding
           symbol.contains("$u20$") || symbol.contains("$u27$") || // Rust's space and quote encoding
           symbol.starts_with("anon.") || // Anonymous symbols in Rust
           rustc_demangle::try_demangle(symbol).is_ok()
        {
            evidence.rust_symbols += 1;
        }
        // C++ name mangling patterns (Itanium: _Z... but not Rust patterns)
        else if symbol.starts_with("_Z") && !symbol.contains("17h") && !symbol.contains("$LT$") {
            evidence.cpp_itanium_symbols += 1;
        } else if symbol.starts_with("?") || symbol.starts_with("@@") {
            evidence.cpp_msvc_symbols += 1;
        }
        // Go symbols (dot notation)
        else if (symbol.contains(".")
            && (symbol.starts_with("main.")
                || symbol.starts_with("runtime.")
                || symbol.starts_with("fmt.")
                || symbol.starts_with("net.")
                || symbol.starts_with("os.")))
            || symbol.contains("·")
        {
            // Go middle dot
            evidence.go_symbols += 1;
        }
        // Swift mangling
        else if symbol.starts_with("$s") || symbol.starts_with("_T") {
            evidence.swift_symbols += 1;
        }
        // Objective-C
        else if symbol.starts_with("+[")
            || symbol.starts_with("-[")
            || symbol.starts_with("objc_")
            || symbol.contains("NSObject")
        {
            evidence.objc_symbols += 1;
        }
        // Plain C (no mangling, standard library functions)
        else if matches!(
            symbol.as_str(),
            "malloc"
                | "free"
                | "printf"
                | "scanf"
                | "memcpy"
                | "strlen"
                | "fopen"
                | "fclose"
                | "main"
                | "exit"
                | "abort"
        ) {
            evidence.plain_c_symbols += 1;
        }
    }

    evidence
}

/// Detect runtime libraries from imports/dependencies
pub fn detect_runtime_libraries(libraries: &[String]) -> LanguageEvidence {
    let mut evidence = LanguageEvidence::default();

    for lib in libraries {
        let lib_lower = lib.to_lowercase();

        // C++ standard libraries
        if lib_lower.contains("libstdc++") || lib_lower.contains("stdc++") {
            evidence.libstdcpp_imports += 1;
        } else if lib_lower.contains("libc++") || lib_lower.contains("c++abi") {
            evidence.libcpp_imports += 1;
        } else if lib_lower.starts_with("msvcp") || lib_lower.starts_with("vcruntime") {
            evidence.msvcrt_imports += 1;
        }
        // Microsoft C runtime
        else if lib_lower.starts_with("msvcr") || lib_lower.starts_with("ucrtbase") {
            evidence.msvcrt_imports += 1;
        }
        // Rust standard library (usually statically linked, but may have deps)
        else if lib_lower.contains("rust") {
            evidence.rust_std_imports += 1;
        }
    }

    evidence
}

/// Detect language from string content patterns
pub fn detect_language_from_strings(strings: &[String]) -> LanguageEvidence {
    let mut evidence = LanguageEvidence::default();

    for s in strings {
        // Rust panic messages
        if s.contains("panicked at")
            || s.contains("called `Option::unwrap()` on a `None` value")
            || s.contains("called `Result::unwrap()` on an `Err` value")
            || s.contains("attempt to ") && (s.contains("overflow") || s.contains("divide by zero"))
        {
            evidence.rust_panic_strings += 1;
        }
        // Go runtime errors
        else if s.contains("runtime error:")
            || s.contains("goroutine")
            || s.contains("fatal error:") && s.contains("runtime:")
            || s.contains("sync.")
            || s.contains("syscall.")
        {
            evidence.go_error_strings += 1;
        }
        // C++ STL exceptions
        else if s.contains("std::")
            || s.contains("bad_alloc")
            || s.contains("out_of_range")
            || s.contains("logic_error")
            || s.contains("runtime_error")
        {
            evidence.cpp_error_strings += 1;
        }
    }

    evidence
}

/// Parse compiler info from PE Rich Header
pub fn detect_from_rich_header(
    rich_header: &crate::triage::rich_header::RichHeader,
) -> Option<CompilerInfo> {
    // Map Visual Studio versions from Rich Header product IDs
    for entry in &rich_header.entries {
        let (product_name, major, minor) = match entry.product_id {
            0x5d..=0x5f => ("Visual C++ 2002", 7, 0),
            0x6d..=0x6f => ("Visual C++ 2003", 7, 1),
            0x83..=0x86 => ("Visual C++ 2005", 8, 0),
            0x91..=0x94 => ("Visual C++ 2008", 9, 0),
            0x9b..=0x9e => ("Visual C++ 2010", 10, 0),
            0xa5..=0xa8 => ("Visual C++ 2012", 11, 0),
            0xaf..=0xb2 => ("Visual C++ 2013", 12, 0),
            0xb9..=0xbc => ("Visual C++ 2015", 14, 0),
            0xc3..=0xc6 => ("Visual C++ 2017", 14, 1),
            0xcd..=0xd0 => ("Visual C++ 2019", 14, 2),
            0xd7..=0xda => ("Visual C++ 2022", 14, 3),
            _ => continue,
        };

        return Some(CompilerInfo {
            vendor: CompilerVendor::Microsoft,
            product_name: product_name.to_string(),
            version_major: Some(major),
            version_minor: Some(minor),
            version_patch: None,
            build_number: Some(entry.build_id as u32),
            target_triple: None,
        });
    }

    None
}

/// Parse compiler info from ELF comment section
pub fn detect_from_elf_comment(comment: &str) -> Option<CompilerInfo> {
    // Check for Clang first - it's more specific and Clang binaries
    // often contain both GCC and clang strings
    if let Some(pos) = comment.find("clang version ") {
        let version_str = &comment[pos + 14..];
        let parts: Vec<&str> = version_str.split_whitespace().collect();
        if !parts.is_empty() {
            let version_parts: Vec<&str> = parts[0].split('.').collect();
            return Some(CompilerInfo {
                vendor: CompilerVendor::Llvm,
                product_name: "Clang".to_string(),
                version_major: version_parts.get(0).and_then(|s| s.parse().ok()),
                version_minor: version_parts.get(1).and_then(|s| s.parse().ok()),
                version_patch: version_parts.get(2).and_then(|s| s.parse().ok()),
                build_number: None,
                target_triple: parts.get(1).map(|s| s.to_string()),
            });
        }
    }

    // rustc version string: "rustc version 1.65.0"
    if comment.contains("rustc") {
        if let Some(pos) = comment.find("rustc ") {
            let version_str = &comment[pos + 6..];
            let parts: Vec<&str> = version_str.split_whitespace().collect();
            if parts.len() >= 2 {
                let version_parts: Vec<&str> = parts[1].split('.').collect();
                return Some(CompilerInfo {
                    vendor: CompilerVendor::Rustc,
                    product_name: "rustc".to_string(),
                    version_major: version_parts.get(0).and_then(|s| s.parse().ok()),
                    version_minor: version_parts.get(1).and_then(|s| s.parse().ok()),
                    version_patch: version_parts.get(2).and_then(|s| s.parse().ok()),
                    build_number: None,
                    target_triple: None,
                });
            }
        }
    }

    // GCC version string: "GCC: (GNU) 11.2.0" or "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0"
    // Only check GCC if clang wasn't found (since clang binaries often have GCC strings too)
    if let Some(pos) = comment.find("GCC: ") {
        let version_str = &comment[pos + 5..];
        // Extract version from patterns like "(Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0"
        // The actual version is usually the last version-like string
        let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
        let mut versions = vec![];
        for cap in re.captures_iter(version_str) {
            if let Some(m) = cap.get(1) {
                versions.push(m.as_str());
            }
        }
        if let Some(version) = versions.last() {
            let version_parts: Vec<&str> = version.split('.').collect();
            return Some(CompilerInfo {
                vendor: CompilerVendor::Gnu,
                product_name: "GCC".to_string(),
                version_major: version_parts.get(0).and_then(|s| s.parse().ok()),
                version_minor: version_parts.get(1).and_then(|s| s.parse().ok()),
                version_patch: version_parts.get(2).and_then(|s| s.parse().ok()),
                build_number: None,
                target_triple: None,
            });
        }
    }

    None
}

/// Detect bytecode formats from magic numbers
pub fn detect_bytecode_format(data: &[u8]) -> Option<SourceLanguage> {
    if data.len() < 4 {
        return None;
    }

    // Java class file: 0xCAFEBABE
    if data[0..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
        return Some(SourceLanguage::Java);
    }

    // Python compiled bytecode: varies by version but has common patterns
    // Python 3.8+: 0x550D0D0A
    // Python 3.7: 0x420D0D0A
    // Python 3.6: 0x330D0D0A
    if data.len() >= 4 && data[1..4] == [0x0D, 0x0D, 0x0A] {
        return Some(SourceLanguage::Python);
    }

    // Lua bytecode: 0x1B4C7561 (ESC "Lua")
    if data[0..4] == [0x1B, 0x4C, 0x75, 0x61] {
        return Some(SourceLanguage::Unknown); // We don't have Lua enum yet
    }

    // .NET/C# PE files often have specific CLI headers
    // Check for "BSJB" signature in CLR metadata
    if data.len() > 0x100 {
        for window in data.windows(4) {
            if window == b"BSJB" {
                return Some(SourceLanguage::CSharp);
            }
        }
    }

    None
}

/// Packer types that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerType {
    UPX,
    ASPack,
    PECompact,
    Themida,
    VMProtect,
    Unknown,
}

/// Detect if binary is packed and identify packer
pub fn detect_packer(data: &[u8]) -> Option<PackerType> {
    // UPX detection - look for "UPX!" signature
    if data.windows(4).any(|w| w == b"UPX!") {
        return Some(PackerType::UPX);
    }

    // UPX alternate signatures
    if data.windows(3).any(|w| w == b"UPX") {
        // Additional check for UPX0, UPX1, UPX2 section names
        for upx_section in &[b"UPX0", b"UPX1", b"UPX2"] {
            if data.windows(4).any(|w| w == *upx_section) {
                return Some(PackerType::UPX);
            }
        }
    }

    // ASPack signature
    if data.windows(8).any(|w| w == b".aspack\x00") {
        return Some(PackerType::ASPack);
    }

    // PECompact signature
    if data.windows(9).any(|w| w == b"PECompact") {
        return Some(PackerType::PECompact);
    }

    // Themida/WinLicense signatures
    if data.windows(7).any(|w| w == b"Themida") || data.windows(10).any(|w| w == b"WinLicense") {
        return Some(PackerType::Themida);
    }

    // VMProtect signatures
    if data.windows(8).any(|w| w == b".vmp0\x00\x00\x00")
        || data.windows(8).any(|w| w == b".vmp1\x00\x00\x00")
    {
        return Some(PackerType::VMProtect);
    }

    None
}

/// Check if binary appears to be stripped (has minimal symbols)
pub fn is_likely_stripped(symbols: &[String]) -> bool {
    // Stripped binaries typically have very few symbols
    // Usually just dynamic symbols like _start, main (if exported), and plt entries

    if symbols.is_empty() {
        return true;
    }

    // Count non-dynamic symbols
    let non_dynamic_symbols = symbols
        .iter()
        .filter(|s| {
            !s.starts_with("_DYNAMIC")
                && !s.starts_with("_GLOBAL_OFFSET_TABLE")
                && !s.starts_with("__libc_")
                && !s.starts_with("_IO_stdin_used")
                && !s.contains("@plt")
                && !s.contains("@GLIBC")
        })
        .count();

    // If we have very few real symbols, likely stripped
    non_dynamic_symbols < 10
}

/// Guess language from compiler name (fallback for stripped binaries)
pub fn guess_language_from_compiler(compiler: &CompilerInfo) -> SourceLanguage {
    match &compiler.product_name.to_lowercase()[..] {
        name if name.contains("g++") || name.contains("c++") => SourceLanguage::Cpp,
        name if name.contains("gcc") => SourceLanguage::C,
        name if name.contains("clang++") => SourceLanguage::Cpp,
        name if name.contains("clang") => SourceLanguage::C,
        name if name.contains("gfortran") => SourceLanguage::Fortran,
        name if name.contains("rustc") => SourceLanguage::Rust,
        name if name.contains("go") || name.contains("gc") => SourceLanguage::Go,
        name if name.contains("swiftc") => SourceLanguage::Swift,
        name if name.contains("fpc") || name.contains("pascal") => SourceLanguage::Pascal,
        name if name.contains("gnat") || name.contains("ada") => SourceLanguage::Ada,
        _ => SourceLanguage::Unknown,
    }
}

/// Check if file appears to be a shared library
pub fn is_shared_library(path: &str) -> bool {
    path.ends_with(".so")
        || path.contains(".so.")
        || path.ends_with(".dll")
        || path.ends_with(".dylib")
}

/// Check for Go build ID in ELF notes
pub fn has_go_buildid(data: &[u8]) -> bool {
    // Look for Go build info markers
    // 1. "Go buildinf:" marker in the binary
    let go_buildinf_marker = b"Go buildinf:";
    if data
        .windows(go_buildinf_marker.len())
        .any(|window| window == go_buildinf_marker)
    {
        return true;
    }

    // 2. .note.go.buildid ELF section (starts with "Go\0\0" in note name)
    let go_note_marker = b"Go\x00";
    if data
        .windows(go_note_marker.len())
        .any(|window| window == go_note_marker)
    {
        return true;
    }

    false
}

/// Extract Go version from binary if present
pub fn extract_go_version(data: &[u8]) -> Option<String> {
    // Look for "go1.XX.YY" pattern after "Go buildinf:" marker
    let go_buildinf = b"Go buildinf:";

    for (i, window) in data.windows(go_buildinf.len()).enumerate() {
        if window == go_buildinf {
            // Look for go version pattern in next 100 bytes
            let start = i + go_buildinf.len();
            let end = (start + 100).min(data.len());
            let search_area = &data[start..end];

            // Find "go1." pattern
            if let Some(go_pos) = search_area.windows(4).position(|w| &w[0..4] == b"go1.") {
                // Extract version string (e.g., "go1.23.5")
                let version_start = go_pos;
                let mut version_end = version_start + 4;
                while version_end < search_area.len() {
                    let c = search_area[version_end];
                    if c.is_ascii_digit() || c == b'.' {
                        version_end += 1;
                    } else {
                        break;
                    }
                }
                if version_end > version_start + 4 {
                    return String::from_utf8(search_area[version_start..version_end].to_vec())
                        .ok();
                }
            }
        }
    }
    None
}

/// Main detection algorithm combining all evidence
pub fn detect_language_and_compiler(
    symbols: &[String],
    libraries: &[String],
    strings: &[String],
    rich_header: Option<&crate::triage::rich_header::RichHeader>,
    elf_comment: Option<&str>,
    binary_data: &[u8],
) -> LanguageDetectionResult {
    detect_language_and_compiler_with_path(
        symbols,
        libraries,
        strings,
        rich_header,
        elf_comment,
        binary_data,
        None,
    )
}

/// Main detection algorithm with file path context
pub fn detect_language_and_compiler_with_path(
    symbols: &[String],
    libraries: &[String],
    strings: &[String],
    rich_header: Option<&crate::triage::rich_header::RichHeader>,
    elf_comment: Option<&str>,
    binary_data: &[u8],
    file_path: Option<&str>,
) -> LanguageDetectionResult {
    let mut evidence = LanguageEvidence::default();

    // Collect evidence from all sources
    let symbol_evidence = detect_language_from_symbols(symbols);
    let runtime_evidence = detect_runtime_libraries(libraries);
    let string_evidence = detect_language_from_strings(strings);

    // Merge evidence
    evidence.cpp_itanium_symbols = symbol_evidence.cpp_itanium_symbols;
    evidence.cpp_msvc_symbols = symbol_evidence.cpp_msvc_symbols;
    evidence.rust_symbols = symbol_evidence.rust_symbols;
    evidence.go_symbols = symbol_evidence.go_symbols;
    evidence.swift_symbols = symbol_evidence.swift_symbols;
    evidence.objc_symbols = symbol_evidence.objc_symbols;
    evidence.plain_c_symbols = symbol_evidence.plain_c_symbols;

    evidence.libstdcpp_imports = runtime_evidence.libstdcpp_imports;
    evidence.libcpp_imports = runtime_evidence.libcpp_imports;
    evidence.msvcrt_imports = runtime_evidence.msvcrt_imports;
    evidence.rust_std_imports = runtime_evidence.rust_std_imports;

    evidence.cpp_error_strings = string_evidence.cpp_error_strings;
    evidence.rust_panic_strings = string_evidence.rust_panic_strings;
    evidence.go_error_strings = string_evidence.go_error_strings;

    // Check metadata
    evidence.has_rich_header = rich_header.is_some();
    evidence.has_go_buildid = has_go_buildid(binary_data);

    // Extract Go version if present
    let go_version = extract_go_version(binary_data);

    // Check for bytecode formats first (they have specific magic numbers)
    if let Some(bytecode_lang) = detect_bytecode_format(binary_data) {
        return LanguageDetectionResult {
            language: bytecode_lang,
            compiler: None,
            confidence: 0.95, // High confidence for magic number match
            alternative_languages: vec![],
            evidence_summary: format!("{:?} bytecode magic number detected", bytecode_lang),
        };
    }

    // Check for packed binaries
    if let Some(packer) = detect_packer(binary_data) {
        return LanguageDetectionResult {
            language: SourceLanguage::Unknown,
            compiler: None,
            confidence: 0.9, // High confidence for packer detection
            alternative_languages: vec![],
            evidence_summary: format!("Packed with {:?} - original language unknown", packer),
        };
    }

    // Detect compiler from metadata
    let mut compiler_info = None;
    if let Some(rh) = rich_header {
        compiler_info = detect_from_rich_header(rh);
    } else if let Some(comment) = elf_comment {
        compiler_info = detect_from_elf_comment(comment);
    }

    // Calculate language scores
    let mut scores = HashMap::new();

    // C++ evidence
    let cpp_score = (evidence.cpp_itanium_symbols as f32 * 2.0)
        + (evidence.cpp_msvc_symbols as f32 * 2.0)
        + (evidence.libstdcpp_imports as f32 * 1.5)
        + (evidence.libcpp_imports as f32 * 1.5)
        + (evidence.msvcrt_imports as f32 * 1.0)
        + (evidence.cpp_error_strings as f32 * 0.5);
    if cpp_score > 0.0 {
        scores.insert(SourceLanguage::Cpp, cpp_score);
    }

    // Rust evidence - boost score if we have many Rust symbols
    let rust_boost = if evidence.rust_symbols > 10 {
        10.0
    } else {
        0.0
    };
    let rust_score = (evidence.rust_symbols as f32 * 2.0)
        + (evidence.rust_std_imports as f32 * 1.5)
        + (evidence.rust_panic_strings as f32 * 1.0)
        + rust_boost;
    if rust_score > 0.0 {
        scores.insert(SourceLanguage::Rust, rust_score);
    }

    // Go evidence
    let go_score = (evidence.go_symbols as f32 * 2.0)
        + (evidence.go_runtime_refs as f32 * 1.5)
        + (evidence.go_error_strings as f32 * 1.0)
        + (if evidence.has_go_buildid { 5.0 } else { 0.0 });
    if go_score > 0.0 {
        scores.insert(SourceLanguage::Go, go_score);
    }

    // C evidence (if no C++ indicators)
    if cpp_score == 0.0 && evidence.plain_c_symbols > 0 {
        let c_score = evidence.plain_c_symbols as f32 * 1.5;
        scores.insert(SourceLanguage::C, c_score);
    }

    // Swift evidence
    if evidence.swift_symbols > 0 {
        scores.insert(SourceLanguage::Swift, evidence.swift_symbols as f32 * 2.0);
    }

    // Objective-C evidence
    if evidence.objc_symbols > 0 {
        scores.insert(
            SourceLanguage::ObjectiveC,
            evidence.objc_symbols as f32 * 2.0,
        );
    }

    // Find the highest scoring language
    let (mut detected_language, mut max_score) = scores
        .iter()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        .map(|(lang, score)| (*lang, *score))
        .unwrap_or((SourceLanguage::Unknown, 0.0));

    // Override compiler info for language-specific cases
    if detected_language == SourceLanguage::Go && compiler_info.is_none() {
        compiler_info = Some(CompilerInfo {
            vendor: CompilerVendor::Go,
            product_name: "gc".to_string(),
            version_major: go_version.as_ref().and_then(|v| {
                // Parse "go1.23.5" -> major = 1
                v.strip_prefix("go")
                    .and_then(|s| s.split('.').next().and_then(|n| n.parse().ok()))
            }),
            version_minor: go_version.as_ref().and_then(|v| {
                // Parse "go1.23.5" -> minor = 23
                v.strip_prefix("go")
                    .and_then(|s| s.split('.').nth(1).and_then(|n| n.parse().ok()))
            }),
            version_patch: go_version.as_ref().and_then(|v| {
                // Parse "go1.23.5" -> patch = 5
                v.strip_prefix("go")
                    .and_then(|s| s.split('.').nth(2).and_then(|n| n.parse().ok()))
            }),
            build_number: None,
            target_triple: None,
        });
    } else if detected_language == SourceLanguage::Rust && compiler_info.is_none() {
        compiler_info = Some(CompilerInfo {
            vendor: CompilerVendor::Rustc,
            product_name: "rustc".to_string(),
            version_major: None,
            version_minor: None,
            version_patch: None,
            build_number: None,
            target_triple: None,
        });
    }

    // Fallback for stripped binaries: Use compiler info to guess language
    if detected_language == SourceLanguage::Unknown && is_likely_stripped(symbols) {
        if let Some(ref compiler) = compiler_info {
            let guessed_lang = guess_language_from_compiler(compiler);
            if guessed_lang != SourceLanguage::Unknown {
                detected_language = guessed_lang;
                max_score = 30.0; // Lower confidence for guessed language
            }
        }
    }

    // Fallback for shared libraries: Default to C if only basic symbols
    if detected_language == SourceLanguage::Unknown {
        if let Some(path) = file_path {
            if is_shared_library(path) && evidence.plain_c_symbols > 0 {
                detected_language = SourceLanguage::C;
                max_score = 40.0; // Moderate confidence
            }
        }
    }

    // Calculate confidence (normalize score)
    let confidence = if max_score > 0.0 {
        (max_score / 100.0).min(1.0) // Cap at 1.0
    } else {
        0.0
    };

    // Get alternative languages
    let mut alternatives: Vec<(SourceLanguage, f32)> = scores
        .into_iter()
        .filter(|(lang, _)| *lang != detected_language)
        .map(|(lang, score)| (lang, (score / 100.0).min(1.0)))
        .collect();
    alternatives.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap());
    alternatives.truncate(3); // Top 3 alternatives

    // Build evidence summary
    let mut summary_parts = Vec::new();
    if evidence.cpp_itanium_symbols > 0 {
        summary_parts.push(format!(
            "{} C++ symbols (Itanium ABI)",
            evidence.cpp_itanium_symbols
        ));
    }
    if evidence.cpp_msvc_symbols > 0 {
        summary_parts.push(format!("{} C++ symbols (MSVC)", evidence.cpp_msvc_symbols));
    }
    if evidence.rust_symbols > 0 {
        summary_parts.push(format!("{} Rust symbols", evidence.rust_symbols));
    }
    if evidence.go_symbols > 0 {
        summary_parts.push(format!("{} Go symbols", evidence.go_symbols));
    }
    if evidence.has_go_buildid {
        summary_parts.push("Go build ID present".to_string());
    }
    if evidence.has_rich_header {
        summary_parts.push("PE Rich Header (MSVC)".to_string());
    }

    // Add additional diagnostic info
    if is_likely_stripped(symbols) {
        summary_parts.push("Binary appears stripped".to_string());
    }
    if file_path.map_or(false, |p| is_shared_library(p)) {
        summary_parts.push("Shared library".to_string());
    }

    let evidence_summary = if summary_parts.is_empty() {
        if is_likely_stripped(symbols) && compiler_info.is_some() {
            "Stripped binary - language guessed from compiler".to_string()
        } else {
            "No strong evidence found".to_string()
        }
    } else {
        summary_parts.join(", ")
    };

    LanguageDetectionResult {
        language: detected_language,
        compiler: compiler_info,
        confidence,
        alternative_languages: alternatives,
        evidence_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpp_symbol_detection() {
        let symbols = vec![
            "_ZN3std6vectorIiE9push_backEi".to_string(),
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev".to_string(),
        ];

        let evidence = detect_language_from_symbols(&symbols);
        assert_eq!(evidence.cpp_itanium_symbols, 2);
        assert_eq!(evidence.cpp_msvc_symbols, 0);
    }

    #[test]
    fn test_go_symbol_detection() {
        let symbols = vec![
            "main.main".to_string(),
            "runtime.newobject".to_string(),
            "fmt.Println".to_string(),
        ];

        let evidence = detect_language_from_symbols(&symbols);
        assert_eq!(evidence.go_symbols, 3);
    }

    #[test]
    fn test_rust_panic_string_detection() {
        let strings = vec![
            "panicked at 'index out of bounds', src/main.rs:42:5".to_string(),
            "called `Option::unwrap()` on a `None` value".to_string(),
        ];

        let evidence = detect_language_from_strings(&strings);
        assert_eq!(evidence.rust_panic_strings, 2);
    }

    #[test]
    fn test_gcc_version_detection() {
        let comment = "GCC: (GNU) 11.2.0 20211203";
        let info = detect_from_elf_comment(comment).unwrap();

        assert_eq!(info.vendor, CompilerVendor::Gnu);
        assert_eq!(info.version_major, Some(11));
        assert_eq!(info.version_minor, Some(2));
        assert_eq!(info.version_patch, Some(0));
    }

    #[test]
    fn test_clang_version_detection() {
        let comment = "clang version 14.0.6 (https://github.com/llvm/llvm-project)";
        let info = detect_from_elf_comment(comment).unwrap();

        assert_eq!(info.vendor, CompilerVendor::Llvm);
        assert_eq!(info.version_major, Some(14));
        assert_eq!(info.version_minor, Some(0));
        assert_eq!(info.version_patch, Some(6));
    }
}
