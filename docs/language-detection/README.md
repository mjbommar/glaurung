# Programming Language and Compiler Detection

## Overview

Glaurung implements comprehensive detection of the original programming language and compiler toolchain used to create binaries. This capability is essential for:
- Malware attribution and tracking
- Vulnerability research (compiler-specific bugs)
- Optimization analysis
- Reverse engineering workflow optimization

## Detection Strategies

### 1. Name Mangling Schemes

Different languages/compilers use distinctive symbol name mangling:

| Language | Compiler | Mangling Pattern | Example |
|----------|----------|------------------|---------|
| **C** | All | None | `malloc`, `printf`, `main` |
| **C++ (Itanium ABI)** | g++, clang++ | `_Z` prefix | `_ZN3std6vectorIiE9push_backEi` |
| **C++ (MSVC)** | Visual Studio | `?` or `@` prefix | `?foo@@YAHXZ` |
| **Rust** | rustc | `_R` or legacy `_ZN` | `_RNvC6module8function` |
| **Go** | gc | Dot notation | `main.main`, `runtime.newobject` |
| **Swift** | swiftc | `_T` or `$s` prefix | `$s4main3fooyyF` |
| **D** | dmd, ldc | `_D` prefix | `_D6module8functionFZv` |
| **Objective-C** | clang | `+[`/`-[` | `-[NSString stringWithFormat:]` |

```rust
// src/core/compiler_detection.rs
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
    Unknown,
}

pub fn detect_language_from_symbols(symbols: &[Symbol]) -> LanguageEvidence {
    let mut evidence = LanguageEvidence::default();
    
    for symbol in symbols {
        // Check mangling schemes
        if symbol.name.starts_with("_Z") && !symbol.name.starts_with("_ZN") {
            evidence.cpp_itanium += 1;
        } else if symbol.name.starts_with("?") || symbol.name.starts_with("@") {
            evidence.cpp_msvc += 1;
        } else if rustc_demangle::try_demangle(&symbol.name).is_ok() {
            evidence.rust += 1;
        } else if symbol.name.contains(".") && 
                  (symbol.name.starts_with("main.") || 
                   symbol.name.starts_with("runtime.")) {
            evidence.go += 1;
        }
        
        // Check runtime library signatures
        match symbol.name.as_str() {
            // C++ STL
            s if s.contains("std::") || s.contains("__cxx") => evidence.cpp_runtime += 1,
            // Rust std library
            s if s.contains("core::") || s.contains("alloc::") => evidence.rust_runtime += 1,
            // Go runtime
            s if s.starts_with("runtime.") || s.starts_with("fmt.") => evidence.go_runtime += 1,
            // Objective-C
            s if s.starts_with("objc_") || s.contains("NSObject") => evidence.objc_runtime += 1,
            _ => {}
        }
    }
    
    evidence
}
```

### 2. Compiler-Specific Metadata

#### PE Rich Header (Windows)
```rust
pub struct CompilerInfo {
    pub vendor: CompilerVendor,
    pub product: String,
    pub version: Version,
    pub build: u32,
}

pub enum CompilerVendor {
    Microsoft,      // MSVC, Visual Studio
    Gnu,           // GCC, G++
    Llvm,          // Clang, Clang++
    Intel,         // ICC
    Borland,       // Legacy
    Watcom,        // Legacy
    MinGW,         // MinGW-w64
}

// Parse Rich Header for MSVC detection
pub fn detect_msvc_compiler(rich_header: &RichHeader) -> Option<CompilerInfo> {
    for entry in &rich_header.entries {
        match entry.product_id {
            0x5d..=0x5f => return Some(CompilerInfo {
                vendor: CompilerVendor::Microsoft,
                product: "Visual C++ 2002".to_string(),
                version: Version::new(7, 0, 0),
                build: entry.build_id as u32,
            }),
            0x83..=0x86 => return Some(CompilerInfo {
                vendor: CompilerVendor::Microsoft,
                product: "Visual C++ 2005".to_string(),
                version: Version::new(8, 0, 0),
                build: entry.build_id as u32,
            }),
            // ... more versions
            _ => continue,
        }
    }
    None
}
```

#### ELF Note Sections
```rust
// Parse .note.gnu.build-id, .note.go.buildid, etc.
pub fn detect_from_elf_notes(elf: &object::File) -> LanguageInfo {
    for section in elf.sections() {
        let name = section.name().unwrap_or("");
        match name {
            ".note.go.buildid" => return LanguageInfo::Go {
                compiler: "gc".to_string(),
                buildid: parse_go_buildid(section.data()),
            },
            ".note.rust" => return LanguageInfo::Rust {
                compiler: "rustc".to_string(),
                version: parse_rust_version(section.data()),
            },
            ".comment" => {
                // GCC/Clang version strings
                let comment = String::from_utf8_lossy(section.data());
                if comment.contains("GCC:") {
                    return LanguageInfo::C_Cpp {
                        compiler: "gcc".to_string(),
                        version: extract_gcc_version(&comment),
                    };
                } else if comment.contains("clang version") {
                    return LanguageInfo::C_Cpp {
                        compiler: "clang".to_string(),
                        version: extract_clang_version(&comment),
                    };
                }
            }
            _ => continue,
        }
    }
    LanguageInfo::Unknown
}
```

### 3. Runtime Library Detection

```rust
pub struct RuntimeSignatures {
    // C++ Runtime Libraries
    pub libstdcpp: bool,     // GNU libstdc++ (g++)
    pub libc_plus_plus: bool, // LLVM libc++ (clang++)
    pub msvcrt: bool,         // Microsoft Visual C++ Runtime
    pub msvcp: bool,          // Microsoft C++ Standard Library
    
    // Language-Specific Runtimes
    pub go_runtime: bool,     // Go runtime
    pub rust_std: bool,       // Rust standard library
    pub swift_runtime: bool,  // Swift runtime
    pub dotnet_clr: bool,     // .NET CLR
    pub jvm: bool,            // Java Virtual Machine
    pub python_runtime: bool, // Python (libpython)
    pub ruby_runtime: bool,   // Ruby (libruby)
    pub node_runtime: bool,   // Node.js (V8)
}

pub fn detect_runtime_libraries(imports: &[String]) -> RuntimeSignatures {
    let mut sigs = RuntimeSignatures::default();
    
    for import in imports {
        match import.as_str() {
            // C++ Runtimes
            s if s.starts_with("libstdc++") => sigs.libstdcpp = true,
            s if s.starts_with("libc++") => sigs.libc_plus_plus = true,
            s if s.starts_with("MSVCR") || s.starts_with("VCRUNTIME") => sigs.msvcrt = true,
            s if s.starts_with("MSVCP") => sigs.msvcp = true,
            
            // Language Runtimes
            s if s.contains("libpython") => sigs.python_runtime = true,
            s if s.contains("libruby") => sigs.ruby_runtime = true,
            s if s.contains("KERNEL32.dll") && has_go_symbols => sigs.go_runtime = true,
            _ => {}
        }
    }
    
    sigs
}
```

### 4. Code Pattern Recognition

Different compilers produce distinctive instruction patterns:

```rust
pub struct CodePatterns {
    pub prologue_style: PrologueStyle,
    pub calling_convention: CallingConvention,
    pub optimization_patterns: Vec<OptimizationPattern>,
    pub exception_handling: ExceptionStyle,
}

pub enum PrologueStyle {
    StandardFrame,      // push rbp; mov rbp, rsp
    FramePointerOmit,   // No frame pointer (optimized)
    HotPatchable,       // MSVC hot-patchable prologue
    GoSplitStack,       // Go's split stack check
    RustPanic,          // Rust panic handler setup
}

pub enum ExceptionStyle {
    SjLj,              // setjmp/longjmp (older GCC)
    DwarfEH,           // DWARF exception handling (GCC/Clang)
    SEH,               // Structured Exception Handling (Windows)
    CxxEH,             // C++ exceptions
    GoPanic,           // Go panic/recover
    RustPanic,         // Rust panic
}

pub fn analyze_function_prologue(bytes: &[u8]) -> PrologueStyle {
    // x86-64 patterns
    match bytes {
        [0x55, 0x48, 0x89, 0xe5, ..] => PrologueStyle::StandardFrame,  // push rbp; mov rbp,rsp
        [0x48, 0x83, 0xec, ..] => PrologueStyle::FramePointerOmit,     // sub rsp, XX
        [0x90, 0x90, 0x90, 0x90, 0x90, ..] => PrologueStyle::HotPatchable, // MSVC nops
        [0x64, 0x48, 0x8b, 0x0c, 0x25, ..] => PrologueStyle::GoSplitStack, // Go stack check
        _ => PrologueStyle::StandardFrame,
    }
}
```

### 5. String and Metadata Analysis

```rust
pub struct LanguageStrings {
    pub error_messages: HashMap<String, SourceLanguage>,
    pub runtime_strings: HashMap<String, SourceLanguage>,
    pub version_strings: HashMap<String, CompilerInfo>,
}

impl LanguageStrings {
    pub fn new() -> Self {
        let mut s = Self::default();
        
        // Go-specific strings
        s.runtime_strings.insert("runtime.throw".to_string(), SourceLanguage::Go);
        s.runtime_strings.insert("sync.(*Mutex).Lock".to_string(), SourceLanguage::Go);
        
        // Rust-specific strings
        s.error_messages.insert("attempt to divide by zero".to_string(), SourceLanguage::Rust);
        s.error_messages.insert("called `Option::unwrap()`".to_string(), SourceLanguage::Rust);
        
        // C++ STL strings
        s.runtime_strings.insert("std::bad_alloc".to_string(), SourceLanguage::Cpp);
        s.runtime_strings.insert("vector::_M_realloc_insert".to_string(), SourceLanguage::Cpp);
        
        // Compiler version strings
        s.version_strings.insert("GCC: (GNU)".to_string(), CompilerInfo::gcc());
        s.version_strings.insert("clang version".to_string(), CompilerInfo::clang());
        s.version_strings.insert("rustc version".to_string(), CompilerInfo::rustc());
        
        s
    }
}
```

### 6. Build Artifact Detection

```rust
pub struct BuildArtifacts {
    pub debug_info_format: Option<DebugFormat>,
    pub build_id: Option<String>,
    pub source_paths: Vec<String>,
    pub compilation_units: Vec<String>,
    pub pdb_path: Option<String>,
}

pub enum DebugFormat {
    Dwarf,          // GCC/Clang on Unix
    Pdb,            // MSVC on Windows
    Stabs,          // Legacy Unix
    CodeView,       // Embedded in PE
    GoLineTable,    // Go's compressed line table
}

pub fn extract_build_artifacts(binary: &Binary) -> BuildArtifacts {
    let mut artifacts = BuildArtifacts::default();
    
    // Check for debug sections
    if binary.has_section(".debug_info") {
        artifacts.debug_info_format = Some(DebugFormat::Dwarf);
        artifacts.compilation_units = parse_dwarf_compilation_units(binary);
    }
    
    // Extract source file paths from debug info
    if let Some(line_program) = binary.debug_line_program() {
        for file in line_program.files() {
            artifacts.source_paths.push(file.path_name());
        }
    }
    
    // Look for language-specific paths
    for path in &artifacts.source_paths {
        if path.ends_with(".go") {
            // Go source file
        } else if path.ends_with(".rs") {
            // Rust source file
        } else if path.contains("/rustc/") {
            // Rust standard library
        } else if path.contains("\\VC\\") {
            // MSVC paths
        }
    }
    
    artifacts
}
```

## Comprehensive Detection Algorithm

```rust
pub struct LanguageDetector {
    symbol_analyzer: SymbolAnalyzer,
    runtime_detector: RuntimeDetector,
    pattern_matcher: PatternMatcher,
    metadata_parser: MetadataParser,
}

impl LanguageDetector {
    pub fn detect(&self, binary: &Binary) -> DetectionResult {
        let mut scores = HashMap::new();
        
        // 1. Symbol-based detection (highest confidence)
        let symbol_evidence = self.symbol_analyzer.analyze(&binary.symbols);
        self.update_scores(&mut scores, symbol_evidence, 1.0);
        
        // 2. Runtime library detection
        let runtime_evidence = self.runtime_detector.detect(&binary.imports);
        self.update_scores(&mut scores, runtime_evidence, 0.8);
        
        // 3. Metadata detection (build IDs, version strings)
        let metadata_evidence = self.metadata_parser.parse(binary);
        self.update_scores(&mut scores, metadata_evidence, 0.9);
        
        // 4. Code pattern analysis
        let pattern_evidence = self.pattern_matcher.analyze(&binary.code);
        self.update_scores(&mut scores, pattern_evidence, 0.6);
        
        // 5. String content analysis
        let string_evidence = analyze_strings(&binary.strings);
        self.update_scores(&mut scores, string_evidence, 0.5);
        
        // Return highest scoring language/compiler combination
        DetectionResult {
            language: scores.iter().max_by_key(|(_,v)| *v).map(|(k,_)| k.clone()),
            confidence: scores.values().max().copied().unwrap_or(0.0),
            compiler: detect_specific_compiler(binary),
            evidence: collect_evidence(scores),
        }
    }
}
```

## Integration with Glaurung

### Python API
```python
import glaurung

# Analyze binary for language/compiler
binary = glaurung.Binary.from_path("sample.exe")
detection = glaurung.detect_language(binary)

print(f"Language: {detection.language}")
print(f"Compiler: {detection.compiler}")
print(f"Version: {detection.compiler_version}")
print(f"Confidence: {detection.confidence:.2%}")

# Detailed evidence
for evidence in detection.evidence:
    print(f"  - {evidence.type}: {evidence.description}")
```

### CLI Usage
```bash
# Quick detection
glaurung detect-language binary.exe

# Detailed analysis
glaurung detect-language --verbose --show-evidence binary.exe

# Batch analysis
glaurung detect-language --json samples/*.exe > detections.json
```

## Detection Confidence Levels

| Confidence | Criteria |
|------------|----------|
| **High (>90%)** | Multiple consistent indicators (symbols + runtime + metadata) |
| **Medium (70-90%)** | Symbol mangling or runtime libraries present |
| **Low (50-70%)** | Only pattern matching or string analysis |
| **Uncertain (<50%)** | Conflicting or minimal evidence |

## Known Limitations

1. **Stripped Binaries**: Greatly reduces detection accuracy
2. **Static Linking**: Harder to identify runtime libraries
3. **Obfuscation**: Deliberately obscured symbols and patterns
4. **Cross-compilation**: May show target platform characteristics
5. **LTO/WPO**: Link-time optimization changes patterns
6. **Language Mixing**: C++ with C, or Rust with C FFI

## Language-Specific Indicators

### Go
- `.note.go.buildid` section
- `runtime.` prefixed symbols
- Split-stack prologues
- Goroutine scheduler artifacts
- String: "fatal error: " followed by Go runtime errors

### Rust
- `_R` mangled symbols (v0 mangling)
- `core::` and `alloc::` symbols
- Panic handler infrastructure
- `.note.rust` section
- String: "panicked at" with file:line

### C++
- Name mangling (Itanium or MSVC)
- Exception handling tables
- RTTI (Run-Time Type Information)
- STL container signatures
- Virtual function tables (vtables)

### Swift
- `$s` or `_T` mangled symbols
- Swift runtime library imports
- Objective-C interop bridges
- Witness tables for protocols
- String metadata tables

### C
- No name mangling
- Simple calling conventions
- Minimal runtime (just libc)
- No exception handling tables
- Direct system call wrappers

## Testing Dataset

Sample binaries in `samples/binaries/platforms/`:
- C: `hello-c-gcc-*.exe`, `hello-c-clang-*.exe`
- C++: `hello-cpp-g++-*.exe`, `hello-cpp-clang++-*.exe`
- Rust: `hello-rust-*.exe`
- Go: `hello-go-*.exe`
- C#: `Hello-mono.exe`
- Java: `HelloWorld.jar`
- Python: `hello-python.pyc`

## Future Enhancements

1. **Machine Learning Models**: Train on large corpus for pattern recognition
2. **Compiler Version Database**: Detailed version fingerprinting
3. **Toolchain Detection**: Build system identification (CMake, Cargo, etc.)
4. **Mixed Language Detection**: Identify FFI boundaries
5. **Optimization Level Detection**: -O0 vs -O3 patterns
6. **Security Feature Detection**: Stack protectors, CFI, etc.

## References

- "Compiler Provenance Attribution" (Rosenblum et al., 2010)
- "BinComp: A Compiler Identification Framework" (Alrabaee et al., 2014)
- "Recognizing Functions in Binaries with Neural Networks" (Shin et al., 2015)
- MSVC Rich Header documentation (unofficial)
- ELF/DWARF specifications
- Language-specific ABI documentation