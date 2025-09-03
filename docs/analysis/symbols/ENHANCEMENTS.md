# Symbol Extraction Enhancements

## Overview
This document outlines 15 critical enhancements to improve the symbol extraction and analysis capabilities in Glaurung's triage system. These improvements focus on security analysis, exploitation detection, and anti-analysis techniques commonly used by malware.

## Priority Classification
- **🔴 Critical** - Security vulnerabilities and exploitation detection
- **🟡 Important** - Malware analysis and attribution
- **🟢 Nice-to-have** - Performance and extended analysis

---

## 1. PLT/GOT Analysis for Security 🔴

### Motivation
The Procedure Linkage Table (PLT) and Global Offset Table (GOT) are prime targets for exploitation. Attackers use GOT overwriting for control flow hijacking, especially in binaries without PIE (Position Independent Executable).

### Implementation Details

#### Data Structures
```rust
// src/triage/symbols/got_plt.rs
pub struct GotPltAnalysis {
    /// GOT entries with resolved addresses and target functions
    pub got_entries: Vec<GotEntry>,
    /// PLT stub locations and their GOT references
    pub plt_stubs: Vec<PltStub>,
    /// Security flags
    pub security: GotPltSecurity,
}

pub struct GotEntry {
    pub address: u64,           // GOT entry address
    pub target_name: String,     // Resolved function name
    pub writable: bool,          // Is GOT writable at runtime?
    pub resolved: bool,          // Already resolved vs lazy binding
}

pub struct PltStub {
    pub plt_address: u64,        // PLT stub location
    pub got_offset: u64,         // Corresponding GOT entry
    pub function_name: String,
}

pub struct GotPltSecurity {
    pub relro: RelroLevel,       // RELRO protection level
    pub pie_enabled: bool,       // Position Independent Executable
    pub bind_now: bool,          // Immediate binding (no lazy resolution)
    pub executable_stack: bool,  // NX bit status
}

pub enum RelroLevel {
    None,        // No RELRO
    Partial,     // .got.plt remains writable
    Full,        // All GOT read-only after relocation
}
```

#### Implementation Steps

1. **Parse Dynamic Section**
```rust
fn analyze_got_plt_elf(data: &[u8]) -> Option<GotPltAnalysis> {
    // Step 1: Find PT_GNU_RELRO segment to determine RELRO
    let relro_level = detect_relro_level(data);
    
    // Step 2: Parse .got and .got.plt sections
    let got_section = find_section(data, ".got");
    let got_plt_section = find_section(data, ".got.plt");
    
    // Step 3: Parse .plt section for stubs
    let plt_section = find_section(data, ".plt");
    let plt_stubs = parse_plt_stubs(data, plt_section)?;
    
    // Step 4: Resolve GOT entries using dynamic relocations
    let got_entries = resolve_got_entries(data, &got_section, &got_plt_section)?;
    
    // Step 5: Check security flags from DT_FLAGS and DT_FLAGS_1
    let security = analyze_security_flags(data);
    
    Some(GotPltAnalysis {
        got_entries,
        plt_stubs,
        security,
    })
}

fn detect_relro_level(data: &[u8]) -> RelroLevel {
    // Check for PT_GNU_RELRO segment
    if has_gnu_relro_segment(data) {
        // Check if DT_BIND_NOW is set
        if has_bind_now_flag(data) {
            RelroLevel::Full
        } else {
            RelroLevel::Partial
        }
    } else {
        RelroLevel::None
    }
}
```

2. **Security Scoring**
```rust
impl GotPltAnalysis {
    pub fn security_score(&self) -> f32 {
        let mut score = 0.0;
        
        // RELRO protection
        match self.security.relro {
            RelroLevel::Full => score += 1.0,
            RelroLevel::Partial => score += 0.5,
            RelroLevel::None => score += 0.0,
        }
        
        // PIE enabled
        if self.security.pie_enabled {
            score += 1.0;
        }
        
        // Immediate binding
        if self.security.bind_now {
            score += 0.5;
        }
        
        // NX bit
        if !self.security.executable_stack {
            score += 0.5;
        }
        
        score / 3.0  // Normalize to 0-1
    }
}
```

### Testing Strategy
- Test with binaries compiled with different security flags
- Verify RELRO detection with `checksec` tool comparison
- Test GOT overwriting detection in known vulnerable binaries

---

## 2. Enhanced Suspicious Import Detection 🔴

### Motivation
Current detection misses modern injection techniques (APC, process hollowing), credential theft APIs, and anti-analysis patterns.

### Implementation Details

#### Categorized Suspicious APIs
```rust
// src/triage/symbols/suspicious_patterns.rs

pub struct SuspiciousPatterns {
    pub injection: Vec<InjectionPattern>,
    pub anti_analysis: Vec<AntiAnalysisPattern>,
    pub credential_theft: Vec<CredentialPattern>,
    pub persistence: Vec<PersistencePattern>,
    pub network: Vec<NetworkPattern>,
}

pub struct InjectionPattern {
    pub apis: Vec<&'static str>,
    pub severity: Severity,
    pub description: &'static str,
    pub mitre_attack_id: &'static str,
}

impl SuspiciousPatterns {
    pub fn default() -> Self {
        Self {
            injection: vec![
                InjectionPattern {
                    apis: vec!["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    severity: Severity::Critical,
                    description: "Classic process injection pattern",
                    mitre_attack_id: "T1055.001",
                },
                InjectionPattern {
                    apis: vec!["QueueUserAPC", "NtQueueApcThread", "NtAlertResumeThread"],
                    severity: Severity::Critical,
                    description: "APC injection pattern",
                    mitre_attack_id: "T1055.004",
                },
                InjectionPattern {
                    apis: vec!["NtUnmapViewOfSection", "NtMapViewOfSection", "NtWriteVirtualMemory"],
                    severity: Severity::Critical,
                    description: "Process hollowing pattern",
                    mitre_attack_id: "T1055.012",
                },
                InjectionPattern {
                    apis: vec!["SetThreadContext", "GetThreadContext", "ResumeThread"],
                    severity: Severity::High,
                    description: "Thread context manipulation",
                    mitre_attack_id: "T1055.003",
                },
            ],
            anti_analysis: vec![
                AntiAnalysisPattern {
                    apis: vec!["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
                    severity: Severity::Medium,
                    description: "Anti-debugging checks",
                    mitre_attack_id: "T1622",
                },
                AntiAnalysisPattern {
                    apis: vec!["GetTickCount", "QueryPerformanceCounter", "rdtsc"],
                    severity: Severity::Low,
                    description: "Timing-based anti-analysis",
                    mitre_attack_id: "T1497.003",
                },
            ],
            credential_theft: vec![
                CredentialPattern {
                    apis: vec!["CredEnumerate", "CredRead", "CredWrite"],
                    severity: Severity::High,
                    description: "Windows Credential Manager access",
                    mitre_attack_id: "T1555.004",
                },
                CredentialPattern {
                    apis: vec!["SamIConnect", "SamrOpenDomain", "SamrEnumerateUsersInDomain"],
                    severity: Severity::Critical,
                    description: "SAM database access",
                    mitre_attack_id: "T1003.002",
                },
                CredentialPattern {
                    apis: vec!["LsaEnumerateLogonSessions", "LsaGetLogonSessionData"],
                    severity: Severity::High,
                    description: "LSA secrets access",
                    mitre_attack_id: "T1003.004",
                },
            ],
            // ... more categories
        }
    }
}
```

#### Pattern Matching Engine
```rust
pub struct PatternMatcher {
    patterns: SuspiciousPatterns,
    api_cache: HashMap<String, Vec<PatternMatch>>,
}

impl PatternMatcher {
    pub fn analyze_imports(&mut self, imports: &[String]) -> SuspiciousAnalysis {
        let mut matches = Vec::new();
        let normalized: Vec<String> = imports.iter()
            .map(|s| normalize_api_name(s))
            .collect();
        
        // Check injection patterns (require ALL APIs in pattern)
        for pattern in &self.patterns.injection {
            if self.has_all_apis(&normalized, &pattern.apis) {
                matches.push(PatternMatch {
                    pattern_type: PatternType::Injection,
                    matched_apis: pattern.apis.iter().map(|s| s.to_string()).collect(),
                    severity: pattern.severity,
                    description: pattern.description.to_string(),
                    mitre_id: pattern.mitre_attack_id.to_string(),
                });
            }
        }
        
        // Check for API combinations
        let combinations = self.find_suspicious_combinations(&normalized);
        
        SuspiciousAnalysis {
            pattern_matches: matches,
            suspicious_combinations: combinations,
            risk_score: self.calculate_risk_score(&matches),
        }
    }
    
    fn find_suspicious_combinations(&self, apis: &[String]) -> Vec<ApiCombination> {
        let mut combinations = Vec::new();
        
        // VirtualAlloc* + WriteProcessMemory + CreateRemoteThread
        if apis.iter().any(|a| a.starts_with("virtualalloc")) &&
           apis.iter().any(|a| a.contains("writeprocessmemory")) &&
           apis.iter().any(|a| a.contains("createremotethread")) {
            combinations.push(ApiCombination {
                apis: vec!["VirtualAlloc*", "WriteProcessMemory", "CreateRemoteThread"],
                risk: RiskLevel::Critical,
                technique: "Process Injection",
            });
        }
        
        combinations
    }
}
```

### Testing Strategy
- Create test binaries with known malware API patterns
- Validate against MITRE ATT&CK framework mappings
- Compare with commercial AV detection patterns

---

## 3. DWARF Debug Symbol Extraction 🟡

### Motivation
DWARF debug information reveals compilation environment, source paths, compiler versions, and can aid in vulnerability discovery and attribution.

### Implementation Details

#### DWARF Parser
```rust
// src/triage/symbols/dwarf.rs
use gimli::{Dwarf, EndianSlice, RunTimeEndian};

pub struct DwarfAnalysis {
    pub compilation_units: Vec<CompilationUnit>,
    pub source_files: HashSet<String>,
    pub producer_info: Vec<ProducerInfo>,
    pub language_stats: HashMap<DwarfLang, u32>,
    pub has_split_dwarf: bool,
    pub dwarf_version: u8,
}

pub struct CompilationUnit {
    pub name: String,
    pub comp_dir: String,           // Compilation directory
    pub producer: String,            // Compiler version/name
    pub language: DwarfLang,
    pub optimized: bool,
    pub source_files: Vec<String>,
}

pub struct ProducerInfo {
    pub compiler: CompilerType,
    pub version: String,
    pub flags: Vec<String>,          // Compilation flags if present
}

impl DwarfAnalysis {
    pub fn extract(data: &[u8]) -> Result<Self, Error> {
        // Load all DWARF sections
        let dwarf = load_dwarf_sections(data)?;
        
        let mut units = Vec::new();
        let mut source_files = HashSet::new();
        let mut producers = Vec::new();
        
        // Iterate compilation units
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            
            if let Some((_, entry)) = entries.next_dfs()? {
                // Extract compilation unit info
                let cu_info = extract_cu_info(&dwarf, &unit, &entry)?;
                
                // Extract source file list
                if let Some(line_program) = unit.line_program.clone() {
                    let header = line_program.header();
                    for file in header.file_names() {
                        let path = extract_file_path(&dwarf, &unit, header, file)?;
                        source_files.insert(path.clone());
                        cu_info.source_files.push(path);
                    }
                }
                
                // Parse producer string for compiler info
                if let Some(producer) = cu_info.producer.as_ref() {
                    producers.push(parse_producer_string(producer));
                }
                
                units.push(cu_info);
            }
        }
        
        Ok(DwarfAnalysis {
            compilation_units: units,
            source_files,
            producer_info: producers,
            language_stats: calculate_language_stats(&units),
            has_split_dwarf: check_for_split_dwarf(data),
            dwarf_version: extract_dwarf_version(&dwarf),
        })
    }
}

fn parse_producer_string(producer: &str) -> ProducerInfo {
    // Parse strings like "GNU C++14 9.3.0 -mtune=generic -march=x86-64 -g -O2"
    let parts: Vec<&str> = producer.split_whitespace().collect();
    
    let compiler = if producer.starts_with("GNU") {
        CompilerType::GCC
    } else if producer.contains("clang") {
        CompilerType::Clang
    } else if producer.contains("rustc") {
        CompilerType::Rustc
    } else if producer.contains("Microsoft") {
        CompilerType::MSVC
    } else {
        CompilerType::Unknown
    };
    
    // Extract version and flags
    let version = extract_version(&parts);
    let flags = extract_compilation_flags(&parts);
    
    ProducerInfo {
        compiler,
        version,
        flags,
    }
}
```

#### Security Analysis from DWARF
```rust
impl DwarfAnalysis {
    pub fn security_analysis(&self) -> DwarfSecurityInfo {
        let mut info = DwarfSecurityInfo::default();
        
        // Check for security-relevant paths
        for path in &self.source_files {
            // Temporary directories suggest build farms
            if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") {
                info.suspicious_paths.push(path.clone());
            }
            
            // Home directories may leak usernames
            if path.starts_with("/home/") || path.starts_with("/Users/") {
                info.leaked_usernames.insert(extract_username(path));
            }
            
            // Check for known vulnerable library paths
            if path.contains("openssl") || path.contains("libssl") {
                info.potentially_vulnerable_libs.push(path.clone());
            }
        }
        
        // Analyze compiler flags for security
        for producer in &self.producer_info {
            for flag in &producer.flags {
                if flag == "-fno-stack-protector" {
                    info.security_issues.push("Stack protector disabled");
                }
                if flag == "-O0" {
                    info.security_issues.push("No optimization (possible debug build)");
                }
                if flag.starts_with("-f") && flag.contains("sanitize") {
                    info.sanitizers_enabled.push(flag.clone());
                }
            }
        }
        
        info
    }
}
```

### Testing Strategy
- Test with binaries compiled with different `-g` levels
- Verify split DWARF (.dwo) detection
- Compare extracted info with `dwarfdump` output

---

## 4. PDB Symbol Server Integration 🟡

### Motivation
For Windows binaries, PDB files contain the richest debug information. Integrating with Microsoft's symbol servers allows for fetching PDBs on-demand, enabling deep analysis of system DLLs and stripped binaries where PDBs are available publicly.

### Implementation Details

#### PDB Downloader and Parser
```rust
// src/triage/symbols/pdb.rs
use pdb::PDB;
use std::fs::File;

pub struct PdbAnalysis {
    pub symbols: Vec<SymbolInfo>,
    pub type_information: Vec<TypeInfo>,
    pub source_files: HashSet<String>,
    pub age: u32,
    pub guid: String,
}

pub fn download_and_parse_pdb(guid: &str, age: u32, file_name: &str) -> Result<PdbAnalysis, Error> {
    // Construct symbol server URL
    let url = format!("http://msdl.microsoft.com/download/symbols/{}/{:x}/{}", file_name, age, guid);
    
    // Download PDB file
    let pdb_data = download_file(&url)?;
    
    // Parse PDB using the `pdb` crate
    let pdb = PDB::open(&pdb_data)?;
    
    // Extract symbols, types, and source file information
    let symbols = extract_symbols(&pdb)?;
    let types = extract_type_info(&pdb)?;
    let source_files = extract_source_files(&pdb)?;
    
    Ok(PdbAnalysis {
        symbols,
        type_information: types,
        source_files,
        age,
        guid: guid.to_string(),
    })
}
```

### Testing Strategy
- Test with common system DLLs (kernel32.dll, ntdll.dll)
- Verify correct PDB fetching and parsing
- Test with binaries that have no available PDBs (graceful failure)

---

## 5. Control Flow Guard (CFG) Detection 🔴

### Motivation
Control Flow Guard (CFG) is a critical Windows security mitigation that makes exploiting memory corruption vulnerabilities harder. Detecting its presence is a key indicator of a binary's security posture.

### Implementation Details

#### CFG Flag Analysis
```rust
// src/triage/symbols/pe_security.rs

pub struct PeSecurity {
    pub has_cfg: bool,
    pub aslr: bool,
    pub dep: bool,
    // ... other security flags
}

pub fn analyze_pe_security(pe: &object::File) -> PeSecurity {
    let mut security = PeSecurity::default();
    
    if let Some(optional_header) = pe.pe_optional_header() {
        let dll_characteristics = optional_header.dll_characteristics();
        
        security.aslr = dll_characteristics & 0x0040 != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        security.dep = dll_characteristics & 0x0100 != 0;  // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        
        // Check for CFG in the load config directory
        if let Some(load_config) = pe.pe_load_config() {
            security.has_cfg = load_config.guard_flags & 0x00000100 != 0; // IMAGE_GUARD_CF_INSTRUMENTED
        }
    }
    
    security
}
```

### Testing Strategy
- Test with binaries compiled with and without `/guard:cf`
- Verify detection against tools like `dumpbin`
- Test on both 32-bit and 64-bit PE files

---

## 6. Export Forwarding Detection 🟡

### Motivation
Export forwarding is used in DLL proxying attacks and API redirection. Detecting forwarded exports helps identify potential DLL hijacking and persistence mechanisms.

### Implementation Details

#### Export Forwarding Parser
```rust
// src/triage/symbols/export_analysis.rs

pub struct ExportAnalysis {
    pub direct_exports: Vec<DirectExport>,
    pub forwarded_exports: Vec<ForwardedExport>,
    pub ordinal_only_exports: Vec<OrdinalExport>,
    pub export_timestamp: Option<u32>,
    pub mangled_exports: Vec<MangledExport>,
}

pub struct ForwardedExport {
    pub name: String,
    pub target_dll: String,
    pub target_function: String,
    pub is_circular: bool,  // Forwards to itself
}

pub struct MangledExport {
    pub mangled_name: String,
    pub demangled: Option<String>,
    pub language: ManglingScheme,
}

pub enum ManglingScheme {
    Cpp,        // C++ name mangling
    Rust,       // Rust name mangling
    Swift,      // Swift name mangling
    Unknown,
}

impl ExportAnalysis {
    pub fn analyze_pe_exports(data: &[u8], export_dir_rva: u32) -> Result<Self, Error> {
        let export_dir = parse_export_directory(data, export_dir_rva)?;
        
        let mut direct = Vec::new();
        let mut forwarded = Vec::new();
        let mut ordinal_only = Vec::new();
        let mut mangled = Vec::new();
        
        // Parse export address table
        for i in 0..export_dir.number_of_functions {
            let export_rva = read_export_rva(data, &export_dir, i)?;
            
            // Check if it's a forwarder (RVA points within export directory)
            if is_forwarder_rva(export_rva, &export_dir) {
                let forward_string = read_forward_string(data, export_rva)?;
                let parsed = parse_forward_string(&forward_string)?;
                
                forwarded.push(ForwardedExport {
                    name: get_export_name(data, &export_dir, i)?,
                    target_dll: parsed.dll,
                    target_function: parsed.function,
                    is_circular: check_circular_forward(&forward_string),
                });
            } else {
                // Check if export has a name or is ordinal-only
                if let Some(name) = get_export_name(data, &export_dir, i) {
                    // Check for name mangling
                    if is_mangled_name(&name) {
                        mangled.push(MangledExport {
                            mangled_name: name.clone(),
                            demangled: demangle_name(&name),
                            language: detect_mangling_scheme(&name),
                        });
                    }
                    
                    direct.push(DirectExport {
                        name,
                        ordinal: export_dir.base + i as u32,
                        rva: export_rva,
                    });
                } else {
                    ordinal_only.push(OrdinalExport {
                        ordinal: export_dir.base + i as u32,
                        rva: export_rva,
                    });
                }
            }
        }
        
        Ok(ExportAnalysis {
            direct_exports: direct,
            forwarded_exports: forwarded,
            ordinal_only_exports: ordinal_only,
            export_timestamp: Some(export_dir.timestamp),
            mangled_exports: mangled,
        })
    }
}

fn parse_forward_string(forward: &str) -> Result<ForwardTarget, Error> {
    // Format: "DLLNAME.FunctionName" or "DLLNAME.#Ordinal"
    let parts: Vec<&str> = forward.split('.').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidForwardString);
    }
    
    let dll = parts[0].to_string();
    let function = if parts[1].starts_with('#') {
        // Ordinal forward
        let ordinal = parts[1][1..].parse::<u32>()?;
        format!("#{}", ordinal)
    } else {
        parts[1].to_string()
    };
    
    Ok(ForwardTarget { dll, function })
}
```

#### DLL Proxy Detection
```rust
pub struct DllProxyDetector {
    exports: ExportAnalysis,
}

impl DllProxyDetector {
    pub fn detect_proxy_patterns(&self) -> Vec<ProxyPattern> {
        let mut patterns = Vec::new();
        
        // Pattern 1: High percentage of forwarded exports
        let forward_ratio = self.exports.forwarded_exports.len() as f32 / 
                          (self.exports.direct_exports.len() + 
                           self.exports.forwarded_exports.len()) as f32;
        
        if forward_ratio > 0.8 {
            patterns.push(ProxyPattern::HighForwardRatio(forward_ratio));
        }
        
        // Pattern 2: All forwards to same DLL (classic proxy)
        let target_dlls: HashSet<_> = self.exports.forwarded_exports
            .iter()
            .map(|f| &f.target_dll)
            .collect();
        
        if target_dlls.len() == 1 && self.exports.forwarded_exports.len() > 10 {
            patterns.push(ProxyPattern::SingleTargetDll(
                target_dlls.into_iter().next().unwrap().clone()
            ));
        }
        
        // Pattern 3: Circular forwarding (suspicious)
        if self.exports.forwarded_exports.iter().any(|f| f.is_circular) {
            patterns.push(ProxyPattern::CircularForwarding);
        }
        
        patterns
    }
}
```

### Testing Strategy
- Test with known DLL proxy samples
- Verify forwarding detection with system DLLs (e.g., kernel32 -> kernelbase)
- Test ordinal-only export detection

---

## 7. Symbol Stripping and Obfuscation Detection 🔴

### Motivation
Symbol stripping level indicates anti-analysis intent. Obfuscated symbols suggest malware or heavily protected software.

### Implementation Details

#### Stripping Level Detection
```rust
// src/triage/symbols/stripping.rs

pub struct SymbolIntegrity {
    pub stripped_level: StrippedLevel,
    pub symbol_table_stats: SymbolTableStats,
    pub obfuscation_indicators: Vec<ObfuscationIndicator>,
    pub symbol_entropy: f32,
}

pub enum StrippedLevel {
    None,           // Full symbols, debug info present
    DebugOnly,      // Debug symbols stripped, regular symbols remain
    AllButDynamic,  // Only dynamic symbols for linking remain
    Full,           // All possible symbols stripped
}

pub struct SymbolTableStats {
    pub symtab_present: bool,
    pub symtab_entries: u32,
    pub dynsym_present: bool,
    pub dynsym_entries: u32,
    pub strtab_size: u32,
    pub dynstr_size: u32,
}

pub enum ObfuscationIndicator {
    HighEntropy(f32),              // Random-looking names
    PatternedNames(String),        // a, aa, aaa pattern
    SingleCharNames(u32),          // Count of single-char symbols
    HexStringNames(u32),           // Names that look like hex
    Base64Names(u32),              // Names that look like base64
    MinimalExports,                // Suspiciously few exports
    TimestampAnomaly,              // Export timestamp doesn't match PE timestamp
}

impl SymbolIntegrity {
    pub fn analyze_elf(data: &[u8]) -> Result<Self, Error> {
        let elf = parse_elf_headers(data)?;
        
        // Check for symbol tables
        let symtab = find_section(&elf, ".symtab");
        let dynsym = find_section(&elf, ".dynsym");
        let strtab = find_section(&elf, ".strtab");
        let dynstr = find_section(&elf, ".dynstr");
        
        // Determine stripping level
        let stripped_level = match (symtab.is_some(), dynsym.is_some()) {
            (true, true) => {
                // Check for debug sections
                if has_debug_sections(&elf) {
                    StrippedLevel::None
                } else {
                    StrippedLevel::DebugOnly
                }
            },
            (false, true) => StrippedLevel::AllButDynamic,
            (false, false) => StrippedLevel::Full,
            (true, false) => StrippedLevel::DebugOnly,  // Unusual case
        };
        
        // Analyze symbol names for obfuscation
        let mut all_symbols = Vec::new();
        if let Some(symtab) = symtab {
            all_symbols.extend(extract_symbol_names(data, &symtab, &strtab)?);
        }
        if let Some(dynsym) = dynsym {
            all_symbols.extend(extract_symbol_names(data, &dynsym, &dynstr)?);
        }
        
        let obfuscation = detect_obfuscation_patterns(&all_symbols);
        let entropy = calculate_symbol_entropy(&all_symbols);
        
        Ok(SymbolIntegrity {
            stripped_level,
            symbol_table_stats: SymbolTableStats {
                symtab_present: symtab.is_some(),
                symtab_entries: symtab.map(|s| s.entry_count).unwrap_or(0),
                dynsym_present: dynsym.is_some(),
                dynsym_entries: dynsym.map(|s| s.entry_count).unwrap_or(0),
                strtab_size: strtab.map(|s| s.size).unwrap_or(0),
                dynstr_size: dynstr.map(|s| s.size).unwrap_or(0),
            },
            obfuscation_indicators: obfuscation,
            symbol_entropy: entropy,
        })
    }
}

fn detect_obfuscation_patterns(symbols: &[String]) -> Vec<ObfuscationIndicator> {
    let mut indicators = Vec::new();
    
    // Check for sequential patterns (a, aa, aaa, ...)
    let sequential = detect_sequential_pattern(symbols);
    if let Some(pattern) = sequential {
        indicators.push(ObfuscationIndicator::PatternedNames(pattern));
    }
    
    // Count single character names
    let single_char = symbols.iter()
        .filter(|s| s.len() == 1 && s.chars().all(|c| c.is_ascii_alphabetic()))
        .count() as u32;
    if single_char > 10 {
        indicators.push(ObfuscationIndicator::SingleCharNames(single_char));
    }
    
    // Check for hex-like names
    let hex_names = symbols.iter()
        .filter(|s| s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .count() as u32;
    if hex_names > 5 {
        indicators.push(ObfuscationIndicator::HexStringNames(hex_names));
    }
    
    // Check for base64-like names
    let base64_names = symbols.iter()
        .filter(|s| looks_like_base64(s))
        .count() as u32;
    if base64_names > 5 {
        indicators.push(ObfuscationIndicator::Base64Names(base64_names));
    }
    
    // Calculate overall entropy
    let avg_entropy = calculate_average_entropy(symbols);
    if avg_entropy > 4.5 {  // High entropy threshold
        indicators.push(ObfuscationIndicator::HighEntropy(avg_entropy));
    }
    
    indicators
}

fn calculate_symbol_entropy(symbols: &[String]) -> f32 {
    if symbols.is_empty() {
        return 0.0;
    }
    
    // Calculate Shannon entropy of symbol names
    let all_chars: String = symbols.join("");
    let mut freq = HashMap::new();
    
    for ch in all_chars.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }
    
    let total = all_chars.len() as f32;
    let mut entropy = 0.0;
    
    for count in freq.values() {
        let p = *count as f32 / total;
        entropy -= p * p.log2();
    }
    
    entropy
}
```

### Testing Strategy
- Test with stripped vs non-stripped binaries
- Verify against UPX-packed samples (high entropy)
- Test with known obfuscators (VMProtect, Themida)

---

## 8. Delayed Import Analysis (PE) 🟢

### Motivation
Delayed imports are loaded on-demand and can evade static analysis. They're commonly used in packers, loaders, and evasive malware.

### Implementation Details

#### Delayed Import Parser
```rust
// src/triage/symbols/delayed_imports.rs

pub struct DelayedImportInfo {
    pub delayed_dlls: Vec<DelayedDll>,
    pub total_delayed_imports: u32,
    pub has_unload_info: bool,
    pub bound_imports: bool,
}

pub struct DelayedDll {
    pub name: String,
    pub functions: Vec<DelayedFunction>,
    pub attributes: DelayLoadAttributes,
    pub module_handle_rva: u32,
}

pub struct DelayedFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub bound_rva: Option<u32>,  // If bound
}

bitflags! {
    pub struct DelayLoadAttributes: u32 {
        const RVA_BASED = 0x01;  // RVAs instead of VAs
        const NO_UNLOAD = 0x02;  // Don't unload DLL
    }
}

impl DelayedImportInfo {
    pub fn parse_delay_imports(data: &[u8], delay_dir: &DataDirectory) -> Result<Self, Error> {
        let mut delayed_dlls = Vec::new();
        let mut total_imports = 0;
        let mut has_unload = false;
        let mut bound = false;
        
        let mut offset = rva_to_offset(delay_dir.rva)?;
        
        // Parse delay import descriptors
        loop {
            if offset + 32 > data.len() {
                break;
            }
            
            let desc = parse_delay_descriptor(data, offset)?;
            
            // Check for null terminator
            if desc.is_null() {
                break;
            }
            
            // Parse DLL name
            let dll_name = read_string_rva(data, desc.dll_name_rva)?;
            
            // Parse functions
            let mut functions = Vec::new();
            let iat_offset = rva_to_offset(desc.iat_rva)?;
            let int_offset = rva_to_offset(desc.int_rva)?;
            
            // Iterate through Import Name Table
            let mut idx = 0;
            loop {
                let int_entry = read_thunk(data, int_offset + idx)?;
                if int_entry == 0 {
                    break;
                }
                
                let function = if is_ordinal_import(int_entry) {
                    DelayedFunction {
                        name: None,
                        ordinal: Some(extract_ordinal(int_entry)),
                        hint: None,
                        bound_rva: check_if_bound(data, iat_offset + idx),
                    }
                } else {
                    let hint_name = read_hint_name(data, int_entry as u32)?;
                    DelayedFunction {
                        name: Some(hint_name.name),
                        ordinal: None,
                        hint: Some(hint_name.hint),
                        bound_rva: check_if_bound(data, iat_offset + idx),
                    }
                };
                
                functions.push(function);
                total_imports += 1;
                idx += if is_pe32_plus { 8 } else { 4 };
            }
            
            // Check attributes
            if desc.attributes & 0x01 != 0 {
                bound = true;
            }
            if desc.unload_info_table_rva != 0 {
                has_unload = true;
            }
            
            delayed_dlls.push(DelayedDll {
                name: dll_name,
                functions,
                attributes: DelayLoadAttributes::from_bits_truncate(desc.attributes),
                module_handle_rva: desc.module_handle_rva,
            });
            
            offset += 32;  // Size of IMAGE_DELAYLOAD_DESCRIPTOR
        }
        
        Ok(DelayedImportInfo {
            delayed_dlls,
            total_delayed_imports: total_imports,
            has_unload_info: has_unload,
            bound_imports: bound,
        })
    }
}
```

#### Suspicious Delay Load Detection
```rust
impl DelayedImportInfo {
    pub fn detect_suspicious_patterns(&self) -> Vec<SuspiciousDelayPattern> {
        let mut patterns = Vec::new();
        
        // Pattern 1: Delayed loading of critical system DLLs
        let critical_dlls = ["kernel32.dll", "ntdll.dll", "user32.dll"];
        for dll in &self.delayed_dlls {
            if critical_dlls.iter().any(|&c| dll.name.eq_ignore_ascii_case(c)) {
                patterns.push(SuspiciousDelayPattern::CriticalDllDelayed(dll.name.clone()));
            }
        }
        
        // Pattern 2: Delayed injection-related APIs
        let injection_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
        for dll in &self.delayed_dlls {
            for func in &dll.functions {
                if let Some(name) = &func.name {
                    if injection_apis.iter().any(|&api| name.eq_ignore_ascii_case(api)) {
                        patterns.push(SuspiciousDelayPattern::DelayedInjectionApi {
                            dll: dll.name.clone(),
                            api: name.clone(),
                        });
                    }
                }
            }
        }
        
        // Pattern 3: All imports are delayed (evasion)
        if self.delayed_dlls.len() > 5 && /* check if normal imports are minimal */ {
            patterns.push(SuspiciousDelayPattern::AllImportsDelayed);
        }
        
        patterns
    }
}
```

### Testing Strategy
- Test with legitimate software using delay loading (browsers, plugins)
- Verify against malware samples with delayed injection APIs
- Test bound vs unbound delayed imports

---

## 9. Cross-Reference Analysis 🔴

### Motivation
Unusual import combinations (e.g., VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) strongly indicate malicious behavior.

### Implementation Details

#### Cross-Reference Engine
```rust
// src/triage/symbols/xref_analysis.rs

pub struct SymbolXrefs {
    pub import_graph: ImportGraph,
    pub api_combinations: Vec<ApiCombination>,
    pub unusual_patterns: Vec<UnusualPattern>,
}

pub struct ImportGraph {
    // Map of API -> [DLLs that export it]
    pub api_to_dlls: HashMap<String, Vec<String>>,
    // Map of DLL -> [APIs imported from it]
    pub dll_to_apis: HashMap<String, Vec<String>>,
    // Duplicate imports (same API from multiple DLLs)
    pub duplicates: Vec<DuplicateImport>,
}

pub struct ApiCombination {
    pub apis: Vec<String>,
    pub risk_level: RiskLevel,
    pub technique: String,
    pub mitre_id: String,
}

pub struct UnusualPattern {
    pub description: String,
    pub involved_apis: Vec<String>,
    pub reason: UnusualReason,
}

pub enum UnusualReason {
    RareApiCombination,
    MixedSubsystems,      // Mixing kernel/user APIs unusually
    VersionMismatch,      // Old and new API versions together
    UncommonSource,       // API from unusual DLL
}

impl SymbolXrefs {
    pub fn analyze(imports: &[ImportedSymbol]) -> Self {
        let graph = build_import_graph(imports);
        let combinations = detect_api_combinations(imports);
        let unusual = detect_unusual_patterns(&graph, imports);
        
        Self {
            import_graph: graph,
            api_combinations: combinations,
            unusual_patterns: unusual,
        }
    }
}

fn detect_api_combinations(imports: &[ImportedSymbol]) -> Vec<ApiCombination> {
    let mut combinations = Vec::new();
    let api_names: HashSet<String> = imports.iter()
        .map(|i| i.name.to_lowercase())
        .collect();
    
    // Define known malicious combinations
    let patterns = vec![
        // Classic process injection
        (
            vec!["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            RiskLevel::Critical,
            "Process Injection",
            "T1055.001"
        ),
        // SetWindowsHookEx injection
        (
            vec!["SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx"],
            RiskLevel::High,
            "SetWindowsHookEx Injection",
            "T1055.011"
        ),
        // Process hollowing
        (
            vec!["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", 
                 "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
            RiskLevel::Critical,
            "Process Hollowing",
            "T1055.012"
        ),
        // Token manipulation
        (
            vec!["OpenProcessToken", "DuplicateTokenEx", "SetThreadToken", 
                 "ImpersonateLoggedOnUser"],
            RiskLevel::High,
            "Token Impersonation",
            "T1134.001"
        ),
        // UAC bypass preparation
        (
            vec!["GetTokenInformation", "TokenElevationType", "ShellExecute",
                 "CoGetObject", "Elevation:Administrator"],
            RiskLevel::High,
            "UAC Bypass Preparation",
            "T1548.002"
        ),
        // Registry persistence
        (
            vec!["RegOpenKeyEx", "RegSetValueEx", "RegCreateKeyEx",
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            RiskLevel::Medium,
            "Registry Persistence",
            "T1547.001"
        ),
    ];
    
    // Check each pattern
    for (apis, risk, technique, mitre) in patterns {
        let matched = apis.iter()
            .filter(|api| api_names.contains(&api.to_lowercase()))
            .count();
        
        let threshold = (apis.len() as f32 * 0.75) as usize;  // 75% match threshold
        
        if matched >= threshold {
            combinations.push(ApiCombination {
                apis: apis.iter().map(|s| s.to_string()).collect(),
                risk_level: risk,
                technique: technique.to_string(),
                mitre_id: mitre.to_string(),
            });
        }
    }
    
    // Detect custom combinations based on heuristics
    combinations.extend(detect_heuristic_combinations(&api_names));
    
    combinations
}

fn detect_heuristic_combinations(apis: &HashSet<String>) -> Vec<ApiCombination> {
    let mut combinations = Vec::new();
    
    // Memory allocation + process access + thread creation
    let has_mem_alloc = apis.iter().any(|a| a.contains("virtualalloc"));
    let has_proc_access = apis.iter().any(|a| a.contains("openprocess"));
    let has_thread_create = apis.iter().any(|a| a.contains("createthread"));
    
    if has_mem_alloc && has_proc_access && has_thread_create {
        combinations.push(ApiCombination {
            apis: vec!["VirtualAlloc*", "OpenProcess", "*CreateThread"],
            risk_level: RiskLevel::High,
            technique: "Generic Injection Pattern",
            mitre_id: "T1055",
        });
    }
    
    // Network + file + crypto (potential ransomware)
    let has_network = apis.iter().any(|a| 
        a.contains("winhttp") || a.contains("wininet") || a.contains("ws2_"));
    let has_file = apis.iter().any(|a| 
        a.contains("createfile") || a.contains("writefile"));
    let has_crypto = apis.iter().any(|a| 
        a.contains("crypt") && !a.contains("decrypt"));
    
    if has_network && has_file && has_crypto {
        combinations.push(ApiCombination {
            apis: vec!["Network APIs", "File APIs", "Crypto APIs"],
            risk_level: RiskLevel::High,
            technique: "Potential Ransomware Pattern",
            mitre_id: "T1486",
        });
    }
    
    combinations
}
```

### Testing Strategy
- Test with known malware families and their characteristic API patterns
- Validate against benign software to reduce false positives
- Cross-reference with MITRE ATT&CK techniques

---

## 10. Version Information Extraction 🟢

### Motivation
Version information helps identify vulnerable libraries, compiler bugs, compatibility issues, and aids in vulnerability management.

### Implementation Details

#### Version Extractor
```rust
// src/triage/symbols/version_info.rs

pub struct LibraryVersions {
    pub minimum_os_version: Option<OsVersion>,
    pub linked_libraries: Vec<LinkedLibrary>,
    pub runtime_versions: Vec<RuntimeVersion>,
    pub compiler_info: Option<CompilerInfo>,
    pub vulnerability_assessment: Vec<VulnerabilityInfo>,
}

pub struct LinkedLibrary {
    pub name: String,
    pub version: Option<Version>,
    pub build_id: Option<String>,  // ELF build ID
    pub timestamp: Option<u32>,    // PE timestamp
}

pub struct RuntimeVersion {
    pub runtime_type: RuntimeType,
    pub version: String,
    pub features: Vec<String>,
}

pub enum RuntimeType {
    DotNet,
    JavaVM,
    Python,
    NodeJS,
    GoRuntime,
    RustStd,
}

pub struct VulnerabilityInfo {
    pub library: String,
    pub version: String,
    pub cve_ids: Vec<String>,
    pub severity: VulnSeverity,
}

impl LibraryVersions {
    pub fn extract_from_pe(data: &[u8]) -> Result<Self, Error> {
        let mut versions = Self::default();
        
        // Extract from PE optional header
        let pe = parse_pe_headers(data)?;
        versions.minimum_os_version = Some(OsVersion {
            major: pe.major_os_version,
            minor: pe.minor_os_version,
            build: pe.major_subsystem_version,
        });
        
        // Extract from version resource
        if let Some(rsrc) = find_resource_section(data) {
            versions.extract_version_resource(&rsrc)?;
        }
        
        // Extract from import descriptors
        for import in parse_imports(data)? {
            versions.linked_libraries.push(LinkedLibrary {
                name: import.dll_name,
                version: extract_dll_version(&import),
                build_id: None,
                timestamp: import.timestamp,
            });
        }
        
        // Detect runtime versions
        versions.runtime_versions = detect_runtime_versions(data)?;
        
        // Check for vulnerabilities
        versions.vulnerability_assessment = check_known_vulnerabilities(&versions.linked_libraries)?;
        
        Ok(versions)
    }
    
    pub fn extract_from_elf(data: &[u8]) -> Result<Self, Error> {
        let mut versions = Self::default();
        
        // Extract from .note.gnu.build-id
        if let Some(build_id) = extract_build_id(data)? {
            // Can be used to look up exact binary version
        }
        
        // Extract from .gnu.version_r (version requirements)
        if let Some(verneed) = find_section(data, ".gnu.version_r")? {
            versions.parse_version_requirements(&verneed)?;
        }
        
        // Extract from .comment section (compiler info)
        if let Some(comment) = find_section(data, ".comment")? {
            versions.compiler_info = parse_compiler_comment(&comment);
        }
        
        // Extract from DT_NEEDED and DT_SONAME
        for needed in parse_needed_libraries(data)? {
            // Parse version from SONAME (e.g., libssl.so.1.1)
            let (name, version) = parse_soname(&needed);
            versions.linked_libraries.push(LinkedLibrary {
                name,
                version,
                build_id: None,
                timestamp: None,
            });
        }
        
        Ok(versions)
    }
}

fn check_known_vulnerabilities(libs: &[LinkedLibrary]) -> Result<Vec<VulnerabilityInfo>, Error> {
    let mut vulns = Vec::new();
    
    // Check against known vulnerable versions
    for lib in libs {
        let lib_lower = lib.name.to_lowercase();
        
        // OpenSSL vulnerabilities
        if lib_lower.contains("libssl") || lib_lower.contains("ssleay") {
            if let Some(version) = &lib.version {
                if version.starts_with("1.0.1") && version < "1.0.1g" {
                    vulns.push(VulnerabilityInfo {
                        library: lib.name.clone(),
                        version: version.clone(),
                        cve_ids: vec!["CVE-2014-0160".to_string()],  // Heartbleed
                        severity: VulnSeverity::Critical,
                    });
                }
            }
        }
        
        // Log4j vulnerabilities
        if lib_lower.contains("log4j") {
            if let Some(version) = &lib.version {
                if version.starts_with("2.") && version < "2.17.0" {
                    vulns.push(VulnerabilityInfo {
                        library: lib.name.clone(),
                        version: version.clone(),
                        cve_ids: vec!["CVE-2021-44228".to_string()],  // Log4Shell
                        severity: VulnSeverity::Critical,
                    });
                }
            }
        }
        
        // Add more vulnerability checks...
    }
    
    Ok(vulns)
}
```

### Testing Strategy
- Test with binaries linking known vulnerable library versions
- Verify runtime detection (.NET, Java, Python interpreters)
- Compare with `ldd` and `otool -L` output

---

## 11. TLS Callback Analysis 🔴

### Motivation
TLS callbacks execute before main() and are abused by malware for anti-debugging, early injection, and evasion.

### Implementation Details

#### TLS Analysis
```rust
// src/triage/symbols/tls_analysis.rs

pub struct TlsAnalysis {
    pub callbacks: Vec<TlsCallback>,
    pub tls_data: TlsDataInfo,
    pub suspicious_indicators: Vec<TlsSuspicion>,
}

pub struct TlsCallback {
    pub rva: u64,
    pub file_offset: u64,
    pub disassembly: Option<Vec<Instruction>>,  // First few instructions
    pub suspicious_apis: Vec<String>,
}

pub struct TlsDataInfo {
    pub start_rva: u64,
    pub end_rva: u64,
    pub index_rva: u64,
    pub callbacks_rva: u64,
    pub zero_fill_size: u32,
    pub characteristics: u32,
    pub actual_data_size: u32,
}

pub enum TlsSuspicion {
    NoActualTlsData,           // Callbacks without TLS data
    AntiDebugInCallback,       // IsDebuggerPresent in TLS
    ProcessManipulation,       // Process/thread APIs in TLS
    MultipleCallbacks(u32),    // Unusual number of callbacks
    ObfuscatedCallback,        // Heavily obfuscated code
}

impl TlsAnalysis {
    pub fn analyze_pe_tls(data: &[u8], tls_dir: &DataDirectory) -> Result<Self, Error> {
        let tls_data = parse_tls_directory(data, tls_dir)?;
        let callbacks = extract_tls_callbacks(data, &tls_data)?;
        let suspicious = analyze_tls_suspicion(&callbacks, &tls_data);
        
        Ok(Self {
            callbacks,
            tls_data,
            suspicious_indicators: suspicious,
        })
    }
}

fn extract_tls_callbacks(data: &[u8], tls: &TlsDataInfo) -> Result<Vec<TlsCallback>, Error> {
    let mut callbacks = Vec::new();
    let callbacks_offset = rva_to_offset(tls.callbacks_rva)?;
    
    // Read callback array (null-terminated)
    let mut offset = callbacks_offset;
    loop {
        let callback_va = if is_pe64 {
            read_u64(data, offset)?
        } else {
            read_u32(data, offset)? as u64
        };
        
        if callback_va == 0 {
            break;  // Null terminator
        }
        
        // Convert VA to RVA
        let callback_rva = va_to_rva(callback_va, image_base)?;
        let file_offset = rva_to_offset(callback_rva)?;
        
        // Disassemble first few instructions
        let disasm = disassemble_bytes(&data[file_offset..file_offset + 64])?;
        
        // Look for suspicious API calls
        let suspicious = detect_suspicious_calls(&disasm);
        
        callbacks.push(TlsCallback {
            rva: callback_rva,
            file_offset,
            disassembly: Some(disasm),
            suspicious_apis: suspicious,
        });
        
        offset += if is_pe64 { 8 } else { 4 };
    }
    
    Ok(callbacks)
}

fn analyze_tls_suspicion(callbacks: &[TlsCallback], tls: &TlsDataInfo) -> Vec<TlsSuspicion> {
    let mut suspicions = Vec::new();
    
    // Check for TLS callbacks without actual TLS data
    if tls.actual_data_size == 0 && !callbacks.is_empty() {
        suspicions.push(TlsSuspicion::NoActualTlsData);
    }
    
    // Multiple callbacks is unusual
    if callbacks.len() > 2 {
        suspicions.push(TlsSuspicion::MultipleCallbacks(callbacks.len() as u32));
    }
    
    // Check for anti-debug APIs
    for callback in callbacks {
        if callback.suspicious_apis.iter().any(|api| 
            api.contains("IsDebuggerPresent") || 
            api.contains("CheckRemoteDebuggerPresent") ||
            api.contains("NtQueryInformationProcess")
        ) {
            suspicions.push(TlsSuspicion::AntiDebugInCallback);
        }
        
        // Check for process manipulation
        if callback.suspicious_apis.iter().any(|api|
            api.contains("OpenProcess") ||
            api.contains("WriteProcessMemory") ||
            api.contains("CreateRemoteThread")
        ) {
            suspicions.push(TlsSuspicion::ProcessManipulation);
        }
    }
    
    suspicions
}

fn detect_suspicious_calls(instructions: &[Instruction]) -> Vec<String> {
    let mut apis = Vec::new();
    
    for insn in instructions {
        // Look for CALL instructions
        if insn.mnemonic == "call" {
            // Try to resolve target
            if let Some(target) = resolve_call_target(insn) {
                if let Some(api_name) = resolve_import_by_address(target) {
                    apis.push(api_name);
                }
            }
        }
        
        // Look for indirect calls through IAT
        if insn.mnemonic == "call" && insn.operand.contains("dword ptr") {
            if let Some(api_name) = resolve_iat_call(insn) {
                apis.push(api_name);
            }
        }
    }
    
    apis
}
```

### Testing Strategy
- Test with known packers using TLS (UPX, Themida)
- Verify anti-debug detection in TLS callbacks
- Test with legitimate software using TLS (e.g., C++ static initializers)

---

## 12. Import Hashing (ImpHash) 🟡

### Motivation
ImpHash is a hash of a PE file's import table that can be used to pivot and find related malware samples. It is a powerful tool for malware family attribution.

### Implementation Details

#### ImpHash Calculation
```rust
// src/triage/symbols/imphash.rs
use md5;

pub fn calculate_imphash(imports: &[ImportedSymbol]) -> String {
    let mut imphash_string = String::new();
    
    for import in imports {
        let dll_name = import.library.to_lowercase();
        let func_name = import.symbol.name.to_lowercase();
        imphash_string.push_str(&format!(