# M2 - Symbols Implementation Plan (Revised)

## Overview
This document provides a comprehensive implementation plan for the M2 - Symbols milestone, focusing on extracting and analyzing symbols, imports/exports, and metadata from PE, ELF, and Mach-O binaries.

## Goals
- Cross-format symbol summaries with strict caps: imports, exports, libraries.
- Detect debug-info presence, stripped status, TLS presence, and basic flags.
- Identify suspicious imports using normalized API names (low-noise, exact-match).
- Expose summaries via the existing `triage` Python submodule (typed stubs updated).
- Keep analysis fast and bounded; prefer `object` crate with optional fallbacks.

## Architecture

We align with the current repo layout and triage plumbing. In M2 we avoid a heavy full symbol table and focus on a lightweight, budgeted summary that fits the triage pipeline.

### Components

```
src/
├── core/
│   ├── symbol.rs            # ✓ Exists – Symbol types
│   └── triage.rs            # UPDATED – add SymbolSummary; TriagedArtifact.symbols
└── triage/
    ├── symbols/
    │   ├── mod.rs           # Dispatcher + budgets
    │   ├── pe.rs            # PE summary (imports/exports/debug/TLS)
    │   ├── elf.rs           # ELF summary (dynsym/symtab, DT_NEEDED, NX/RELRO/PIE)
    │   └── macho.rs         # Mach-O summary (LC_SYMTAB/DYSYMTAB, dylibs/rpaths, minOS, code-sign bit)
    └── suspicious.rs        # Suspicious API detection (normalized names)
```

Parsers: Use `object` crate as the primary parser for all formats. Gate optional cross-checks (`goblin`, `pelite`) behind the existing `triage-parsers-extra` feature.

## Phase 1: Core Symbol Infrastructure

### 1.1 Symbol Summary Types (lightweight)
Add an additive summary type to `src/core/triage.rs` to mirror `StringsSummary` and ensure Python bindings remain consistent.

```rust
// In core::triage (additive fields)
pub struct SymbolSummary {
    pub imports_count: u32,
    pub exports_count: u32,
    pub libs_count: u32,
    pub stripped: bool,
    pub tls_used: bool,
    pub debug_info_present: bool,
    pub suspicious_imports: Option<Vec<String>>, // normalized API names
    pub entry_section: Option<String>,           // best-effort
}

// TriagedArtifact gains: pub symbols: Option<SymbolSummary>
```

We intentionally defer a full `SymbolTable` (indexing, demangling, address lookups) to a later milestone. If needed, we can add a feature-gated richer table after the summary lands.

### 1.2 Suspicious Import Analysis
Place suspicious import logic in `src/triage/suspicious.rs` and operate on normalized import names. Avoid substring matches to reduce noise; compare against canonical base names ignoring case and decoration (e.g., strip stdcall suffixes, A/W suffixes).

## Phase 2: PE Format Implementation

Use `object::read::pe` as the primary parser. When the `triage-parsers-extra` feature is enabled, we may cross-check with `pelite`.

### 2.1 PE Import/Export Summary
**File:** `src/triage/symbols/pe.rs`

Outline:
- Parse PE header via `object::File`.
- Imports: iterate import descriptors and thunk tables (cap total entries and distinct DLLs).
- Delay-load imports: include with the same caps.
- Exports: count names/ordinals; cap total.
- Debug directory presence: set `debug_info_present`.
- TLS directory presence: set `tls_used`.
- Suspicious imports: normalize base names and exact-match against allowlist.

### 2.2 PE Debug Directory
**File:** `src/formats/pe/debug.rs`

```rust
pub struct PEDebugInfo {
    pub has_debug_directory: bool,
    pub pdb_path: Option<String>,
    pub rsds_guid: Option<String>,
    pub stripped: bool,
}

pub fn extract_debug_info(pe: &PeFile) -> PEDebugInfo {
    // Parse IMAGE_DEBUG_DIRECTORY
    // Extract RSDS/NB10 CodeView info
    // Check for PDB path
}
```

### 2.3 PE TLS Callbacks
**File:** `src/formats/pe/tls.rs`

```rust
pub fn detect_tls_callbacks(pe: &PeFile) -> Option<Vec<u64>> {
    // Parse TLS directory
    // Extract callback addresses
}
```

## Phase 3: ELF Format Implementation

### 3.1 ELF Symbol Summary
**File:** `src/triage/symbols/elf.rs`

```rust
Count-only summary using `goblin::elf::Elf` (behind feature) or `object` where feasible:
- dynsym/symtab counts; set `stripped = symtab.is_empty()`.
- DT_NEEDED libraries (distinct) with caps; rpath/runpath optional.
- Security flags: NX (PT_GNU_STACK), RELRO (PT_GNU_RELRO), PIE (ET_DYN + flags).
```

Handle dynamic section within `elf.rs` to keep surface small.

Analyze NX/RELRO/PIE in `elf.rs` via program headers; avoid DWARF.

## Phase 4: Mach-O Format Implementation

### 4.1 Mach-O Symbol Summary
**File:** `src/triage/symbols/macho.rs`

```rust
Outline:
- Count LC_SYMTAB/DYSYMTAB entries; set stripped if no symtab.
- Imported dylibs (distinct), rpaths, minOS (optional string fields later if needed).
- Code signature presence bit only (validation deferred to M4).
- Handle FAT (universal) by selecting a primary slice within budget.
```

Keep dylib and code-sign presence detection inside `macho.rs` for M2.

## Phase 5: Triage Integration

### 5.1 Symbol Extraction for Triage
**File:** `src/triage/symbols/mod.rs`

```rust
use crate::core::triage::TriagedArtifact;

// Dispatcher used by triage API after sniffing format
pub(crate) fn summarize_symbols(
    data: &[u8],
    format: crate::core::binary::Format,
    caps: &BudgetCaps,
) -> SymbolSummary { /* calls into pe/elf/macho modules */ }

// Symbol-specific caps to avoid churning global budgets in M2
pub struct BudgetCaps {
    pub max_imports: u32,
    pub max_exports: u32,
    pub max_libs: u32,
    pub time_guard_ms: u64,
}
```

### 5.2 Suspicious API Detection
**File:** `src/triage/suspicious.rs`

```rust
const SUSPICIOUS_APIS: &[(&str, SuspiciousReason)] = &[
    // Process manipulation
    ("CreateRemoteThread", SuspiciousReason::ProcessManipulation),
    ("WriteProcessMemory", SuspiciousReason::ProcessManipulation),
    ("ReadProcessMemory", SuspiciousReason::ProcessManipulation),
    ("OpenProcess", SuspiciousReason::ProcessManipulation),
    ("NtWriteVirtualMemory", SuspiciousReason::ProcessManipulation),
    
    // Memory allocation
    ("VirtualAllocEx", SuspiciousReason::MemoryAllocation),
    ("NtAllocateVirtualMemory", SuspiciousReason::MemoryAllocation),
    ("NtMapViewOfSection", SuspiciousReason::MemoryAllocation),
    
    // Anti-debugging
    ("IsDebuggerPresent", SuspiciousReason::AntiDebugging),
    ("CheckRemoteDebuggerPresent", SuspiciousReason::AntiDebugging),
    ("NtQueryInformationProcess", SuspiciousReason::AntiDebugging),
    ("OutputDebugString", SuspiciousReason::AntiDebugging),
    
    // Privilege escalation
    ("AdjustTokenPrivileges", SuspiciousReason::PrivilegeEscalation),
    ("LookupPrivilegeValue", SuspiciousReason::PrivilegeEscalation),
    
    // Network
    ("WinHttpOpen", SuspiciousReason::NetworkActivity),
    ("InternetOpenA", SuspiciousReason::NetworkActivity),
    ("WSAStartup", SuspiciousReason::NetworkActivity),
    ("connect", SuspiciousReason::NetworkActivity),
    ("send", SuspiciousReason::NetworkActivity),
    ("recv", SuspiciousReason::NetworkActivity),
    
    // Persistence
    ("SetWindowsHookEx", SuspiciousReason::Persistence),
    ("RegSetValueEx", SuspiciousReason::Persistence),
    ("CreateService", SuspiciousReason::Persistence),
    
    // Evasion
    ("NtSetInformationThread", SuspiciousReason::Evasion),
    ("ZwSetInformationThread", SuspiciousReason::Evasion),
    
    // Linux/Unix suspicious
    ("ptrace", SuspiciousReason::AntiDebugging),
    ("dlopen", SuspiciousReason::ProcessManipulation),
    ("mprotect", SuspiciousReason::MemoryAllocation),
    ("fork", SuspiciousReason::ProcessManipulation),
    ("execve", SuspiciousReason::ProcessManipulation),
];

pub fn detect_suspicious_imports(imports: &[ImportedSymbol]) -> Vec<SuspiciousImport> {
    let mut suspicious = Vec::new();
    
    for import in imports {
        for (api, reason) in SUSPICIOUS_APIS {
            // Compare normalized base names exactly (case-insensitive),
            // avoid substring matches to reduce noise.
            if import_base_eq(&import.symbol.name, api) {
                suspicious.push(SuspiciousImport {
                    name: import.symbol.name.clone(),
                    reason: *reason,
                    severity: classify_severity(*reason),
                });
            }
        }
    }
    
    suspicious
}
```

## Phase 6: Python Bindings

Expose `SymbolSummary` in the existing `triage` submodule and add it to `TriagedArtifact`.

### 6.1 Update lib.rs (triage submodule)
Add: `triage.add_class::<crate::core::triage::SymbolSummary>()?;` and ensure `TriagedArtifact` includes an optional `symbols` field.

### 6.2 Python Stubs
Update: `python/glaurung/triage.pyi`

```python
from typing import List, Optional, Dict
from glaurung import Address, Format

class SymbolKind:
    Function: SymbolKind
    Object: SymbolKind
    Section: SymbolKind
    Import: SymbolKind
    Export: SymbolKind
    Thunk: SymbolKind
    Debug: SymbolKind
    Synthetic: SymbolKind
    Other: SymbolKind

class SymbolBinding:
    Local: SymbolBinding
    Global: SymbolBinding
    Weak: SymbolBinding

class SymbolVisibility:
    Public: SymbolVisibility
    Private: SymbolVisibility
    Protected: SymbolVisibility
    Hidden: SymbolVisibility

class SymbolSource:
    DebugInfo: SymbolSource
    ImportTable: SymbolSource
    ExportTable: SymbolSource
    Heuristic: SymbolSource
    Pdb: SymbolSource
    Dwarf: SymbolSource
    Ai: SymbolSource

class Symbol:
    id: str
    name: str
    demangled: Optional[str]
    kind: SymbolKind
    address: Optional[Address]
    size: Optional[int]
    binding: Optional[SymbolBinding]
    module: Optional[str]
    visibility: Optional[SymbolVisibility]
    source: SymbolSource
    
    def display_name(self) -> str: ...
    def is_function(self) -> bool: ...
    def is_import(self) -> bool: ...
    def is_export(self) -> bool: ...

class ImportedSymbol:
    symbol: Symbol
    library: str
    ordinal: Optional[int]
    delayed: bool

class ExportedSymbol:
    symbol: Symbol
    ordinal: Optional[int]
    forwarded_to: Optional[str]

class SymbolSummary:
    imports_count: int
    exports_count: int
    libs_count: int
    stripped: bool
    tls_used: bool
    debug_info_present: bool
    suspicious_imports: Optional[List[str]]
    entry_section: Optional[str]

class TriagedArtifact:
    symbols: Optional[SymbolSummary]
```

## Phase 7: Testing

### 7.1 Unit Tests (Rust)
- Unit tests per module: `triage/symbols/{pe,elf,macho}.rs` for counts and flags
- Tests for suspicious import normalization and matching (no substrings)
- Integration tests in `tests/` using `samples/` binaries (skip if missing)

### 7.2 Python Tests
- `python/tests/` add tests asserting `symbols` in `TriagedArtifact` JSON and stubs
- CLI tests: pretty output includes concise symbols line (counts + suspicious count)

### 7.3 Fuzzing
- Fuzz import/export iterators with count caps; assert no panics

## Phase 8: Integration with Triage

Update `TriagedArtifact` with an optional `symbols` field and plumb the dispatcher from `triage/api.rs` based on sniffed format and caps.

Add config knobs for caps if useful; default to conservative values.

## Phase 9: Performance & Budgets

Budgets and guardrails:
- Enforce symbol-specific caps: `max_imports`, `max_exports`, `max_libs`, and a `time_guard_ms` check inside hot loops.
- Respect global IO budgets already present in triage (bounded reads); avoid mmapping entire files.
- On cap/time breaches, stop early and return partial counts (no panics).

Defer demangling and caching to a later milestone to keep M2 minimal.

## Phase 10: Documentation

### 10.1 API Documentation
- Document all public types and functions
- Provide examples for common use cases
- Document performance characteristics

### 10.2 User Guide
**File:** `docs/symbols/USER_GUIDE.md`
- How to read symbol summaries in pretty and JSON outputs
- Suspicious import matching rules and normalization
- Performance/budget tuning flags and examples

## Implementation Timeline

### Week 1: Core Infrastructure
- [ ] Add SymbolSummary to `core::triage`; Python bindings and stubs
- [ ] Add `triage/symbols/` module with dispatcher and caps
- [ ] Add suspicious imports detection with normalized matches

### Week 2: PE Format
- [ ] PE import/export counts (incl. delay-load); libs_count
- [ ] Debug directory and TLS presence flags; stripped heuristic
- [ ] Suspicious imports detection (Windows APIs)
- [ ] PE-specific tests (samples/binaries)

### Week 3: ELF Format
- [ ] ELF dynsym/symtab counts; stripped detection
- [ ] DT_NEEDED, rpath/runpath; NX/RELRO/PIE flags
- [ ] ELF-specific tests (samples/binaries)

### Week 4: Mach-O Format
- [ ] Mach-O symtab/dysymtab counts; stripped detection
- [ ] Imported dylibs, rpaths, minOS; code-sign presence bit
- [ ] Mach-O-specific tests (samples/binaries)

### Week 5: Integration & Optimization
- [ ] Triage integration: thread caps from CLI/config into symbols
- [ ] Pretty output: concise symbols line; JSON fields added
- [ ] Budget enforcement checks + Criterion microbench (smoke)
- [ ] Fuzzing (bounds/limits) on import parsers

### Week 6: Python Bindings & Documentation
- [ ] Finalize Python stubs and pretty output
- [ ] Python tests for CLI/JSON fields
- [ ] Documentation and examples

## Success Metrics

1. **Correctness**
   - Rust + Python tests added for each format pass
   - Fuzz tests (bounded) for import parsers; no panics
   - Validated against known samples in `samples/`

2. **Performance**
   - Summary extraction < 100ms typical; bounded by caps
   - No unbounded memory growth; respects IO budgets
   - Graceful handling of malformed/truncated inputs

3. **Coverage**
   - PE: imports/exports/lib counts; debug/TLS presence
   - ELF: dynsym/symtab counts; DT_NEEDED; NX/RELRO/PIE
   - Mach-O: symtab/dysymtab counts; dylibs; code-sign presence

4. **Usability**
   - Fields exposed in JSON and pretty CLI
   - Typed Python stubs; stable names
   - Examples in docs with CLI flags

## Risk Mitigation

1. **Malformed Input Handling**
   - Map parser failures to structured `TriageErrorKind`
   - Validate offsets and counts; cap iterations
   - Enforce strict budgets; stop early on cap/time hits

2. **Performance Issues**
   - Prefer `object` crate fast paths; avoid mmapping entire files
   - Periodic time checks in hot loops; reduce allocations
   - Defer demangling/caching to future milestone

3. **Compatibility**
   - Test with multiple parser libraries
   - Handle format variations gracefully
   - Provide fallback implementations

## Dependencies

### Required Crates (no new mandatory deps for M2)
```toml
[dependencies]
object = "0.36"          # Primary parser (already present)
goblin = "0.8"          # Secondary parser
pelite = "0.10"         # PE-specific parser

# (Optional later) Caching/demangling
# lru = "0.12"
# cpp_demangle = "0.4"
# rustc-demangle = "0.1"

[dev-dependencies]
criterion = "0.5"       # Benchmarking
proptest = "1.5"       # Property testing
```

## Notes

### Sample Binaries Available
From examination of `samples/binaries/`:
- PE files: Windows executables (various optimizations)
- ELF files: Linux binaries (multiple architectures)
- Cross-compiled binaries
- Debug vs. release builds
- Various languages (C, C++, Rust, Go, etc.)

### Existing Code to Leverage
- `src/core/symbol.rs` - Already has Symbol types defined
- `src/triage/parsers.rs` - Has object/goblin parser integration
- `reference/symbolic/` - Reference implementation for ideas

### Integration Points
1. Triage pipeline - Add symbols to TriagedArtifact
2. Python API - Expose through PyO3 bindings
3. CLI - Add flags for symbol extraction options
4. Performance monitoring - Track extraction times

This implementation plan provides a complete roadmap for implementing comprehensive symbol support across all major binary formats, with proper testing, documentation, and Python bindings.
