# ELF Parser Migration Guide

This guide provides step-by-step instructions for migrating existing ELF parsing code to the new consolidated parser.

## Quick Start

```rust
// Old (using object crate)
use object::read::Object;
let obj = object::read::File::parse(data)?;

// New (using our ELF parser)
use crate::formats::elf::ElfParser;
let elf = ElfParser::parse(data)?;
```

## Module-by-Module Migration

### 1. Migrating src/symbols/elf.rs

#### Symbol Extraction

**Before:**
```rust
pub fn summarize_elf(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    // Manual parsing with helper functions
    let class = data[4];
    let is_le = match data[5] {
        1 => true,
        2 => false,
        _ => true,
    };
    // ... manual section parsing
    for i in 0..(e_shnum as usize) {
        let off = shoff + i * shentsize;
        // ... manual field extraction
    }
}
```

**After:**
```rust
pub fn summarize_elf(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    let elf = ElfParser::parse(data)?;
    
    // Direct access to parsed structures
    let sections = elf.sections()?;
    let symbols = elf.symbols()?;
    let dynamic = elf.dynamic()?;
    
    // Security features are now built-in
    let security = elf.security_features();
    
    SymbolSummary {
        imports_count: symbols.imports().count() as u32,
        exports_count: symbols.exports().count() as u32,
        libs_count: dynamic.needed_libraries().len() as u32,
        stripped: !elf.has_debug_info(),
        nx: Some(security.nx),
        aslr: Some(security.pie),
        relro: Some(security.relro != RelroLevel::None),
        pie: Some(security.pie),
        // ...
    }
}
```

#### Library Dependencies

**Before:**
```rust
// Manual DT_NEEDED parsing
for s in &shdrs {
    if s.sh_type != 6 { continue; } // SHT_DYNAMIC
    // ... manual dynamic entry parsing
    if d_tag == 1 { // DT_NEEDED
        let so = str_base.saturating_add(d_val as usize);
        // ... manual string extraction
    }
}
```

**After:**
```rust
let dynamic = elf.dynamic()?;
let libs: Vec<&str> = dynamic.needed_libraries();
let rpaths = dynamic.rpath();
let runpaths = dynamic.runpath();
```

#### Import/Export Symbols

**Before:**
```rust
// Manual symbol table parsing
for s in &shdrs {
    if s.sh_type != 11 { continue; } // SHT_DYNSYM
    // ... manual symbol parsing
    let is_undef = if class == 2 {
        let shndx = read_u16(data, off + 6, is_le).unwrap_or(0);
        shndx == 0
    } else {
        let shndx = read_u16(data, off + 14, is_le).unwrap_or(0);
        shndx == 0
    };
}
```

**After:**
```rust
let symbols = elf.symbols()?;

let imports: Vec<&str> = symbols.imports()
    .map(|sym| sym.name())
    .collect();

let exports: Vec<&str> = symbols.exports()
    .map(|sym| sym.name())
    .collect();

// With demangling
let demangled: Vec<String> = symbols.exports()
    .filter_map(|sym| sym.demangled_name())
    .collect();
```

### 2. Migrating src/analysis/elf_got.rs

#### GOT Mapping

**Before:**
```rust
pub fn elf_got_map(data: &[u8]) -> Vec<(u64, String)> {
    let Ok(obj) = object::read::File::parse(data) else {
        return out;
    };
    // Manual section iteration
    for sec in obj.sections() {
        if let Ok(name) = sec.name() {
            match name {
                ".dynsym" => { /* ... */ }
                ".dynstr" => { /* ... */ }
                _ => {}
            }
        }
    }
    // Manual relocation parsing
    for chunk in bytes.chunks_exact(24) {
        let r_offset = if is_le {
            u64::from_le_bytes(chunk[0..8].try_into().unwrap())
        } else {
            u64::from_be_bytes(chunk[0..8].try_into().unwrap())
        };
        // ...
    }
}
```

**After:**
```rust
pub fn elf_got_map(data: &[u8]) -> Vec<(u64, String)> {
    let elf = ElfParser::parse(data)?;
    let relocations = elf.relocations()?;
    
    // GOT map is built automatically
    relocations.got_entries()
        .map(|(addr, name)| (addr, name.to_string()))
        .collect()
}
```

### 3. Migrating src/analysis/elf_plt.rs

#### PLT Mapping

**Before:**
```rust
pub fn elf_plt_map(data: &[u8]) -> Vec<(u64, String)> {
    let Ok(obj) = object::read::File::parse(data) else {
        return out;
    };
    // Locate .plt section manually
    for sec in obj.sections() {
        if let Ok(name) = sec.name() {
            if name == ".plt" {
                let addr = sec.address();
                let size = sec.size();
                // ...
            }
        }
    }
    // Manual .rela.plt parsing
    // ...
}
```

**After:**
```rust
pub fn elf_plt_map(data: &[u8]) -> Vec<(u64, String)> {
    let elf = ElfParser::parse(data)?;
    let relocations = elf.relocations()?;
    
    // PLT map is built automatically
    relocations.plt_entries()
        .map(|(addr, name)| (addr, format!("{}@plt", name)))
        .collect()
}
```

### 4. Migrating src/triage/headers.rs

#### Header Validation

**Before:**
```rust
pub fn validate(data: &[u8]) -> HeaderResult {
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        let class = data.get(4).copied().unwrap_or(1);
        let bits = if class == 2 { 64 } else { 32 };
        // Manual validation checks
        let ehsize = read_u16(ehsize_off);
        if ehsize as u32 != exp_eh {
            errors.push(TriageError::new(
                TriageErrorKind::IncoherentFields,
                Some("ELF header sizes unexpected".into()),
            ));
        }
    }
}
```

**After:**
```rust
pub fn validate(data: &[u8]) -> HeaderResult {
    match ElfParser::parse(data) {
        Ok(elf) => {
            // Parser handles all validation internally
            let header = elf.header();
            let verdict = TriageVerdict {
                format: Format::ELF,
                arch: header.architecture(),
                bits: header.bits(),
                endianness: header.endianness(),
                confidence: 1.0,
            };
            HeaderResult {
                candidates: vec![verdict],
                errors: vec![],
            }
        }
        Err(e) => {
            // Detailed error information
            let error = match e {
                ElfError::InvalidMagic => TriageError::new(
                    TriageErrorKind::BadMagic,
                    Some("Not an ELF file".into())
                ),
                ElfError::Truncated { offset, needed } => TriageError::new(
                    TriageErrorKind::Truncated,
                    Some(format!("Truncated at {:#x}, needed {} bytes", offset, needed))
                ),
                // ...
            };
            HeaderResult {
                candidates: vec![],
                errors: vec![error],
            }
        }
    }
}
```

### 5. Migrating src/triage/parsers.rs

#### Multi-Parser Validation

**Before:**
```rust
pub fn parse(data: &[u8]) -> Vec<ParserResult> {
    let obj_res = match object::File::parse(data) {
        Ok(_f) => ParserResult::new(ParserKind::Object, true, None),
        Err(e) => ParserResult::new(
            ParserKind::Object,
            false,
            Some(TriageError::new(
                TriageErrorKind::ParserMismatch,
                Some(format!("{}", e)),
            )),
        ),
    };
}
```

**After:**
```rust
pub fn parse(data: &[u8]) -> Vec<ParserResult> {
    // Use our parser instead of object
    let elf_res = match ElfParser::parse(data) {
        Ok(_) => ParserResult::new(ParserKind::Native, true, None),
        Err(e) => ParserResult::new(
            ParserKind::Native,
            false,
            Some(TriageError::from(e)),
        ),
    };
    vec![elf_res]
}
```

### 6. Migrating src/symbols/analysis/env.rs

#### Environment Analysis

**Before:**
```rust
fn analyze_elf_env(data: &[u8]) -> Option<BinaryEnv> {
    let obj = object::read::File::parse(data).ok()?;
    
    // Extract libraries from imports
    let mut libs = Vec::new();
    if let Ok(imps) = obj.imports() {
        for imp in imps {
            let lib = String::from_utf8_lossy(imp.library()).to_string();
            if !lib.is_empty() {
                libs.push(lib);
            }
        }
    }
    
    // Use old summarizer for paths
    let caps = crate::symbols::types::BudgetCaps::default();
    let sum = crate::symbols::elf::summarize_elf(data, &caps);
}
```

**After:**
```rust
fn analyze_elf_env(data: &[u8]) -> Option<BinaryEnv> {
    let elf = ElfParser::parse(data).ok()?;
    let dynamic = elf.dynamic().ok()?;
    let security = elf.security_features();
    
    Some(BinaryEnv {
        libs: dynamic.needed_libraries()
            .map(|s| s.to_string())
            .collect(),
        rpaths: dynamic.rpath().map(|s| vec![s.to_string()]),
        runpaths: dynamic.runpath().map(|s| vec![s.to_string()]),
        pdb_path: None, // ELF doesn't have PDB
        tls_callbacks: None, // ELF TLS is different
        entry_section: elf.entry_section().map(|s| s.name().to_string()),
        relocations_present: Some(elf.has_relocations()),
        minos: None, // Not applicable to ELF
        code_signature: None, // Not applicable to ELF
    })
}
```

## Common Patterns

### Lazy Loading

```rust
// Parser only loads what you access
let elf = ElfParser::parse(data)?;

// Nothing is parsed yet except the header

let sections = elf.sections()?;  // Sections parsed on first access
let symbols = elf.symbols()?;    // Symbols parsed on first access

// Subsequent calls return cached results (no re-parsing)
let sections2 = elf.sections()?; // Returns same reference
```

### Error Handling

```rust
// Old: Generic errors or panics
let obj = object::read::File::parse(data)
    .map_err(|e| format!("Parse failed: {}", e))?;

// New: Specific, actionable errors
let elf = ElfParser::parse(data).map_err(|e| match e {
    ElfError::InvalidMagic => "Not an ELF file",
    ElfError::UnsupportedClass(c) => "Unsupported ELF class",
    ElfError::Truncated { .. } => "File is truncated",
    _ => "Parse error",
})?;
```

### Performance Optimization

```rust
// Old: Multiple passes over data
let obj1 = object::read::File::parse(data)?; // Parse 1
let obj2 = object::read::File::parse(data)?; // Parse 2 for different info

// New: Single parse, multiple views
let elf = ElfParser::parse(data)?; // Parse once
let sections = elf.sections()?;    // View 1
let symbols = elf.symbols()?;      // View 2
let dynamic = elf.dynamic()?;      // View 3
```

### Memory Safety

```rust
// Old: Potential panics on malformed input
let section = obj.section_by_name(".text").unwrap(); // Panic if missing

// New: Safe error handling
let section = elf.sections()?.by_name(".text"); // Returns Option
if let Some(section) = section {
    // Handle section
}
```

## Feature Comparison

| Feature | Object Crate | New ELF Parser |
|---------|-------------|----------------|
| Zero-copy parsing | ✓ | ✓ |
| Lazy loading | ✗ | ✓ |
| GOT/PLT mapping | Manual | Built-in |
| Security analysis | Manual | Built-in |
| Symbol demangling | External | Built-in |
| RPATH/RUNPATH | Manual | Built-in |
| Architecture support | Limited | Comprehensive |
| Error detail | Generic | Specific |
| Performance | Good | Better |
| Memory usage | Higher | Lower |

## Migration Checklist

- [ ] Update imports: Remove `object` crate, add `formats::elf`
- [ ] Replace `object::read::File` with `ElfParser`
- [ ] Update error handling to use `ElfError`
- [ ] Remove manual parsing code
- [ ] Update section access patterns
- [ ] Update symbol access patterns
- [ ] Remove redundant security checks
- [ ] Test with malformed inputs
- [ ] Benchmark performance improvements
- [ ] Update documentation

## Deprecation Timeline

1. **Phase 1** (Weeks 1-4): New parser available alongside old code
2. **Phase 2** (Weeks 5-6): Old code marked as deprecated
3. **Phase 3** (Weeks 7-8): Old code removed

## Getting Help

If you encounter issues during migration:

1. Check the [Technical Design](elf-technical-design.md) document
2. Review the API documentation: `cargo doc --open`
3. Look at the test suite for examples
4. File an issue with specific error details

## Performance Tips

1. **Parse once, access many times** - The parser caches results
2. **Use specific accessors** - Don't load sections if you only need symbols
3. **Handle errors early** - Check parse result before accessing fields
4. **Use iterators** - They're more efficient than collecting into vectors

## Code Examples

### Complete Symbol Extraction Example

```rust
use crate::formats::elf::{ElfParser, SecurityFeatures};

pub fn analyze_elf_binary(data: &[u8]) -> Result<BinaryAnalysis> {
    let elf = ElfParser::parse(data)?;
    
    // Basic info
    let header = elf.header();
    let arch = header.architecture();
    let bits = header.bits();
    
    // Sections
    let sections = elf.sections()?;
    let text = sections.by_name(".text");
    let data_section = sections.by_name(".data");
    
    // Symbols
    let symbols = elf.symbols()?;
    let imports: Vec<_> = symbols.imports().collect();
    let exports: Vec<_> = symbols.exports().collect();
    
    // Dynamic info
    let dynamic = elf.dynamic()?;
    let libs = dynamic.needed_libraries();
    let rpath = dynamic.rpath();
    
    // Security
    let security = elf.security_features();
    
    // Relocations
    let relocations = elf.relocations()?;
    let got_map = relocations.got_entries();
    let plt_map = relocations.plt_entries();
    
    Ok(BinaryAnalysis {
        format: "ELF",
        architecture: arch,
        bits,
        entry_point: header.entry_point(),
        sections: sections.count(),
        imports: imports.len(),
        exports: exports.len(),
        libraries: libs.to_vec(),
        security,
        // ...
    })
}
```

### GOT/PLT Resolution Example

```rust
use crate::formats::elf::ElfParser;

pub fn resolve_indirect_calls(data: &[u8]) -> Result<Vec<ResolvedCall>> {
    let elf = ElfParser::parse(data)?;
    let relocations = elf.relocations()?;
    
    let mut calls = Vec::new();
    
    // Resolve GOT calls
    for (addr, name) in relocations.got_entries() {
        calls.push(ResolvedCall {
            address: addr,
            target: name.to_string(),
            call_type: CallType::Got,
        });
    }
    
    // Resolve PLT calls
    for (addr, name) in relocations.plt_entries() {
        calls.push(ResolvedCall {
            address: addr,
            target: format!("{}@plt", name),
            call_type: CallType::Plt,
        });
    }
    
    Ok(calls)
}
```

## Testing Your Migration

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_elf_parsing_compatibility() {
        let data = include_bytes!("../samples/test.elf");
        
        // Old way
        let old_result = old_parse_function(data);
        
        // New way
        let new_result = new_parse_function(data);
        
        // Results should be equivalent
        assert_eq!(old_result.symbols, new_result.symbols);
        assert_eq!(old_result.libraries, new_result.libraries);
    }
    
    #[test]
    fn test_malformed_input_handling() {
        let bad_data = b"not an elf file";
        
        // Should not panic
        let result = ElfParser::parse(bad_data);
        assert!(result.is_err());
        
        // Should have specific error
        match result {
            Err(ElfError::InvalidMagic) => {},
            _ => panic!("Wrong error type"),
        }
    }
}
```