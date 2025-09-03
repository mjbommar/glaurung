//! # Symbols Module
//!
//! Top-level module for symbol extraction and analysis across all binary formats.
//! This module provides unified interfaces for extracting, analyzing, and working
//! with symbols from PE, ELF, and Mach-O binaries.

use crate::core::binary::Format;

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

pub mod analysis;
pub mod elf;
pub mod macho;
pub mod pe;
pub mod types;

// Re-export core types
pub use types::{BudgetCaps, SymbolBinding, SymbolInfo, SymbolSummary, SymbolType};

/// Main entry point for symbol extraction with format detection
pub fn extract_symbols(data: &[u8], format: Format, caps: &BudgetCaps) -> Option<SymbolSummary> {
    match format {
        Format::PE => Some(pe::summarize_pe(data, caps)),
        Format::ELF => Some(elf::summarize_elf(data, caps)),
        Format::MachO => Some(macho::summarize_macho(data, caps)),
        _ => None,
    }
}

/// Summarize symbols from binary data with automatic format detection
pub fn summarize_symbols(data: &[u8], format: Format, caps: &BudgetCaps) -> SymbolSummary {
    extract_symbols(data, format, caps).unwrap_or_default()
}

/// Python binding for listing symbols from a file
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "list_symbols")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
pub fn list_symbols_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<(
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
)> {
    use crate::triage::io;
    use object::read::{Object, ObjectSymbol}; // Import the trait!

    let mut all_syms: Vec<String> = Vec::new();
    let mut dyn_syms: Vec<String> = Vec::new();
    let mut imports: Vec<String> = Vec::new();
    let mut exports: Vec<String> = Vec::new();
    let mut libs: Vec<String> = Vec::new();

    // Read file with bounded buffer
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("{:?}", e)))?;

    // Try to parse with the object crate for generic symbol extraction
    if let Ok(obj) = object::read::File::parse(&data[..]) {
        // Collect all symbols
        for sym in obj.symbols() {
            if let Ok(name) = sym.name() {
                let name = name.to_string();
                if !name.is_empty() {
                    all_syms.push(name);
                }
            }
        }

        // Collect dynamic symbols
        for sym in obj.dynamic_symbols() {
            if let Ok(name) = sym.name() {
                let name = name.to_string();
                if !name.is_empty() {
                    dyn_syms.push(name);
                }
            }
        }

        // Imports (cross-format via object trait)
        if let Ok(imps) = obj.imports() {
            for imp in imps {
                let name_str = String::from_utf8_lossy(imp.name()).to_string();
                if !name_str.is_empty() {
                    imports.push(name_str);
                }
                let lib_str = String::from_utf8_lossy(imp.library()).to_string();
                if !lib_str.is_empty() {
                    libs.push(lib_str);
                }
            }
        } else {
            // Fallback: undefined dynamic symbols
            for sym in obj.dynamic_symbols() {
                if sym.is_undefined() {
                    if let Ok(name) = sym.name() {
                        let name = name.to_string();
                        if !name.is_empty() {
                            imports.push(name);
                        }
                    }
                }
            }
        }

        // Exports (cross-format via object trait)
        if let Ok(exps) = obj.exports() {
            for ex in exps {
                let name_str = String::from_utf8_lossy(ex.name()).to_string();
                if !name_str.is_empty() {
                    exports.push(name_str);
                }
            }
        } else {
            // Fallback: defined dynamic symbols
            for sym in obj.dynamic_symbols() {
                if sym.is_definition() {
                    if let Ok(name) = sym.name() {
                        let name = name.to_string();
                        if !name.is_empty() {
                            exports.push(name);
                        }
                    }
                }
            }
        }

        // Fallback: scan data for library-like strings (best-effort)
        let scan = &data[..data.len().min(64 * 1024)];
        let mut i = 0usize;
        while i < scan.len() {
            if scan[i].is_ascii_graphic() {
                let start = i;
                while i < scan.len() && scan[i].is_ascii_graphic() && (i - start) < 256 {
                    i += 1;
                }
                if i > start {
                    if let Ok(s) = std::str::from_utf8(&scan[start..i]) {
                        let sl = s.to_ascii_lowercase();
                        if sl.ends_with(".dll")
                            || s.ends_with(".dylib")
                            || sl.ends_with(".so")
                            || s.contains(".so.")
                        {
                            libs.push(s.to_string());
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // Deduplicate
    all_syms.sort();
    all_syms.dedup();
    dyn_syms.sort();
    dyn_syms.dedup();
    imports.sort();
    imports.dedup();
    exports.sort();
    exports.dedup();
    libs.sort();
    libs.dedup();

    Ok((all_syms, dyn_syms, imports, exports, libs))
}

/// Python binding for listing demangled symbols from a file
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "list_symbols_demangled")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
pub fn list_symbols_demangled_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<(
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
)> {
    let (all_syms, dyn_syms, imports, exports, libs) =
        list_symbols_py(path, max_read_bytes, max_file_size)?;
    let mut demangled_all = Vec::with_capacity(all_syms.len());
    for s in &all_syms {
        if let Some(r) = crate::demangle::demangle_one(s) {
            demangled_all.push(r.demangled);
        } else {
            demangled_all.push(s.clone());
        }
    }
    let mut demangled_dyn = Vec::with_capacity(dyn_syms.len());
    for s in &dyn_syms {
        if let Some(r) = crate::demangle::demangle_one(s) {
            demangled_dyn.push(r.demangled);
        } else {
            demangled_dyn.push(s.clone());
        }
    }
    let mut demangled_imports = Vec::with_capacity(imports.len());
    for s in &imports {
        if let Some(r) = crate::demangle::demangle_one(s) {
            demangled_imports.push(r.demangled);
        } else {
            demangled_imports.push(s.clone());
        }
    }
    let mut demangled_exports = Vec::with_capacity(exports.len());
    for s in &exports {
        if let Some(r) = crate::demangle::demangle_one(s) {
            demangled_exports.push(r.demangled);
        } else {
            demangled_exports.push(s.clone());
        }
    }
    Ok((
        demangled_all,
        demangled_dyn,
        demangled_imports,
        demangled_exports,
        libs,
    ))
}
