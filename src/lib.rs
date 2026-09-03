/// Core data types module
/// Rust-side global allocator.
///
/// A release decompile of `/usr/bin/bash` spends **26% of its cycles in glibc
/// malloc**, and the shape is free-path coalescing -- `_int_free_merge_chunk`
/// 7.7%, `_int_malloc` 7.4%, `cfree` 4.7%, `unlink_chunk` 2.8%. That is what
/// high-churn allocation of many short-lived, varied-size objects costs in an
/// allocator tuned for general workloads. Decompilation is exactly that
/// workload: per-instruction `Vec`s and `String`s, per-function maps, and
/// expression trees built and dropped for every one of thousands of functions.
///
/// This replaces the allocator for RUST allocations in this crate only. Python
/// keeps `pymalloc`; the interpreter is unaffected.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod core;

/// Error types and error handling
pub mod error;

/// Logging and tracing infrastructure
pub mod logging;

/// Timeout utilities for analysis operations
pub mod timeout;

/// Canonical machine-target, register-role, and ABI facts.
pub mod target;

/// Triage runtime implementation
pub mod triage;

/// Symbol extraction and analysis
pub mod symbols;

/// Symbol name demangling helpers
pub mod demangle;

/// Similarity and fuzzy hashing (CTPH)
pub mod similarity;

/// Content-derived function identity schemes (WARP GUIDs, structural
/// invariants, the canonical function representation).
pub mod identity;

/// Cross-platform string scanning and language detection
pub mod strings;

/// High-performance entropy calculation and analysis
pub mod entropy;

/// Analysis-time program and memory views
pub mod analysis;

/// Debug-info ingestion (DWARF, PDB)
pub mod debug;

/// FLIRT-style signature matching for stripped binaries
pub mod flirt;

/// Disassembly engines and adapters
pub mod disasm;

/// Low-Level Intermediate Representation (Phase 2)
pub mod ir;

/// Language-neutral parsing substrate: spans, interning, tokens, events, CFGs
pub mod syntax;

/// C source front end: lexer, parser, control flow, and the parity layer
pub mod csource;


/// Shared decompilation pipeline and diagnostics.
pub mod decompile;

/// Binary format parsers
pub mod formats;

/// Windows metadata extraction
pub mod winmd;

/// Native execution engine (concrete emulation + symbolic execution) over the
/// LLIR. See `docs/history/execution-engine-2026-06/`. Feature-gated; pure Rust.
#[cfg(feature = "exec")]
pub mod exec;

/// Symbolic / concolic execution: a bitvector expression IR and a symbolic
/// `Domain` over the same interpreter. See `docs/history/execution-engine-2026-06/`.
#[cfg(feature = "symbolic")]
pub mod symbolic;

/// Test-only support: visible skips for tests that compile fixtures.
///
/// Gated on `cfg(test)` so it ships in no build. See the module docs for why a
/// silently-skipped test is worse than a failing one.
#[cfg(test)]
pub mod testing;

pub mod program;

/// Python bindings module
#[cfg(feature = "python-ext")]
pub mod python_bindings;
/// Undoing what a packer did: static recovery of the original image, so that
/// analysis reports the program's functions rather than the unpacker's.
pub mod unpack;

#[cfg(feature = "python-ext")]
use pyo3::{prelude::*, wrap_pyfunction};

/// A Python module implemented in Rust.
#[cfg(feature = "python-ext")]
#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register all Python bindings through the organized modules
    python_bindings::register_python_bindings(py, m)?;

    // Register logging functions
    m.add_function(wrap_pyfunction!(crate::logging::init_logging, m)?)?;
    m.add_function(wrap_pyfunction!(crate::logging::log_message, m)?)?;
    m.add_class::<crate::logging::LogLevel>()?;

    // Top-level helper: symbol address map for a file
    m.add_function(wrap_pyfunction!(symbol_address_map_py, m)?)?;
    m.add_function(wrap_pyfunction!(symbol_table_entries_py, m)?)?;
    m.add_function(wrap_pyfunction!(pe_export_entries_py, m)?)?;

    Ok(())
}

/// PE export-table entries: `(va, name, ordinal, forwarder)`.
///
/// Shipped Windows binaries carry **no COFF symbol table** -- `win10-dismcore.dll`
/// has zero COFF symbols against 4 exports and 222 imports -- so a resolver that
/// reads only `symbol_table_entries` finds nothing in them. Their function
/// identities live in the export table and the PDB.
///
/// `forwarder` is `Some(target)` for a forwarded export (`"OTHERDLL.RealName"`),
/// which is **not a local body**: the code lives in another module, so a
/// local-body request must be refused rather than answered with the forwarder's
/// address. That is the same distinction DecBench failure class F1b draws for
/// imports.
///
/// `va` is `image_base + rva`, matching `symbol_table_entries`. It is 0 for a
/// forwarded export, which has no code in this image.
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "pe_export_entries")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn pe_export_entries_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String, u32, Option<String>)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let Ok(pe) = crate::formats::pe::PeParser::new(&data[..]) else {
        return Ok(Vec::new());
    };
    let Ok(table) = pe.exports() else {
        return Ok(Vec::new());
    };
    let base = pe.image_base();
    let mut out = Vec::new();
    for e in &table.exports {
        let Some(name) = e.name else { continue };
        let forwarder = e.forwarder.map(|f| f.to_string());
        let va = if forwarder.is_some() {
            0
        } else {
            base.saturating_add(e.rva as u64)
        };
        out.push((va, name.to_string(), e.ordinal, forwarder));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

/// Symbol table entries with kind and definedness, for a file.
///
/// `symbol_address_map` answers "what address is this name?" and is
/// deliberately lossy: it dedups by address and drops everything that is not a
/// definition. A caller resolving a *function body* request needs three things
/// that map cannot express -- whether a hit is code or data, whether it is a
/// local definition or an import, and whether two distinct addresses claim the
/// same name. Returning them separately keeps the existing helper's contract
/// intact while letting the DecBench resolver refuse a data symbol, report an
/// import as an import, and treat a duplicate as an ambiguity instead of
/// silently taking the first entry.
///
/// Each entry is `(address, name, kind, defined)` where `kind` is one of
/// `text`, `data`, `tls`, `section`, `file`, `label`, `unknown`.
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "symbol_table_entries")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn symbol_table_entries_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String, String, bool)>> {
    use object::read::Object;
    use object::ObjectSymbol;
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let mut out: Vec<(u64, String, String, bool)> = Vec::new();
    if let Ok(obj) = crate::decompile::profile::parse_object(&data[..]) {
        for sym in obj.symbols().chain(obj.dynamic_symbols()) {
            let name = match sym.name() {
                Ok(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            let kind = match sym.kind() {
                object::SymbolKind::Text => "text",
                object::SymbolKind::Data => "data",
                object::SymbolKind::Tls => "tls",
                object::SymbolKind::Section => "section",
                object::SymbolKind::File => "file",
                object::SymbolKind::Label => "label",
                _ => "unknown",
            };
            out.push((sym.address(), name, kind.to_string(), sym.is_definition()));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    out.dedup();
    Ok(out)
}

/// Symbol address map helper for a file.
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "symbol_address_map")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn symbol_address_map_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String)>> {
    use object::read::Object;
    use object::ObjectSymbol;
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let mut out: Vec<(u64, String)> = Vec::new();
    if let Ok(obj) = crate::decompile::profile::parse_object(&data[..]) {
        for sym in obj.symbols() {
            if sym.is_definition() {
                if let (Ok(name), addr) = (sym.name(), sym.address()) {
                    let s = name.to_string();
                    if !s.is_empty() {
                        out.push((addr, s));
                    }
                }
            }
        }
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                if let (Ok(name), addr) = (sym.name(), sym.address()) {
                    let s = name.to_string();
                    if !s.is_empty() {
                        out.push((addr, s));
                    }
                }
            }
        }
    }
    // Dedup by address, keep first name
    out.sort_by_key(|(a, _)| *a);
    out.dedup_by_key(|(a, _)| *a);
    Ok(out)
}
