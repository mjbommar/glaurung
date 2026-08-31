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

/// Shared decompilation pipeline and diagnostics.
pub mod decompile;

/// Binary format parsers
pub mod formats;

/// Windows metadata extraction
pub mod winmd;

/// Native execution engine (concrete emulation + symbolic execution) over the
/// LLIR. See `docs/design/execution-engine/`. Feature-gated; pure Rust.
#[cfg(feature = "exec")]
pub mod exec;

/// Symbolic / concolic execution: a bitvector expression IR and a symbolic
/// `Domain` over the same interpreter. See `docs/design/execution-engine/`.
#[cfg(feature = "symbolic")]
pub mod symbolic;

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

    Ok(())
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
