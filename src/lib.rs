/// Core data types module
pub mod core;

/// Error types and error handling
pub mod error;

/// Logging and tracing infrastructure
pub mod logging;

/// Timeout utilities for analysis operations
pub mod timeout;

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

/// Disassembly engines and adapters
pub mod disasm;

/// Binary format parsers
pub mod formats;

/// Python bindings module
#[cfg(feature = "python-ext")]
pub mod python_bindings;

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
    if let Ok(obj) = object::read::File::parse(&data[..]) {
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
