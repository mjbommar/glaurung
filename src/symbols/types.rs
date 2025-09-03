//! Symbol types and data structures

use serde::{Deserialize, Serialize};

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// Budget caps for symbol extraction operations
#[derive(Debug, Clone, Copy)]
pub struct BudgetCaps {
    pub max_imports: u32,
    pub max_exports: u32,
    pub max_libs: u32,
    pub time_guard_ms: u64,
}

impl Default for BudgetCaps {
    fn default() -> Self {
        BudgetCaps {
            max_imports: 5000,
            max_exports: 5000,
            max_libs: 256,
            time_guard_ms: 100,
        }
    }
}

/// Summary of symbols extracted from a binary
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct SymbolSummary {
    pub imports_count: u32,
    pub exports_count: u32,
    pub libs_count: u32,
    pub import_names: Option<Vec<String>>,
    pub export_names: Option<Vec<String>>,
    /// Demangled variants of import names, when applicable
    pub demangled_import_names: Option<Vec<String>>,
    /// Demangled variants of export names, when applicable
    pub demangled_export_names: Option<Vec<String>>,
    pub stripped: bool,
    pub tls_used: bool,
    /// Number of TLS callbacks if enumerated (PE-specific)
    pub tls_callback_count: Option<u32>,
    /// Virtual addresses of TLS callbacks, when enumerated (PE-specific)
    pub tls_callback_vas: Option<Vec<u64>>,
    pub debug_info_present: bool,
    pub suspicious_imports: Option<Vec<String>>,
    pub entry_section: Option<String>,
    pub nx: Option<bool>,
    pub aslr: Option<bool>,
    pub relro: Option<bool>,
    pub pie: Option<bool>,
    pub cfg: Option<bool>,
    /// Whether relocations are present (format-specific; e.g., PE base reloc table)
    pub relocations_present: Option<bool>,
    pub rpaths: Option<Vec<String>>,
    pub runpaths: Option<Vec<String>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl SymbolSummary {
    #[new]
    #[pyo3(signature = (
        imports_count,
        exports_count,
        libs_count,
        stripped,
        tls_used,
        debug_info_present,
        suspicious_imports=None,
        entry_section=None,
        import_names=None,
        export_names=None,
        nx=None,
        aslr=None,
        relro=None,
        pie=None,
        cfg=None,
        rpaths=None,
        runpaths=None,
    ))]
    pub fn new_py(
        imports_count: u32,
        exports_count: u32,
        libs_count: u32,
        stripped: bool,
        tls_used: bool,
        debug_info_present: bool,
        suspicious_imports: Option<Vec<String>>,
        entry_section: Option<String>,
        import_names: Option<Vec<String>>,
        export_names: Option<Vec<String>>,
        nx: Option<bool>,
        aslr: Option<bool>,
        relro: Option<bool>,
        pie: Option<bool>,
        cfg: Option<bool>,
        rpaths: Option<Vec<String>>,
        runpaths: Option<Vec<String>>,
    ) -> Self {
        Self {
            imports_count,
            exports_count,
            libs_count,
            import_names,
            export_names,
            demangled_import_names: None,
            demangled_export_names: None,
            stripped,
            tls_used,
            tls_callback_count: None,
            tls_callback_vas: None,
            debug_info_present,
            suspicious_imports,
            entry_section,
            nx,
            aslr,
            relro,
            pie,
            cfg,
            relocations_present: None,
            rpaths,
            runpaths,
        }
    }

    #[getter]
    fn imports_count(&self) -> u32 {
        self.imports_count
    }

    #[getter]
    fn exports_count(&self) -> u32 {
        self.exports_count
    }

    #[getter]
    fn libs_count(&self) -> u32 {
        self.libs_count
    }

    #[getter]
    fn import_names(&self) -> Option<Vec<String>> {
        self.import_names.clone()
    }

    #[getter]
    fn export_names(&self) -> Option<Vec<String>> {
        self.export_names.clone()
    }

    #[getter]
    fn demangled_import_names(&self) -> Option<Vec<String>> {
        self.demangled_import_names.clone()
    }
    #[getter]
    fn demangled_export_names(&self) -> Option<Vec<String>> {
        self.demangled_export_names.clone()
    }

    #[getter]
    fn stripped(&self) -> bool {
        self.stripped
    }

    #[getter]
    fn tls_used(&self) -> bool {
        self.tls_used
    }

    #[getter]
    fn tls_callback_count(&self) -> Option<u32> {
        self.tls_callback_count
    }

    #[getter]
    fn tls_callback_vas(&self) -> Option<Vec<u64>> {
        self.tls_callback_vas.clone()
    }

    #[getter]
    fn debug_info_present(&self) -> bool {
        self.debug_info_present
    }

    #[getter]
    fn suspicious_imports(&self) -> Option<Vec<String>> {
        self.suspicious_imports.clone()
    }

    #[getter]
    fn entry_section(&self) -> Option<String> {
        self.entry_section.clone()
    }

    #[getter]
    fn nx(&self) -> Option<bool> {
        self.nx
    }

    #[getter]
    fn aslr(&self) -> Option<bool> {
        self.aslr
    }

    #[getter]
    fn relro(&self) -> Option<bool> {
        self.relro
    }

    #[getter]
    fn pie(&self) -> Option<bool> {
        self.pie
    }

    #[getter]
    fn cfg(&self) -> Option<bool> {
        self.cfg
    }
    #[getter]
    fn relocations_present(&self) -> Option<bool> {
        self.relocations_present
    }
    #[getter]
    fn rpaths(&self) -> Option<Vec<String>> {
        self.rpaths.clone()
    }
    #[getter]
    fn runpaths(&self) -> Option<Vec<String>> {
        self.runpaths.clone()
    }
}

/// Type of symbol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    Function,
    Data,
    Section,
    File,
    Object,
    Common,
    TLS,
    Unknown,
}

/// Symbol binding/visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown,
}

/// Detailed information about a single symbol
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: SymbolType,
    pub binding: SymbolBinding,
    pub section: Option<String>,
    pub is_imported: bool,
    pub is_exported: bool,
}
