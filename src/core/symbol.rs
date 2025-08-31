//! Symbol type for named program entities.
//!
//! Symbol represents named program entities from symbol tables, debug info,
//! imports, exports, and other sources.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;

/// Symbol kinds for different types of program entities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum SymbolKind {
    /// Function symbol
    Function,
    /// Data object symbol
    Object,
    /// Section symbol
    Section,
    /// Imported symbol
    Import,
    /// Exported symbol
    Export,
    /// Thunk symbol (jump table entry, etc.)
    Thunk,
    /// Debug symbol
    Debug,
    /// Synthetically created symbol
    Synthetic,
    /// Other/unknown symbol type
    Other,
}

#[pymethods]
impl SymbolKind {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolKind::Function => write!(f, "Function"),
            SymbolKind::Object => write!(f, "Object"),
            SymbolKind::Section => write!(f, "Section"),
            SymbolKind::Import => write!(f, "Import"),
            SymbolKind::Export => write!(f, "Export"),
            SymbolKind::Thunk => write!(f, "Thunk"),
            SymbolKind::Debug => write!(f, "Debug"),
            SymbolKind::Synthetic => write!(f, "Synthetic"),
            SymbolKind::Other => write!(f, "Other"),
        }
    }
}

/// Symbol binding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum SymbolBinding {
    /// Local symbol
    Local,
    /// Global symbol
    Global,
    /// Weak symbol
    Weak,
}

#[pymethods]
impl SymbolBinding {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for SymbolBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolBinding::Local => write!(f, "Local"),
            SymbolBinding::Global => write!(f, "Global"),
            SymbolBinding::Weak => write!(f, "Weak"),
        }
    }
}

/// Symbol visibility levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum SymbolVisibility {
    /// Public/default visibility
    Public,
    /// Private visibility
    Private,
    /// Protected visibility
    Protected,
    /// Hidden visibility
    Hidden,
}

#[pymethods]
impl SymbolVisibility {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for SymbolVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolVisibility::Public => write!(f, "Public"),
            SymbolVisibility::Private => write!(f, "Private"),
            SymbolVisibility::Protected => write!(f, "Protected"),
            SymbolVisibility::Hidden => write!(f, "Hidden"),
        }
    }
}

/// Symbol source types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum SymbolSource {
    /// From debug information
    DebugInfo,
    /// From import table
    ImportTable,
    /// From export table
    ExportTable,
    /// From heuristic analysis
    Heuristic,
    /// From PDB file
    Pdb,
    /// From DWARF debug info
    Dwarf,
    /// From AI analysis
    Ai,
}

#[pymethods]
impl SymbolSource {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for SymbolSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolSource::DebugInfo => write!(f, "DebugInfo"),
            SymbolSource::ImportTable => write!(f, "ImportTable"),
            SymbolSource::ExportTable => write!(f, "ExportTable"),
            SymbolSource::Heuristic => write!(f, "Heuristic"),
            SymbolSource::Pdb => write!(f, "Pdb"),
            SymbolSource::Dwarf => write!(f, "Dwarf"),
            SymbolSource::Ai => write!(f, "Ai"),
        }
    }
}

/// Named program entity from various sources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub struct Symbol {
    /// Unique identifier for the symbol
    #[pyo3(get, set)]
    pub id: String,
    /// Mangled/exported name
    #[pyo3(get, set)]
    pub name: String,
    /// Demangled name (optional)
    #[pyo3(get, set)]
    pub demangled: Option<String>,
    /// Symbol kind
    #[pyo3(get, set)]
    pub kind: SymbolKind,
    /// Address where symbol is located (optional)
    #[pyo3(get, set)]
    pub address: Option<Address>,
    /// Size of the symbol (optional)
    #[pyo3(get, set)]
    pub size: Option<u64>,
    /// Symbol binding (optional)
    #[pyo3(get, set)]
    pub binding: Option<SymbolBinding>,
    /// Module/library source (optional)
    #[pyo3(get, set)]
    pub module: Option<String>,
    /// Symbol visibility (optional)
    #[pyo3(get, set)]
    pub visibility: Option<SymbolVisibility>,
    /// Source of the symbol information
    #[pyo3(get, set)]
    pub source: SymbolSource,
}

#[pymethods]
impl Symbol {
    /// Create a new Symbol instance
    #[new]
    #[pyo3(signature = (
        id,
        name,
        kind,
        source,
        demangled=None,
        address=None,
        size=None,
        binding=None,
        module=None,
        visibility=None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        name: String,
        kind: SymbolKind,
        source: SymbolSource,
        demangled: Option<String>,
        address: Option<Address>,
        size: Option<u64>,
        binding: Option<SymbolBinding>,
        module: Option<String>,
        visibility: Option<SymbolVisibility>,
    ) -> Self {
        Self {
            id,
            name,
            demangled,
            kind,
            address,
            size,
            binding,
            module,
            visibility,
            source,
        }
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Get the display name (demangled if available, otherwise mangled)
    pub fn display_name(&self) -> &str {
        self.demangled.as_ref().unwrap_or(&self.name)
    }

    /// Check if this is a function symbol
    pub fn is_function(&self) -> bool {
        self.kind == SymbolKind::Function
    }

    /// Check if this is a data object symbol
    pub fn is_object(&self) -> bool {
        self.kind == SymbolKind::Object
    }

    /// Check if this is an imported symbol
    pub fn is_import(&self) -> bool {
        self.kind == SymbolKind::Import
    }

    /// Check if this is an exported symbol
    pub fn is_export(&self) -> bool {
        self.kind == SymbolKind::Export
    }

    /// Check if this is a global symbol
    pub fn is_global(&self) -> bool {
        self.binding == Some(SymbolBinding::Global)
    }

    /// Check if this is a local symbol
    pub fn is_local(&self) -> bool {
        self.binding == Some(SymbolBinding::Local)
    }

    /// Check if this is a weak symbol
    pub fn is_weak(&self) -> bool {
        self.binding == Some(SymbolBinding::Weak)
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        let display_name = self.display_name();
        let kind_str = format!("{}", self.kind);
        let binding_str = self
            .binding
            .as_ref()
            .map(|b| format!(" {}", b))
            .unwrap_or_default();

        let address_str = self
            .address
            .as_ref()
            .map(|addr| format!(" at {}", addr))
            .unwrap_or_default();

        format!(
            "Symbol '{}' ({}{}{})",
            display_name, kind_str, binding_str, address_str
        )
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_name = self.display_name();
        write!(f, "Symbol '{}' ({})", display_name, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_symbol_kind_display() {
        assert_eq!(format!("{}", SymbolKind::Function), "Function");
        assert_eq!(format!("{}", SymbolKind::Object), "Object");
        assert_eq!(format!("{}", SymbolKind::Import), "Import");
        assert_eq!(format!("{}", SymbolKind::Export), "Export");
        assert_eq!(format!("{}", SymbolKind::Other), "Other");
    }

    #[test]
    fn test_symbol_binding_display() {
        assert_eq!(format!("{}", SymbolBinding::Local), "Local");
        assert_eq!(format!("{}", SymbolBinding::Global), "Global");
        assert_eq!(format!("{}", SymbolBinding::Weak), "Weak");
    }

    #[test]
    fn test_symbol_visibility_display() {
        assert_eq!(format!("{}", SymbolVisibility::Public), "Public");
        assert_eq!(format!("{}", SymbolVisibility::Private), "Private");
        assert_eq!(format!("{}", SymbolVisibility::Hidden), "Hidden");
    }

    #[test]
    fn test_symbol_source_display() {
        assert_eq!(format!("{}", SymbolSource::DebugInfo), "DebugInfo");
        assert_eq!(format!("{}", SymbolSource::ImportTable), "ImportTable");
        assert_eq!(format!("{}", SymbolSource::ExportTable), "ExportTable");
        assert_eq!(format!("{}", SymbolSource::Heuristic), "Heuristic");
        assert_eq!(format!("{}", SymbolSource::Ai), "Ai");
    }

    #[test]
    fn test_symbol_creation() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let symbol = Symbol::new(
            "sym_1".to_string(),
            "_ZN4test7exampleEv".to_string(),
            SymbolKind::Function,
            SymbolSource::DebugInfo,
            Some("test::example()".to_string()),
            Some(address),
            Some(42),
            Some(SymbolBinding::Global),
            Some("test.so".to_string()),
            Some(SymbolVisibility::Public),
        );

        assert_eq!(symbol.id, "sym_1");
        assert_eq!(symbol.name, "_ZN4test7exampleEv");
        assert_eq!(symbol.demangled, Some("test::example()".to_string()));
        assert_eq!(symbol.kind, SymbolKind::Function);
        assert_eq!(symbol.display_name(), "test::example()");
        assert!(symbol.is_function());
        assert!(symbol.is_global());
        assert!(!symbol.is_import());
    }

    #[test]
    fn test_symbol_without_demangled_name() {
        let symbol = Symbol::new(
            "sym_1".to_string(),
            "simple_function".to_string(),
            SymbolKind::Function,
            SymbolSource::Heuristic,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(symbol.display_name(), "simple_function");
        assert_eq!(symbol.name, "simple_function");
        assert_eq!(symbol.demangled, None);
    }

    #[test]
    fn test_symbol_type_checks() {
        let func_symbol = Symbol::new(
            "func".to_string(),
            "test".to_string(),
            SymbolKind::Function,
            SymbolSource::DebugInfo,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let import_symbol = Symbol::new(
            "import".to_string(),
            "external_func".to_string(),
            SymbolKind::Import,
            SymbolSource::ImportTable,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let global_symbol = Symbol::new(
            "global".to_string(),
            "var".to_string(),
            SymbolKind::Object,
            SymbolSource::DebugInfo,
            None,
            None,
            None,
            Some(SymbolBinding::Global),
            None,
            None,
        );

        assert!(func_symbol.is_function());
        assert!(!func_symbol.is_object());

        assert!(import_symbol.is_import());
        assert!(!import_symbol.is_export());

        assert!(global_symbol.is_global());
        assert!(!global_symbol.is_local());
        assert!(!global_symbol.is_weak());
    }
}
