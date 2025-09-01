//! Relocation type for link-time relocation entries.
//!
//! Relocation represents link-time relocation entries that need to be resolved
//! when loading or linking executable files. These specify how addresses should
//! be adjusted based on the final load address or symbol resolution.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;

/// Relocation types for different executable formats and architectures.
/// These represent common relocation types found in ELF, PE, MachO, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum RelocationType {
    /// Absolute relocation (direct address)
    Absolute,
    /// Relative to program counter (PC-relative)
    PcRelative,
    /// Global Offset Table entry
    Got,
    /// Procedure Linkage Table entry
    Plt,
    /// Thread-Local Storage
    Tls,
    /// Copy relocation for dynamic linking
    Copy,
    /// Jump slot for dynamic linking
    JumpSlot,
    /// Relative relocation
    Relative,
    /// 32-bit absolute relocation
    Abs32,
    /// 64-bit absolute relocation
    Abs64,
    /// 32-bit PC-relative relocation
    Pc32,
    /// 64-bit PC-relative relocation
    Pc64,
    /// GOT PC-relative relocation
    GotPc,
    /// PLT PC-relative relocation
    PltPc,
    /// TLS offset relocation
    TlsOffset,
    /// TLS module relocation
    TlsModule,
    /// TLS module + offset relocation
    TlsModuleOffset,
    /// Unknown or format-specific relocation type
    Unknown,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl RelocationType {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for RelocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelocationType::Absolute => write!(f, "Absolute"),
            RelocationType::PcRelative => write!(f, "PcRelative"),
            RelocationType::Got => write!(f, "Got"),
            RelocationType::Plt => write!(f, "Plt"),
            RelocationType::Tls => write!(f, "Tls"),
            RelocationType::Copy => write!(f, "Copy"),
            RelocationType::JumpSlot => write!(f, "JumpSlot"),
            RelocationType::Relative => write!(f, "Relative"),
            RelocationType::Abs32 => write!(f, "Abs32"),
            RelocationType::Abs64 => write!(f, "Abs64"),
            RelocationType::Pc32 => write!(f, "Pc32"),
            RelocationType::Pc64 => write!(f, "Pc64"),
            RelocationType::GotPc => write!(f, "GotPc"),
            RelocationType::PltPc => write!(f, "PltPc"),
            RelocationType::TlsOffset => write!(f, "TlsOffset"),
            RelocationType::TlsModule => write!(f, "TlsModule"),
            RelocationType::TlsModuleOffset => write!(f, "TlsModuleOffset"),
            RelocationType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Link-time relocation entry that specifies how an address should be adjusted
/// during loading or linking of executable files.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Relocation {
    /// Unique identifier for the relocation
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub id: String,
    /// Address where the relocation should be applied
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub address: Address,
    /// Type of relocation to perform
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub kind: RelocationType,
    /// Resolved value or addend for the relocation (optional)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub value: Option<u64>,
    /// Symbol reference if this relocation references a symbol (optional)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub symbol: Option<String>,
    /// Additional offset to add to the resolved address (optional)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub addend: Option<i64>,
    /// Size of the relocation in bytes (optional, usually 4 or 8)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub size: Option<u8>,
}

impl Relocation {
    pub fn new(
        id: String,
        address: Address,
        kind: RelocationType,
        value: Option<u64>,
        symbol: Option<String>,
        addend: Option<i64>,
        size: Option<u8>,
    ) -> Self {
        Self { id, address, kind, value, symbol, addend, size }
    }

    pub fn is_resolved(&self) -> bool { self.value.is_some() }
    pub fn has_symbol(&self) -> bool { self.symbol.is_some() }
    pub fn has_addend(&self) -> bool { self.addend.is_some() }
    pub fn effective_size(&self) -> u8 { self.size.unwrap_or(4) }
    pub fn is_absolute(&self) -> bool { matches!(self.kind, RelocationType::Absolute | RelocationType::Abs32 | RelocationType::Abs64) }
    pub fn is_pc_relative(&self) -> bool { matches!(self.kind, RelocationType::PcRelative | RelocationType::Pc32 | RelocationType::Pc64) }
    pub fn is_got_related(&self) -> bool { matches!(self.kind, RelocationType::Got | RelocationType::GotPc) }
    pub fn is_plt_related(&self) -> bool { matches!(self.kind, RelocationType::Plt | RelocationType::PltPc | RelocationType::JumpSlot) }
    pub fn is_tls_related(&self) -> bool { matches!(self.kind, RelocationType::Tls | RelocationType::TlsOffset | RelocationType::TlsModule | RelocationType::TlsModuleOffset) }
    pub fn description(&self) -> String {
        let symbol_str = self.symbol.as_ref().map(|s| format!(" -> {}", s)).unwrap_or_default();
        let value_str = self.value.map(|v| format!(" (value: 0x{:x})", v)).unwrap_or_default();
        let addend_str = self.addend.filter(|&a| a != 0).map(|a| format!(" (addend: {})", a)).unwrap_or_default();
        format!("Relocation '{}' at {}: {}{}{}{}", self.id, self.address, self.kind, symbol_str, value_str, addend_str)
    }
    pub fn calculate_relocated_address(&self, base_address: u64) -> Option<u64> {
        match self.kind {
            RelocationType::Absolute | RelocationType::Abs32 | RelocationType::Abs64 => self.value.map(|v| v.wrapping_add(self.addend.unwrap_or(0) as u64)),
            RelocationType::Relative => self.value.map(|v| base_address.wrapping_add(v).wrapping_add(self.addend.unwrap_or(0) as u64)),
            RelocationType::PcRelative | RelocationType::Pc32 | RelocationType::Pc64 => {
                self.value.map(|v| self.address.value.wrapping_add(v).wrapping_add(self.addend.unwrap_or(0) as u64))
            }
            _ => self.value.map(|v| v.wrapping_add(self.addend.unwrap_or(0) as u64)),
        }
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Relocation {
    /// Create a new Relocation instance
    #[new]
    #[pyo3(signature = (
        id,
        address,
        kind,
        value=None,
        symbol=None,
        addend=None,
        size=None
    ))]
    pub fn new(
        id: String,
        address: Address,
        kind: RelocationType,
        value: Option<u64>,
        symbol: Option<String>,
        addend: Option<i64>,
        size: Option<u8>,
    ) -> Self {
        Self {
            id,
            address,
            kind,
            value,
            symbol,
            addend,
            size,
        }
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Check if this relocation has a resolved value
    pub fn is_resolved(&self) -> bool {
        self.value.is_some()
    }

    /// Check if this relocation references a symbol
    pub fn has_symbol(&self) -> bool {
        self.symbol.is_some()
    }

    /// Check if this relocation has an addend
    pub fn has_addend(&self) -> bool {
        self.addend.is_some()
    }

    /// Get the effective size of this relocation (defaulting to 4 bytes if not specified)
    pub fn effective_size(&self) -> u8 {
        self.size.unwrap_or(4)
    }

    /// Check if this is an absolute relocation
    pub fn is_absolute(&self) -> bool {
        matches!(
            self.kind,
            RelocationType::Absolute | RelocationType::Abs32 | RelocationType::Abs64
        )
    }

    /// Check if this is a PC-relative relocation
    pub fn is_pc_relative(&self) -> bool {
        matches!(
            self.kind,
            RelocationType::PcRelative | RelocationType::Pc32 | RelocationType::Pc64
        )
    }

    /// Check if this is a GOT-related relocation
    pub fn is_got_related(&self) -> bool {
        matches!(self.kind, RelocationType::Got | RelocationType::GotPc)
    }

    /// Check if this is a PLT-related relocation
    pub fn is_plt_related(&self) -> bool {
        matches!(
            self.kind,
            RelocationType::Plt | RelocationType::PltPc | RelocationType::JumpSlot
        )
    }

    /// Check if this is a TLS-related relocation
    pub fn is_tls_related(&self) -> bool {
        matches!(
            self.kind,
            RelocationType::Tls
                | RelocationType::TlsOffset
                | RelocationType::TlsModule
                | RelocationType::TlsModuleOffset
        )
    }

    /// Get a human-readable description of the relocation
    pub fn description(&self) -> String {
        let symbol_str = self
            .symbol
            .as_ref()
            .map(|s| format!(" -> {}", s))
            .unwrap_or_default();

        let value_str = self
            .value
            .map(|v| format!(" (value: 0x{:x})", v))
            .unwrap_or_default();

        let addend_str = self
            .addend
            .filter(|&a| a != 0)
            .map(|a| format!(" (addend: {})", a))
            .unwrap_or_default();

        format!(
            "Relocation '{}' at {}: {}{}{}{}",
            self.id, self.address, self.kind, symbol_str, value_str, addend_str
        )
    }

    /// Calculate the final relocated address (if possible)
    /// This is a simplified calculation - real relocation processing is more complex
    pub fn calculate_relocated_address(&self, base_address: u64) -> Option<u64> {
        match self.kind {
            RelocationType::Absolute | RelocationType::Abs32 | RelocationType::Abs64 => self
                .value
                .map(|v| v.wrapping_add(self.addend.unwrap_or(0) as u64)),
            RelocationType::Relative => self.value.map(|v| {
                base_address
                    .wrapping_add(v)
                    .wrapping_add(self.addend.unwrap_or(0) as u64)
            }),
            RelocationType::PcRelative | RelocationType::Pc32 | RelocationType::Pc64 => {
                self.value.map(|v| {
                    self.address
                        .value
                        .wrapping_add(v)
                        .wrapping_add(self.addend.unwrap_or(0) as u64)
                })
            }
            _ => {
                // For other types, we would need more context (GOT, PLT, etc.)
                // This is a simplified implementation
                self.value
                    .map(|v| v.wrapping_add(self.addend.unwrap_or(0) as u64))
            }
        }
    }
}

impl fmt::Display for Relocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol_part = self
            .symbol
            .as_ref()
            .map(|s| format!(" -> {}", s))
            .unwrap_or_default();

        write!(f, "Relocation '{}' ({}{})", self.id, self.kind, symbol_part)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_relocation_type_display() {
        assert_eq!(format!("{}", RelocationType::Absolute), "Absolute");
        assert_eq!(format!("{}", RelocationType::PcRelative), "PcRelative");
        assert_eq!(format!("{}", RelocationType::Got), "Got");
        assert_eq!(format!("{}", RelocationType::Plt), "Plt");
        assert_eq!(format!("{}", RelocationType::Tls), "Tls");
        assert_eq!(format!("{}", RelocationType::Unknown), "Unknown");
    }

    #[test]
    fn test_relocation_creation_minimal() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let relocation = Relocation::new(
            "reloc_1".to_string(),
            address,
            RelocationType::Absolute,
            None,
            None,
            None,
            None,
        );

        assert_eq!(relocation.id, "reloc_1");
        assert_eq!(relocation.address.value, 0x400000);
        assert_eq!(relocation.kind, RelocationType::Absolute);
        assert!(!relocation.is_resolved());
        assert!(!relocation.has_symbol());
        assert!(!relocation.has_addend());
        assert_eq!(relocation.effective_size(), 4);
    }

    #[test]
    fn test_relocation_creation_full() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let relocation = Relocation::new(
            "reloc_2".to_string(),
            address,
            RelocationType::PcRelative,
            Some(0x1000),
            Some("printf".to_string()),
            Some(8),
            Some(8),
        );

        assert_eq!(relocation.id, "reloc_2");
        assert_eq!(relocation.kind, RelocationType::PcRelative);
        assert_eq!(relocation.value, Some(0x1000));
        assert_eq!(relocation.symbol, Some("printf".to_string()));
        assert_eq!(relocation.addend, Some(8));
        assert_eq!(relocation.size, Some(8));
        assert!(relocation.is_resolved());
        assert!(relocation.has_symbol());
        assert!(relocation.has_addend());
        assert_eq!(relocation.effective_size(), 8);
    }

    #[test]
    fn test_relocation_type_checks() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let abs_reloc = Relocation::new(
            "abs".to_string(),
            address.clone(),
            RelocationType::Absolute,
            None,
            None,
            None,
            None,
        );
        let pc_reloc = Relocation::new(
            "pc".to_string(),
            address.clone(),
            RelocationType::PcRelative,
            None,
            None,
            None,
            None,
        );
        let got_reloc = Relocation::new(
            "got".to_string(),
            address.clone(),
            RelocationType::Got,
            None,
            None,
            None,
            None,
        );
        let plt_reloc = Relocation::new(
            "plt".to_string(),
            address.clone(),
            RelocationType::Plt,
            None,
            None,
            None,
            None,
        );
        let tls_reloc = Relocation::new(
            "tls".to_string(),
            address,
            RelocationType::Tls,
            None,
            None,
            None,
            None,
        );

        assert!(abs_reloc.is_absolute());
        assert!(pc_reloc.is_pc_relative());
        assert!(got_reloc.is_got_related());
        assert!(plt_reloc.is_plt_related());
        assert!(tls_reloc.is_tls_related());

        assert!(!abs_reloc.is_pc_relative());
        assert!(!pc_reloc.is_absolute());
        assert!(!got_reloc.is_plt_related());
        assert!(!plt_reloc.is_got_related());
        assert!(!tls_reloc.is_absolute());
    }

    #[test]
    fn test_relocation_calculate_address() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        // Test absolute relocation
        let abs_reloc = Relocation::new(
            "abs".to_string(),
            address.clone(),
            RelocationType::Absolute,
            Some(0x1000),
            None,
            Some(0x10),
            None,
        );
        assert_eq!(abs_reloc.calculate_relocated_address(0), Some(0x1010));

        // Test PC-relative relocation
        let pc_reloc = Relocation::new(
            "pc".to_string(),
            address,
            RelocationType::PcRelative,
            Some(0x100),
            None,
            Some(4),
            None,
        );
        assert_eq!(pc_reloc.calculate_relocated_address(0), Some(0x400104));
    }

    #[test]
    fn test_relocation_description() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let simple_reloc = Relocation::new(
            "simple".to_string(),
            address.clone(),
            RelocationType::Absolute,
            None,
            None,
            None,
            None,
        );
        let desc = simple_reloc.description();
        assert!(desc.contains("simple"));
        assert!(desc.contains("Absolute"));
        assert!(desc.contains("VA:400000"));

        let complex_reloc = Relocation::new(
            "complex".to_string(),
            address,
            RelocationType::PcRelative,
            Some(0x1000),
            Some("target_func".to_string()),
            Some(8),
            Some(8),
        );
        let desc = complex_reloc.description();
        assert!(desc.contains("complex"));
        assert!(desc.contains("PcRelative"));
        assert!(desc.contains("target_func"));
        assert!(desc.contains("value: 0x1000"));
        assert!(desc.contains("addend: 8"));
    }

    #[test]
    fn test_relocation_display() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let reloc_with_symbol = Relocation::new(
            "test_reloc".to_string(),
            address,
            RelocationType::Plt,
            None,
            Some("external_func".to_string()),
            None,
            None,
        );

        let display = format!("{}", reloc_with_symbol);
        assert!(display.contains("test_reloc"));
        assert!(display.contains("Plt"));
        assert!(display.contains("external_func"));

        let reloc_without_symbol = Relocation::new(
            "no_symbol".to_string(),
            Address::new(AddressKind::VA, 0x500000, 64, None, None).unwrap(),
            RelocationType::Absolute,
            None,
            None,
            None,
            None,
        );

        let display = format!("{}", reloc_without_symbol);
        assert!(display.contains("no_symbol"));
        assert!(display.contains("Absolute"));
        assert!(!display.contains("->"));
    }
}
