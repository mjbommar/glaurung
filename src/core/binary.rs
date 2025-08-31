//! Binary types for binary analysis.
//!
//! This module provides the Binary type that represents a program under analysis,
//! including its format, architecture, entry points, and metadata.

use crate::core::address::Address;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// The executable format of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass(eq, eq_int)]
pub enum Format {
    /// Executable and Linkable Format (Linux, Unix)
    ELF,
    /// Portable Executable (Windows)
    PE,
    /// Mach Object file format (macOS, iOS)
    MachO,
    /// WebAssembly binary format
    Wasm,
    /// Common Object File Format (Unix)
    COFF,
    /// Raw binary (no format)
    Raw,
    /// Unknown or unsupported format
    Unknown,
}

#[pymethods]
impl Format {
    /// String representation for display.
    fn __str__(&self) -> String {
        match self {
            Format::ELF => "ELF".to_string(),
            Format::PE => "PE".to_string(),
            Format::MachO => "MachO".to_string(),
            Format::Wasm => "Wasm".to_string(),
            Format::COFF => "COFF".to_string(),
            Format::Raw => "Raw".to_string(),
            Format::Unknown => "Unknown".to_string(),
        }
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("Format.{}", self.__str__())
    }
}

/// The CPU architecture of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass(eq, eq_int)]
pub enum Arch {
    /// 32-bit x86
    X86,
    /// 64-bit x86
    X86_64,
    /// 32-bit ARM
    ARM,
    /// 64-bit ARM
    AArch64,
    /// MIPS (32-bit)
    MIPS,
    /// MIPS (64-bit)
    MIPS64,
    /// PowerPC (32-bit)
    PPC,
    /// PowerPC (64-bit)
    PPC64,
    /// RISC-V (32-bit)
    RISCV,
    /// RISC-V (64-bit)
    RISCV64,
    /// Unknown or unsupported architecture
    Unknown,
}

#[pymethods]
impl Arch {
    /// String representation for display.
    fn __str__(&self) -> String {
        match self {
            Arch::X86 => "x86".to_string(),
            Arch::X86_64 => "x86_64".to_string(),
            Arch::ARM => "arm".to_string(),
            Arch::AArch64 => "aarch64".to_string(),
            Arch::MIPS => "mips".to_string(),
            Arch::MIPS64 => "mips64".to_string(),
            Arch::PPC => "ppc".to_string(),
            Arch::PPC64 => "ppc64".to_string(),
            Arch::RISCV => "riscv".to_string(),
            Arch::RISCV64 => "riscv64".to_string(),
            Arch::Unknown => "unknown".to_string(),
        }
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("Arch.{}", self.__str__())
    }

    /// Check if this is a 64-bit architecture.
    ///
    /// Returns:
    ///     bool: True if 64-bit, False if 32-bit
    fn is_64_bit(&self) -> bool {
        matches!(
            self,
            Arch::X86_64 | Arch::AArch64 | Arch::MIPS64 | Arch::PPC64 | Arch::RISCV64
        )
    }

    /// Get the bit width of this architecture.
    ///
    /// Returns:
    ///     int: 64 for 64-bit architectures, 32 for 32-bit
    fn bits(&self) -> u8 {
        if self.is_64_bit() {
            64
        } else {
            32
        }
    }
}

/// The endianness of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass(eq, eq_int)]
pub enum Endianness {
    /// Little-endian byte order
    Little,
    /// Big-endian byte order
    Big,
}

#[pymethods]
impl Endianness {
    /// String representation for display.
    fn __str__(&self) -> String {
        match self {
            Endianness::Little => "Little".to_string(),
            Endianness::Big => "Big".to_string(),
        }
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("Endianness.{}", self.__str__())
    }
}

/// Cryptographic hashes for a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[pyclass]
pub struct Hashes {
    /// SHA-256 hash (hex string)
    #[pyo3(get, set)]
    pub sha256: Option<String>,
    /// MD5 hash (hex string)
    #[pyo3(get, set)]
    pub md5: Option<String>,
    /// SHA-1 hash (hex string)
    #[pyo3(get, set)]
    pub sha1: Option<String>,
    /// Additional hashes as key-value pairs
    #[pyo3(get, set)]
    pub additional: Option<HashMap<String, String>>,
}

#[pymethods]
impl Hashes {
    /// Create a new Hashes instance.
    ///
    /// Args:
    ///     sha256: SHA-256 hash as hex string
    ///     md5: MD5 hash as hex string (optional)
    ///     sha1: SHA-1 hash as hex string (optional)
    ///     additional: Additional hashes as dict (optional)
    ///
    /// Returns:
    ///     Hashes: A new Hashes instance
    #[new]
    #[pyo3(signature = (sha256=None, md5=None, sha1=None, additional=None))]
    fn new_py(
        sha256: Option<String>,
        md5: Option<String>,
        sha1: Option<String>,
        additional: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        Self::new(sha256, md5, sha1, additional).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hashes: {}", e))
        })
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref sha256) = self.sha256 {
            parts.push(format!("sha256='{}'", sha256));
        }
        if let Some(ref md5) = self.md5 {
            parts.push(format!("md5='{}'", md5));
        }
        if let Some(ref sha1) = self.sha1 {
            parts.push(format!("sha1='{}'", sha1));
        }
        format!("Hashes({})", parts.join(", "))
    }

    /// Check if the hashes are valid.
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    /// Get a hash by name.
    ///
    /// Args:
    ///     name: Hash algorithm name ('sha256', 'md5', 'sha1', or custom)
    ///
    /// Returns:
    ///     str or None: The hash value if found
    fn get_hash(&self, name: &str) -> Option<String> {
        match name {
            "sha256" => self.sha256.clone(),
            "md5" => self.md5.clone(),
            "sha1" => self.sha1.clone(),
            _ => self.additional.as_ref()?.get(name).cloned(),
        }
    }

    /// Set a hash value.
    ///
    /// Args:
    ///     name: Hash algorithm name
    ///     value: Hash value as hex string
    fn set_hash(&mut self, name: String, value: String) {
        match name.as_str() {
            "sha256" => self.sha256 = Some(value),
            "md5" => self.md5 = Some(value),
            "sha1" => self.sha1 = Some(value),
            _ => {
                self.additional
                    .get_or_insert_with(HashMap::new)
                    .insert(name, value);
            }
        }
    }

    /// Check if SHA-256 hash is available.
    ///
    /// Returns:
    ///     bool: True if SHA-256 hash is present
    fn has_sha256(&self) -> bool {
        self.sha256.is_some()
    }

    /// Check if any hashes are present.
    ///
    /// Returns:
    ///     bool: True if at least one hash is present
    fn has_any_hash(&self) -> bool {
        self.sha256.is_some()
            || self.md5.is_some()
            || self.sha1.is_some()
            || self.additional.is_some()
    }
}

impl Hashes {
    /// Create a new Hashes instance.
    ///
    /// # Arguments
    /// * `sha256` - SHA-256 hash as hex string
    /// * `md5` - MD5 hash as hex string
    /// * `sha1` - SHA-1 hash as hex string
    /// * `additional` - Additional hashes
    ///
    /// # Errors
    /// Returns an error if validation fails
    pub fn new(
        sha256: Option<String>,
        md5: Option<String>,
        sha1: Option<String>,
        additional: Option<HashMap<String, String>>,
    ) -> Result<Self, String> {
        let hashes = Self {
            sha256,
            md5,
            sha1,
            additional,
        };

        hashes.validate()?;
        Ok(hashes)
    }

    /// Validate the hashes.
    pub fn validate(&self) -> Result<(), String> {
        // Validate SHA-256 if present
        if let Some(ref sha256) = self.sha256 {
            if !Self::is_valid_hex_hash(sha256, 64) {
                return Err("Invalid SHA-256 hash format".to_string());
            }
        }

        // Validate MD5 if present
        if let Some(ref md5) = self.md5 {
            if !Self::is_valid_hex_hash(md5, 32) {
                return Err("Invalid MD5 hash format".to_string());
            }
        }

        // Validate SHA-1 if present
        if let Some(ref sha1) = self.sha1 {
            if !Self::is_valid_hex_hash(sha1, 40) {
                return Err("Invalid SHA-1 hash format".to_string());
            }
        }

        // Validate additional hashes
        if let Some(ref additional) = self.additional {
            for (name, value) in additional {
                if name.trim().is_empty() {
                    return Err("Hash name cannot be empty".to_string());
                }
                if value.trim().is_empty() {
                    return Err(format!("Hash value for '{}' cannot be empty", name));
                }
                // For additional hashes, just check they're not empty hex
                if !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!("Hash value for '{}' must be hex", name));
                }
            }
        }

        Ok(())
    }

    /// Check if the hashes are valid.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Check if a string is a valid hex hash of the expected length.
    fn is_valid_hex_hash(s: &str, expected_len: usize) -> bool {
        s.len() == expected_len && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl fmt::Display for Hashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(ref sha256) = self.sha256 {
            parts.push(format!("SHA256:{}", &sha256[..16]));
        }
        if let Some(ref md5) = self.md5 {
            parts.push(format!("MD5:{}", &md5[..16]));
        }
        if let Some(ref sha1) = self.sha1 {
            parts.push(format!("SHA1:{}", &sha1[..16]));
        }
        if let Some(ref additional) = self.additional {
            parts.push(format!("+{} more", additional.len()));
        }

        if parts.is_empty() {
            write!(f, "No hashes")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

/// A program under analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[pyclass]
pub struct Binary {
    /// Unique identifier for this binary
    #[pyo3(get, set)]
    pub id: String,
    /// Filesystem path to the binary
    #[pyo3(get, set)]
    pub path: String,
    /// Executable format
    #[pyo3(get, set)]
    pub format: Format,
    /// CPU architecture
    #[pyo3(get, set)]
    pub arch: Arch,
    /// Bit width (32 or 64)
    #[pyo3(get, set)]
    pub bits: u8,
    /// Endianness
    #[pyo3(get, set)]
    pub endianness: Endianness,
    /// Entry point addresses
    #[pyo3(get, set)]
    pub entry_points: Vec<Address>,
    /// Size in bytes
    #[pyo3(get, set)]
    pub size_bytes: u64,
    /// Cryptographic hashes
    #[pyo3(get, set)]
    pub hashes: Option<Hashes>,
    /// UUID/build-id (Mach-O UUID, ELF build-id)
    #[pyo3(get, set)]
    pub uuid: Option<String>,
    /// Format-specific timestamps
    #[pyo3(get, set)]
    pub timestamps: Option<HashMap<String, u64>>,
}

#[pymethods]
impl Binary {
    /// Create a new Binary instance.
    ///
    /// Args:
    ///     id: Unique identifier for the binary
    ///     path: Filesystem path to the binary
    ///     format: Executable format (Format enum)
    ///     arch: CPU architecture (Arch enum)
    ///     bits: Bit width (32 or 64)
    ///     endianness: Endianness (Endianness enum)
    ///     entry_points: List of entry point addresses
    ///     size_bytes: Size in bytes
    ///     hashes: Cryptographic hashes (optional)
    ///     uuid: UUID/build-id (optional)
    ///     timestamps: Format-specific timestamps (optional)
    ///
    /// Returns:
    ///     Binary: A new Binary instance
    #[new]
    #[pyo3(signature = (
        id,
        path,
        format,
        arch,
        bits,
        endianness,
        entry_points,
        size_bytes,
        hashes=None,
        uuid=None,
        timestamps=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new_py(
        id: String,
        path: String,
        format: Format,
        arch: Arch,
        bits: u8,
        endianness: Endianness,
        entry_points: Vec<Address>,
        size_bytes: u64,
        hashes: Option<Hashes>,
        uuid: Option<String>,
        timestamps: Option<HashMap<String, u64>>,
    ) -> PyResult<Self> {
        Self::new(
            id,
            path,
            format,
            arch,
            bits,
            endianness,
            entry_points,
            size_bytes,
            hashes,
            uuid,
            timestamps,
        )
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid binary: {}", e))
        })
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        format!(
            "Binary(id={}, path={}, format={}, arch={}, bits={})",
            self.id, self.path, self.format, self.arch, self.bits
        )
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!(
            "Binary(id={:?}, path={:?}, format={:?}, arch={:?}, bits={})",
            self.id, self.path, self.format, self.arch, self.bits
        )
    }

    /// Check if the binary is valid.
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    /// Get the number of entry points.
    ///
    /// Returns:
    ///     int: Number of entry points
    fn entry_point_count(&self) -> usize {
        self.entry_points.len()
    }

    /// Check if the binary has any entry points.
    ///
    /// Returns:
    ///     bool: True if entry points exist
    fn has_entry_points(&self) -> bool {
        !self.entry_points.is_empty()
    }

    /// Get the primary entry point (first one).
    ///
    /// Returns:
    ///     Address or None: Primary entry point if available
    fn primary_entry_point(&self) -> Option<Address> {
        self.entry_points.first().cloned()
    }

    /// Check if the binary is 64-bit.
    ///
    /// Returns:
    ///     bool: True if 64-bit
    fn is_64_bit(&self) -> bool {
        self.bits == 64
    }

    /// Check if the binary has cryptographic hashes.
    ///
    /// Returns:
    ///     bool: True if hashes are present
    fn has_hashes(&self) -> bool {
        self.hashes.is_some()
    }

    /// Get a timestamp by name.
    ///
    /// Args:
    ///     name: Timestamp name (e.g., 'TimeDateStamp' for PE)
    ///
    /// Returns:
    ///     int or None: Timestamp value if found
    fn get_timestamp(&self, name: &str) -> Option<u64> {
        self.timestamps.as_ref()?.get(name).copied()
    }

    /// Set a timestamp value.
    ///
    /// Args:
    ///     name: Timestamp name
    ///     value: Timestamp value
    fn set_timestamp(&mut self, name: String, value: u64) {
        self.timestamps
            .get_or_insert_with(HashMap::new)
            .insert(name, value);
    }

    /// Serialize to JSON string.
    fn to_json_py(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Serialization error: {}", e))
        })
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json_py(json_str: &str) -> PyResult<Self> {
        serde_json::from_str(json_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Deserialization error: {}", e))
        })
    }
}

impl Binary {
    /// Create a new Binary instance.
    ///
    /// # Arguments
    /// * `id` - Unique identifier
    /// * `path` - Filesystem path
    /// * `format` - Executable format
    /// * `arch` - CPU architecture
    /// * `bits` - Bit width (32 or 64)
    /// * `endianness` - Endianness
    /// * `entry_points` - Entry point addresses
    /// * `size_bytes` - Size in bytes
    /// * `hashes` - Cryptographic hashes
    /// * `uuid` - UUID/build-id
    /// * `timestamps` - Format-specific timestamps
    ///
    /// # Errors
    /// Returns an error if validation fails
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        path: String,
        format: Format,
        arch: Arch,
        bits: u8,
        endianness: Endianness,
        entry_points: Vec<Address>,
        size_bytes: u64,
        hashes: Option<Hashes>,
        uuid: Option<String>,
        timestamps: Option<HashMap<String, u64>>,
    ) -> Result<Self, String> {
        let binary = Self {
            id,
            path,
            format,
            arch,
            bits,
            endianness,
            entry_points,
            size_bytes,
            hashes,
            uuid,
            timestamps,
        };

        binary.validate()?;
        Ok(binary)
    }

    /// Validate the binary.
    pub fn validate(&self) -> Result<(), String> {
        // Validate ID
        if self.id.trim().is_empty() {
            return Err("Binary ID cannot be empty".to_string());
        }

        // Validate path
        if self.path.trim().is_empty() {
            return Err("Binary path cannot be empty".to_string());
        }

        // Validate bits
        if ![32, 64].contains(&self.bits) {
            return Err("Bits must be 32 or 64".to_string());
        }

        // Validate architecture and bits consistency
        if self.arch.is_64_bit() && self.bits != 64 {
            return Err("64-bit architecture requires bits=64".to_string());
        }
        if !self.arch.is_64_bit() && self.bits != 32 {
            return Err("32-bit architecture requires bits=32".to_string());
        }

        // Validate size
        if self.size_bytes == 0 {
            return Err("Size cannot be 0".to_string());
        }

        // Validate entry points
        for (i, entry_point) in self.entry_points.iter().enumerate() {
            if !entry_point.is_valid() {
                return Err(format!("Invalid entry point at index {}", i));
            }
        }

        // Validate hashes if present
        if let Some(ref hashes) = self.hashes {
            if !hashes.is_valid() {
                return Err("Invalid hashes".to_string());
            }
        }

        Ok(())
    }

    /// Check if the binary is valid.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_format_display() {
        assert_eq!(format!("{}", Format::ELF), "ELF");
        assert_eq!(format!("{}", Format::PE), "PE");
        assert_eq!(format!("{}", Format::MachO), "MachO");
    }

    #[test]
    fn test_arch_bits() {
        assert_eq!(Arch::X86.bits(), 32);
        assert_eq!(Arch::X86_64.bits(), 64);
        assert_eq!(Arch::ARM.bits(), 32);
        assert_eq!(Arch::AArch64.bits(), 64);
    }

    #[test]
    fn test_arch_is_64_bit() {
        assert!(!Arch::X86.is_64_bit());
        assert!(Arch::X86_64.is_64_bit());
        assert!(!Arch::ARM.is_64_bit());
        assert!(Arch::AArch64.is_64_bit());
    }

    #[test]
    fn test_hashes_creation() {
        let hashes = Hashes::new(
            Some("abcd1234".repeat(8)),
            Some("abcd1234".repeat(4)),
            Some("abcd1234".repeat(5)),
            None,
        )
        .unwrap();

        assert!(hashes.has_sha256());
        assert!(hashes.has_any_hash());
        assert_eq!(hashes.get_hash("sha256"), Some("abcd1234".repeat(8)));
    }

    #[test]
    fn test_hashes_validation() {
        // Valid hashes
        let valid = Hashes::new(Some("a".repeat(64)), Some("b".repeat(32)), None, None).unwrap();
        assert!(valid.is_valid());

        // Invalid SHA-256 length
        let invalid = Hashes::new(Some("short".to_string()), None, None, None);
        assert!(invalid.is_err());

        // Invalid hex characters
        let invalid = Hashes::new(Some("gggggggg".repeat(8).to_string()), None, None, None);
        assert!(invalid.is_err());
    }

    #[test]
    fn test_binary_creation() {
        let entry_point = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let hashes = Hashes::new(Some("a".repeat(64)), None, None, None).unwrap();

        let binary = Binary::new(
            "test-binary".to_string(),
            "/path/to/binary".to_string(),
            Format::ELF,
            Arch::X86_64,
            64,
            Endianness::Little,
            vec![entry_point.clone()],
            1024,
            Some(hashes),
            Some("uuid-123".to_string()),
            None,
        )
        .unwrap();

        assert_eq!(binary.id, "test-binary");
        assert_eq!(binary.format, Format::ELF);
        assert_eq!(binary.arch, Arch::X86_64);
        assert_eq!(binary.bits, 64);
        assert!(binary.is_64_bit());
        assert_eq!(binary.entry_points.len(), 1);
        assert_eq!(binary.primary_entry_point(), Some(entry_point));
        assert!(binary.has_entry_points());
        assert!(binary.has_hashes());
    }

    #[test]
    fn test_binary_validation() {
        let entry_point = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();

        // Valid binary
        let valid = Binary::new(
            "test".to_string(),
            "/path".to_string(),
            Format::PE,
            Arch::X86,
            32,
            Endianness::Little,
            vec![entry_point],
            1024,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(valid.is_valid());

        // Invalid: empty ID
        let invalid = Binary::new(
            "".to_string(),
            "/path".to_string(),
            Format::PE,
            Arch::X86,
            32,
            Endianness::Little,
            vec![],
            1024,
            None,
            None,
            None,
        );
        assert!(invalid.is_err());

        // Invalid: architecture/bits mismatch
        let invalid = Binary::new(
            "test".to_string(),
            "/path".to_string(),
            Format::PE,
            Arch::X86_64,
            32, // Should be 64
            Endianness::Little,
            vec![],
            1024,
            None,
            None,
            None,
        );
        assert!(invalid.is_err());
    }

    #[test]
    fn test_binary_serialization() {
        let entry_point = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();

        let original = Binary::new(
            "test-binary".to_string(),
            "/path/to/binary".to_string(),
            Format::ELF,
            Arch::X86,
            32,
            Endianness::Little,
            vec![entry_point],
            1024,
            None,
            None,
            None,
        )
        .unwrap();

        // JSON serialization
        let json_str = original.to_json_py().unwrap();
        let deserialized = Binary::from_json_py(&json_str).unwrap();

        assert_eq!(original, deserialized);
    }
}
