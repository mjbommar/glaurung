//! Core PE data types and structures

use std::fmt;
use std::ops::Range;

// PE constants
pub const DOS_SIGNATURE: u16 = 0x5A4D; // MZ
pub const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
pub const PE32_MAGIC: u16 = 0x10B;
pub const PE32PLUS_MAGIC: u16 = 0x20B;

// Data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// DLL characteristics
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

// Section characteristics
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// PE parsing error types
#[derive(Debug, Clone)]
pub enum PeError {
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidMachine(u16),
    InvalidMagic(u16),
    TruncatedHeader { expected: usize, actual: usize },
    InvalidRva { rva: u32 },
    InvalidOffset { offset: usize },
    MalformedImportTable,
    MalformedExportTable,
    MalformedResourceDirectory,
    ResourceDepthExceeded,
    SectionNotFound { name: String },
    DataDirectoryNotFound { index: usize },
    Timeout,
    LimitExceeded(&'static str),
    InvalidString,
    IoError(String),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDosSignature => write!(f, "Invalid DOS signature"),
            Self::InvalidPeSignature => write!(f, "Invalid PE signature"),
            Self::InvalidMachine(m) => write!(f, "Invalid machine type: 0x{:04x}", m),
            Self::InvalidMagic(m) => write!(f, "Invalid optional header magic: 0x{:04x}", m),
            Self::TruncatedHeader { expected, actual } => {
                write!(
                    f,
                    "Truncated header: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidRva { rva } => write!(f, "Invalid RVA: 0x{:08x}", rva),
            Self::InvalidOffset { offset } => write!(f, "Invalid file offset: 0x{:x}", offset),
            Self::MalformedImportTable => write!(f, "Malformed import table"),
            Self::MalformedExportTable => write!(f, "Malformed export table"),
            Self::MalformedResourceDirectory => write!(f, "Malformed resource directory"),
            Self::ResourceDepthExceeded => write!(f, "Resource directory depth exceeded"),
            Self::SectionNotFound { name } => write!(f, "Section not found: {}", name),
            Self::DataDirectoryNotFound { index } => {
                write!(f, "Data directory {} not found", index)
            }
            Self::Timeout => write!(f, "Parsing timeout exceeded"),
            Self::LimitExceeded(what) => write!(f, "Limit exceeded: {}", what),
            Self::InvalidString => write!(f, "Invalid string encoding"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for PeError {}

pub type Result<T> = std::result::Result<T, PeError>;

/// Machine types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    Unknown,
    I386,   // 0x014c
    X86_64, // 0x8664
    Arm,    // 0x01c0
    Arm64,  // 0xaa64
    ArmNT,  // 0x01c4
    IA64,   // 0x0200
    EBC,    // 0x0ebc
    Other(u16),
}

impl From<u16> for Machine {
    fn from(value: u16) -> Self {
        match value {
            0x014c => Self::I386,
            0x8664 => Self::X86_64,
            0x01c0 => Self::Arm,
            0xaa64 => Self::Arm64,
            0x01c4 => Self::ArmNT,
            0x0200 => Self::IA64,
            0x0ebc => Self::EBC,
            0 => Self::Unknown,
            other => Self::Other(other),
        }
    }
}

/// Subsystem types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    Unknown,
    Native,                 // 1
    WindowsGui,             // 2
    WindowsCui,             // 3
    Os2Cui,                 // 5
    PosixCui,               // 7
    WindowsCeGui,           // 9
    EfiApplication,         // 10
    EfiBootServiceDriver,   // 11
    EfiRuntimeDriver,       // 12
    EfiRom,                 // 13
    Xbox,                   // 14
    WindowsBootApplication, // 16
    Other(u16),
}

impl From<u16> for Subsystem {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Unknown,
            1 => Self::Native,
            2 => Self::WindowsGui,
            3 => Self::WindowsCui,
            5 => Self::Os2Cui,
            7 => Self::PosixCui,
            9 => Self::WindowsCeGui,
            10 => Self::EfiApplication,
            11 => Self::EfiBootServiceDriver,
            12 => Self::EfiRuntimeDriver,
            13 => Self::EfiRom,
            14 => Self::Xbox,
            16 => Self::WindowsBootApplication,
            other => Self::Other(other),
        }
    }
}

/// DOS header (64 bytes)
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_magic: u16,    // Magic number (MZ)
    pub e_cblp: u16,     // Bytes on last page of file
    pub e_cp: u16,       // Pages in file
    pub e_crlc: u16,     // Relocations
    pub e_cparhdr: u16,  // Size of header in paragraphs
    pub e_minalloc: u16, // Minimum extra paragraphs needed
    pub e_maxalloc: u16, // Maximum extra paragraphs needed
    pub e_ss: u16,       // Initial (relative) SS value
    pub e_sp: u16,       // Initial SP value
    pub e_csum: u16,     // Checksum
    pub e_ip: u16,       // Initial IP value
    pub e_cs: u16,       // Initial (relative) CS value
    pub e_lfarlc: u16,   // File address of relocation table
    pub e_ovno: u16,     // Overlay number
    pub e_lfanew: u32,   // File address of PE header
}

/// COFF header (20 bytes)
#[derive(Debug, Clone, Copy)]
pub struct CoffHeader {
    pub machine: Machine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Data directory entry
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Optional header - common fields
#[derive(Debug, Clone)]
pub struct OptionalHeaderCommon {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
}

/// 32-bit optional header
#[derive(Debug, Clone)]
pub struct OptionalHeader32 {
    pub common: OptionalHeaderCommon,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: Subsystem,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// 64-bit optional header
#[derive(Debug, Clone)]
pub struct OptionalHeader64 {
    pub common: OptionalHeaderCommon,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: Subsystem,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// Combined optional header enum
#[derive(Debug, Clone)]
pub enum OptionalHeader {
    Pe32(OptionalHeader32),
    Pe32Plus(OptionalHeader64),
}

impl OptionalHeader {
    pub fn magic(&self) -> u16 {
        match self {
            Self::Pe32(h) => h.common.magic,
            Self::Pe32Plus(h) => h.common.magic,
        }
    }

    pub fn entry_point(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.common.address_of_entry_point,
            Self::Pe32Plus(h) => h.common.address_of_entry_point,
        }
    }

    pub fn image_base(&self) -> u64 {
        match self {
            Self::Pe32(h) => h.image_base as u64,
            Self::Pe32Plus(h) => h.image_base,
        }
    }

    pub fn subsystem(&self) -> Subsystem {
        match self {
            Self::Pe32(h) => h.subsystem,
            Self::Pe32Plus(h) => h.subsystem,
        }
    }

    pub fn dll_characteristics(&self) -> u16 {
        match self {
            Self::Pe32(h) => h.dll_characteristics,
            Self::Pe32Plus(h) => h.dll_characteristics,
        }
    }

    pub fn checksum(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.checksum,
            Self::Pe32Plus(h) => h.checksum,
        }
    }

    pub fn number_of_rva_and_sizes(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.number_of_rva_and_sizes,
            Self::Pe32Plus(h) => h.number_of_rva_and_sizes,
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, Self::Pe32Plus(_))
    }
}

/// NT headers (PE signature + COFF + Optional)
#[derive(Debug, Clone)]
pub struct NtHeaders {
    pub signature: [u8; 4],
    pub file_header: CoffHeader,
    pub optional_header: OptionalHeader,
}

/// Section header
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.size_of_raw_data);
        rva >= self.virtual_address && rva < self.virtual_address + size
    }

    pub fn is_executable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
    }

    pub fn is_readable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_READ) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_WRITE) != 0
    }

    pub fn contains_code(&self) -> bool {
        (self.characteristics & IMAGE_SCN_CNT_CODE) != 0
    }
}

/// Section with data reference
#[derive(Debug, Clone)]
pub struct Section {
    pub header: SectionHeader,
    pub data: Range<usize>, // Range in file
}

/// Import descriptor
#[derive(Debug, Clone)]
pub struct ImportDescriptor<'a> {
    pub dll_name: &'a str,
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub first_thunk: u32,
    pub entries: Vec<ImportEntry<'a>>,
}

/// Import entry
#[derive(Debug, Clone)]
pub struct ImportEntry<'a> {
    pub name: Option<&'a str>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub iat_va: u64,
}

/// Export entry
#[derive(Debug, Clone)]
pub struct ExportEntry<'a> {
    pub name: Option<&'a str>,
    pub ordinal: u32,
    pub rva: u32,
    pub forwarder: Option<&'a str>,
}

/// Security features
#[derive(Debug, Clone, Default)]
pub struct SecurityFeatures {
    pub nx_compatible: bool,
    pub aslr_enabled: bool,
    pub dep_enabled: bool,
    pub cfg_enabled: bool,
    pub seh_enabled: bool,
    pub safe_seh: bool,
    pub high_entropy_va: bool,
    pub force_integrity: bool,
    pub isolation_aware: bool,
    pub no_bind: bool,
    pub appcontainer: bool,
    pub wdm_driver: bool,
    pub terminal_server_aware: bool,
}

/// Parse options
#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub parse_imports: bool,
    pub parse_exports: bool,
    pub parse_resources: bool,
    pub parse_certificates: bool,
    pub parse_debug_info: bool,
    pub parse_rich_header: bool,
    pub parse_relocations: bool,
    pub parse_tls: bool,
    pub max_resource_depth: usize,
    pub max_imports: usize,
    pub max_exports: usize,
    pub timeout_ms: Option<u64>,
    pub validate_checksums: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            parse_imports: true,
            parse_exports: true,
            parse_resources: true,
            parse_certificates: true,
            parse_debug_info: true,
            parse_rich_header: true,
            parse_relocations: true,
            parse_tls: true,
            max_resource_depth: 32,
            max_imports: 10000,
            max_exports: 10000,
            timeout_ms: None,
            validate_checksums: false,
        }
    }
}

/// Rich header entry
#[derive(Debug, Clone)]
pub struct RichHeaderEntry {
    pub product_id: u16,
    pub build_id: u16,
    pub use_count: u32,
    pub tool_name: Option<String>,
}

/// Rich header
#[derive(Debug, Clone)]
pub struct RichHeader {
    pub offset: u32,
    pub size: u32,
    pub xor_key: u32,
    pub entries: Vec<RichHeaderEntry>,
    pub checksum_valid: bool,
    pub rich_hash: String,
}

/// Debug directory entry
#[derive(Debug, Clone)]
pub struct DebugEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// TLS directory
#[derive(Debug, Clone)]
pub struct TlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

/// Certificate/Authenticode entry
#[derive(Debug, Clone)]
pub struct Certificate {
    pub certificate_type: u16,
    pub data: Vec<u8>,
}

/// Resource directory node
#[derive(Debug, Clone)]
pub enum ResourceNode<'a> {
    Directory { entries: Vec<ResourceEntry<'a>> },
    Data { data: &'a [u8], code_page: u32 },
}

/// Resource entry
#[derive(Debug, Clone)]
pub struct ResourceEntry<'a> {
    pub id: ResourceId<'a>,
    pub node: ResourceNode<'a>,
}

/// Resource ID
#[derive(Debug, Clone)]
pub enum ResourceId<'a> {
    Name(&'a str),
    Id(u32),
}

/// Anomaly types for detection
#[derive(Debug, Clone)]
pub enum PeAnomaly {
    SuspiciousEntryPoint { section: String },
    UnusualSectionName { name: String },
    OverlappingSections { section1: String, section2: String },
    SectionSizeMismatch { section: String },
    InvalidTimestamp { value: u32 },
    SuspiciousImport { name: String },
    TlsCallbackPresent { count: usize },
    PackerDetected { packer: String },
    EntropyAnomaly { section: String, entropy: f64 },
    CertificateAnomaly { reason: String },
}

/// Packer detection result
#[derive(Debug, Clone)]
pub struct PackerDetection {
    pub is_packed: bool,
    pub packer_name: Option<String>,
    pub confidence: f32,
    pub indicators: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_from_u16() {
        assert_eq!(Machine::from(0x014c), Machine::I386);
        assert_eq!(Machine::from(0x8664), Machine::X86_64);
        assert_eq!(Machine::from(0xaa64), Machine::Arm64);
        assert_eq!(Machine::from(0x9999), Machine::Other(0x9999));
    }

    #[test]
    fn test_subsystem_from_u16() {
        assert_eq!(Subsystem::from(2), Subsystem::WindowsGui);
        assert_eq!(Subsystem::from(3), Subsystem::WindowsCui);
        assert_eq!(Subsystem::from(10), Subsystem::EfiApplication);
        assert_eq!(Subsystem::from(999), Subsystem::Other(999));
    }

    #[test]
    fn test_section_header_name() {
        let mut header = SectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: 0,
        };

        // Test with null-terminated string
        header.name[0..5].copy_from_slice(b".text");
        assert_eq!(header.name(), ".text");

        // Test with full 8-byte name
        header.name.copy_from_slice(b".textbss");
        assert_eq!(header.name(), ".textbss");
    }

    #[test]
    fn test_section_contains_rva() {
        let header = SectionHeader {
            name: [0; 8],
            virtual_size: 0x1000,
            virtual_address: 0x2000,
            size_of_raw_data: 0x800,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: 0,
        };

        assert!(!header.contains_rva(0x1999));
        assert!(header.contains_rva(0x2000));
        assert!(header.contains_rva(0x2500));
        assert!(header.contains_rva(0x2FFF));
        assert!(!header.contains_rva(0x3000));
    }

    #[test]
    fn test_error_display() {
        let err = PeError::InvalidMachine(0x1234);
        assert_eq!(format!("{}", err), "Invalid machine type: 0x1234");

        let err = PeError::TruncatedHeader {
            expected: 100,
            actual: 50,
        };
        assert_eq!(
            format!("{}", err),
            "Truncated header: expected 100 bytes, got 50"
        );
    }
}
