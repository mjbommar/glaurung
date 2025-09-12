//! Unified PE parser implementation

use std::cell::OnceCell;
use std::collections::BTreeMap;

pub mod directories;
pub mod headers;
pub mod sections;
pub mod types;
pub mod utils;

use directories::*;
use headers::*;
use sections::*;
pub use types::*;
use utils::*;

/// Main PE parser
pub struct PeParser<'data> {
    data: &'data [u8],
    dos_header: DosHeader,
    nt_headers: NtHeaders,
    data_directories: Vec<DataDirectory>,
    section_table: SectionTable,
    options: ParseOptions,

    // Lazy-loaded data
    imports: OnceCell<ImportTable<'data>>,
    exports: OnceCell<ExportTable<'data>>,
}

impl<'data> PeParser<'data> {
    /// Create parser with default options
    pub fn new(data: &'data [u8]) -> Result<Self> {
        Self::with_options(data, ParseOptions::default())
    }

    /// Create parser with custom options
    pub fn with_options(data: &'data [u8], options: ParseOptions) -> Result<Self> {
        // Parse DOS header
        let dos_header = parse_dos_header(data)?;

        // Parse NT headers
        let (nt_headers, data_directories) = parse_nt_headers(data, dos_header.e_lfanew as usize)?;

        // Parse section headers
        let section_offset = dos_header.e_lfanew as usize
            + 24
            + nt_headers.file_header.size_of_optional_header as usize;
        let section_headers = parse_section_headers(
            data,
            section_offset,
            nt_headers.file_header.number_of_sections,
        )?;

        // Create section table
        let sections = create_sections(section_headers);
        let section_table = SectionTable::new(sections);

        Ok(Self {
            data,
            dos_header,
            nt_headers,
            data_directories,
            section_table,
            options,
            imports: OnceCell::new(),
            exports: OnceCell::new(),
        })
    }

    // Header access methods

    /// Get DOS header
    pub fn dos_header(&self) -> &DosHeader {
        &self.dos_header
    }

    /// Get NT headers
    pub fn nt_headers(&self) -> &NtHeaders {
        &self.nt_headers
    }

    /// Get optional header
    pub fn optional_header(&self) -> &OptionalHeader {
        &self.nt_headers.optional_header
    }

    /// Check if PE is 64-bit
    pub fn is_64bit(&self) -> bool {
        self.nt_headers.optional_header.is_64bit()
    }

    /// Get machine type
    pub fn machine(&self) -> Machine {
        self.nt_headers.file_header.machine
    }

    /// Get entry point RVA
    pub fn entry_point(&self) -> u32 {
        self.nt_headers.optional_header.entry_point()
    }

    /// Get image base
    pub fn image_base(&self) -> u64 {
        self.nt_headers.optional_header.image_base()
    }

    /// Get subsystem
    pub fn subsystem(&self) -> Subsystem {
        self.nt_headers.optional_header.subsystem()
    }

    // Section access methods

    /// Get all sections
    pub fn sections(&self) -> &[Section] {
        self.section_table.sections()
    }

    /// Find section by name
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.section_table.section_by_name(name)
    }

    /// Find section containing RVA
    pub fn section_containing_rva(&self, rva: u32) -> Option<&Section> {
        self.section_table.section_containing_rva(rva)
    }

    /// Get entry point section
    pub fn entry_section(&self) -> Option<String> {
        self.section_table
            .entry_section(self.entry_point())
            .map(|s| s.header.name())
    }

    // Import/Export methods

    /// Get imports (lazy-loaded)
    pub fn imports(&self) -> Result<&ImportTable<'data>> {
        if let Some(imports) = self.imports.get() {
            return Ok(imports);
        }

        let import_dir = self.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)?;
        let delay_dir = self.data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?;

        let imports = parse_imports(
            self.data,
            &self.section_table,
            import_dir,
            delay_dir,
            self.image_base(),
            self.is_64bit(),
            &self.options,
        )?;

        Ok(self.imports.get_or_init(|| imports))
    }

    /// Get exports (lazy-loaded)
    pub fn exports(&self) -> Result<&ExportTable<'data>> {
        if let Some(exports) = self.exports.get() {
            return Ok(exports);
        }

        let export_dir = self.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)?;

        let exports = parse_exports(self.data, &self.section_table, export_dir, &self.options)?;

        Ok(self.exports.get_or_init(|| exports))
    }

    /// Get import hash (imphash)
    pub fn import_hash(&self) -> Result<String> {
        Ok(self.imports()?.import_hash())
    }

    /// Get IAT map for resolving indirect calls
    pub fn iat_map(&self) -> Result<BTreeMap<u64, String>> {
        let imports = self.imports()?;
        Ok(imports
            .iat_map
            .iter()
            .map(|(&va, &name)| (va, name.to_string()))
            .collect())
    }

    // Security features

    /// Get security features
    pub fn security_features(&self) -> SecurityFeatures {
        parse_security_features(self.nt_headers.optional_header.dll_characteristics())
    }

    /// Check if ASLR is enabled
    pub fn has_aslr(&self) -> bool {
        self.security_features().aslr_enabled
    }

    /// Check if DEP/NX is enabled
    pub fn has_nx(&self) -> bool {
        self.security_features().nx_compatible
    }

    /// Check if CFG is enabled
    pub fn has_cfg(&self) -> bool {
        self.security_features().cfg_enabled
    }

    // Utilities

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.section_table.rva_to_offset(rva)
    }

    /// Convert file offset to RVA
    pub fn offset_to_rva(&self, offset: usize) -> Option<u32> {
        self.section_table.offset_to_rva(offset)
    }

    /// Read string at RVA
    pub fn read_string_at_rva(&self, rva: u32) -> Result<&'data str> {
        let offset = self.rva_to_offset(rva).ok_or(PeError::InvalidRva { rva })?;
        read_cstring(self.data, offset, 1024)
    }

    /// Get data directory by index
    pub fn data_directory(&self, index: usize) -> Result<&DataDirectory> {
        self.data_directories
            .get(index)
            .ok_or(PeError::DataDirectoryNotFound { index })
    }

    /// Check if file has debug info
    pub fn has_debug_info(&self) -> bool {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)
            .map(|d| d.virtual_address != 0 && d.size > 0)
            .unwrap_or(false)
    }

    /// Check if file has resources
    pub fn has_resources(&self) -> bool {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)
            .map(|d| d.virtual_address != 0 && d.size > 0)
            .unwrap_or(false)
    }

    /// Check if file has relocations
    pub fn has_relocations(&self) -> bool {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .map(|d| d.virtual_address != 0 && d.size > 0)
            .unwrap_or(false)
    }

    /// Check if file has TLS
    pub fn has_tls(&self) -> bool {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_TLS)
            .map(|d| d.virtual_address != 0 && d.size > 0)
            .unwrap_or(false)
    }

    /// Check if file is signed (has certificate table)
    pub fn is_signed(&self) -> bool {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
            .map(|d| d.virtual_address != 0 && d.size > 0)
            .unwrap_or(false)
    }

    /// Check if file is .NET/CLR
    pub fn is_dotnet(&self) -> bool {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            .map(|d| d.virtual_address != 0 && d.size > 0)
            .unwrap_or(false)
    }

    /// Validate checksum
    pub fn checksum_valid(&self) -> bool {
        let stored = self.nt_headers.optional_header.checksum();
        if stored == 0 {
            return true; // No checksum to validate
        }

        let checksum_offset = self.dos_header.e_lfanew as usize + 24 + 64; // Approximate
        let calculated = calculate_pe_checksum(self.data, checksum_offset);
        stored == calculated
    }

    /// Detect anomalies
    pub fn anomalies(&self) -> Vec<PeAnomaly> {
        let mut anomalies = self.section_table.detect_anomalies();

        // Check for suspicious entry point
        if let Some(entry_section) = self.entry_section() {
            if !entry_section.starts_with(".text") && !entry_section.starts_with("CODE") {
                anomalies.push(PeAnomaly::SuspiciousEntryPoint {
                    section: entry_section,
                });
            }
        }

        // Check for invalid timestamp
        let timestamp = self.nt_headers.file_header.time_date_stamp;
        if timestamp != 0 {
            // Check if timestamp is reasonable (between 1990 and 2030)
            let year_1990 = 631152000u32;
            let year_2030 = 1893456000u32;
            if timestamp < year_1990 || timestamp > year_2030 {
                anomalies.push(PeAnomaly::InvalidTimestamp { value: timestamp });
            }
        }

        // Check for TLS callbacks
        if self.has_tls() {
            anomalies.push(PeAnomaly::TlsCallbackPresent { count: 0 }); // Would need to parse TLS
        }

        // Check for high entropy sections (likely packed)
        let high_entropy = self.section_table.has_high_entropy_sections(self.data);
        for (section, entropy) in high_entropy {
            anomalies.push(PeAnomaly::EntropyAnomaly { section, entropy });
        }

        anomalies
    }

    /// Simple packer detection
    pub fn packer_detection(&self) -> PackerDetection {
        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;
        let mut packer_name = None;

        // Check section names
        for section in self.sections() {
            let name = section.header.name();
            if name.contains("UPX") {
                packer_name = Some("UPX".to_string());
                confidence = 0.9;
                indicators.push("UPX section name".to_string());
            } else if name.contains("ASPack") {
                packer_name = Some("ASPack".to_string());
                confidence = 0.9;
                indicators.push("ASPack section name".to_string());
            } else if name == ".nsp0" || name == ".nsp1" {
                packer_name = Some("NsPack".to_string());
                confidence = 0.8;
                indicators.push("NsPack section name".to_string());
            }
        }

        // Check for high entropy executable sections
        let exec_sections = self.section_table.executable_sections();
        for section in exec_sections {
            if let Some(entropy) = section.entropy(self.data) {
                if entropy > 7.0 {
                    indicators.push(format!(
                        "High entropy in {}: {:.2}",
                        section.header.name(),
                        entropy
                    ));
                    confidence = confidence.max(0.6);
                }
            }
        }

        // Check for few imports (packed files often have minimal imports)
        if let Ok(imports) = self.imports() {
            if imports.count() < 10 {
                indicators.push(format!("Low import count: {}", imports.count()));
                confidence = confidence.max(0.4);
            }
        }

        // Check for TLS callbacks (often used by packers)
        if self.has_tls() {
            indicators.push("TLS callbacks present".to_string());
            confidence = confidence.max(0.3);
        }

        PackerDetection {
            is_packed: confidence > 0.5,
            packer_name,
            confidence,
            indicators,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header
        data[0] = 0x4D; // MZ
        data[1] = 0x5A;
        data[60] = 0x80; // e_lfanew

        // PE signature at offset 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;

        // COFF header at 0x84
        data[0x84] = 0x4C; // Machine: x86
        data[0x85] = 0x01;
        data[0x86] = 0x01; // Number of sections: 1
        data[0x87] = 0x00;
        data[0x94] = 0x60; // Size of optional header
        data[0x95] = 0x00;

        // Optional header at 0x98
        data[0x98] = 0x0B; // Magic: PE32
        data[0x99] = 0x01;

        // Entry point
        data[0xA8] = 0x00;
        data[0xA9] = 0x10;
        data[0xAA] = 0x00;
        data[0xAB] = 0x00;

        // Image base
        data[0xB4] = 0x00;
        data[0xB5] = 0x00;
        data[0xB6] = 0x40;
        data[0xB7] = 0x00;

        // Number of RVA and sizes
        data[0xE4] = 0x10;

        // Section header at 0xF8
        let section_offset = 0xF8;
        data[section_offset..section_offset + 5].copy_from_slice(b".text");

        // Virtual size
        data[section_offset + 8] = 0x00;
        data[section_offset + 9] = 0x10;

        // Virtual address
        data[section_offset + 12] = 0x00;
        data[section_offset + 13] = 0x10;

        // Size of raw data
        data[section_offset + 16] = 0x00;
        data[section_offset + 17] = 0x02;

        // Pointer to raw data
        data[section_offset + 20] = 0x00;
        data[section_offset + 21] = 0x02;

        // Characteristics (executable, readable)
        data[section_offset + 36] = 0x20;
        data[section_offset + 39] = 0x60;

        data
    }

    #[test]
    fn test_parse_minimal_pe() {
        let data = create_minimal_pe();
        let parser = PeParser::new(&data).unwrap();

        assert_eq!(parser.machine(), Machine::I386);
        assert!(!parser.is_64bit());
        assert_eq!(parser.entry_point(), 0x1000);
        assert_eq!(parser.image_base(), 0x400000);

        let sections = parser.sections();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header.name(), ".text");
    }

    #[test]
    fn test_rva_to_offset() {
        let data = create_minimal_pe();
        let parser = PeParser::new(&data).unwrap();

        // RVA 0x1000 should map to offset 0x200
        assert_eq!(parser.rva_to_offset(0x1000), Some(0x200));

        // Invalid RVA should return None
        assert_eq!(parser.rva_to_offset(0x5000), None);
    }

    #[test]
    fn test_security_features() {
        let data = create_minimal_pe();
        let parser = PeParser::new(&data).unwrap();

        let features = parser.security_features();
        assert!(!features.aslr_enabled);
        assert!(!features.nx_compatible);
        assert!(!features.cfg_enabled);
    }

    #[test]
    fn test_anomaly_detection() {
        let data = create_minimal_pe();
        let parser = PeParser::new(&data).unwrap();

        let anomalies = parser.anomalies();
        // Minimal PE should have no major anomalies
        assert!(anomalies.is_empty() || anomalies.len() < 3);
    }

    #[test]
    fn test_packer_detection() {
        let data = create_minimal_pe();
        let parser = PeParser::new(&data).unwrap();

        let detection = parser.packer_detection();
        // Minimal PE should not be detected as packed
        assert!(!detection.is_packed);
        assert!(detection.confidence < 0.5);
    }
}
