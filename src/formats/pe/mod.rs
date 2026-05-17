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
    debug: OnceCell<DebugDirectory>,
    resources: OnceCell<ResourceDirectory<'data>>,
    tls: OnceCell<TlsDirectory>,
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
            debug: OnceCell::new(),
            resources: OnceCell::new(),
            tls: OnceCell::new(),
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

    /// Get the debug directory and first CodeView RSDS record, when present.
    pub fn debug_directory(&self) -> Result<&DebugDirectory> {
        if let Some(debug) = self.debug.get() {
            return Ok(debug);
        }

        let debug_dir = self.data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)?;
        let debug = if self.options.parse_debug_info {
            parse_debug_directory(self.data, &self.section_table, debug_dir)?
        } else {
            DebugDirectory::default()
        };

        Ok(self.debug.get_or_init(|| debug))
    }

    /// Get the first CodeView RSDS record from the debug directory.
    pub fn codeview_rsds(&self) -> Result<Option<&CodeViewRsds>> {
        Ok(self.debug_directory()?.codeview.as_ref())
    }

    /// Resolve the first CodeView RSDS record against a local PDB cache.
    pub fn resolve_pdb_cache(
        &self,
        cache_dir: &std::path::Path,
    ) -> Result<Option<std::path::PathBuf>> {
        Ok(self
            .codeview_rsds()?
            .and_then(|rsds| rsds.resolve_pdb_path(cache_dir)))
    }

    /// Get resources (lazy-loaded)
    pub fn resources(&self) -> Result<&ResourceDirectory<'data>> {
        if let Some(resources) = self.resources.get() {
            return Ok(resources);
        }

        let resource_dir = self.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        let resources =
            parse_resources(self.data, &self.section_table, resource_dir, &self.options)?;

        Ok(self.resources.get_or_init(|| resources))
    }

    /// Get the TLS directory + walked callback list (lazy-loaded).
    ///
    /// Returns an empty `TlsDirectory` when the PE has no TLS data
    /// directory entry or when `parse_tls` is disabled in the
    /// parser's `ParseOptions`. Soft errors (truncated header,
    /// unmapped RVA) are recorded in `TlsDirectory::stop_reasons`
    /// rather than failing the call.
    pub fn tls(&self) -> Result<&TlsDirectory> {
        if let Some(tls) = self.tls.get() {
            return Ok(tls);
        }

        let tls_dir = self.data_directory(IMAGE_DIRECTORY_ENTRY_TLS)?;
        let tls = parse_tls(
            self.data,
            &self.section_table,
            tls_dir,
            self.image_base(),
            self.is_64bit(),
            &self.options,
        )?;

        Ok(self.tls.get_or_init(|| tls))
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

    fn create_pe_with_version_resource() -> Vec<u8> {
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
        data[0x94] = 0xE0; // Size of optional header: PE32 standard size
        data[0x95] = 0x00;

        // Optional header at 0x98
        data[0x98] = 0x0B; // Magic: PE32
        data[0x99] = 0x01;
        data[0xA8] = 0x00; // Entry point RVA 0x1000
        data[0xA9] = 0x10;
        data[0xB4] = 0x00; // Image base 0x400000
        data[0xB5] = 0x00;
        data[0xB6] = 0x40;
        data[0xB7] = 0x00;
        data[0xBC] = 0x00; // section alignment 0x1000
        data[0xBD] = 0x10;
        data[0xC0] = 0x00; // file alignment 0x200
        data[0xC1] = 0x02;
        data[0xF4] = 0x10; // NumberOfRvaAndSizes = 16

        // Resource data directory: optional header + 96 + (2 * 8).
        let resource_dir = 0x98 + 96 + (IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
        data[resource_dir] = 0x00;
        data[resource_dir + 1] = 0x10; // RVA 0x1000
        data[resource_dir + 4] = 0x90; // size 0x90

        // Section header at 0x178
        let section_offset = 0x178;
        data[section_offset..section_offset + 5].copy_from_slice(b".rsrc");
        data[section_offset + 8] = 0x00;
        data[section_offset + 9] = 0x02; // VirtualSize 0x200
        data[section_offset + 12] = 0x00;
        data[section_offset + 13] = 0x10; // VirtualAddress 0x1000
        data[section_offset + 16] = 0x00;
        data[section_offset + 17] = 0x02; // SizeOfRawData 0x200
        data[section_offset + 20] = 0x00;
        data[section_offset + 21] = 0x02; // PointerToRawData 0x200
        data[section_offset + 36] = 0x40; // initialized data, readable
        data[section_offset + 39] = 0x40;

        // Resource tree at file offset 0x200, resource RVA 0x1000:
        // root -> VERSIONINFO (16) -> resource id 1 -> language 1033 -> data.
        let base = 0x200usize;
        data[base + 14] = 0x01; // root NumberOfIdEntries
        data[base + 16] = 16; // type id VERSIONINFO
        data[base + 20] = 0x18;
        data[base + 23] = 0x80; // subdirectory at offset 0x18

        let name_dir = base + 0x18;
        data[name_dir + 14] = 0x01;
        data[name_dir + 16] = 0x01; // resource id 1
        data[name_dir + 20] = 0x30;
        data[name_dir + 23] = 0x80; // subdirectory at offset 0x30

        let lang_dir = base + 0x30;
        data[lang_dir + 14] = 0x01;
        data[lang_dir + 16] = 0x09;
        data[lang_dir + 17] = 0x04; // language id 0x0409
        data[lang_dir + 20] = 0x48; // data entry at offset 0x48

        let data_entry = base + 0x48;
        data[data_entry] = 0x80;
        data[data_entry + 1] = 0x10; // DataRVA 0x1080
        data[data_entry + 4] = 0x05; // Size 5
        data[data_entry + 8] = 0xE4;
        data[data_entry + 9] = 0x04; // CodePage 1252

        data[0x280..0x285].copy_from_slice(b"hello");

        data
    }

    fn write_resource_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_resource_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn create_pe_with_named_resource_type() -> Vec<u8> {
        let mut data = create_pe_with_version_resource();
        let base = 0x200usize;
        let name_rel = 0x70usize;
        let name = "WEVT_TEMPLATE";

        write_resource_u16(&mut data, base + 12, 1);
        write_resource_u16(&mut data, base + 14, 0);
        write_resource_u32(&mut data, base + 16, 0x8000_0000 | name_rel as u32);

        write_resource_u16(&mut data, base + name_rel, name.len() as u16);
        for (index, word) in name.encode_utf16().enumerate() {
            write_resource_u16(&mut data, base + name_rel + 2 + (index * 2), word);
        }

        data
    }

    fn create_pe_with_duplicate_overlapping_resources() -> Vec<u8> {
        let mut data = create_pe_with_version_resource();
        let base = 0x200usize;
        let lang_dir = base + 0x30;
        let first_data_entry_rel = 0x60u32;
        let second_data_entry_rel = 0x70u32;

        write_resource_u16(&mut data, lang_dir + 14, 2);
        write_resource_u32(&mut data, lang_dir + 20, first_data_entry_rel);
        write_resource_u32(&mut data, lang_dir + 24, 0x0409);
        write_resource_u32(&mut data, lang_dir + 28, second_data_entry_rel);

        let first_data_entry = base + first_data_entry_rel as usize;
        write_resource_u32(&mut data, first_data_entry, 0x1080);
        write_resource_u32(&mut data, first_data_entry + 4, 5);
        write_resource_u32(&mut data, first_data_entry + 8, 1252);

        let second_data_entry = base + second_data_entry_rel as usize;
        write_resource_u32(&mut data, second_data_entry, 0x1082);
        write_resource_u32(&mut data, second_data_entry + 4, 4);
        write_resource_u32(&mut data, second_data_entry + 8, 1252);

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

    #[test]
    fn test_resource_enumeration_for_version_info() {
        let data = create_pe_with_version_resource();
        let parser = PeParser::new(&data).unwrap();

        assert!(parser.has_resources());
        let resources = parser.resources().unwrap();

        assert_eq!(resources.leaf_count(), 1);
        assert!(resources.stop_reasons.is_empty());
        assert!(resources.warnings.is_empty());

        let resource = &resources.resources[0];
        assert_eq!(resource.type_id.as_id(), Some(16));
        assert_eq!(resource.type_name.as_deref(), Some("VERSIONINFO"));
        assert_eq!(resource.name.as_id(), Some(1));
        assert_eq!(resource.language_id, Some(0x0409));
        assert_eq!(resource.code_page, 1252);
        assert_eq!(resource.data_rva, 0x1080);
        assert_eq!(resource.data_offset, 0x280);
        assert_eq!(resource.size, 5);
        assert_eq!(resource.section_name.as_deref(), Some(".rsrc"));
        assert_eq!(resource.data, b"hello");
        assert_eq!(resource.magic, "ascii_text");
    }

    #[test]
    fn test_resource_enumeration_respects_resource_budget() {
        let data = create_pe_with_version_resource();
        let mut options = ParseOptions::default();
        options.max_resources = 0;
        let parser = PeParser::with_options(&data, options).unwrap();

        let resources = parser.resources().unwrap();
        assert_eq!(resources.leaf_count(), 0);
        assert!(resources
            .stop_reasons
            .iter()
            .any(|reason| reason == "max_resources"));
    }

    #[test]
    fn test_resource_enumeration_decodes_named_resource_type() {
        let data = create_pe_with_named_resource_type();
        let parser = PeParser::new(&data).unwrap();

        let resources = parser.resources().unwrap();

        assert_eq!(resources.leaf_count(), 1);
        assert_eq!(resources.total_named_entries, 1);
        let resource = &resources.resources[0];
        assert_eq!(resource.type_id.as_name(), Some("WEVT_TEMPLATE"));
        assert_eq!(resource.type_name, None);
        assert_eq!(resource.name.as_id(), Some(1));
    }

    #[test]
    fn test_resource_enumeration_flags_duplicate_and_overlapping_leaves() {
        let data = create_pe_with_duplicate_overlapping_resources();
        let parser = PeParser::new(&data).unwrap();

        let resources = parser.resources().unwrap();

        assert_eq!(resources.leaf_count(), 2);
        assert_eq!(resources.total_id_entries, 4);
        assert!(resources
            .warnings
            .iter()
            .any(|warning| warning == "duplicate_resource_triplet"));
        assert!(resources
            .warnings
            .iter()
            .any(|warning| warning == "overlapping_resource_data"));
    }

    #[test]
    fn test_resource_enumeration_respects_depth_budget() {
        let data = create_pe_with_version_resource();
        let mut options = ParseOptions::default();
        options.max_resource_depth = 1;
        let parser = PeParser::with_options(&data, options).unwrap();

        let resources = parser.resources().unwrap();

        assert_eq!(resources.leaf_count(), 0);
        assert!(resources
            .stop_reasons
            .iter()
            .any(|reason| reason == "max_resource_depth"));
        assert!(resources
            .warnings
            .iter()
            .any(|warning| warning == "resource_depth_exceeded"));
    }

    #[test]
    fn test_resource_enumeration_warns_on_invalid_data_rva() {
        let mut data = create_pe_with_version_resource();
        write_resource_u32(&mut data, 0x200 + 0x48, 0x5000);
        let parser = PeParser::new(&data).unwrap();

        let resources = parser.resources().unwrap();

        assert_eq!(resources.leaf_count(), 0);
        assert!(resources
            .warnings
            .iter()
            .any(|warning| warning == "invalid_resource_data_rva"));
    }
}
