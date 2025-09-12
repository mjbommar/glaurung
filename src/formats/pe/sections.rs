//! Section management for PE files

use crate::formats::pe::types::*;
use crate::formats::pe::utils::{calculate_entropy, ReadExt};

/// Section table for efficient RVA resolution
#[derive(Debug, Clone)]
pub struct SectionTable {
    sections: Vec<Section>,
}

impl SectionTable {
    /// Create a new section table
    pub fn new(sections: Vec<Section>) -> Self {
        // Sort by virtual address for binary search
        let mut sections = sections;
        sections.sort_by_key(|s| s.header.virtual_address);
        Self { sections }
    }

    /// Get all sections
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Find section by name
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.header.name() == name)
    }

    /// Find section containing RVA
    pub fn section_containing_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.header.contains_rva(rva))
    }

    /// Convert RVA to file offset - O(log n) with binary search
    #[inline]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // Binary search for containing section
        let idx = self
            .sections
            .binary_search_by(|s| {
                let size = s.header.virtual_size.max(s.header.size_of_raw_data);
                if rva < s.header.virtual_address {
                    std::cmp::Ordering::Greater
                } else if rva >= s.header.virtual_address + size {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;

        let section = &self.sections[idx];
        let offset = rva - section.header.virtual_address;
        Some((section.header.pointer_to_raw_data + offset) as usize)
    }

    /// Convert file offset to RVA
    pub fn offset_to_rva(&self, offset: usize) -> Option<u32> {
        for section in &self.sections {
            let raw_start = section.header.pointer_to_raw_data as usize;
            let raw_end = raw_start + section.header.size_of_raw_data as usize;

            if offset >= raw_start && offset < raw_end {
                let delta = (offset - raw_start) as u32;
                return Some(section.header.virtual_address + delta);
            }
        }
        None
    }

    /// Batch RVA resolution for efficiency
    pub fn rva_to_offset_batch(&self, rvas: &[u32]) -> Vec<Option<usize>> {
        // Sort RVAs to improve cache locality
        let mut indexed_rvas: Vec<(usize, u32)> =
            rvas.iter().enumerate().map(|(i, &r)| (i, r)).collect();
        indexed_rvas.sort_by_key(|&(_, rva)| rva);

        let mut results = vec![None; rvas.len()];
        let mut section_idx = 0;

        for (orig_idx, rva) in indexed_rvas {
            // Start search from last successful section
            while section_idx < self.sections.len() {
                let section = &self.sections[section_idx];
                let size = section
                    .header
                    .virtual_size
                    .max(section.header.size_of_raw_data);

                if rva < section.header.virtual_address {
                    break;
                }
                if rva < section.header.virtual_address + size {
                    let offset = rva - section.header.virtual_address;
                    results[orig_idx] =
                        Some((section.header.pointer_to_raw_data + offset) as usize);
                    break;
                }
                section_idx += 1;
            }
        }

        results
    }

    /// Get the entry point section
    pub fn entry_section(&self, entry_rva: u32) -> Option<&Section> {
        self.section_containing_rva(entry_rva)
    }

    /// Check if any section has high entropy (likely packed)
    pub fn has_high_entropy_sections(&self, data: &[u8]) -> Vec<(String, f64)> {
        let mut high_entropy = Vec::new();

        for section in &self.sections {
            if section.header.size_of_raw_data == 0 {
                continue;
            }

            let start = section.header.pointer_to_raw_data as usize;
            let end = start + section.header.size_of_raw_data as usize;

            if end <= data.len() {
                let entropy = calculate_entropy(&data[start..end]);
                if entropy > 7.0 {
                    high_entropy.push((section.header.name(), entropy));
                }
            }
        }

        high_entropy
    }

    /// Get executable sections
    pub fn executable_sections(&self) -> Vec<&Section> {
        self.sections
            .iter()
            .filter(|s| s.header.is_executable())
            .collect()
    }

    /// Get writable sections
    pub fn writable_sections(&self) -> Vec<&Section> {
        self.sections
            .iter()
            .filter(|s| s.header.is_writable())
            .collect()
    }

    /// Detect anomalies in sections
    pub fn detect_anomalies(&self) -> Vec<PeAnomaly> {
        let mut anomalies = Vec::new();

        // Check for unusual section names
        const KNOWN_SECTIONS: &[&str] = &[
            ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".tls",
            ".debug", ".pdata", ".xdata", "CODE", "DATA", "BSS", ".CRT", ".INIT", ".PAGE",
        ];

        for section in &self.sections {
            let name = section.header.name();

            // Check for unusual names
            if !name.is_empty() && !KNOWN_SECTIONS.iter().any(|&s| name.starts_with(s)) {
                // Flag as unusual if not in known list
                anomalies.push(PeAnomaly::UnusualSectionName { name: name.clone() });
            }

            // Check for size mismatches
            if section.header.virtual_size > 0 && section.header.size_of_raw_data > 0 {
                let ratio =
                    section.header.virtual_size as f64 / section.header.size_of_raw_data as f64;
                if !(0.1..=10.0).contains(&ratio) {
                    anomalies.push(PeAnomaly::SectionSizeMismatch {
                        section: name.clone(),
                    });
                }
            }

            // Check for overlapping sections
            for other in &self.sections {
                if std::ptr::eq(section, other) {
                    continue;
                }

                let s1_start = section.header.virtual_address;
                let s1_end = s1_start
                    + section
                        .header
                        .virtual_size
                        .max(section.header.size_of_raw_data);
                let s2_start = other.header.virtual_address;
                let s2_end =
                    s2_start + other.header.virtual_size.max(other.header.size_of_raw_data);

                if s1_start < s2_end && s2_start < s1_end {
                    anomalies.push(PeAnomaly::OverlappingSections {
                        section1: section.header.name(),
                        section2: other.header.name(),
                    });
                }
            }
        }

        anomalies
    }
}

/// Parse section headers from data
pub fn parse_section_headers(data: &[u8], offset: usize, count: u16) -> Result<Vec<SectionHeader>> {
    let mut sections = Vec::new();

    for i in 0..count {
        let section_offset = offset + (i as usize * 40);
        if section_offset + 40 > data.len() {
            return Err(PeError::TruncatedHeader {
                expected: section_offset + 40,
                actual: data.len(),
            });
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&data[section_offset..section_offset + 8]);

        let header = SectionHeader {
            name,
            virtual_size: data.read_u32_le_at(section_offset + 8).unwrap(),
            virtual_address: data.read_u32_le_at(section_offset + 12).unwrap(),
            size_of_raw_data: data.read_u32_le_at(section_offset + 16).unwrap(),
            pointer_to_raw_data: data.read_u32_le_at(section_offset + 20).unwrap(),
            pointer_to_relocations: data.read_u32_le_at(section_offset + 24).unwrap(),
            pointer_to_line_numbers: data.read_u32_le_at(section_offset + 28).unwrap(),
            number_of_relocations: data.read_u16_le_at(section_offset + 32).unwrap(),
            number_of_line_numbers: data.read_u16_le_at(section_offset + 34).unwrap(),
            characteristics: data.read_u32_le_at(section_offset + 36).unwrap(),
        };

        sections.push(header);
    }

    Ok(sections)
}

/// Create section objects with data ranges
pub fn create_sections(headers: Vec<SectionHeader>) -> Vec<Section> {
    headers
        .into_iter()
        .map(|header| {
            let start = header.pointer_to_raw_data as usize;
            let end = start + header.size_of_raw_data as usize;
            Section {
                header,
                data: start..end,
            }
        })
        .collect()
}

impl Section {
    /// Get section data from the file
    pub fn data<'a>(&self, file_data: &'a [u8]) -> Option<&'a [u8]> {
        file_data.get(self.data.clone())
    }

    /// Calculate entropy of section data
    pub fn entropy(&self, file_data: &[u8]) -> Option<f64> {
        self.data(file_data).map(calculate_entropy)
    }

    /// Check if section is likely packed
    pub fn is_likely_packed(&self, file_data: &[u8]) -> bool {
        self.entropy(file_data).is_some_and(|e| e > 7.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_section(name: &str, va: u32, vsize: u32, raw: u32, rsize: u32) -> Section {
        let mut name_bytes = [0u8; 8];
        let bytes = name.as_bytes();
        let len = bytes.len().min(8);
        name_bytes[..len].copy_from_slice(&bytes[..len]);

        Section {
            header: SectionHeader {
                name: name_bytes,
                virtual_address: va,
                virtual_size: vsize,
                pointer_to_raw_data: raw,
                size_of_raw_data: rsize,
                pointer_to_relocations: 0,
                pointer_to_line_numbers: 0,
                number_of_relocations: 0,
                number_of_line_numbers: 0,
                characteristics: IMAGE_SCN_MEM_READ,
            },
            data: (raw as usize)..(raw as usize + rsize as usize),
        }
    }

    #[test]
    fn test_section_table_rva_to_offset() {
        let sections = vec![
            create_test_section(".text", 0x1000, 0x1000, 0x400, 0x1000),
            create_test_section(".data", 0x2000, 0x1000, 0x1400, 0x1000),
            create_test_section(".rsrc", 0x3000, 0x1000, 0x2400, 0x1000),
        ];

        let table = SectionTable::new(sections);

        // Test RVA in .text section
        assert_eq!(table.rva_to_offset(0x1000), Some(0x400));
        assert_eq!(table.rva_to_offset(0x1500), Some(0x900));
        assert_eq!(table.rva_to_offset(0x1FFF), Some(0x13FF));

        // Test RVA in .data section
        assert_eq!(table.rva_to_offset(0x2000), Some(0x1400));
        assert_eq!(table.rva_to_offset(0x2500), Some(0x1900));

        // Test RVA in .rsrc section
        assert_eq!(table.rva_to_offset(0x3000), Some(0x2400));

        // Test invalid RVA
        assert_eq!(table.rva_to_offset(0x500), None);
        assert_eq!(table.rva_to_offset(0x5000), None);
    }

    #[test]
    fn test_section_table_offset_to_rva() {
        let sections = vec![
            create_test_section(".text", 0x1000, 0x1000, 0x400, 0x1000),
            create_test_section(".data", 0x2000, 0x1000, 0x1400, 0x1000),
        ];

        let table = SectionTable::new(sections);

        // Test offset in .text section
        assert_eq!(table.offset_to_rva(0x400), Some(0x1000));
        assert_eq!(table.offset_to_rva(0x900), Some(0x1500));

        // Test offset in .data section
        assert_eq!(table.offset_to_rva(0x1400), Some(0x2000));
        assert_eq!(table.offset_to_rva(0x1900), Some(0x2500));

        // Test invalid offset
        assert_eq!(table.offset_to_rva(0x100), None);
        assert_eq!(table.offset_to_rva(0x5000), None);
    }

    #[test]
    fn test_section_by_name() {
        let sections = vec![
            create_test_section(".text", 0x1000, 0x1000, 0x400, 0x1000),
            create_test_section(".data", 0x2000, 0x1000, 0x1400, 0x1000),
            create_test_section(".rsrc", 0x3000, 0x1000, 0x2400, 0x1000),
        ];

        let table = SectionTable::new(sections);

        assert!(table.section_by_name(".text").is_some());
        assert!(table.section_by_name(".data").is_some());
        assert!(table.section_by_name(".rsrc").is_some());
        assert!(table.section_by_name(".fake").is_none());
    }

    #[test]
    fn test_batch_rva_resolution() {
        let sections = vec![
            create_test_section(".text", 0x1000, 0x1000, 0x400, 0x1000),
            create_test_section(".data", 0x2000, 0x1000, 0x1400, 0x1000),
        ];

        let table = SectionTable::new(sections);

        let rvas = vec![0x1000, 0x2000, 0x1500, 0x500, 0x2500];
        let offsets = table.rva_to_offset_batch(&rvas);

        assert_eq!(offsets[0], Some(0x400));
        assert_eq!(offsets[1], Some(0x1400));
        assert_eq!(offsets[2], Some(0x900));
        assert_eq!(offsets[3], None);
        assert_eq!(offsets[4], Some(0x1900));
    }

    #[test]
    fn test_section_characteristics() {
        let mut section = create_test_section(".text", 0x1000, 0x1000, 0x400, 0x1000);
        section.header.characteristics =
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

        assert!(section.header.is_executable());
        assert!(section.header.is_readable());
        assert!(!section.header.is_writable());
        assert!(section.header.contains_code());

        section.header.characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
        assert!(!section.header.is_executable());
        assert!(section.header.is_readable());
        assert!(section.header.is_writable());
        assert!(!section.header.contains_code());
    }

    #[test]
    fn test_detect_anomalies() {
        let sections = vec![
            create_test_section(".text", 0x1000, 0x1000, 0x400, 0x1000),
            create_test_section(".pack", 0x2000, 0x1000, 0x1400, 0x1000), // Unusual name
            create_test_section(".data", 0x1500, 0x1000, 0x2400, 0x1000), // Overlapping
        ];

        let table = SectionTable::new(sections);
        let anomalies = table.detect_anomalies();

        // Should detect unusual section name
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, PeAnomaly::UnusualSectionName { name } if name == ".pack")));

        // Should detect overlapping sections
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, PeAnomaly::OverlappingSections { .. })));
    }
}
