//! Overlay detection and analysis for PE and ELF files.
//!
//! Overlays are data appended after the official end of a binary file,
//! commonly used for self-extracting archives, installers, and digital signatures.

use crate::core::binary::Format;
use crate::entropy::shannon_entropy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Analysis results for overlay data found in binary files.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct OverlayAnalysis {
    /// Offset in file where overlay starts
    pub offset: u64,

    /// Size of overlay data in bytes
    pub size: u64,

    /// Shannon entropy of overlay data
    pub entropy: f32,

    /// First 256 bytes for quick analysis (or less if overlay is smaller)
    pub header: Vec<u8>,

    /// Detected format of overlay (if recognizable)
    pub detected_format: Option<OverlayFormat>,

    /// If overlay contains or appears to be a digital signature
    pub has_signature: bool,

    /// If overlay appears to be an archive format
    pub is_archive: bool,

    /// SHA256 hash of overlay data
    pub sha256: String,
}

/// Known overlay formats that can be detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub enum OverlayFormat {
    /// ZIP archive format
    ZIP,
    /// Microsoft Cabinet archive
    CAB,
    /// 7-Zip archive
    SevenZip,
    /// RAR archive
    RAR,
    /// NSIS installer
    NSIS,
    /// Inno Setup installer
    InnoSetup,
    /// Digital certificate/signature data
    Certificate,
    /// AppImage (ELF with embedded squashfs)
    AppImage,
    /// SquashFS filesystem
    SquashFS,
    /// ISO 9660 filesystem
    ISO9660,
    /// Unknown or unrecognized format
    Unknown,
}

impl OverlayAnalysis {
    /// Create a new OverlayAnalysis from raw overlay data
    fn from_data(offset: u64, data: &[u8]) -> Self {
        let size = data.len() as u64;
        let entropy = if !data.is_empty() {
            shannon_entropy(data) as f32
        } else {
            0.0
        };

        // Extract header (up to 256 bytes)
        let header_size = data.len().min(256);
        let header = data[..header_size].to_vec();

        // Detect format
        let detected_format = detect_overlay_format(data);
        let has_signature = matches!(detected_format, Some(OverlayFormat::Certificate))
            || check_for_signature(data);
        let is_archive = matches!(
            detected_format,
            Some(OverlayFormat::ZIP)
                | Some(OverlayFormat::CAB)
                | Some(OverlayFormat::SevenZip)
                | Some(OverlayFormat::RAR)
        );

        // Calculate SHA256
        let sha256 = calculate_sha256(data);

        Self {
            offset,
            size,
            entropy,
            header,
            detected_format,
            has_signature,
            is_archive,
            sha256,
        }
    }
}

/// Detect overlay data in a binary file based on its format.
pub fn detect_overlay(data: &[u8], format: Format) -> Option<OverlayAnalysis> {
    match format {
        Format::PE => detect_pe_overlay(data),
        Format::ELF => detect_elf_overlay(data),
        Format::MachO => detect_macho_overlay(data),
        _ => None,
    }
}

/// Detect overlay in PE files using the object crate.
/// Based on LIEF's approach: find max(section_offset + section_size).
///
/// Security considerations:
/// - MS13-098: Attackers can modify overlays without breaking Authenticode signatures
/// - Certificate directory size can be manipulated to cover overlay data
/// - WinVerifyTrust doesn't hash all bytes (not a flat file hash)
fn detect_pe_overlay(data: &[u8]) -> Option<OverlayAnalysis> {
    // Parse PE file
    let pe = match object::read::pe::PeFile32::parse(data) {
        Ok(pe) => pe,
        Err(_) => {
            // Try 64-bit
            match object::read::pe::PeFile64::parse(data) {
                Ok(pe) => return detect_pe_overlay_impl(data, pe),
                Err(_) => return None,
            }
        }
    };
    detect_pe_overlay_impl(data, pe)
}

/// Internal implementation for PE overlay detection.
fn detect_pe_overlay_impl<Pe: object::read::pe::ImageNtHeaders>(
    data: &[u8],
    pe: object::read::pe::PeFile<Pe>,
) -> Option<OverlayAnalysis> {
    // Find the end of the last section
    // This follows LIEF's approach: max(section.offset + section.size)
    let last_section_end = pe
        .section_table()
        .iter()
        .map(|section| {
            let offset = section.pointer_to_raw_data.get(object::LittleEndian) as u64;
            let size = section.size_of_raw_data.get(object::LittleEndian) as u64;
            offset + size
        })
        .max()
        .unwrap_or(0);

    // Check if there's data after the last section
    let file_size = data.len() as u64;
    if last_section_end >= file_size {
        return None;
    }

    // Extract overlay data
    let overlay_offset = last_section_end;
    let overlay_data = &data[overlay_offset as usize..];

    // Skip if overlay is too small to be meaningful
    if overlay_data.len() < 8 {
        return None;
    }

    Some(OverlayAnalysis::from_data(overlay_offset, overlay_data))
}

/// Detect overlay in ELF files using the object crate.
fn detect_elf_overlay(data: &[u8]) -> Option<OverlayAnalysis> {
    use object::read::elf::{ElfFile32, ElfFile64};
    use object::{Object, ObjectSection};

    // Try parsing as 64-bit ELF first
    let last_section_end = if let Ok(elf) = ElfFile64::<object::Endianness>::parse(data) {
        elf.sections()
            .filter_map(|section| {
                // Use file_range() to get physical file location
                if let Some((offset, size)) = section.file_range() {
                    Some(offset + size)
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(0)
    } else if let Ok(elf) = ElfFile32::<object::Endianness>::parse(data) {
        // Try 32-bit ELF
        elf.sections()
            .filter_map(|section| {
                if let Some((offset, size)) = section.file_range() {
                    Some(offset + size)
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(0)
    } else {
        return None;
    };

    // Check if there's data after the last section
    let file_size = data.len() as u64;
    if last_section_end >= file_size {
        return None;
    }

    // Extract overlay data
    let overlay_offset = last_section_end;
    let overlay_data = &data[overlay_offset as usize..];

    // Skip if overlay is too small
    if overlay_data.len() < 8 {
        return None;
    }

    Some(OverlayAnalysis::from_data(overlay_offset, overlay_data))
}

/// Detect overlay in Mach-O files using the object crate.
fn detect_macho_overlay(data: &[u8]) -> Option<OverlayAnalysis> {
    use object::read::macho::{MachOFile32, MachOFile64};
    use object::{Object, ObjectSegment};

    // Try parsing as 64-bit Mach-O first
    let last_segment_end = if let Ok(macho) = MachOFile64::<object::Endianness>::parse(data) {
        macho
            .segments()
            .map(|segment| {
                // Use file_range() to get physical file location
                let (offset, size) = segment.file_range();
                offset + size
            })
            .max()
            .unwrap_or(0)
    } else if let Ok(macho) = MachOFile32::<object::Endianness>::parse(data) {
        // Try 32-bit Mach-O
        macho
            .segments()
            .map(|segment| {
                let (offset, size) = segment.file_range();
                offset + size
            })
            .max()
            .unwrap_or(0)
    } else {
        return None;
    };

    // Check if there's data after the last segment
    let file_size = data.len() as u64;
    if last_segment_end >= file_size {
        return None;
    }

    // Extract overlay data
    let overlay_offset = last_segment_end;
    let overlay_data = &data[overlay_offset as usize..];

    // Skip if overlay is too small
    if overlay_data.len() < 8 {
        return None;
    }

    Some(OverlayAnalysis::from_data(overlay_offset, overlay_data))
}

/// Detect the format of overlay data based on magic bytes and patterns.
fn detect_overlay_format(data: &[u8]) -> Option<OverlayFormat> {
    if data.len() < 4 {
        return None;
    }

    // Check magic bytes at the beginning
    match &data[..4.min(data.len())] {
        b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08" => return Some(OverlayFormat::ZIP),
        b"MSCF" => return Some(OverlayFormat::CAB),
        b"7z\xBC\xAF" => return Some(OverlayFormat::SevenZip),
        b"Rar!" => return Some(OverlayFormat::RAR),
        b"hsqs" | b"sqsh" => return Some(OverlayFormat::SquashFS), // SquashFS magic
        _ => {}
    }

    // Check for AppImage magic (AI\x01 or AI\x02)
    if data.len() >= 3 && data[0] == b'A' && data[1] == b'I' && (data[2] == 0x01 || data[2] == 0x02)
    {
        return Some(OverlayFormat::AppImage);
    }

    // Check for ISO 9660 (CD001)
    if data.len() >= 32769 {
        // ISO 9660 Primary Volume Descriptor at offset 0x8001
        if let Some(window) = data.get(0x8001..0x8006) {
            if window == b"CD001" {
                return Some(OverlayFormat::ISO9660);
            }
        }
    }

    // Check for larger magic patterns
    if data.len() >= 6 && &data[..6] == b"7z\xBC\xAF\x27\x1C" {
        return Some(OverlayFormat::SevenZip);
    }

    // Check for NSIS installer patterns
    if data.windows(4).any(|w| w == b"NSIS") {
        return Some(OverlayFormat::NSIS);
    }

    // Check for Inno Setup patterns
    if data.len() >= 64 {
        // Inno Setup has various signatures, check common ones
        if data.windows(12).any(|w| w == b"Inno Setup") {
            return Some(OverlayFormat::InnoSetup);
        }
        // Check for "zlb" compressed Inno Setup
        if data.starts_with(b"zlb\x1A") {
            return Some(OverlayFormat::InnoSetup);
        }
    }

    // Check for certificate/signature patterns
    // Look for PKCS#7 SignedData OID
    if data.len() >= 32 {
        // Check for common certificate patterns
        if data.starts_with(&[0x30, 0x82]) {
            // ASN.1 SEQUENCE with length
            // This could be a certificate or PKCS#7 structure
            if check_for_pkcs7_signature(data) {
                return Some(OverlayFormat::Certificate);
            }
        }
    }

    // If we can't identify the format
    Some(OverlayFormat::Unknown)
}

/// Check if data contains a digital signature/certificate.
///
/// SECURITY WARNING (MS13-098):
/// - Certificate directory size can be manipulated to cover overlay data
/// - Malicious actors can modify overlays without breaking Authenticode signatures
/// - The signature only covers specific PE sections, not the entire file
fn check_for_signature(data: &[u8]) -> bool {
    if data.len() < 32 {
        return false;
    }

    // Check for ASN.1 DER encoded structures (certificates start with 0x30)
    if data[0] == 0x30 {
        // Check for PKCS#7 SignedData
        return check_for_pkcs7_signature(data);
    }

    // Check for WIN_CERTIFICATE structure (PE authenticode)
    if data.len() >= 8 {
        // WIN_CERTIFICATE starts with length (4 bytes) and revision (2 bytes)
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let revision = u16::from_le_bytes([data[4], data[5]]);
        let cert_type = u16::from_le_bytes([data[6], data[7]]);

        // Check for valid WIN_CERTIFICATE
        // revision 0x0200 = WIN_CERT_REVISION_2_0
        // cert_type 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        if revision == 0x0200 && cert_type == 0x0002 && length <= data.len() {
            return true;
        }
    }

    false
}

/// Check for PKCS#7 SignedData structure.
fn check_for_pkcs7_signature(data: &[u8]) -> bool {
    // Look for PKCS#7 SignedData OID: 1.2.840.113549.1.7.2
    // In hex: 06 09 2A 86 48 86 F7 0D 01 07 02
    const PKCS7_SIGNED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];

    // Search for the OID in the first 256 bytes
    let search_len = data.len().min(256);
    data[..search_len]
        .windows(PKCS7_SIGNED_DATA_OID.len())
        .any(|w| w == PKCS7_SIGNED_DATA_OID)
}

/// Calculate SHA256 hash of data.
fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(feature = "python-ext")]
mod python {
    use super::*;
    use pyo3::prelude::*;

    #[pymethods]
    impl OverlayAnalysis {
        #[getter]
        fn offset(&self) -> u64 {
            self.offset
        }

        #[getter]
        fn size(&self) -> u64 {
            self.size
        }

        #[getter]
        fn entropy(&self) -> f32 {
            self.entropy
        }

        #[getter]
        fn header(&self) -> Vec<u8> {
            self.header.clone()
        }

        #[getter]
        fn detected_format(&self) -> Option<OverlayFormat> {
            self.detected_format.clone()
        }

        #[getter]
        fn has_signature(&self) -> bool {
            self.has_signature
        }

        #[getter]
        fn is_archive(&self) -> bool {
            self.is_archive
        }

        #[getter]
        fn sha256(&self) -> String {
            self.sha256.clone()
        }

        fn __repr__(&self) -> String {
            format!(
                "OverlayAnalysis(offset={}, size={}, format={:?})",
                self.offset, self.size, self.detected_format
            )
        }
    }

    #[pymethods]
    impl OverlayFormat {
        fn __str__(&self) -> String {
            format!("{:?}", self)
        }

        fn __repr__(&self) -> String {
            format!("OverlayFormat::{:?}", self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_format_detection() {
        // Test ZIP detection
        let zip_data = b"PK\x03\x04some other data";
        assert_eq!(detect_overlay_format(zip_data), Some(OverlayFormat::ZIP));

        // Test CAB detection
        let cab_data = b"MSCFsome other data";
        assert_eq!(detect_overlay_format(cab_data), Some(OverlayFormat::CAB));

        // Test 7-Zip detection
        let seven_zip_data = b"7z\xBC\xAF\x27\x1Csome other data";
        assert_eq!(
            detect_overlay_format(seven_zip_data),
            Some(OverlayFormat::SevenZip)
        );

        // Test RAR detection
        let rar_data = b"Rar!some other data";
        assert_eq!(detect_overlay_format(rar_data), Some(OverlayFormat::RAR));
    }

    #[test]
    fn test_sha256_calculation() {
        let data = b"test data";
        let hash = calculate_sha256(data);
        assert_eq!(
            hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_overlay_analysis_creation() {
        let data = b"PK\x03\x04test overlay data with some content";
        let analysis = OverlayAnalysis::from_data(1000, data);

        assert_eq!(analysis.offset, 1000);
        assert_eq!(analysis.size, data.len() as u64);
        assert!(analysis.entropy > 0.0);
        assert_eq!(analysis.detected_format, Some(OverlayFormat::ZIP));
        assert!(analysis.is_archive);
        assert!(!analysis.has_signature);
    }
}
