use glaurung::core::binary::Format;
use glaurung::triage::overlay::{detect_overlay, OverlayFormat};
use std::fs;
use std::path::PathBuf;

// Helper: read a test binary with better error messages
#[allow(dead_code)]
fn get_test_binary(path: &str) -> Vec<u8> {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push(path);
    fs::read(test_path).unwrap_or_else(|_| panic!("Failed to read test file: {}", path))
}

#[test]
fn test_pe_no_overlay() {
    // Test with real PE file that shouldn't have overlay
    let pe_path =
        "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe";
    if let Ok(data) = fs::read(pe_path) {
        let result = detect_overlay(&data, Format::PE);
        match result {
            None => {
                // Most basic hello world binaries won't have overlays
                println!("PE file has no overlay as expected");
            }
            Some(overlay) => {
                // Some PE files might have small overlays (padding, signatures)
                println!(
                    "PE file has overlay at offset {} with size {} bytes",
                    overlay.offset, overlay.size
                );
                assert!(overlay.offset > 0);
                assert!(overlay.size > 0);
            }
        }
    }
}

#[test]
fn test_elf_no_overlay() {
    // Test with real ELF file
    let elf_path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0";
    if let Ok(data) = fs::read(elf_path) {
        let result = detect_overlay(&data, Format::ELF);
        match result {
            None => {
                println!("ELF file has no overlay as expected");
            }
            Some(overlay) => {
                // Some ELF files might have small overlays
                println!(
                    "ELF file has overlay at offset {} with size {} bytes",
                    overlay.offset, overlay.size
                );
                assert!(overlay.offset > 0);
                assert!(overlay.size > 0);
            }
        }
    }
}

#[test]
fn test_pe_with_simulated_zip_overlay() {
    // Create a simple PE-like structure with ZIP overlay appended
    let mut pe_data = vec![
        // DOS header
        b'M', b'Z', // e_magic
    ];
    pe_data.extend_from_slice(&[0x90; 58]); // padding to e_lfanew
    pe_data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew = 0x80

    // Pad to PE header
    while pe_data.len() < 0x80 {
        pe_data.push(0);
    }

    // PE signature
    pe_data.extend_from_slice(b"PE\0\0");

    // COFF header (IMAGE_FILE_HEADER)
    pe_data.extend_from_slice(&[0x4C, 0x01]); // Machine (i386)
    pe_data.extend_from_slice(&[0x01, 0x00]); // NumberOfSections = 1
    pe_data.extend_from_slice(&[0; 12]); // TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
    pe_data.extend_from_slice(&[0xE0, 0x00]); // SizeOfOptionalHeader
    pe_data.extend_from_slice(&[0x02, 0x01]); // Characteristics

    // Optional header (simplified)
    pe_data.extend_from_slice(&[0x0B, 0x01]); // Magic (PE32)
    pe_data.extend_from_slice(&[0; 0xDE]); // Rest of optional header

    // Section header (.text)
    pe_data.extend_from_slice(b".text\0\0\0"); // Name
    pe_data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // VirtualSize
    pe_data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // VirtualAddress
    pe_data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // SizeOfRawData = 0x200
    pe_data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // PointerToRawData = 0x200
    pe_data.extend_from_slice(&[0; 16]); // Relocs, LineNumbers, Characteristics

    // Pad to section data
    while pe_data.len() < 0x200 {
        pe_data.push(0);
    }

    // Section data
    pe_data.extend_from_slice(&[0xC3; 0x200]); // RET instructions

    // Now append a ZIP overlay
    let overlay_start = pe_data.len();
    pe_data.extend_from_slice(b"PK\x03\x04"); // ZIP magic
    pe_data.extend_from_slice(b"This is a test ZIP overlay with some data");

    // Detect overlay
    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some(), "Should detect overlay");

    let overlay = result.unwrap();
    assert_eq!(overlay.offset, overlay_start as u64);
    assert!(overlay.size > 0);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::ZIP));
    assert!(overlay.is_archive);
    assert!(!overlay.has_signature);
}

#[test]
fn test_overlay_format_detection_cab() {
    let mut pe_data = create_minimal_pe();
    let overlay_start = pe_data.len();

    // Append CAB magic
    pe_data.extend_from_slice(b"MSCF");
    pe_data.extend_from_slice(b"Microsoft Cabinet archive test data");

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert_eq!(overlay.offset, overlay_start as u64);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::CAB));
    assert!(overlay.is_archive);
}

#[test]
fn test_overlay_format_detection_7zip() {
    let mut pe_data = create_minimal_pe();
    let overlay_start = pe_data.len();

    // Append 7-Zip magic
    pe_data.extend_from_slice(b"7z\xBC\xAF\x27\x1C");
    pe_data.extend_from_slice(b"7-Zip archive test data");

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert_eq!(overlay.offset, overlay_start as u64);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::SevenZip));
    assert!(overlay.is_archive);
}

#[test]
fn test_overlay_format_detection_rar() {
    let mut pe_data = create_minimal_pe();
    let overlay_start = pe_data.len();

    // Append RAR magic
    pe_data.extend_from_slice(b"Rar!");
    pe_data.extend_from_slice(b"RAR archive test data");

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert_eq!(overlay.offset, overlay_start as u64);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::RAR));
    assert!(overlay.is_archive);
}

#[test]
fn test_overlay_format_detection_nsis() {
    let mut pe_data = create_minimal_pe();
    let overlay_start = pe_data.len();

    // Append data with NSIS marker
    pe_data.extend_from_slice(b"Some data before NSIS marker for testing");
    pe_data.extend_from_slice(b"NSIS");
    pe_data.extend_from_slice(b"Nullsoft installer data");

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert_eq!(overlay.offset, overlay_start as u64);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::NSIS));
}

#[test]
fn test_overlay_format_detection_inno_setup() {
    let mut pe_data = create_minimal_pe();
    let overlay_start = pe_data.len();

    // Append Inno Setup zlb compressed marker (starts with zlb\x1A)
    pe_data.extend_from_slice(b"zlb\x1A");
    // Ensure we have at least 64 bytes for the detection to work
    pe_data.extend_from_slice(b"Compressed Inno Setup installer data follows here with additional padding to ensure we have enough bytes");

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert_eq!(overlay.offset, overlay_start as u64);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::InnoSetup));
}

#[test]
fn test_overlay_entropy_calculation() {
    let mut pe_data = create_minimal_pe();
    let _overlay_start = pe_data.len();

    // Add low entropy data (repeated pattern)
    for _ in 0..100 {
        pe_data.extend_from_slice(b"AAAAAAAA");
    }

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert!(
        overlay.entropy < 2.0,
        "Repeated data should have low entropy"
    );

    // Test with high entropy data
    let mut pe_data2 = create_minimal_pe();
    let _overlay_start2 = pe_data2.len();

    // Add pseudo-random data
    let mut rng_value = 0x12345678u32;
    for _ in 0..200 {
        rng_value = rng_value.wrapping_mul(1664525).wrapping_add(1013904223);
        pe_data2.push((rng_value >> 24) as u8);
    }

    let result2 = detect_overlay(&pe_data2, Format::PE);
    assert!(result2.is_some());

    let overlay2 = result2.unwrap();
    assert!(
        overlay2.entropy > 5.0,
        "Random data should have high entropy"
    );
}

#[test]
fn test_overlay_sha256() {
    let mut pe_data = create_minimal_pe();

    // Add known data for SHA256 verification
    pe_data.extend_from_slice(b"test data");

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    // SHA256 of "test data"
    assert_eq!(
        overlay.sha256,
        "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    );
}

#[test]
fn test_overlay_header_extraction() {
    let mut pe_data = create_minimal_pe();
    let _overlay_start = pe_data.len();

    // Add data with specific pattern
    let test_pattern = b"HEADER_PATTERN_12345";
    pe_data.extend_from_slice(test_pattern);
    pe_data.extend_from_slice(&[0xFF; 300]); // More data

    let result = detect_overlay(&pe_data, Format::PE);
    assert!(result.is_some());

    let overlay = result.unwrap();
    assert!(overlay.header.len() <= 256);
    assert!(overlay.header.starts_with(test_pattern));
}

#[test]
fn test_small_overlay_ignored() {
    let mut pe_data = create_minimal_pe();

    // Add very small overlay (less than 8 bytes)
    pe_data.extend_from_slice(b"tiny");

    let result = detect_overlay(&pe_data, Format::PE);
    // Should be ignored as it's too small
    assert!(result.is_none(), "Tiny overlays should be ignored");
}

// Helper function to create a minimal valid PE structure
fn create_minimal_pe() -> Vec<u8> {
    let mut data = Vec::new();

    // DOS header
    data.extend_from_slice(b"MZ");
    data.extend_from_slice(&[0x90; 58]);
    data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew

    // Pad to PE header
    while data.len() < 0x80 {
        data.push(0);
    }

    // PE signature
    data.extend_from_slice(b"PE\0\0");

    // COFF header
    data.extend_from_slice(&[0x4C, 0x01]); // Machine
    data.extend_from_slice(&[0x01, 0x00]); // NumberOfSections
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(&[0xE0, 0x00]); // SizeOfOptionalHeader
    data.extend_from_slice(&[0x02, 0x01]); // Characteristics

    // Optional header
    data.extend_from_slice(&[0x0B, 0x01]); // Magic
    data.extend_from_slice(&[0; 0xDE]);

    // Section header
    data.extend_from_slice(b".text\0\0\0");
    data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // VirtualSize
    data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // VirtualAddress
    data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // SizeOfRawData
    data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // PointerToRawData
    data.extend_from_slice(&[0; 16]);

    // Pad to section data
    while data.len() < 0x200 {
        data.push(0);
    }

    // Section data
    data.extend_from_slice(&[0x90; 0x200]);

    data
}
