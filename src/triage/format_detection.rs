//! Format detection logic for binary artifacts.
//!
//! This module provides clean, performant logic to derive binary formats
//! from triage hints including labels, file extensions, and MIME types.

use crate::core::binary::Format;
use crate::core::triage::TriageHint;
use std::collections::HashMap;

/// Lazily-initialized lookup tables for format detection
struct FormatLookups {
    label_formats: HashMap<&'static str, Format>,
    extension_formats: HashMap<&'static str, Format>,
    mime_formats: HashMap<&'static str, Format>,
}

impl FormatLookups {
    fn new() -> Self {
        let label_formats = [
            ("elf", Format::ELF),
            ("pe", Format::PE),
            ("exe", Format::PE),
            ("executable", Format::PE),
            ("macho", Format::MachO),
            ("wasm", Format::Wasm),
            ("pyc", Format::PythonBytecode),
            ("python", Format::PythonBytecode),
        ]
        .into_iter()
        .collect();

        let extension_formats = [
            ("exe", Format::PE),
            ("dll", Format::PE),
            ("elf", Format::ELF),
            ("so", Format::ELF),
            ("wasm", Format::Wasm),
            ("pyc", Format::PythonBytecode),
            ("dylib", Format::MachO),
            ("macho", Format::MachO),
        ]
        .into_iter()
        .collect();

        let mime_formats = [
            ("application/x-elf", Format::ELF),
            ("application/x-dosexec", Format::PE),
            ("application/x-pe", Format::PE),
            ("application/x-msdownload", Format::PE),
            ("application/wasm", Format::Wasm),
            ("application/x-sharedlib", Format::ELF),
        ]
        .into_iter()
        .collect();

        Self {
            label_formats,
            extension_formats,
            mime_formats,
        }
    }
}

static LOOKUPS: std::sync::OnceLock<FormatLookups> = std::sync::OnceLock::new();

fn get_lookups() -> &'static FormatLookups {
    LOOKUPS.get_or_init(FormatLookups::new)
}

/// Derive a binary format from a triage hint using efficient lookup tables.
///
/// This function attempts to map sniffer hints to expected binary formats by
/// examining labels, extensions, and MIME types in order of precedence.
/// Container labels (zip, tar, etc.) are intentionally not mapped to binary formats.
///
/// # Arguments
/// * `hint` - The triage hint containing label, extension, and/or MIME type information
///
/// # Returns
/// * `Some(Format)` - If a binary format can be determined from the hint
/// * `None` - If no binary format mapping exists for the hint
pub fn derive_format_from_hint(hint: &TriageHint) -> Option<Format> {
    let lookups = get_lookups();

    // 1. Label-based detection (highest priority)
    if let Some(label) = &hint.label {
        let label_lower = label.to_ascii_lowercase();

        // Direct lookup first
        if let Some(&format) = lookups.label_formats.get(label_lower.as_str()) {
            return Some(format);
        }

        // Substring matching for composite labels
        for (&key, &format) in &lookups.label_formats {
            if label_lower.contains(key) {
                return Some(format);
            }
        }
    }

    // 2. Extension-based detection (medium priority)
    if let Some(extension) = &hint.extension {
        let ext_lower = extension.to_ascii_lowercase();
        if let Some(&format) = lookups.extension_formats.get(ext_lower.as_str()) {
            return Some(format);
        }
    }

    // 3. MIME-based detection (lowest priority)
    if let Some(mime) = &hint.mime {
        let mime_lower = mime.to_ascii_lowercase();

        // Direct lookup first
        for (&key, &format) in &lookups.mime_formats {
            if mime_lower.contains(key) {
                return Some(format);
            }
        }

        // Special case for Python bytecode (broader matching)
        if mime_lower.contains("python") {
            return Some(Format::PythonBytecode);
        }
    }

    None
}

/// Check if a hint represents a container format that should not be mapped to a binary format.
///
/// Container formats like ZIP, TAR, GZIP are intentionally excluded from binary format
/// detection as they are archive/compression formats, not executable binary formats.
pub fn is_container_hint(hint: &TriageHint) -> bool {
    if let Some(label) = &hint.label {
        let label_lower = label.to_ascii_lowercase();
        matches!(
            label_lower.as_str(),
            "zip"
                | "jar"
                | "gzip"
                | "tar"
                | "7z"
                | "xz"
                | "bzip2"
                | "zstd"
                | "lz4"
                | "rar"
                | "rar5"
                | "ar"
                | "cpio"
        )
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_hint(label: Option<&str>, extension: Option<&str>, mime: Option<&str>) -> TriageHint {
        TriageHint::new(
            crate::core::triage::SnifferSource::Other,
            mime.map(String::from),
            extension.map(String::from),
            label.map(String::from),
        )
    }

    #[test]
    fn test_label_detection() {
        assert_eq!(
            derive_format_from_hint(&create_hint(Some("elf"), None, None)),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("pe"), None, None)),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("executable"), None, None)),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("macho"), None, None)),
            Some(Format::MachO)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("wasm"), None, None)),
            Some(Format::Wasm)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("python"), None, None)),
            Some(Format::PythonBytecode)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("pyc"), None, None)),
            Some(Format::PythonBytecode)
        );
    }

    #[test]
    fn test_extension_detection() {
        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("exe"), None)),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("dll"), None)),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("elf"), None)),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("so"), None)),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("dylib"), None)),
            Some(Format::MachO)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("macho"), None)),
            Some(Format::MachO)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("wasm"), None)),
            Some(Format::Wasm)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("pyc"), None)),
            Some(Format::PythonBytecode)
        );
    }

    #[test]
    fn test_mime_detection() {
        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("application/x-elf"))),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("application/x-dosexec"))),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("application/x-pe"))),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("application/x-msdownload"))),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("application/wasm"))),
            Some(Format::Wasm)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("application/x-sharedlib"))),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("text/x-python"))),
            Some(Format::PythonBytecode)
        );
    }

    #[test]
    fn test_precedence_order() {
        // Label should take precedence over extension
        assert_eq!(
            derive_format_from_hint(&create_hint(Some("elf"), Some("exe"), None)),
            Some(Format::ELF)
        );

        // Label should take precedence over MIME
        assert_eq!(
            derive_format_from_hint(&create_hint(Some("macho"), None, Some("application/x-elf"))),
            Some(Format::MachO)
        );

        // Extension should take precedence over MIME
        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("dll"), Some("application/x-elf"))),
            Some(Format::PE)
        );
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(
            derive_format_from_hint(&create_hint(Some("ELF"), None, None)),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, Some("DLL"), None)),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, Some("APPLICATION/X-ELF"))),
            Some(Format::ELF)
        );
    }

    #[test]
    fn test_substring_matching_in_labels() {
        assert_eq!(
            derive_format_from_hint(&create_hint(Some("linux-elf-binary"), None, None)),
            Some(Format::ELF)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("windows-pe-executable"), None, None)),
            Some(Format::PE)
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(Some("macos-macho-library"), None, None)),
            Some(Format::MachO)
        );
    }

    #[test]
    fn test_no_match() {
        assert_eq!(
            derive_format_from_hint(&create_hint(
                Some("unknown"),
                Some("txt"),
                Some("text/plain")
            )),
            None
        );

        assert_eq!(
            derive_format_from_hint(&create_hint(None, None, None)),
            None
        );
    }

    #[test]
    fn test_container_detection() {
        assert!(is_container_hint(&create_hint(Some("zip"), None, None)));
        assert!(is_container_hint(&create_hint(Some("tar"), None, None)));
        assert!(is_container_hint(&create_hint(Some("gzip"), None, None)));
        assert!(is_container_hint(&create_hint(Some("jar"), None, None)));
        assert!(is_container_hint(&create_hint(Some("7z"), None, None)));
        assert!(is_container_hint(&create_hint(Some("xz"), None, None)));
        assert!(is_container_hint(&create_hint(Some("bzip2"), None, None)));
        assert!(is_container_hint(&create_hint(Some("zstd"), None, None)));
        assert!(is_container_hint(&create_hint(Some("lz4"), None, None)));
        assert!(is_container_hint(&create_hint(Some("rar"), None, None)));
        assert!(is_container_hint(&create_hint(Some("rar5"), None, None)));
        assert!(is_container_hint(&create_hint(Some("ar"), None, None)));
        assert!(is_container_hint(&create_hint(Some("cpio"), None, None)));

        // Non-container formats should return false
        assert!(!is_container_hint(&create_hint(Some("elf"), None, None)));
        assert!(!is_container_hint(&create_hint(Some("pe"), None, None)));
        assert!(!is_container_hint(&create_hint(Some("macho"), None, None)));
        assert!(!is_container_hint(&create_hint(None, None, None)));
    }

    #[test]
    fn test_case_insensitive_containers() {
        assert!(is_container_hint(&create_hint(Some("ZIP"), None, None)));
        assert!(is_container_hint(&create_hint(Some("TAR"), None, None)));
        assert!(is_container_hint(&create_hint(Some("GZIP"), None, None)));
    }
}
