//! Binary environment analysis across multiple formats.
//!
//! This module provides a unified interface for analyzing binary environment
//! information including libraries, paths, and other metadata.

use object::read::Object;

/// Analyze binary environment information from raw data.
///
/// This function extracts environment-specific information from different
/// binary formats (ELF, PE, Mach-O) and returns it in a consistent format.
pub fn analyze_env(data: &[u8]) -> Option<BinaryEnv> {
    // Try different formats in order of likelihood
    if data.len() >= 4 && &data[0..4] == b"\x7FELF" {
        analyze_elf_env(data)
    } else if data.len() >= 2 && &data[0..2] == b"MZ" {
        analyze_pe_env(data)
    } else if data.len() >= 4 && data[0..4] == [0xCF, 0xFA, 0xED, 0xFE] {
        // Mach-O magic (little endian)
        analyze_macho_env(data)
    } else {
        None
    }
}

/// Unified binary environment information.
#[derive(Debug, Clone)]
pub struct BinaryEnv {
    /// Libraries imported by the binary
    pub libs: Vec<String>,
    /// RPATHs (ELF/Mach-O)
    pub rpaths: Option<Vec<String>>,
    /// RUNPATHs (ELF)
    pub runpaths: Option<Vec<String>>,
    /// PDB path (PE)
    pub pdb_path: Option<String>,
    /// TLS callbacks count (PE)
    pub tls_callbacks: Option<u32>,
    /// Entry section name (PE)
    pub entry_section: Option<String>,
    /// Whether relocations are present (PE)
    pub relocations_present: Option<bool>,
    /// Minimum OS version (Mach-O)
    pub minos: Option<String>,
    /// Code signature present (Mach-O)
    pub code_signature: Option<bool>,
}

/// Analyze ELF environment information.
fn analyze_elf_env(data: &[u8]) -> Option<BinaryEnv> {
    let obj = object::read::File::parse(data).ok()?;

    // Extract libraries from imports
    let mut libs = Vec::new();
    if let Ok(imps) = obj.imports() {
        for imp in imps {
            let lib = String::from_utf8_lossy(imp.library()).to_string();
            if !lib.is_empty() {
                libs.push(lib);
            }
        }
    }

    // Extract rpaths/runpaths using our summarizer
    let caps = crate::symbols::types::BudgetCaps::default();
    let sum = crate::symbols::elf::summarize_elf(data, &caps);

    Some(BinaryEnv {
        libs,
        rpaths: sum.rpaths,
        runpaths: sum.runpaths,
        pdb_path: None,
        tls_callbacks: None,
        entry_section: None,
        relocations_present: None,
        minos: None,
        code_signature: None,
    })
}

/// Analyze PE environment information.
fn analyze_pe_env(data: &[u8]) -> Option<BinaryEnv> {
    let obj = object::read::File::parse(data).ok()?;

    // Extract libraries from imports
    let mut libs = Vec::new();
    if let Ok(imps) = obj.imports() {
        for imp in imps {
            let lib = String::from_utf8_lossy(imp.library()).to_string();
            if !lib.is_empty() {
                libs.push(lib);
            }
        }
    }

    // Extract PE-specific information
    let pe_env = crate::symbols::analysis::pe_env::analyze_pe_env(data)?;

    Some(BinaryEnv {
        libs,
        rpaths: None,
        runpaths: None,
        pdb_path: pe_env.pdb_path,
        tls_callbacks: Some(pe_env.tls_callbacks as u32),
        entry_section: pe_env.entry_section,
        relocations_present: Some(pe_env.relocations_present),
        minos: None,
        code_signature: None,
    })
}

/// Analyze Mach-O environment information.
fn analyze_macho_env(data: &[u8]) -> Option<BinaryEnv> {
    let obj = object::read::File::parse(data).ok()?;

    // Extract libraries from imports
    let mut libs = Vec::new();
    if let Ok(imps) = obj.imports() {
        for imp in imps {
            let lib = String::from_utf8_lossy(imp.library()).to_string();
            if !lib.is_empty() {
                libs.push(lib);
            }
        }
    }

    // Extract Mach-O-specific information
    let macho_env = crate::symbols::analysis::macho_env::analyze_macho_env(data)?;

    Some(BinaryEnv {
        libs,
        rpaths: if macho_env.rpaths.is_empty() {
            None
        } else {
            Some(macho_env.rpaths)
        },
        runpaths: None,
        pdb_path: None,
        tls_callbacks: None,
        entry_section: None,
        relocations_present: None,
        minos: macho_env.minos,
        code_signature: Some(macho_env.code_signature),
    })
}
