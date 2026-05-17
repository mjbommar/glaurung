//! PE debug-directory parsing.

use std::path::{Path, PathBuf};

use crate::formats::pe::sections::SectionTable;
use crate::formats::pe::types::{DataDirectory, DebugEntry, PeError, Result};
use crate::formats::pe::utils::ReadExt;

const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;
const CODEVIEW_RSDS_SIGNATURE: &[u8; 4] = b"RSDS";

/// CodeView RSDS record from a PE debug directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeViewRsds {
    /// CodeView GUID bytes in on-disk order.
    pub guid: [u8; 16],
    /// Microsoft symbol-server GUID spelling, uppercase 32 hex chars.
    pub guid_string: String,
    /// CodeView age value.
    pub age: u32,
    /// PDB path as embedded in the PE.
    pub pdb_path: String,
    /// Basename used by Microsoft symbol-server paths.
    pub pdb_name: String,
}

impl CodeViewRsds {
    /// Microsoft symbol-server key: `<GUID><AGE>`.
    pub fn guid_age_key(&self) -> String {
        format!("{}{:X}", self.guid_string, self.age)
    }

    /// Canonical Microsoft symbol-cache path for this RSDS record.
    pub fn symbol_cache_path(&self, cache_dir: &Path) -> PathBuf {
        cache_dir
            .join(&self.pdb_name)
            .join(self.guid_age_key())
            .join(&self.pdb_name)
    }

    /// Flat fixture-cache fallback path for this RSDS record.
    pub fn flat_cache_path(&self, cache_dir: &Path) -> PathBuf {
        cache_dir.join(&self.pdb_name)
    }

    /// Resolve this RSDS record against a local cache.
    pub fn resolve_pdb_path(&self, cache_dir: &Path) -> Option<PathBuf> {
        pdb_cache_candidates(self, cache_dir)
            .into_iter()
            .find(|candidate| candidate.is_file())
    }
}

/// Parsed PE debug-directory summary.
#[derive(Debug, Clone, Default)]
pub struct DebugDirectory {
    /// IMAGE_DEBUG_DIRECTORY entries.
    pub entries: Vec<DebugEntry>,
    /// First CodeView RSDS record, when present.
    pub codeview: Option<CodeViewRsds>,
    /// Non-fatal parse warnings.
    pub warnings: Vec<&'static str>,
}

/// Parse the PE debug directory and extract the first CodeView RSDS record.
pub fn parse_debug_directory(
    data: &[u8],
    sections: &SectionTable,
    debug_dir: &DataDirectory,
) -> Result<DebugDirectory> {
    let mut directory = DebugDirectory::default();

    if debug_dir.virtual_address == 0 || debug_dir.size == 0 {
        return Ok(directory);
    }

    let Some(debug_offset) = sections.rva_to_offset(debug_dir.virtual_address) else {
        directory.warnings.push("invalid_debug_directory_rva");
        return Ok(directory);
    };

    let entry_count = (debug_dir.size as usize) / IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
    for index in 0..entry_count {
        let entry_offset = debug_offset + index * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
        let Some(entry) = parse_debug_entry(data, entry_offset) else {
            directory.warnings.push("truncated_debug_directory");
            break;
        };

        if directory.codeview.is_none() && entry.debug_type == IMAGE_DEBUG_TYPE_CODEVIEW {
            match parse_codeview_rsds(data, sections, &entry) {
                Ok(Some(rsds)) => directory.codeview = Some(rsds),
                Ok(None) => directory.warnings.push("missing_codeview_rsds"),
                Err(_) => directory.warnings.push("malformed_codeview_rsds"),
            }
        }

        directory.entries.push(entry);
    }

    Ok(directory)
}

fn parse_debug_entry(data: &[u8], offset: usize) -> Option<DebugEntry> {
    Some(DebugEntry {
        characteristics: data.read_u32_le_at(offset)?,
        time_date_stamp: data.read_u32_le_at(offset + 4)?,
        major_version: data.read_u16_le_at(offset + 8)?,
        minor_version: data.read_u16_le_at(offset + 10)?,
        debug_type: data.read_u32_le_at(offset + 12)?,
        size_of_data: data.read_u32_le_at(offset + 16)?,
        address_of_raw_data: data.read_u32_le_at(offset + 20)?,
        pointer_to_raw_data: data.read_u32_le_at(offset + 24)?,
    })
}

fn parse_codeview_rsds(
    data: &[u8],
    sections: &SectionTable,
    entry: &DebugEntry,
) -> Result<Option<CodeViewRsds>> {
    let data_offset = if entry.pointer_to_raw_data != 0 {
        entry.pointer_to_raw_data as usize
    } else {
        sections
            .rva_to_offset(entry.address_of_raw_data)
            .ok_or(PeError::InvalidRva {
                rva: entry.address_of_raw_data,
            })?
    };

    let data_size = entry.size_of_data as usize;
    if data_offset + data_size > data.len() || data_size < 24 {
        return Ok(None);
    }

    let record = &data[data_offset..data_offset + data_size];
    if record.get(0..4) != Some(CODEVIEW_RSDS_SIGNATURE) {
        return Ok(None);
    }

    let mut guid = [0u8; 16];
    guid.copy_from_slice(&record[4..20]);
    let age = u32::from_le_bytes([record[20], record[21], record[22], record[23]]);
    let pdb_path = read_nul_terminated_utf8(&record[24..]).ok_or(PeError::InvalidString)?;
    let pdb_name = pdb_basename(&pdb_path);

    Ok(Some(CodeViewRsds {
        guid,
        guid_string: format_codeview_guid(&guid),
        age,
        pdb_path,
        pdb_name,
    }))
}

fn read_nul_terminated_utf8(data: &[u8]) -> Option<String> {
    let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let value = std::str::from_utf8(&data[..len]).ok()?.to_string();
    (!value.is_empty()).then_some(value)
}

fn pdb_basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn format_codeview_guid(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    let mut out = format!("{d1:08X}{d2:04X}{d3:04X}");
    for byte in &guid[8..] {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn pdb_cache_candidates(rsds: &CodeViewRsds, cache_dir: &Path) -> Vec<PathBuf> {
    let key = rsds.guid_age_key();
    let lower_name = rsds.pdb_name.to_ascii_lowercase();
    let mut candidates = vec![
        rsds.symbol_cache_path(cache_dir),
        rsds.flat_cache_path(cache_dir),
    ];

    if lower_name != rsds.pdb_name {
        candidates.push(cache_dir.join(&lower_name).join(&key).join(&lower_name));
        candidates.push(cache_dir.join(&lower_name));
    }

    candidates
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::formats::pe::PeParser;

    fn fixture(name: &str) -> Option<PathBuf> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
            .join(name);
        path.is_file().then_some(path)
    }

    #[test]
    fn parses_ntoskrnl_codeview_rsds() {
        let Some(path) = fixture("ntoskrnl.exe") else {
            eprintln!("skipping RSDS fixture test: ntoskrnl.exe is not present");
            return;
        };

        let data = fs::read(path).expect("read ntoskrnl.exe");
        let parser = PeParser::new(&data).expect("parse PE");
        let debug = parser.debug_directory().expect("parse debug directory");
        let rsds = debug
            .codeview
            .as_ref()
            .expect("ntoskrnl.exe should contain CodeView RSDS");

        assert_eq!(rsds.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(rsds.guid_string, "CF32DE2E4A334C7C06FB63FCB6FAFB5C");
        assert_eq!(rsds.age, 1);
        assert_eq!(rsds.guid_age_key(), "CF32DE2E4A334C7C06FB63FCB6FAFB5C1");
    }
}
