//! APK / AAB / JAR reader.
//!
//! An APK is a ZIP archive. This provides just enough ZIP support to enumerate
//! members and extract the ones that matter for Android analysis — every
//! `classes*.dex`, the binary `AndroidManifest.xml`, and `resources.arsc` —
//! without pulling in a full ZIP crate. It reads the central directory (so the
//! member list is authoritative) and inflates `stored`/`deflate` members.
//!
//! Together with [`crate::formats::dex`] and [`crate::formats::axml`] this closes
//! the loop from an on-disk APK to its class list and exported components.

use std::collections::BTreeMap;
use std::io::Read;

/// APK reading errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApkError {
    /// No End-Of-Central-Directory record was found (not a ZIP).
    NotZip,
    /// A record ran past the end of the buffer.
    Truncated,
    /// An unsupported compression method was encountered.
    UnsupportedCompression(u16),
    /// The named member does not exist.
    NotFound(String),
    /// DEFLATE decompression failed.
    Inflate(String),
}

impl std::fmt::Display for ApkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotZip => write!(f, "not a ZIP/APK (no EOCD record)"),
            Self::Truncated => write!(f, "ZIP structure truncated"),
            Self::UnsupportedCompression(m) => write!(f, "unsupported compression method {}", m),
            Self::NotFound(n) => write!(f, "member not found: {}", n),
            Self::Inflate(e) => write!(f, "inflate failed: {}", e),
        }
    }
}

impl std::error::Error for ApkError {}

pub type Result<T> = std::result::Result<T, ApkError>;

const EOCD_SIG: u32 = 0x0605_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

#[derive(Debug, Clone)]
struct Entry {
    method: u16,
    comp_size: u64,
    uncomp_size: u64,
    local_header_off: u64,
}

/// A parsed ZIP/APK archive over borrowed bytes.
pub struct ApkReader<'a> {
    data: &'a [u8],
    entries: BTreeMap<String, Entry>,
}

fn u16le(d: &[u8], o: usize) -> Result<u16> {
    let b = d.get(o..o + 2).ok_or(ApkError::Truncated)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Result<u32> {
    let b = d.get(o..o + 4).ok_or(ApkError::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

impl<'a> ApkReader<'a> {
    /// Parse the central directory of a ZIP/APK.
    pub fn open(data: &'a [u8]) -> Result<Self> {
        let eocd = find_eocd(data).ok_or(ApkError::NotZip)?;
        let cd_entries = u16le(data, eocd + 10)? as usize;
        let cd_off = u32le(data, eocd + 16)? as usize;

        let mut entries = BTreeMap::new();
        let mut off = cd_off;
        for _ in 0..cd_entries {
            if u32le(data, off)? != CDFH_SIG {
                break;
            }
            let method = u16le(data, off + 10)?;
            let comp_size = u32le(data, off + 20)? as u64;
            let uncomp_size = u32le(data, off + 24)? as u64;
            let name_len = u16le(data, off + 28)? as usize;
            let extra_len = u16le(data, off + 30)? as usize;
            let comment_len = u16le(data, off + 32)? as usize;
            let local_header_off = u32le(data, off + 42)? as u64;
            let name_bytes = data
                .get(off + 46..off + 46 + name_len)
                .ok_or(ApkError::Truncated)?;
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            entries.insert(
                name,
                Entry {
                    method,
                    comp_size,
                    uncomp_size,
                    local_header_off,
                },
            );
            off += 46 + name_len + extra_len + comment_len;
        }

        Ok(Self { data, entries })
    }

    /// Sorted list of member paths.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    /// True if the archive contains a member with this exact path.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Extract and decompress a member by exact path.
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let e = self
            .entries
            .get(name)
            .ok_or_else(|| ApkError::NotFound(name.to_string()))?;

        // The local header repeats the name/extra lengths (which may differ from
        // the central directory), so the data offset must be computed from it.
        let lho = e.local_header_off as usize;
        let name_len = u16le(self.data, lho + 26)? as usize;
        let extra_len = u16le(self.data, lho + 28)? as usize;
        let data_off = lho + 30 + name_len + extra_len;
        let comp = self
            .data
            .get(data_off..data_off + e.comp_size as usize)
            .ok_or(ApkError::Truncated)?;

        match e.method {
            METHOD_STORED => Ok(comp.to_vec()),
            METHOD_DEFLATE => {
                let mut out = Vec::with_capacity(e.uncomp_size as usize);
                flate2::read::DeflateDecoder::new(comp)
                    .read_to_end(&mut out)
                    .map_err(|err| ApkError::Inflate(err.to_string()))?;
                Ok(out)
            }
            other => Err(ApkError::UnsupportedCompression(other)),
        }
    }

    /// All `classes*.dex` member paths, in natural multidex order
    /// (`classes.dex`, `classes2.dex`, `classes3.dex`, …).
    pub fn dex_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .entries
            .keys()
            .filter(|n| is_classes_dex(n))
            .cloned()
            .collect();
        names.sort_by_key(|n| dex_ordinal(n));
        names
    }

    /// Extract the binary `AndroidManifest.xml`, if present.
    pub fn manifest_bytes(&self) -> Option<Vec<u8>> {
        self.read("AndroidManifest.xml").ok()
    }

    /// Extract `resources.arsc`, if present.
    pub fn resources_arsc(&self) -> Option<Vec<u8>> {
        self.read("resources.arsc").ok()
    }
}

/// Whether a member path is a top-level `classesN.dex`.
fn is_classes_dex(name: &str) -> bool {
    name == "classes.dex"
        || (name.starts_with("classes")
            && name.ends_with(".dex")
            && name["classes".len()..name.len() - 4]
                .chars()
                .all(|c| c.is_ascii_digit()))
}

/// Sort key giving `classes.dex` ordinal 1 and `classesN.dex` ordinal N.
fn dex_ordinal(name: &str) -> u32 {
    if name == "classes.dex" {
        return 1;
    }
    name.get("classes".len()..name.len() - 4)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

/// Scan backwards for the End-Of-Central-Directory signature.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let scan_start = data.len().saturating_sub(22 + 65_535);
    for i in (scan_start..=data.len() - 22).rev() {
        if u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) == EOCD_SIG {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests;
