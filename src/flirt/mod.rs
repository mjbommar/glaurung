//! FLIRT-style signature matching (#158).
//!
//! Loads a JSON signature library produced by
//! `python -m glaurung.tools.build_flirt_library` and uses it to rename
//! `sub_*` functions in stripped binaries during the analysis pass.
//!
//! v1 design: exact-byte-equality match on a fixed-length prologue
//! starting at the function's entry VA. Library signatures with
//! identical prologues but different names were already pruned at
//! build time, so a hit here is unambiguous.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::core::function::Function;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtSignatureEntry {
    pub name: String,
    pub prologue_hex: String,
    #[serde(default)]
    pub source_binary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtLibraryFile {
    pub schema_version: String,
    pub arch: String,
    pub prologue_len: usize,
    pub entries: Vec<FlirtSignatureEntry>,
    /// Hex-prefix → indices into `entries`. Built by the Python tool;
    /// we don't strictly need it (we rebuild the runtime index ourselves)
    /// but we keep the field so deserialization is symmetric.
    #[serde(default)]
    pub index: HashMap<String, Vec<usize>>,
    #[serde(default)]
    pub stats: serde_json::Value,
}

/// In-memory matcher: prologue bytes → (name, length).
pub struct FlirtLibrary {
    pub arch: String,
    pub prologue_len: usize,
    by_prologue: HashMap<Vec<u8>, String>,
}

impl FlirtLibrary {
    pub fn from_file(file: FlirtLibraryFile) -> Self {
        let mut by_prologue: HashMap<Vec<u8>, String> = HashMap::new();
        for e in &file.entries {
            if let Ok(bytes) = hex_to_bytes(&e.prologue_hex) {
                if bytes.len() == file.prologue_len {
                    by_prologue.insert(bytes, e.name.clone());
                }
            }
        }
        Self {
            arch: file.arch,
            prologue_len: file.prologue_len,
            by_prologue,
        }
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let f: FlirtLibraryFile = serde_json::from_str(s)?;
        Ok(Self::from_file(f))
    }

    pub fn match_prologue(&self, prologue: &[u8]) -> Option<&str> {
        if prologue.len() != self.prologue_len {
            return None;
        }
        self.by_prologue.get(prologue).map(|s| s.as_str())
    }

    pub fn signature_count(&self) -> usize {
        self.by_prologue.len()
    }
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("odd hex length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex")?;
        out.push(byte);
    }
    Ok(out)
}

/// Look up the default library file. Search order:
///   1. `GLAURUNG_FLIRT_LIB` env var (single file).
///   2. `data/sigs/glaurung-base.<arch>.flirt.json` relative to the cwd.
///   3. `data/sigs/glaurung-base.x86_64.flirt.json` as a final fallback.
///
/// Returns `None` if no library is reachable — that's fine, the matcher
/// pass becomes a no-op when no library is available.
pub fn default_library_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GLAURUNG_FLIRT_LIB") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    let candidate = cwd.join("data/sigs/glaurung-base.x86_64.flirt.json");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

/// Try to load the default FLIRT library. Returns `None` silently if no
/// library is available; analysis falls back to whatever DWARF and
/// symbol-table renaming already accomplished.
pub fn load_default_library() -> Option<FlirtLibrary> {
    let path = default_library_path()?;
    let text = std::fs::read_to_string(&path).ok()?;
    FlirtLibrary::from_json(&text).ok()
}

/// Build a (vm_start, vm_size, file_offset) → (vm_start, vm_size, file_offset)
/// projection for the binary, used to map VA ↔ file offset.
fn build_va_map(data: &[u8]) -> Vec<(u64, u64, u64)> {
    use object::{Object, ObjectSection, ObjectSegment};
    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let mut maps: Vec<(u64, u64, u64)> = Vec::new();
    let mut have_segments = false;
    for seg in obj.segments() {
        let (faddr, fsize) = seg.file_range();
        if fsize == 0 {
            continue;
        }
        let vaddr = seg.address();
        let vsize = seg.size();
        if vsize == 0 {
            continue;
        }
        maps.push((vaddr, vsize, faddr));
        have_segments = true;
    }
    if !have_segments {
        for sec in obj.sections() {
            let vaddr = sec.address();
            let vsize = sec.size();
            if vsize == 0 {
                continue;
            }
            if let Some((faddr, _flen)) = sec.file_range() {
                maps.push((vaddr, vsize, faddr));
            }
        }
    }
    maps
}

fn va_to_file_off(maps: &[(u64, u64, u64)], va: u64) -> Option<usize> {
    for (vaddr, vsize, faddr) in maps {
        if va >= *vaddr && va < vaddr + vsize {
            let delta = va - vaddr;
            return Some((faddr + delta) as usize);
        }
    }
    None
}

/// Scan executable regions for prologue matches against `lib`, returning
/// `(va, name)` pairs for every byte offset where a known signature
/// matches. This is what gives FLIRT real teeth on stripped binaries:
/// the symbol table is gone, so seed discovery from FLIRT hits.
///
/// Skips matches that would land inside a known existing Function chunk
/// to avoid duplicate seeding.
pub fn discover_flirt_seeds(
    data: &[u8],
    existing: &[Function],
    lib: &FlirtLibrary,
) -> Vec<(u64, String)> {
    use object::{Object, ObjectSection, SectionKind};

    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let known_starts: std::collections::HashSet<u64> =
        existing.iter().map(|f| f.entry_point.value).collect();

    let mut seeds: Vec<(u64, String)> = Vec::new();
    let mut seen_vas: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for sec in obj.sections() {
        if !matches!(
            sec.kind(),
            SectionKind::Text | SectionKind::OtherString | SectionKind::Other
        ) && sec.kind() != SectionKind::Text
        {
            // Restrict scanning to executable code sections.
            continue;
        }
        let (faddr, fsize) = match sec.file_range() {
            Some(t) => t,
            None => continue,
        };
        if fsize == 0 {
            continue;
        }
        let start = faddr as usize;
        let end = std::cmp::min(data.len(), (faddr + fsize) as usize);
        if end <= start || end - start < lib.prologue_len {
            continue;
        }
        let vbase = sec.address();

        // Slide a window byte by byte. Could be sped up with a 4-byte
        // prefix index, but on small text sections this is already
        // sub-millisecond; keep v1 simple.
        let mut off = start;
        while off + lib.prologue_len <= end {
            let proto = &data[off..off + lib.prologue_len];
            if let Some(name) = lib.match_prologue(proto) {
                let va = vbase + (off as u64 - faddr);
                if !known_starts.contains(&va) && !seen_vas.contains(&va) {
                    // Don't seed the same name twice — typically means
                    // the matcher hit on inlined boilerplate. Prefer the
                    // first match (lower VA).
                    if !seen_names.contains(name) {
                        seen_vas.insert(va);
                        seen_names.insert(name.to_string());
                        seeds.push((va, name.to_string()));
                    }
                }
            }
            off += 1;
        }
    }
    seeds
}

/// Rename every `sub_*` function whose entry-VA prologue exactly matches
/// a signature in `lib`. Reads prologues from `data` via the binary's
/// section table (`object` crate). Returns the number of renames applied.
pub fn apply_flirt_overrides(
    data: &[u8], functions: &mut [Function], lib: &FlirtLibrary,
) -> usize {
    let maps = build_va_map(data);
    let mut renamed = 0usize;
    for f in functions.iter_mut() {
        // Only rename placeholder sub_* names; never overwrite a name we
        // already trust (DWARF, symbol table, manual).
        if !f.name.starts_with("sub_") {
            continue;
        }
        let foff = match va_to_file_off(&maps, f.entry_point.value) {
            Some(o) => o,
            None => continue,
        };
        let end = foff.saturating_add(lib.prologue_len);
        if end > data.len() {
            continue;
        }
        let proto = &data[foff..end];
        if let Some(name) = lib.match_prologue(proto) {
            f.name = name.to_string();
            renamed += 1;
        }
    }
    renamed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _tiny_library() -> FlirtLibrary {
        let json = r#"{
          "schema_version": "1",
          "arch": "x86_64",
          "prologue_len": 8,
          "entries": [
            {"name": "expected_name", "prologue_hex": "554889e54883ec10", "source_binary": "test"}
          ],
          "index": {}
        }"#;
        FlirtLibrary::from_json(json).unwrap()
    }

    #[test]
    fn matches_known_prologue() {
        let lib = _tiny_library();
        assert_eq!(lib.signature_count(), 1);
        let proto = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        assert_eq!(lib.match_prologue(proto), Some("expected_name"));
    }

    #[test]
    fn rejects_wrong_length() {
        let lib = _tiny_library();
        let too_short = &[0x55, 0x48, 0x89, 0xe5];
        assert_eq!(lib.match_prologue(too_short), None);
    }

    #[test]
    fn rejects_non_matching_prologue() {
        let lib = _tiny_library();
        let other = &[0xff; 8];
        assert_eq!(lib.match_prologue(other), None);
    }

    #[test]
    fn from_json_round_trip() {
        let lib = _tiny_library();
        assert_eq!(lib.arch, "x86_64");
        assert_eq!(lib.prologue_len, 8);
    }
}
