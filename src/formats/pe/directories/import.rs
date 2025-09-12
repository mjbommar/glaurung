//! Import table parsing

use std::collections::{BTreeMap, HashMap};

use crate::formats::pe::sections::SectionTable;
use crate::formats::pe::types::*;
use crate::formats::pe::utils::{read_cstring, ReadExt};

/// Import table containing all imports
#[derive(Debug, Clone, Default)]
pub struct ImportTable<'a> {
    pub descriptors: Vec<ImportDescriptor<'a>>,
    pub by_name: HashMap<&'a str, Vec<ImportEntry<'a>>>,
    pub by_dll: HashMap<&'a str, Vec<ImportEntry<'a>>>,
    pub iat_map: BTreeMap<u64, &'a str>,
}

impl<'a> ImportTable<'a> {
    /// Get total import count
    pub fn count(&self) -> usize {
        self.descriptors.iter().map(|d| d.entries.len()).sum()
    }

    /// Get all import names
    pub fn names(&self) -> Vec<&'a str> {
        self.by_name.keys().copied().collect()
    }

    /// Get all DLL names
    pub fn dll_names(&self) -> Vec<&'a str> {
        self.by_dll.keys().copied().collect()
    }

    /// Check if an import exists by name
    pub fn has_import(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Get imports by DLL name
    pub fn imports_from_dll(&self, dll: &str) -> Option<&[ImportEntry<'a>]> {
        self.by_dll.get(dll).map(|v| v.as_slice())
    }

    /// Calculate import hash (for imphash)
    pub fn import_hash(&self) -> String {
        let mut entries = Vec::new();

        for desc in &self.descriptors {
            let dll_name = desc.dll_name.to_ascii_lowercase();
            for entry in &desc.entries {
                if let Some(name) = entry.name {
                    entries.push(format!("{}.{}", dll_name, name.to_ascii_lowercase()));
                }
            }
        }

        entries.sort();
        let joined = entries.join(",");
        format!("{:032x}", md5::compute(joined.as_bytes()))
    }
}

/// Parse import table from PE data
pub fn parse_imports<'a>(
    data: &'a [u8],
    sections: &SectionTable,
    import_dir: &DataDirectory,
    delay_dir: &DataDirectory,
    image_base: u64,
    is_64bit: bool,
    options: &ParseOptions,
) -> Result<ImportTable<'a>> {
    let mut table = ImportTable::default();

    // Parse normal imports
    if import_dir.virtual_address != 0 && import_dir.size > 0 && options.parse_imports {
        parse_import_directory(
            data,
            sections,
            import_dir.virtual_address,
            image_base,
            is_64bit,
            false,
            &mut table,
            options.max_imports,
        )?;
    }

    // Parse delay imports
    if delay_dir.virtual_address != 0 && delay_dir.size > 0 && options.parse_imports {
        parse_import_directory(
            data,
            sections,
            delay_dir.virtual_address,
            image_base,
            is_64bit,
            true,
            &mut table,
            options.max_imports,
        )?;
    }

    Ok(table)
}

fn parse_import_directory<'a>(
    data: &'a [u8],
    sections: &SectionTable,
    dir_rva: u32,
    image_base: u64,
    is_64bit: bool,
    _is_delay: bool,
    table: &mut ImportTable<'a>,
    max_imports: usize,
) -> Result<()> {
    let mut offset = sections
        .rva_to_offset(dir_rva)
        .ok_or(PeError::InvalidRva { rva: dir_rva })?;

    let mut total_imports = 0;

    // Parse import descriptors
    loop {
        if offset + 20 > data.len() {
            break;
        }

        // Check for terminator (all zeros)
        let desc_data = &data[offset..offset + 20];
        if desc_data.iter().all(|&b| b == 0) {
            break;
        }

        let original_first_thunk = data
            .read_u32_le_at(offset)
            .ok_or(PeError::InvalidOffset { offset })?;
        let time_date_stamp = data
            .read_u32_le_at(offset + 4)
            .ok_or(PeError::InvalidOffset { offset: offset + 4 })?;
        let forwarder_chain = data
            .read_u32_le_at(offset + 8)
            .ok_or(PeError::InvalidOffset { offset: offset + 8 })?;
        let name_rva = data
            .read_u32_le_at(offset + 12)
            .ok_or(PeError::InvalidOffset {
                offset: offset + 12,
            })?;
        let first_thunk = data
            .read_u32_le_at(offset + 16)
            .ok_or(PeError::InvalidOffset {
                offset: offset + 16,
            })?;

        // Skip invalid entries
        if name_rva == 0 {
            offset += 20;
            continue;
        }

        // Read DLL name
        let name_offset = sections
            .rva_to_offset(name_rva)
            .ok_or(PeError::InvalidRva { rva: name_rva })?;
        let dll_name = read_cstring(data, name_offset, 256)?;

        // Parse thunks
        let entries = parse_thunks(
            data,
            sections,
            original_first_thunk,
            first_thunk,
            image_base,
            is_64bit,
            max_imports - total_imports,
        )?;

        total_imports += entries.len();

        // Update lookup tables
        for entry in &entries {
            if let Some(name) = entry.name {
                table
                    .by_name
                    .entry(name)
                    .or_default()
                    .push(entry.clone());
            }
            if let Some(va) = entry.iat_va.into() {
                if let Some(name) = entry.name {
                    table.iat_map.insert(va, name);
                }
            }
        }

        table
            .by_dll
            .entry(dll_name)
            .or_default()
            .extend(entries.iter().cloned());

        let descriptor = ImportDescriptor {
            dll_name,
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            first_thunk,
            entries,
        };

        table.descriptors.push(descriptor);

        offset += 20;

        if total_imports >= max_imports {
            break;
        }
    }

    Ok(())
}

fn parse_thunks<'a>(
    data: &'a [u8],
    sections: &SectionTable,
    original_first_thunk: u32,
    first_thunk: u32,
    image_base: u64,
    is_64bit: bool,
    max_count: usize,
) -> Result<Vec<ImportEntry<'a>>> {
    let mut entries = Vec::new();

    // Use original first thunk if available, otherwise first thunk
    let thunk_rva = if original_first_thunk != 0 {
        original_first_thunk
    } else {
        first_thunk
    };

    if thunk_rva == 0 {
        return Ok(entries);
    }

    let mut thunk_offset = sections
        .rva_to_offset(thunk_rva)
        .ok_or(PeError::InvalidRva { rva: thunk_rva })?;

    let entry_size = if is_64bit { 8 } else { 4 };
    let mut index = 0;

    while entries.len() < max_count {
        if thunk_offset + entry_size > data.len() {
            break;
        }

        // Read thunk value
        let val = if is_64bit {
            data.read_u64_le_at(thunk_offset)
                .ok_or(PeError::InvalidOffset {
                    offset: thunk_offset,
                })?
        } else {
            data.read_u32_le_at(thunk_offset)
                .ok_or(PeError::InvalidOffset {
                    offset: thunk_offset,
                })? as u64
        };

        // Check for terminator
        if val == 0 {
            break;
        }

        // Calculate IAT VA
        let iat_va = if first_thunk != 0 {
            image_base + first_thunk as u64 + (index * entry_size) as u64
        } else {
            0
        };

        // Check if this is an ordinal import
        let is_ordinal = if is_64bit {
            (val & (1u64 << 63)) != 0
        } else {
            (val & (1u64 << 31)) != 0
        };

        let (name, ordinal, hint) = if is_ordinal {
            // Ordinal import
            let ord = (val & 0xFFFF) as u16;
            (None, Some(ord), None)
        } else {
            // Name import
            let hint_name_rva = (val & 0x7FFFFFFF) as u32;
            if let Some(hint_offset) = sections.rva_to_offset(hint_name_rva) {
                if hint_offset + 2 <= data.len() {
                    let hint = data
                        .read_u16_le_at(hint_offset)
                        .ok_or(PeError::InvalidOffset {
                            offset: hint_offset,
                        })?;
                    let name = read_cstring(data, hint_offset + 2, 512).ok();
                    (name, None, Some(hint))
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            }
        };

        entries.push(ImportEntry {
            name,
            ordinal,
            hint,
            iat_va,
        });

        thunk_offset += entry_size;
        index += 1;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_hash() {
        let table = ImportTable {
            descriptors: vec![ImportDescriptor {
                dll_name: "KERNEL32.dll",
                original_first_thunk: 0,
                time_date_stamp: 0,
                forwarder_chain: 0,
                name_rva: 0,
                first_thunk: 0,
                entries: vec![
                    ImportEntry {
                        name: Some("CreateFileA"),
                        ordinal: None,
                        hint: None,
                        iat_va: 0,
                    },
                    ImportEntry {
                        name: Some("ReadFile"),
                        ordinal: None,
                        hint: None,
                        iat_va: 0,
                    },
                ],
            }],
            by_name: HashMap::new(),
            by_dll: HashMap::new(),
            iat_map: BTreeMap::new(),
        };

        let hash = table.import_hash();
        // The hash should be deterministic
        assert_eq!(hash.len(), 32); // MD5 hash is 32 hex chars
    }

    #[test]
    fn test_import_table_queries() {
        let mut table = ImportTable::default();

        let entry1 = ImportEntry {
            name: Some("CreateFileA"),
            ordinal: None,
            hint: Some(100),
            iat_va: 0x1000,
        };

        let entry2 = ImportEntry {
            name: Some("ReadFile"),
            ordinal: None,
            hint: Some(200),
            iat_va: 0x1008,
        };

        table.by_name.insert("CreateFileA", vec![entry1.clone()]);
        table.by_name.insert("ReadFile", vec![entry2.clone()]);
        table.by_dll.insert("kernel32.dll", vec![entry1, entry2]);

        assert!(table.has_import("CreateFileA"));
        assert!(table.has_import("ReadFile"));
        assert!(!table.has_import("WriteFile"));

        let dll_imports = table.imports_from_dll("kernel32.dll").unwrap();
        assert_eq!(dll_imports.len(), 2);
    }
}
