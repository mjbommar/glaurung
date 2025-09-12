//! Export table parsing

use std::collections::HashMap;

use crate::formats::pe::sections::SectionTable;
use crate::formats::pe::types::*;
use crate::formats::pe::utils::{read_cstring, ReadExt};

/// Export table containing all exports
#[derive(Debug, Clone, Default)]
pub struct ExportTable<'a> {
    pub dll_name: Option<&'a str>,
    pub ordinal_base: u32,
    pub exports: Vec<ExportEntry<'a>>,
    pub by_name: HashMap<&'a str, usize>,
    pub by_ordinal: HashMap<u32, usize>,
}

impl<'a> ExportTable<'a> {
    /// Get export by name
    pub fn get_by_name(&self, name: &str) -> Option<&ExportEntry<'a>> {
        self.by_name
            .get(name)
            .and_then(|&idx| self.exports.get(idx))
    }

    /// Get export by ordinal
    pub fn get_by_ordinal(&self, ordinal: u32) -> Option<&ExportEntry<'a>> {
        self.by_ordinal
            .get(&ordinal)
            .and_then(|&idx| self.exports.get(idx))
    }

    /// Get all export names
    pub fn names(&self) -> Vec<&'a str> {
        self.exports.iter().filter_map(|e| e.name).collect()
    }

    /// Count of exports
    pub fn count(&self) -> usize {
        self.exports.len()
    }

    /// Count of named exports
    pub fn named_count(&self) -> usize {
        self.exports.iter().filter(|e| e.name.is_some()).count()
    }
}

/// Parse export table from PE data
pub fn parse_exports<'a>(
    data: &'a [u8],
    sections: &SectionTable,
    export_dir: &DataDirectory,
    options: &ParseOptions,
) -> Result<ExportTable<'a>> {
    if export_dir.virtual_address == 0 || export_dir.size == 0 || !options.parse_exports {
        return Ok(ExportTable::default());
    }

    let dir_offset =
        sections
            .rva_to_offset(export_dir.virtual_address)
            .ok_or(PeError::InvalidRva {
                rva: export_dir.virtual_address,
            })?;

    if dir_offset + 40 > data.len() {
        return Err(PeError::TruncatedHeader {
            expected: dir_offset + 40,
            actual: data.len(),
        });
    }

    // Parse export directory table
    let _characteristics = data
        .read_u32_le_at(dir_offset)
        .ok_or(PeError::InvalidOffset { offset: dir_offset })?;
    let _time_date_stamp = data
        .read_u32_le_at(dir_offset + 4)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 4,
        })?;
    let _major_version = data
        .read_u16_le_at(dir_offset + 8)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 8,
        })?;
    let _minor_version = data
        .read_u16_le_at(dir_offset + 10)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 10,
        })?;
    let name_rva = data
        .read_u32_le_at(dir_offset + 12)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 12,
        })?;
    let ordinal_base = data
        .read_u32_le_at(dir_offset + 16)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 16,
        })?;
    let number_of_functions =
        data.read_u32_le_at(dir_offset + 20)
            .ok_or(PeError::InvalidOffset {
                offset: dir_offset + 20,
            })?;
    let number_of_names = data
        .read_u32_le_at(dir_offset + 24)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 24,
        })?;
    let address_table_rva = data
        .read_u32_le_at(dir_offset + 28)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 28,
        })?;
    let name_table_rva = data
        .read_u32_le_at(dir_offset + 32)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 32,
        })?;
    let ordinal_table_rva = data
        .read_u32_le_at(dir_offset + 36)
        .ok_or(PeError::InvalidOffset {
            offset: dir_offset + 36,
        })?;

    // DLL name
    let dll_name = if name_rva != 0 {
        let offset = sections
            .rva_to_offset(name_rva)
            .ok_or(PeError::InvalidRva { rva: name_rva })?;
        Some(read_cstring(data, offset, 256)?)
    } else {
        None
    };

    // Limit exports to prevent DOS
    let number_of_functions = number_of_functions.min(options.max_exports as u32);
    let number_of_names = number_of_names.min(options.max_exports as u32);

    // Parse address table
    let addr_offset = sections
        .rva_to_offset(address_table_rva)
        .ok_or(PeError::InvalidRva {
            rva: address_table_rva,
        })?;

    let mut addresses = Vec::with_capacity(number_of_functions as usize);
    for i in 0..number_of_functions {
        let offset = addr_offset + (i as usize * 4);
        if offset + 4 > data.len() {
            break;
        }
        let rva = data
            .read_u32_le_at(offset)
            .ok_or(PeError::InvalidOffset { offset })?;
        addresses.push(rva);
    }

    // Parse name and ordinal tables
    let mut name_map = HashMap::new();
    if number_of_names > 0 && name_table_rva != 0 && ordinal_table_rva != 0 {
        let name_offset = sections
            .rva_to_offset(name_table_rva)
            .ok_or(PeError::InvalidRva {
                rva: name_table_rva,
            })?;
        let ord_offset = sections
            .rva_to_offset(ordinal_table_rva)
            .ok_or(PeError::InvalidRva {
                rva: ordinal_table_rva,
            })?;

        for i in 0..number_of_names as usize {
            let name_ptr_offset = name_offset + (i * 4);
            let ord_val_offset = ord_offset + (i * 2);

            if name_ptr_offset + 4 > data.len() || ord_val_offset + 2 > data.len() {
                break;
            }

            let name_rva = data
                .read_u32_le_at(name_ptr_offset)
                .ok_or(PeError::InvalidOffset {
                    offset: name_ptr_offset,
                })?;
            let ordinal_index =
                data.read_u16_le_at(ord_val_offset)
                    .ok_or(PeError::InvalidOffset {
                        offset: ord_val_offset,
                    })?;

            if name_rva != 0 {
                let name_off = sections
                    .rva_to_offset(name_rva)
                    .ok_or(PeError::InvalidRva { rva: name_rva })?;
                let name = read_cstring(data, name_off, 512)?;
                name_map.insert(ordinal_index as usize, name);
            }
        }
    }

    // Build export entries
    let mut exports = Vec::new();
    let mut by_name = HashMap::new();
    let mut by_ordinal = HashMap::new();

    for (i, &rva) in addresses.iter().enumerate() {
        if rva == 0 {
            continue; // Unused slot
        }

        let ordinal = ordinal_base + i as u32;
        let name = name_map.get(&i).copied();

        // Check if this is a forwarder
        let forwarder = if rva >= export_dir.virtual_address
            && rva < export_dir.virtual_address + export_dir.size
        {
            // RVA points inside export directory = forwarder
            if let Some(offset) = sections.rva_to_offset(rva) {
                read_cstring(data, offset, 256).ok()
            } else {
                None
            }
        } else {
            None
        };

        let entry_idx = exports.len();
        exports.push(ExportEntry {
            name,
            ordinal,
            rva,
            forwarder,
        });

        if let Some(n) = name {
            by_name.insert(n, entry_idx);
        }
        by_ordinal.insert(ordinal, entry_idx);
    }

    Ok(ExportTable {
        dll_name,
        ordinal_base,
        exports,
        by_name,
        by_ordinal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_table_queries() {
        let mut table = ExportTable::default();
        table.ordinal_base = 1;

        let entry1 = ExportEntry {
            name: Some("Function1"),
            ordinal: 1,
            rva: 0x1000,
            forwarder: None,
        };

        let entry2 = ExportEntry {
            name: Some("Function2"),
            ordinal: 2,
            rva: 0x2000,
            forwarder: None,
        };

        let entry3 = ExportEntry {
            name: None,
            ordinal: 3,
            rva: 0x3000,
            forwarder: None,
        };

        table.exports.push(entry1);
        table.exports.push(entry2);
        table.exports.push(entry3);

        table.by_name.insert("Function1", 0);
        table.by_name.insert("Function2", 1);
        table.by_ordinal.insert(1, 0);
        table.by_ordinal.insert(2, 1);
        table.by_ordinal.insert(3, 2);

        // Test by-name lookup
        let export = table.get_by_name("Function1").unwrap();
        assert_eq!(export.ordinal, 1);
        assert_eq!(export.rva, 0x1000);

        // Test by-ordinal lookup
        let export = table.get_by_ordinal(3).unwrap();
        assert!(export.name.is_none());
        assert_eq!(export.rva, 0x3000);

        // Test counts
        assert_eq!(table.count(), 3);
        assert_eq!(table.named_count(), 2);

        // Test names
        let names = table.names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Function1"));
        assert!(names.contains(&"Function2"));
    }
}
