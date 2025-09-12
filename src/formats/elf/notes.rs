//! Note section parsing

use crate::formats::elf::types::*;
use crate::formats::elf::utils::{align_up, EndianRead};

/// Note section containing build ID and other metadata
pub struct NoteSection<'a> {
    notes: Vec<Note<'a>>,
}

/// Individual note entry
pub struct Note<'a> {
    pub n_type: u32,
    pub name: &'a str,
    pub desc: &'a [u8],
}

impl<'a> NoteSection<'a> {
    /// Parse note section from data
    pub fn parse(data: &'a [u8], endian: ElfData) -> Result<Self> {
        let mut notes = Vec::new();
        let mut offset = 0;

        while offset + 12 <= data.len() {
            // Parse note header
            let n_namesz = data.read_u32(offset, endian)?;
            let n_descsz = data.read_u32(offset + 4, endian)?;
            let n_type = data.read_u32(offset + 8, endian)?;

            offset += 12;

            // Read name (aligned to 4 bytes)
            let name_end = offset + n_namesz as usize;
            if name_end > data.len() {
                break;
            }

            let name_bytes = &data[offset..name_end];
            let name = if n_namesz > 0 {
                // Remove trailing null
                let len = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                std::str::from_utf8(&name_bytes[..len]).unwrap_or("")
            } else {
                ""
            };

            offset = align_up(name_end as u64, 4) as usize;

            // Read descriptor (aligned to 4 bytes)
            let desc_end = offset + n_descsz as usize;
            if desc_end > data.len() {
                break;
            }

            let desc = &data[offset..desc_end];
            offset = align_up(desc_end as u64, 4) as usize;

            notes.push(Note { n_type, name, desc });
        }

        Ok(Self { notes })
    }

    /// Get build ID if present
    pub fn build_id(&self) -> Option<&'a [u8]> {
        self.notes
            .iter()
            .find(|n| n.name == "GNU" && n.n_type == NT_GNU_BUILD_ID)
            .map(|n| n.desc)
    }

    /// Get GNU properties
    pub fn gnu_properties(&self) -> Vec<GnuProperty> {
        self.notes
            .iter()
            .filter(|n| n.name == "GNU" && n.n_type == NT_GNU_PROPERTY_TYPE_0)
            .flat_map(|n| parse_gnu_properties(n.desc))
            .collect()
    }

    /// Get all notes
    pub fn notes(&self) -> &[Note<'a>] {
        &self.notes
    }

    /// Check if has debug link
    pub fn has_debug_link(&self) -> bool {
        self.notes
            .iter()
            .any(|n| n.name == "GNU" && n.n_type == 0x3) // NT_GNU_BUILD_ID
    }
}

/// GNU property types
#[derive(Debug, Clone)]
pub enum GnuProperty {
    StackSize(u64),
    NoExecStack,
    X86Feature { needed: u32, used: u32 },
    Other { type_: u32, data: Vec<u8> },
}

/// Parse GNU properties from descriptor
fn parse_gnu_properties(data: &[u8]) -> Vec<GnuProperty> {
    let mut properties = Vec::new();
    let mut offset = 0;

    // Properties are stored as type-length-value
    while offset + 8 <= data.len() {
        let prop_type = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let prop_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        if offset + prop_size as usize > data.len() {
            break;
        }

        let prop_data = &data[offset..offset + prop_size as usize];

        let property = match prop_type {
            0xc0000002 => {
                // GNU_PROPERTY_STACK_SIZE
                if prop_size >= 8 {
                    let size = u64::from_le_bytes(prop_data[0..8].try_into().unwrap());
                    GnuProperty::StackSize(size)
                } else {
                    GnuProperty::Other {
                        type_: prop_type,
                        data: prop_data.to_vec(),
                    }
                }
            }
            0xc0000003 => GnuProperty::NoExecStack, // GNU_PROPERTY_NO_EXEC_STACK
            0xc0010000 => {
                // GNU_PROPERTY_X86_FEATURE_1_AND
                if prop_size >= 8 {
                    let needed = u32::from_le_bytes(prop_data[0..4].try_into().unwrap());
                    let used = u32::from_le_bytes(prop_data[4..8].try_into().unwrap());
                    GnuProperty::X86Feature { needed, used }
                } else {
                    GnuProperty::Other {
                        type_: prop_type,
                        data: prop_data.to_vec(),
                    }
                }
            }
            _ => GnuProperty::Other {
                type_: prop_type,
                data: prop_data.to_vec(),
            },
        };

        properties.push(property);
        offset = align_up((offset + prop_size as usize) as u64, 8) as usize;
    }

    properties
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_note_section() -> Vec<u8> {
        let mut data = Vec::new();

        // Note 1: GNU Build ID
        // n_namesz = 4 (GNU\0)
        data.extend_from_slice(&4u32.to_le_bytes());
        // n_descsz = 20 (SHA1 build ID)
        data.extend_from_slice(&20u32.to_le_bytes());
        // n_type = NT_GNU_BUILD_ID (3)
        data.extend_from_slice(&3u32.to_le_bytes());
        // Name: "GNU\0"
        data.extend_from_slice(b"GNU\0");
        // Descriptor: 20 bytes of build ID
        data.extend_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ]);

        data
    }

    #[test]
    fn test_parse_note_section() {
        let data = create_test_note_section();
        let notes = NoteSection::parse(&data, ElfData::Little).unwrap();

        assert_eq!(notes.notes().len(), 1);

        // Check build ID
        let build_id = notes.build_id().unwrap();
        assert_eq!(build_id.len(), 20);
        assert_eq!(build_id[0], 0x12);
        assert_eq!(build_id[19], 0xcc);

        // Check note details
        let note = &notes.notes()[0];
        assert_eq!(note.name, "GNU");
        assert_eq!(note.n_type, 3);
    }
}
