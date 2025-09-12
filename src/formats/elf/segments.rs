//! Program header table management

use crate::formats::elf::types::*;
use crate::formats::elf::utils::EndianRead;

/// Segment table for program header management
pub struct SegmentTable<'a> {
    headers: Vec<ProgramHeader>,
    data: &'a [u8],
}

impl<'a> SegmentTable<'a> {
    /// Parse segment table from ELF data
    pub fn parse(data: &'a [u8], header: &ElfHeader) -> Result<Self> {
        let ph_offset = header.e_phoff as usize;
        let ph_entsize = header.e_phentsize as usize;
        let ph_num = header.e_phnum as usize;

        if ph_num == 0 || ph_offset == 0 {
            // No segments
            return Ok(Self {
                headers: Vec::new(),
                data,
            });
        }

        // Check bounds
        let total_size = ph_num * ph_entsize;
        if ph_offset + total_size > data.len() {
            return Err(ElfError::Truncated {
                offset: ph_offset,
                needed: total_size,
            });
        }

        // Parse program headers
        let mut headers = Vec::with_capacity(ph_num);
        for i in 0..ph_num {
            let offset = ph_offset + i * ph_entsize;
            let ph_header =
                parse_program_header(data, offset, header.ident.class, header.ident.data)?;
            headers.push(ph_header);
        }

        // Sort by virtual address for efficient lookups
        headers.sort_by_key(|h| h.p_vaddr);

        Ok(Self { headers, data })
    }

    /// Convert virtual address to file offset
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<usize> {
        // Binary search on sorted LOAD segments
        let load_segments: Vec<_> = self
            .headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .collect();

        let idx = load_segments
            .binary_search_by(|ph| {
                if vaddr < ph.p_vaddr {
                    std::cmp::Ordering::Greater
                } else if vaddr >= ph.p_vaddr + ph.p_memsz {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;

        let ph = load_segments[idx];
        let offset = vaddr - ph.p_vaddr;
        if offset < ph.p_filesz {
            Some((ph.p_offset + offset) as usize)
        } else {
            None // In memory but not in file
        }
    }

    /// Find segment containing virtual address
    pub fn segment_at_vaddr(&self, vaddr: u64) -> Option<Segment<'a>> {
        self.headers
            .iter()
            .find(|ph| vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_memsz)
            .map(|header| self.create_segment(header))
    }

    /// Get all LOAD segments
    pub fn load_segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        self.headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(move |header| self.create_segment(header))
    }

    /// Get all segments
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        self.headers
            .iter()
            .map(move |header| self.create_segment(header))
    }

    /// Check for PT_GNU_STACK (NX bit)
    pub fn has_nx_stack(&self) -> bool {
        self.headers
            .iter()
            .find(|ph| ph.p_type == PT_GNU_STACK)
            .map(|ph| (ph.p_flags & PF_X) == 0) // NX when not executable
            .unwrap_or(false)
    }

    /// Check for PT_GNU_RELRO
    pub fn has_relro(&self) -> bool {
        self.headers.iter().any(|ph| ph.p_type == PT_GNU_RELRO)
    }

    /// Get interpreter path
    pub fn interpreter(&self) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|ph| ph.p_type == PT_INTERP)
            .and_then(|ph| {
                let offset = ph.p_offset as usize;
                let size = ph.p_filesz as usize;
                if offset + size <= self.data.len() {
                    let bytes = &self.data[offset..offset + size];
                    // Remove trailing null
                    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    std::str::from_utf8(&bytes[..len]).ok()
                } else {
                    None
                }
            })
    }

    /// Count segments
    pub fn count(&self) -> usize {
        self.headers.len()
    }

    fn create_segment(&self, header: &ProgramHeader) -> Segment<'a> {
        let offset = header.p_offset as usize;
        let size = header.p_filesz as usize;
        let data = if offset + size <= self.data.len() {
            &self.data[offset..offset + size]
        } else {
            &[]
        };
        Segment {
            header: *header,
            data,
        }
    }
}

/// Parse a single program header
fn parse_program_header(
    data: &[u8],
    offset: usize,
    class: ElfClass,
    endian: ElfData,
) -> Result<ProgramHeader> {
    match class {
        ElfClass::Elf32 => {
            if offset + 32 > data.len() {
                return Err(ElfError::Truncated { offset, needed: 32 });
            }
            Ok(ProgramHeader {
                p_type: data.read_u32(offset, endian)?,
                p_offset: data.read_u32(offset + 4, endian)? as u64,
                p_vaddr: data.read_u32(offset + 8, endian)? as u64,
                p_paddr: data.read_u32(offset + 12, endian)? as u64,
                p_filesz: data.read_u32(offset + 16, endian)? as u64,
                p_memsz: data.read_u32(offset + 20, endian)? as u64,
                p_flags: data.read_u32(offset + 24, endian)?,
                p_align: data.read_u32(offset + 28, endian)? as u64,
            })
        }
        ElfClass::Elf64 => {
            if offset + 56 > data.len() {
                return Err(ElfError::Truncated { offset, needed: 56 });
            }
            Ok(ProgramHeader {
                p_type: data.read_u32(offset, endian)?,
                p_flags: data.read_u32(offset + 4, endian)?,
                p_offset: data.read_u64(offset + 8, endian)?,
                p_vaddr: data.read_u64(offset + 16, endian)?,
                p_paddr: data.read_u64(offset + 24, endian)?,
                p_filesz: data.read_u64(offset + 32, endian)?,
                p_memsz: data.read_u64(offset + 40, endian)?,
                p_align: data.read_u64(offset + 48, endian)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::elf::headers::parse_header;

    fn create_test_elf_with_segments() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // ELF header
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // Little endian
        data[6] = 1; // Version

        // e_type = ET_EXEC
        data[16] = 2;
        // e_machine = EM_X86_64
        data[18] = 62;
        // e_version = 1
        data[20] = 1;

        // e_phoff = 0x40 (program headers at offset 64)
        data[32] = 0x40;

        // e_ehsize = 64
        data[52] = 64;
        // e_phentsize = 56
        data[54] = 56;
        // e_phnum = 2
        data[56] = 2;
        // e_shentsize = 64
        data[58] = 64;

        // Program header 1: PT_LOAD at 0x40
        let ph1_offset = 0x40;
        data[ph1_offset] = 1; // p_type = PT_LOAD
        data[ph1_offset + 4] = 5; // p_flags = PF_R | PF_X
                                  // p_offset = 0
                                  // p_vaddr = 0x1000
        data[ph1_offset + 16] = 0x00;
        data[ph1_offset + 17] = 0x10;
        // p_filesz = 0x100
        data[ph1_offset + 32] = 0x00;
        data[ph1_offset + 33] = 0x01;
        // p_memsz = 0x100
        data[ph1_offset + 40] = 0x00;
        data[ph1_offset + 41] = 0x01;

        // Program header 2: PT_GNU_STACK at 0x78
        let ph2_offset = 0x40 + 56;
        data[ph2_offset] = 0x51; // p_type = PT_GNU_STACK (0x6474e551)
        data[ph2_offset + 1] = 0xe5;
        data[ph2_offset + 2] = 0x74;
        data[ph2_offset + 3] = 0x64;
        data[ph2_offset + 4] = 6; // p_flags = PF_R | PF_W (no X = NX)

        data
    }

    #[test]
    fn test_parse_segment_table() {
        let data = create_test_elf_with_segments();
        let header = parse_header(&data).unwrap();
        let segments = SegmentTable::parse(&data, &header).unwrap();

        assert_eq!(segments.count(), 2);

        // Check LOAD segment
        let load_segs: Vec<_> = segments.load_segments().collect();
        assert_eq!(load_segs.len(), 1);
        assert!(load_segs[0].is_executable());
        assert!(load_segs[0].is_readable());

        // Check NX stack
        assert!(segments.has_nx_stack());
    }

    #[test]
    fn test_vaddr_to_offset() {
        let data = create_test_elf_with_segments();
        let header = parse_header(&data).unwrap();
        let segments = SegmentTable::parse(&data, &header).unwrap();

        // Virtual address 0x1000 maps to file offset 0
        assert_eq!(segments.vaddr_to_offset(0x1000), Some(0));
        // Virtual address 0x1050 maps to file offset 0x50
        assert_eq!(segments.vaddr_to_offset(0x1050), Some(0x50));
        // Virtual address outside segments
        assert_eq!(segments.vaddr_to_offset(0x500), None);
    }
}
