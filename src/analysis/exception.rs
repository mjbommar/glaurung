//! ELF/Itanium exception call-site recovery.
//!
//! Normal control-flow discovery cannot reach C++ landing pads: the transfer
//! from a protected call to its handler is driven by `.eh_frame` and the
//! function's language-specific data area (LSDA), not by a branch instruction.
//! This module recovers those authoritative exceptional edges without treating
//! arbitrary unreachable bytes as code.

use gimli::{BaseAddresses, CieOrFde, EhFrame, Pointer, UnwindSection};
use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationTarget};

/// Semantic class of the first action attached to a landing pad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionAction {
    /// A typed handler (`catch (T)`) is present.
    Catch,
    /// Cleanup-only landing pad, including a zero action-table selector.
    Cleanup,
    /// A negative type filter (legacy exception specification).
    ExceptionSpec,
    /// The action bytes were malformed or used an unsupported encoding.
    Unknown,
}

/// Source-level C++ type proven by an LSDA type-table relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchType {
    /// Itanium ABI fundamental typeinfo symbol `_ZTIi`.
    Int,
}

/// One LSDA-proven exceptional transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionCallSite {
    /// FDE/function start address.
    pub function_start: u64,
    /// Inclusive start of the protected machine-code interval.
    pub protected_start: u64,
    /// Exclusive end of the protected machine-code interval.
    pub protected_end: u64,
    /// Landing-pad entry address.
    pub landing_pad: u64,
    /// First action attached to the landing pad.
    pub action: ExceptionAction,
    /// Typed catch operand, when its typeinfo relocation is unambiguous.
    pub catch_type: Option<CatchType>,
    /// Address of the indirect typeinfo slot named by the LSDA.
    pub type_info_location: Option<u64>,
}

/// Recover every ELF/Itanium exception call site with a concrete landing pad.
///
/// Malformed CFI or LSDA data is ignored record-by-record. This is analysis
/// metadata from an untrusted binary, so no parse failure may panic or create a
/// guessed edge.
pub fn extract_exception_call_sites(data: &[u8]) -> Vec<ExceptionCallSite> {
    let object = match object::read::File::parse(data) {
        Ok(object) => object,
        Err(_) => return Vec::new(),
    };
    let Some(eh_section) = object.section_by_name(".eh_frame") else {
        return Vec::new();
    };
    let Ok(eh_data) = eh_section.uncompressed_data() else {
        return Vec::new();
    };
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let address_size = if object.is_64() { 8 } else { 4 };
    let eh_frame = EhFrame::new(&eh_data, endian);
    let mut bases = BaseAddresses::default().set_eh_frame(eh_section.address());
    if let Some(section) = object.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(section.address());
    }
    if let Some(section) = object.section_by_name(".text") {
        bases = bases.set_text(section.address());
    }
    if let Some(section) = object
        .section_by_name(".got")
        .or_else(|| object.section_by_name(".got.plt"))
    {
        bases = bases.set_got(section.address());
    }

    let mut out = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        let Some(lsda_va) = fde.lsda().and_then(direct_pointer) else {
            continue;
        };
        let Some((section_data, section_va)) = section_containing_va(&object, lsda_va) else {
            continue;
        };
        let Ok(offset) = usize::try_from(lsda_va - section_va) else {
            continue;
        };
        let Some(lsda) = section_data.get(offset..) else {
            continue;
        };
        let mut sites = parse_lsda(lsda, lsda_va, fde.initial_address(), address_size, endian);
        for site in &mut sites {
            site.catch_type = site
                .type_info_location
                .and_then(|location| catch_type_at_relocation(&object, location));
        }
        out.extend(sites);
    }
    out.sort_by_key(|site| (site.function_start, site.protected_start, site.landing_pad));
    out.dedup();
    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() && !out.is_empty() {
        eprintln!("[exception-sites] {out:#?}");
    }
    out
}

fn catch_type_at_relocation(object: &object::read::File<'_>, location: u64) -> Option<CatchType> {
    let relocations = object.dynamic_relocations()?;
    for (place, relocation) in relocations {
        if place != location {
            continue;
        }
        let RelocationTarget::Symbol(index) = relocation.target() else {
            continue;
        };
        let symbol = object.dynamic_symbol_table()?.symbol_by_index(index).ok()?;
        return match symbol.name().ok()?.split('@').next()? {
            "_ZTIi" => Some(CatchType::Int),
            _ => None,
        };
    }
    None
}

/// Clone an LLIR graph and add only its LSDA-proven exceptional successors.
///
/// The normal graph remains the input to region structuring. This augmented
/// view is for SSA/dataflow so catch definitions can reach shared joins without
/// teaching every normal CFG consumer that a throw is an ordinary branch.
pub fn with_exceptional_successors(
    function: &crate::ir::types::LlirFunction,
    sites: &[ExceptionCallSite],
) -> crate::ir::types::LlirFunction {
    let mut augmented = function.clone();
    let starts: std::collections::HashSet<u64> = augmented
        .blocks
        .iter()
        .map(|block| block.start_va)
        .collect();
    for site in sites
        .iter()
        .filter(|site| site.function_start == augmented.entry_va)
    {
        if !starts.contains(&site.landing_pad) {
            continue;
        }
        let Some(source) = augmented.blocks.iter_mut().find(|block| {
            site.protected_start >= block.start_va && site.protected_end == block.end_va
        }) else {
            continue;
        };
        if !source.succs.contains(&site.landing_pad) {
            source.succs.push(site.landing_pad);
        }
    }
    augmented
}

fn direct_pointer(pointer: Pointer) -> Option<u64> {
    match pointer {
        Pointer::Direct(value) => Some(value),
        // An indirect LSDA address points through relocated process memory.
        // A file-only analysis cannot dereference it soundly.
        Pointer::Indirect(_) => None,
    }
}

fn section_containing_va<'data>(
    object: &object::read::File<'data>,
    va: u64,
) -> Option<(std::borrow::Cow<'data, [u8]>, u64)> {
    object.sections().find_map(|section| {
        let start = section.address();
        let end = start.checked_add(section.size())?;
        if !(start..end).contains(&va) {
            return None;
        }
        section.uncompressed_data().ok().map(|data| (data, start))
    })
}

fn parse_lsda(
    data: &[u8],
    lsda_va: u64,
    function_start: u64,
    address_size: u8,
    endian: gimli::RunTimeEndian,
) -> Vec<ExceptionCallSite> {
    let mut reader = LsdaReader::new(data, lsda_va, address_size, endian);
    let Some(lpstart_encoding) = reader.read_u8() else {
        return Vec::new();
    };
    let lpstart = if lpstart_encoding == 0xff {
        function_start
    } else {
        let Some(value) = reader.read_encoded_pointer(lpstart_encoding, function_start) else {
            return Vec::new();
        };
        value
    };

    let Some(ttype_encoding) = reader.read_u8() else {
        return Vec::new();
    };
    let type_table_base = if ttype_encoding == 0xff {
        None
    } else {
        let Some(offset) = reader.read_uleb128() else {
            return Vec::new();
        };
        let Ok(offset) = usize::try_from(offset) else {
            return Vec::new();
        };
        reader.pos.checked_add(offset)
    };
    let Some(call_site_encoding) = reader.read_u8() else {
        return Vec::new();
    };
    let Some(call_site_length) = reader.read_uleb128() else {
        return Vec::new();
    };
    let Ok(call_site_length) = usize::try_from(call_site_length) else {
        return Vec::new();
    };
    let Some(table_end) = reader.pos.checked_add(call_site_length) else {
        return Vec::new();
    };
    if table_end > data.len() {
        return Vec::new();
    }
    let action_table = table_end;
    let mut out = Vec::new();
    while reader.pos < table_end {
        let Some(start) = reader.read_encoded_offset(call_site_encoding) else {
            return Vec::new();
        };
        let Some(length) = reader.read_encoded_offset(call_site_encoding) else {
            return Vec::new();
        };
        let Some(landing) = reader.read_encoded_offset(call_site_encoding) else {
            return Vec::new();
        };
        let Some(action_offset) = reader.read_uleb128() else {
            return Vec::new();
        };
        if reader.pos > table_end {
            return Vec::new();
        }
        if landing == 0 || length == 0 {
            continue;
        }
        let Some(protected_start) = function_start.checked_add(start) else {
            continue;
        };
        let Some(protected_end) = protected_start.checked_add(length) else {
            continue;
        };
        let Some(landing_pad) = lpstart.checked_add(landing) else {
            continue;
        };
        let (action, type_filter) = parse_action(data, action_table, action_offset);
        let type_info_location = type_filter.and_then(|filter| {
            read_type_info_location(
                data,
                lsda_va,
                type_table_base?,
                ttype_encoding,
                filter,
                address_size,
                endian,
            )
        });
        out.push(ExceptionCallSite {
            function_start,
            protected_start,
            protected_end,
            landing_pad,
            action,
            catch_type: None,
            type_info_location,
        });
    }
    out
}

fn parse_action(data: &[u8], action_table: usize, offset: u64) -> (ExceptionAction, Option<u64>) {
    if offset == 0 {
        return (ExceptionAction::Cleanup, None);
    }
    let Ok(offset) = usize::try_from(offset) else {
        return (ExceptionAction::Unknown, None);
    };
    let Some(relative) = offset.checked_sub(1) else {
        return (ExceptionAction::Unknown, None);
    };
    let Some(pos) = action_table.checked_add(relative) else {
        return (ExceptionAction::Unknown, None);
    };
    let Some(rest) = data.get(pos..) else {
        return (ExceptionAction::Unknown, None);
    };
    let mut reader = LsdaReader::new(rest, 0, 8, gimli::RunTimeEndian::Little);
    match reader.read_sleb128() {
        Some(value) if value > 0 => (ExceptionAction::Catch, u64::try_from(value).ok()),
        Some(0) => (ExceptionAction::Cleanup, None),
        Some(_) => (ExceptionAction::ExceptionSpec, None),
        None => (ExceptionAction::Unknown, None),
    }
}

fn read_type_info_location(
    data: &[u8],
    lsda_va: u64,
    table_base: usize,
    encoding: u8,
    filter: u64,
    address_size: u8,
    endian: gimli::RunTimeEndian,
) -> Option<u64> {
    let width = match encoding & 0x0f {
        0x00 => usize::from(address_size),
        0x02 | 0x0a => 2,
        0x03 | 0x0b => 4,
        0x04 | 0x0c => 8,
        _ => return None,
    };
    let distance = usize::try_from(filter).ok()?.checked_mul(width)?;
    let entry = table_base.checked_sub(distance)?;
    let rest = data.get(entry..)?;
    let mut reader = LsdaReader::new(
        rest,
        lsda_va.checked_add(entry as u64)?,
        address_size,
        endian,
    );
    reader.read_encoded_pointer_location(encoding)
}

struct LsdaReader<'data> {
    data: &'data [u8],
    pos: usize,
    base_va: u64,
    address_size: u8,
    endian: gimli::RunTimeEndian,
}

impl<'data> LsdaReader<'data> {
    fn new(
        data: &'data [u8],
        base_va: u64,
        address_size: u8,
        endian: gimli::RunTimeEndian,
    ) -> Self {
        Self {
            data,
            pos: 0,
            base_va,
            address_size,
            endian,
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    fn read_uint(&mut self, width: usize) -> Option<u64> {
        let end = self.pos.checked_add(width)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        let mut value = 0_u64;
        match self.endian {
            gimli::RunTimeEndian::Little => {
                for (shift, byte) in bytes.iter().enumerate() {
                    value |= u64::from(*byte) << (shift * 8);
                }
            }
            gimli::RunTimeEndian::Big => {
                for byte in bytes {
                    value = (value << 8) | u64::from(*byte);
                }
            }
        }
        Some(value)
    }

    fn read_sint(&mut self, width: usize) -> Option<i64> {
        let value = self.read_uint(width)?;
        let shift = 64_u32.checked_sub((width * 8) as u32)?;
        Some(((value << shift) as i64) >> shift)
    }

    fn read_uleb128(&mut self) -> Option<u64> {
        let mut value = 0_u64;
        for shift in (0..64).step_by(7) {
            let byte = self.read_u8()?;
            let payload = u64::from(byte & 0x7f);
            if shift == 63 && payload > 1 {
                return None;
            }
            value |= payload.checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn read_sleb128(&mut self) -> Option<i64> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            if shift >= 64 {
                return None;
            }
            let byte = self.read_u8()?;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    value |= (!0_u64).checked_shl(shift)?;
                }
                return Some(value as i64);
            }
        }
    }

    fn read_encoded_scalar(&mut self, encoding: u8) -> Option<i128> {
        match encoding & 0x0f {
            0x00 => self.read_uint(self.address_size as usize).map(i128::from),
            0x01 => self.read_uleb128().map(i128::from),
            0x02 => self.read_uint(2).map(i128::from),
            0x03 => self.read_uint(4).map(i128::from),
            0x04 => self.read_uint(8).map(i128::from),
            0x09 => self.read_sleb128().map(i128::from),
            0x0a => self.read_sint(2).map(i128::from),
            0x0b => self.read_sint(4).map(i128::from),
            0x0c => self.read_sint(8).map(i128::from),
            _ => None,
        }
    }

    fn read_encoded_offset(&mut self, encoding: u8) -> Option<u64> {
        if encoding == 0xff || encoding & 0xf0 != 0 {
            return None;
        }
        u64::try_from(self.read_encoded_scalar(encoding)?).ok()
    }

    fn read_encoded_pointer(&mut self, encoding: u8, function_start: u64) -> Option<u64> {
        if encoding == 0xff || encoding & 0x80 != 0 {
            return None;
        }
        if encoding & 0x70 == 0x50 {
            let width = self.address_size as usize;
            let current_va = self.base_va.checked_add(self.pos as u64)?;
            let aligned_va = current_va.checked_add(width as u64 - 1)? & !(width as u64 - 1);
            self.pos = usize::try_from(aligned_va.checked_sub(self.base_va)?).ok()?;
        }
        let field_va = self.base_va.checked_add(self.pos as u64)?;
        let raw = self.read_encoded_scalar(encoding)?;
        let base = match encoding & 0x70 {
            0x00 | 0x50 => 0_i128,
            0x10 => i128::from(field_va),
            // LPStart funcrel is useful and has an unambiguous base here.
            0x40 => i128::from(function_start),
            // textrel/datarel require section bases not carried by an LSDA.
            _ => return None,
        };
        u64::try_from(base.checked_add(raw)?).ok()
    }

    fn read_encoded_pointer_location(&mut self, encoding: u8) -> Option<u64> {
        let encoding = encoding & !0x80;
        if encoding == 0xff {
            return None;
        }
        let field_va = self.base_va.checked_add(self.pos as u64)?;
        let raw = self.read_encoded_scalar(encoding)?;
        let base = match encoding & 0x70 {
            0x00 | 0x50 => 0_i128,
            0x10 => i128::from(field_va),
            _ => return None,
        };
        u64::try_from(base.checked_add(raw)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_lsda, with_exceptional_successors, ExceptionAction, ExceptionCallSite};
    use crate::ir::types::{LlirBlock, LlirFunction};

    #[test]
    fn clang_o0_typed_catch_call_site_is_recovered() {
        let bytes = [
            0xff, 0x9b, 0x11, 0x01, 0x08, 0x0e, 0x05, 0x2b, 0x01, 0x13, 0x64, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x2c, 0x1c, 0x00, 0x00,
        ];

        let sites = parse_lsda(&bytes, 0x2464, 0x1360, 8, gimli::RunTimeEndian::Little);

        assert_eq!(
            sites,
            vec![ExceptionCallSite {
                function_start: 0x1360,
                protected_start: 0x136e,
                protected_end: 0x1373,
                landing_pad: 0x138b,
                action: ExceptionAction::Catch,
                catch_type: None,
                type_info_location: Some(0x40a0),
            }]
        );
    }

    #[test]
    fn clang_o2_inlined_throw_landing_pad_is_recovered() {
        let bytes = [
            0xff, 0x9b, 0x15, 0x01, 0x0c, 0x00, 0x1d, 0x00, 0x00, 0x1d, 0x11, 0x2e, 0x01, 0x2e,
            0x16, 0x00, 0x00, 0x01, 0x00, 0x00, 0x44, 0x1e, 0x00, 0x00,
        ];

        let sites = parse_lsda(&bytes, 0x21f0, 0x11c0, 8, gimli::RunTimeEndian::Little);

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].protected_start, 0x11dd);
        assert_eq!(sites[0].protected_end, 0x11ee);
        assert_eq!(sites[0].landing_pad, 0x11ee);
        assert_eq!(sites[0].action, ExceptionAction::Catch);
    }

    #[test]
    fn malformed_lsda_is_rejected_without_partial_edges() {
        let truncated = [0xff, 0x9b, 0x11, 0x01, 0x40, 0x0e];

        assert!(
            parse_lsda(&truncated, 0x1000, 0x2000, 8, gimli::RunTimeEndian::Little,).is_empty()
        );
    }

    #[test]
    fn exceptional_successor_augments_only_the_protected_call_block() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1010,
                    instrs: Vec::new(),
                    succs: vec![0x1010],
                },
                LlirBlock {
                    start_va: 0x1010,
                    end_va: 0x1020,
                    instrs: Vec::new(),
                    succs: Vec::new(),
                },
                LlirBlock {
                    start_va: 0x1030,
                    end_va: 0x1040,
                    instrs: Vec::new(),
                    succs: Vec::new(),
                },
            ],
        };
        let sites = [ExceptionCallSite {
            function_start: 0x1000,
            protected_start: 0x100b,
            protected_end: 0x1010,
            landing_pad: 0x1030,
            action: ExceptionAction::Catch,
            catch_type: None,
            type_info_location: None,
        }];

        let augmented = with_exceptional_successors(&function, &sites);

        assert_eq!(function.blocks[0].succs, vec![0x1010]);
        assert_eq!(augmented.blocks[0].succs, vec![0x1010, 0x1030]);
        assert!(augmented.blocks[1].succs.is_empty());
        assert!(augmented.blocks[2].succs.is_empty());
    }
}
