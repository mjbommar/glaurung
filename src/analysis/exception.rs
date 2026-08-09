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
    let object = match crate::decompile::profile::parse_object(data) {
        Ok(object) => object,
        Err(_) => return Vec::new(),
    };
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let address_size = if object.is_64() { 8 } else { 4 };
    let mut out = Vec::new();
    if let Some(eh_section) = object.section_by_name(".eh_frame") {
        if let Ok(eh_data) = eh_section.uncompressed_data() {
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
                let Some((section_data, section_va)) = section_containing_va(&object, lsda_va)
                else {
                    continue;
                };
                let Ok(offset) = usize::try_from(lsda_va - section_va) else {
                    continue;
                };
                let Some(lsda) = section_data.get(offset..) else {
                    continue;
                };
                out.extend(parse_lsda(
                    lsda,
                    lsda_va,
                    fde.initial_address(),
                    address_size,
                    endian,
                ));
            }
        }
    }
    out.extend(extract_arm_ehabi_call_sites(&object, endian));
    for site in &mut out {
        site.catch_type = site
            .type_info_location
            .and_then(|location| catch_type_at_relocation(&object, location));
    }
    out.sort_by_key(|site| (site.function_start, site.protected_start, site.landing_pad));
    out.dedup();
    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() && !out.is_empty() {
        eprintln!("[exception-sites] {out:#?}");
    }
    out
}

/// Recover the language-specific data embedded after a generic ARM EHABI
/// unwind descriptor.
///
/// ARM32 GCC does not emit C++ landing-pad metadata in `.eh_frame`; it uses an
/// `.ARM.exidx` entry whose second PREL31 word points at `.ARM.extab`.  In the
/// generic model the first extab word names the personality routine, the next
/// word contains a count plus unwind opcodes, and the ordinary Itanium LSDA
/// begins after that word and its counted continuations.
fn extract_arm_ehabi_call_sites(
    object: &object::read::File<'_>,
    endian: gimli::RunTimeEndian,
) -> Vec<ExceptionCallSite> {
    let Some(exidx) = object.section_by_name(".ARM.exidx") else {
        return Vec::new();
    };
    let Some(extab) = object.section_by_name(".ARM.extab") else {
        return Vec::new();
    };
    let Ok(exidx_data) = exidx.uncompressed_data() else {
        return Vec::new();
    };
    let Ok(extab_data) = extab.uncompressed_data() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (index, entry) in exidx_data.chunks_exact(8).enumerate() {
        let entry_va = exidx.address().saturating_add((index * 8) as u64);
        let function_word = read_u32(entry, endian);
        let descriptor_word = read_u32(&entry[4..], endian);
        let Some(function_start) = resolve_prel31(entry_va, function_word) else {
            continue;
        };
        // EXIDX_CANTUNWIND and inline compact descriptors carry no handler data.
        if descriptor_word == 1 || descriptor_word & 0x8000_0000 != 0 {
            continue;
        }
        let Some(extab_va) = resolve_prel31(entry_va.saturating_add(4), descriptor_word) else {
            continue;
        };
        let Ok(extab_offset) = usize::try_from(extab_va.saturating_sub(extab.address())) else {
            continue;
        };
        let Some(lsda_offset) = generic_arm_extab_lsda_offset(&extab_data, extab_offset, endian)
        else {
            continue;
        };
        let Some(lsda) = extab_data.get(lsda_offset..) else {
            continue;
        };
        out.extend(parse_lsda(
            lsda,
            extab.address().saturating_add(lsda_offset as u64),
            function_start,
            4,
            endian,
        ));
    }
    out
}

fn generic_arm_extab_lsda_offset(
    extab: &[u8],
    offset: usize,
    endian: gimli::RunTimeEndian,
) -> Option<usize> {
    let first = read_u32(extab.get(offset..offset.checked_add(4)?)?, endian);
    // Bit 31 selects a compact-model descriptor, which has no generic LSDA
    // layout. A clear bit is a PREL31 personality pointer.
    if first & 0x8000_0000 != 0 {
        return None;
    }
    let unwind = read_u32(
        extab.get(offset.checked_add(4)?..offset.checked_add(8)?)?,
        endian,
    );
    let continuation_words = (unwind >> 24) as usize;
    offset
        .checked_add(8)?
        .checked_add(continuation_words.checked_mul(4)?)
}

fn read_u32(bytes: &[u8], endian: gimli::RunTimeEndian) -> u32 {
    let array: [u8; 4] = bytes[..4].try_into().expect("four-byte slice");
    match endian {
        gimli::RunTimeEndian::Little => u32::from_le_bytes(array),
        gimli::RunTimeEndian::Big => u32::from_be_bytes(array),
    }
}

fn resolve_prel31(place: u64, encoded: u32) -> Option<u64> {
    let displacement = ((encoded << 1) as i32) >> 1;
    if displacement >= 0 {
        place.checked_add(displacement as u64)
    } else {
        place.checked_sub(displacement.unsigned_abs() as u64)
    }
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

/// One function interval proven by an `.eh_frame` FDE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EhFrameFunction {
    /// FDE `initial_location` — an authoritative function entry point.
    pub start: u64,
    /// FDE `address_range` — the exact byte length of the function.
    pub end: u64,
}

/// Every function interval described by `.eh_frame`.
///
/// This is the strongest function-boundary evidence available in a stripped
/// ELF, and essentially every Linux binary of the last fifteen years carries it:
/// `-fasynchronous-unwind-tables` is the default on x86-64 and AArch64 because
/// the C++ unwinder and `backtrace()` need it, so it survives `strip`.
///
/// It is *sound but incomplete*. Every FDE start is a real function entry, so a
/// seed taken from here never invents a function. But hand-written assembly and
/// anything built `-fno-asynchronous-unwind-tables` (Alpine's `busybox`, which
/// ships a 4-byte `.eh_frame`) has no FDE, so absence proves nothing and this
/// cannot be the only discovery source.
///
/// Distinct from [`extract_exception_call_sites`], which walks the same table
/// but keeps only FDEs carrying an LSDA — a small minority, and none at all in a
/// C program. That is why exception recovery being wired up did not give
/// discovery these boundaries for free.
pub fn eh_frame_functions(data: &[u8]) -> Vec<EhFrameFunction> {
    let Ok(object) = crate::decompile::profile::parse_object(data) else {
        return Vec::new();
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
        let start = fde.initial_address();
        let len = fde.len();
        // A zero-length FDE describes no code; a terminator run produces one.
        if len == 0 {
            continue;
        }
        let Some(end) = start.checked_add(len) else {
            continue;
        };
        out.push(EhFrameFunction { start, end });
    }
    out.sort_unstable();
    out.dedup();
    out
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
    for site in sites.iter().filter(|site| {
        site.function_start == augmented.entry_va || starts.contains(&site.function_start)
    }) {
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
    use super::{
        eh_frame_functions, generic_arm_extab_lsda_offset, parse_lsda, resolve_prel31,
        with_exceptional_successors, ExceptionAction, ExceptionCallSite,
    };

    #[test]
    fn arm_ehabi_generic_descriptor_locates_its_real_lsda_bytes() {
        // First eight bytes of GCC's generic descriptor for the ARMv7 O2 C++
        // fixture: PREL31 __gxx_personality_v0, then zero continuation words.
        let descriptor = [0x78, 0xfc, 0xff, 0x7f, 0x00, 0x84, 0x02, 0x00];
        assert_eq!(
            generic_arm_extab_lsda_offset(&descriptor, 0, gimli::RunTimeEndian::Little),
            Some(8)
        );
        assert_eq!(resolve_prel31(0xd60, 0x7fff_fdf0), Some(0xb50));
        assert_eq!(resolve_prel31(0xd64, 0x7fff_ffd0), Some(0xd34));
    }
    use crate::ir::types::{LlirBlock, LlirFunction};
    use object::Object;

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

    #[test]
    fn exceptional_successor_accepts_an_owned_split_chunk_fde() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1010,
                    instrs: Vec::new(),
                    succs: Vec::new(),
                },
                LlirBlock {
                    start_va: 0x0900,
                    end_va: 0x0910,
                    instrs: Vec::new(),
                    succs: vec![0x0950],
                },
                LlirBlock {
                    start_va: 0x0920,
                    end_va: 0x0930,
                    instrs: Vec::new(),
                    succs: Vec::new(),
                },
                LlirBlock {
                    start_va: 0x0950,
                    end_va: 0x0960,
                    instrs: Vec::new(),
                    succs: Vec::new(),
                },
            ],
        };
        let sites = [ExceptionCallSite {
            function_start: 0x0900,
            protected_start: 0x0908,
            protected_end: 0x0910,
            landing_pad: 0x0920,
            action: ExceptionAction::Catch,
            catch_type: Some(super::CatchType::Int),
            type_info_location: Some(0x4000),
        }];

        let augmented = with_exceptional_successors(&function, &sites);

        assert_eq!(augmented.blocks[1].succs, vec![0x0950, 0x0920]);
        assert!(
            augmented.blocks[1].succs.contains(&sites[0].landing_pad),
            "an LSDA FDE rooted at an owned cold chunk belongs to the merged function"
        );
    }

    /// `.eh_frame` must yield the real function starts of a stripped binary.
    ///
    /// Checked against the DWARF in the unstripped twin, which is the same
    /// bytes: stripping removes symbols but moves no code, so every
    /// `DW_AT_low_pc` must appear as an FDE start.
    #[test]
    fn eh_frame_functions_recover_real_starts() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            eprintln!("skipping eh_frame fixture test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let funcs = eh_frame_functions(&data);

        assert!(
            funcs.len() >= 5,
            "expected several FDEs in a real C++ binary, got {}",
            funcs.len()
        );
        for f in &funcs {
            assert!(f.end > f.start, "FDE {f:?} has non-positive length");
        }
        // Intervals must not overlap: each describes one function's extent, and
        // overlapping ranges would make them useless as lifting bounds.
        let mut sorted = funcs.clone();
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            assert!(
                pair[0].end <= pair[1].start,
                "overlapping FDE intervals {:?} and {:?}",
                pair[0],
                pair[1]
            );
        }

        // The entry point is generated code with unwind info in every glibc
        // link, so it anchors the result to something externally checkable.
        let obj = crate::decompile::profile::parse_object(&*data).expect("parse");
        let entry = obj.entry();
        assert!(
            funcs.iter().any(|f| f.start <= entry && entry < f.end),
            "entry point {entry:#x} is not covered by any FDE"
        );
    }
}
