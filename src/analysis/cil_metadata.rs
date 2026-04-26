//! .NET CIL / CLR metadata parser (#210).
//!
//! Recovers (method_rva, full_method_name) pairs from a .NET PE assembly
//! by walking the metadata tables defined in ECMA-335. This unlocks a
//! whole malware-triage class — Mono / .NET Framework / .NET Core
//! binaries that ship with no native symbols but carry full method
//! metadata in the assembly itself.
//!
//! Scope (v0):
//!
//!   * Detect .NET PE via the COM descriptor data directory.
//!   * Parse the metadata root, locate the `#~` (table-stream) and
//!     `#Strings` heap.
//!   * Walk the MethodDef table — every method ships its RVA, name,
//!     signature index, and parameter range.
//!   * Walk TypeDef so we can format names as `Namespace.Type::Method`.
//!   * Variable-width indexes are computed from the row-count bitmap
//!     (heap-pointer width from the heapSizes flag, table-pointer
//!     width from each referenced table's row count).
//!
//! Out of scope (v1):
//!
//!   * Generic-method instantiation tables (MethodSpec).
//!   * Coded-index tables we don't traverse for v0.
//!   * Param/Field row size is computed but not consumed beyond
//!     advancing the cursor.

use object::{Object, ObjectSection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CilMethod {
    /// RVA of the method body. Add the PE image base to get the VA.
    pub rva: u32,
    /// Fully-qualified name `Namespace.Type::Method`. Empty namespace
    /// types render as `Type::Method`.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CilError {
    NoCom,
    NoMetadata,
    BadSignature,
    Truncated(&'static str),
    NoTilde,
    NoStrings,
}

/// Parse a .NET PE and return every recoverable method's (RVA, full name).
pub fn extract_cil_methods(data: &[u8]) -> Result<Vec<CilMethod>, CilError> {
    let obj = object::read::File::parse(data).map_err(|_| CilError::NoCom)?;

    // Locate the CLR data directory. object's PE support exposes the
    // 16 data dirs through `pe_data_directories`. Index 14 is
    // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.
    let (clr_rva, clr_size) = match &obj {
        object::read::File::Pe32(pe) => {
            let dirs = pe.data_directories();
            let dir = dirs.get(14).ok_or(CilError::NoCom)?;
            (dir.virtual_address.get(object::LittleEndian),
             dir.size.get(object::LittleEndian))
        }
        object::read::File::Pe64(pe) => {
            let dirs = pe.data_directories();
            let dir = dirs.get(14).ok_or(CilError::NoCom)?;
            (dir.virtual_address.get(object::LittleEndian),
             dir.size.get(object::LittleEndian))
        }
        _ => return Err(CilError::NoCom),
    };
    if clr_rva == 0 || clr_size == 0 {
        return Err(CilError::NoCom);
    }

    // CLR header is at the COM data dir RVA. We need it as a file slice.
    let clr_header = read_at_rva(&obj, clr_rva as u64, 72)
        .ok_or(CilError::Truncated("clr header"))?;
    if clr_header.len() < 16 {
        return Err(CilError::Truncated("clr header"));
    }
    // CLR header layout (II.25.3.3):
    //   u32 cb
    //   u16 majorRuntimeVersion
    //   u16 minorRuntimeVersion
    //   IMAGE_DATA_DIRECTORY MetaData    (RVA + size)
    //   ... (we only need MetaData)
    let meta_rva = u32::from_le_bytes(clr_header[8..12].try_into().unwrap());
    let meta_size = u32::from_le_bytes(clr_header[12..16].try_into().unwrap());
    if meta_rva == 0 || meta_size == 0 {
        return Err(CilError::NoMetadata);
    }
    let meta = read_at_rva(&obj, meta_rva as u64, meta_size as usize)
        .ok_or(CilError::Truncated("metadata"))?;

    parse_metadata_root(meta)
}

/// Read `len` bytes at the given RVA, returning a borrowed slice.
///
/// PE section addresses come back from `object` as the image-relative
/// VA (i.e. RVA, not absolute VA — `object` doesn't add the image base
/// for PE). We compare against both interpretations defensively so
/// this works with either convention.
fn read_at_rva<'a>(obj: &'a object::read::File<'a>, rva: u64, len: usize) -> Option<&'a [u8]> {
    // First pass: find a section whose [addr, addr+size) contains rva
    // under either RVA or absolute-VA semantics, where the absolute-VA
    // case subtracts the image base.
    let image_base: u64 = match obj {
        object::read::File::Pe32(ref pe) => pe.relative_address_base(),
        object::read::File::Pe64(ref pe) => pe.relative_address_base(),
        _ => 0,
    };
    for sec in obj.sections() {
        let sec_addr_raw = sec.address();
        // Try treating section address as RVA first.
        for sec_addr in &[sec_addr_raw, sec_addr_raw.saturating_sub(image_base)] {
            let sec_size = sec.size();
            if rva >= *sec_addr && rva < *sec_addr + sec_size {
                let off = (rva - *sec_addr) as usize;
                let data = sec.data().ok()?;
                let take = std::cmp::min(len, data.len().saturating_sub(off));
                return Some(&data[off..off + take]);
            }
        }
    }
    None
}

/// Parse the metadata root, locate the streams, and walk the table
/// stream to recover MethodDef + TypeDef rows.
fn parse_metadata_root(meta: &[u8]) -> Result<Vec<CilMethod>, CilError> {
    if meta.len() < 16 {
        return Err(CilError::Truncated("metadata root"));
    }
    let signature = u32::from_le_bytes(meta[0..4].try_into().unwrap());
    if signature != 0x424A_5342 {
        return Err(CilError::BadSignature);
    }
    let version_len = u32::from_le_bytes(meta[12..16].try_into().unwrap()) as usize;
    if 16 + version_len > meta.len() {
        return Err(CilError::Truncated("version string"));
    }
    // Version string is null-padded to a 4-byte boundary.
    let vlen = (version_len + 3) & !3;
    let mut p = 16 + vlen;
    if p + 4 > meta.len() {
        return Err(CilError::Truncated("flags+streams"));
    }
    p += 2; // flags
    let n_streams = u16::from_le_bytes(meta[p..p + 2].try_into().unwrap()) as usize;
    p += 2;

    let mut tilde_off: Option<usize> = None;
    let mut tilde_size: Option<usize> = None;
    let mut strings_off: Option<usize> = None;
    let mut strings_size: Option<usize> = None;

    for _ in 0..n_streams {
        if p + 8 > meta.len() {
            return Err(CilError::Truncated("stream header"));
        }
        let off = u32::from_le_bytes(meta[p..p + 4].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(meta[p + 4..p + 8].try_into().unwrap()) as usize;
        p += 8;
        // Null-terminated stream name, padded to 4-byte boundary.
        let name_start = p;
        let name_end = (name_start..meta.len())
            .find(|&i| meta[i] == 0)
            .ok_or(CilError::Truncated("stream name"))?;
        let name = std::str::from_utf8(&meta[name_start..name_end]).unwrap_or("");
        let pad = ((name_end - name_start + 1) + 3) & !3;
        p = name_start + pad;
        match name {
            "#~" | "#-" => {
                tilde_off = Some(off);
                tilde_size = Some(size);
            }
            "#Strings" => {
                strings_off = Some(off);
                strings_size = Some(size);
            }
            _ => {}
        }
    }

    let tilde_off = tilde_off.ok_or(CilError::NoTilde)?;
    let tilde_size = tilde_size.unwrap_or(meta.len() - tilde_off);
    let strings_off = strings_off.ok_or(CilError::NoStrings)?;
    let strings_size = strings_size.unwrap_or(meta.len() - strings_off);
    if tilde_off + tilde_size > meta.len() {
        return Err(CilError::Truncated("#~"));
    }
    if strings_off + strings_size > meta.len() {
        return Err(CilError::Truncated("#Strings"));
    }
    let tilde = &meta[tilde_off..tilde_off + tilde_size];
    let strings = &meta[strings_off..strings_off + strings_size];

    parse_tilde_stream(tilde, strings)
}

fn read_string(strings: &[u8], idx: u32) -> String {
    if idx as usize >= strings.len() {
        return String::new();
    }
    let s = &strings[idx as usize..];
    let nul = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..nul]).into_owned()
}

fn parse_tilde_stream(tilde: &[u8], strings: &[u8]) -> Result<Vec<CilMethod>, CilError> {
    if tilde.len() < 24 {
        return Err(CilError::Truncated("#~ header"));
    }
    let heap_sizes = tilde[6];
    let valid = u64::from_le_bytes(tilde[8..16].try_into().unwrap());

    // Heap index widths.
    let _string_idx_size = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let _guid_idx_size = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
    let _blob_idx_size = if heap_sizes & 0x04 != 0 { 4 } else { 2 };
    let string_idx_size = _string_idx_size;
    let _ = _guid_idx_size; // guid not used in the rows we walk
    let blob_idx_size = _blob_idx_size;

    // Row counts for present tables.
    let mut p = 24;
    let mut row_counts = [0u32; 64];
    for i in 0..64 {
        if (valid >> i) & 1 == 1 {
            if p + 4 > tilde.len() {
                return Err(CilError::Truncated("row counts"));
            }
            row_counts[i] = u32::from_le_bytes(tilde[p..p + 4].try_into().unwrap());
            p += 4;
        }
    }

    // Helper: row-count-driven table-index width (2 or 4).
    let table_idx_size = |table_id: usize| -> usize {
        if row_counts[table_id] < (1 << 16) { 2 } else { 4 }
    };

    // Coded-index widths (II.24.2.6). The bit count is the tag width;
    // the value field plus the tag must fit in 2 bytes.
    let coded_idx_size = |tables: &[usize], tag_bits: u32| -> usize {
        let max_rows = tables.iter().map(|&t| row_counts[t]).max().unwrap_or(0) as u64;
        let limit = 1u64 << (16 - tag_bits);
        if max_rows < limit { 2 } else { 4 }
    };

    // ECMA-335 table IDs we touch, in walk order: 0..6.
    // 0x00 Module, 0x01 TypeRef, 0x02 TypeDef, 0x03 (deprecated), 0x04 Field,
    // 0x05 (deprecated), 0x06 MethodDef.
    //
    // Row sizes:
    //   Module     (II.22.30): u16 generation, StringIdx Name, GuidIdx (Mvid, EncId, EncBaseId)
    //   TypeRef    (II.22.38): ResolutionScope (coded), StringIdx Name, StringIdx Namespace
    //   TypeDef    (II.22.37): u32 Flags, StringIdx Name, StringIdx Namespace,
    //                          TypeDefOrRef Extends, FieldIdx FieldList,
    //                          MethodDefIdx MethodList
    //   Field      (II.22.15): u16 Flags, StringIdx Name, BlobIdx Signature
    //   MethodDef  (II.22.26): u32 RVA, u16 ImplFlags, u16 Flags, StringIdx Name,
    //                          BlobIdx Signature, ParamIdx ParamList

    let resolution_scope_idx = coded_idx_size(&[0x00, 0x1A, 0x23, 0x01], 2);
    let typedef_or_ref_idx = coded_idx_size(&[0x02, 0x01, 0x1B], 2);
    let _ = resolution_scope_idx; // we skip TypeRef rows wholesale; computed for the row size
    let field_idx_size = table_idx_size(0x04);
    let methoddef_idx_size = table_idx_size(0x06);
    let param_idx_size = table_idx_size(0x08);

    let module_row_size = 2 + string_idx_size + 3 * _guid_idx_size;
    let typeref_row_size = resolution_scope_idx + 2 * string_idx_size;
    let typedef_row_size = 4 + 2 * string_idx_size + typedef_or_ref_idx
        + field_idx_size + methoddef_idx_size;
    let field_row_size = 2 + string_idx_size + blob_idx_size;
    let methoddef_row_size = 4 + 2 + 2 + string_idx_size + blob_idx_size + param_idx_size;

    // Sequence of (table_id, row_count, row_size) for tables present
    // BEFORE MethodDef. Anything after MethodDef in the table order is
    // unused for v0.
    let mut tables_before_method: Vec<(usize, u32, usize)> = Vec::new();
    for tid in 0..0x06 {
        if (valid >> tid) & 1 == 1 {
            let row_size = match tid {
                0x00 => module_row_size,
                0x01 => typeref_row_size,
                0x02 => typedef_row_size,
                0x04 => field_row_size,
                _ => return Err(CilError::Truncated("unsupported pre-method table")),
            };
            tables_before_method.push((tid, row_counts[tid], row_size));
        }
    }

    // Find the byte offset of TypeDef rows (we'll need it for namespacing)
    // and MethodDef rows.
    let mut cur = p;
    let mut typedef_off: Option<usize> = None;
    for &(tid, count, size) in &tables_before_method {
        if tid == 0x02 {
            typedef_off = Some(cur);
        }
        cur += (count as usize) * size;
    }
    let methoddef_off = cur;

    // Read TypeDef rows so we can map MethodDef indexes to types. The
    // MethodList field is a 1-based index into MethodDef; the type's
    // method range is [methodlist_i, methodlist_{i+1}). The last
    // type's range runs to the end of MethodDef.
    let read_index = |buf: &[u8], width: usize| -> u32 {
        match width {
            2 => u16::from_le_bytes(buf[0..2].try_into().unwrap()) as u32,
            4 => u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            _ => 0,
        }
    };

    let mut type_names: Vec<(String, String, u32)> = Vec::new(); // (name, ns, methodlist_start)
    if let Some(off) = typedef_off {
        let count = row_counts[0x02] as usize;
        for i in 0..count {
            let row = &tilde[off + i * typedef_row_size..off + (i + 1) * typedef_row_size];
            let mut q = 4; // skip Flags
            let name_idx = read_index(&row[q..], string_idx_size);
            q += string_idx_size;
            let ns_idx = read_index(&row[q..], string_idx_size);
            q += string_idx_size;
            q += typedef_or_ref_idx; // Extends
            q += field_idx_size; // FieldList
            let methodlist = read_index(&row[q..], methoddef_idx_size);
            type_names.push((
                read_string(strings, name_idx),
                read_string(strings, ns_idx),
                methodlist,
            ));
        }
    }

    // Walk MethodDef rows. For each, find which type owns it by
    // scanning type_names' methodlist bounds.
    let count = row_counts[0x06] as usize;
    if methoddef_off + count * methoddef_row_size > tilde.len() {
        return Err(CilError::Truncated("MethodDef rows"));
    }
    let total_methods = count;
    let owner_for = |method_idx_1based: u32| -> Option<&(String, String, u32)> {
        if type_names.is_empty() {
            return None;
        }
        for i in 0..type_names.len() {
            let start = type_names[i].2;
            let end = if i + 1 < type_names.len() {
                type_names[i + 1].2
            } else {
                (total_methods as u32) + 1
            };
            if method_idx_1based >= start && method_idx_1based < end {
                return Some(&type_names[i]);
            }
        }
        None
    };

    let mut out: Vec<CilMethod> = Vec::with_capacity(count);
    for i in 0..count {
        let row = &tilde[methoddef_off + i * methoddef_row_size
            ..methoddef_off + (i + 1) * methoddef_row_size];
        let rva = u32::from_le_bytes(row[0..4].try_into().unwrap());
        let mut q = 4 + 2 + 2;
        let name_idx = read_index(&row[q..], string_idx_size);
        q += string_idx_size;
        q += blob_idx_size + param_idx_size;
        let _ = q;
        let method_name = read_string(strings, name_idx);
        let owner = owner_for((i + 1) as u32);
        let full = match owner {
            Some((tname, ns, _)) if !ns.is_empty() => {
                format!("{}.{}::{}", ns, tname, method_name)
            }
            Some((tname, _, _)) => format!("{}::{}", tname, method_name),
            None => method_name.clone(),
        };
        out.push(CilMethod { rva, name: full });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn extracts_main_from_hello_mono() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let methods = extract_cil_methods(&data).expect("parse should succeed");
        assert!(!methods.is_empty(), "expected methods");
        // Hello.cs has `public static void Main(string[] args)`.
        let names: Vec<&str> = methods.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.ends_with("::Main") || *n == "Main"),
            "expected Main; got names: {:?}",
            names,
        );
        // Every C# class has a default constructor `.ctor`.
        assert!(
            names.iter().any(|n| n.contains(".ctor")),
            "expected .ctor; got: {:?}",
            names,
        );
    }

    #[test]
    fn errors_on_non_dotnet_pe() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        match extract_cil_methods(&data) {
            Err(CilError::NoCom) => {} // expected — non-CLR PE
            other => panic!("expected NoCom; got {:?}", other),
        }
    }
}
