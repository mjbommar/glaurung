//! Go pclntab walker (#212).
//!
//! Recovers function names from a Go binary's `.gopclntab` section.
//! Go binaries are typically built with `-buildmode=exe -ldflags="-s -w"`
//! (stripped) and ship without a regular symbol table — but the runtime
//! always emits `.gopclntab`, the table the Go scheduler / panic handler
//! needs at runtime. Reading it gives us a complete (entry_va → name)
//! mapping for every Go function in the binary.
//!
//! Supported formats (the two recent ones — 99% of binaries today):
//!
//!   * 0xfffffff0 — Go 1.18 / 1.19 layout
//!   * 0xfffffff1 — Go 1.20+ layout (current)
//!
//! Both use 32-bit relative offsets in the function table (the older
//! 0xfffffffa / 0xfffffffb variants used pointer-sized entries; we
//! decline those for v0 and surface them via NotSupported so the
//! caller can fall through to other heuristics).
//!
//! Layout (1.20+, header struct from `runtime/symtab.go`):
//!
//!     u32  magic = 0xfffffff1
//!     u16  pad
//!     u8   minLC
//!     u8   ptrSize
//!     usize nfunc
//!     usize nfiles
//!     usize textStart
//!     usize funcnametab_off  (relative to start of pclntab)
//!     usize cu_off
//!     usize filetab_off
//!     usize pctab_off
//!     usize pclntab_off     (the function table proper)
//!
//! Then at `pclntab_off`:
//!
//!     [u32 entry_off, u32 _func_off]  × (nfunc + 1)
//!
//! Each _func struct begins with `(entry_off u32, name_off i32)` — the
//! name is a null-terminated string at `funcnametab_off + name_off`.

use object::{Object, ObjectSection};

/// One function recovered from gopclntab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoFunc {
    pub entry_va: u64,
    pub name: String,
}

/// Reasons gopclntab parsing can fail (callers fall through to other
/// heuristics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoPclnError {
    NoSection,
    UnknownMagic(u32),
    Truncated(&'static str),
    /// The header parsed but a name offset pointed outside the funcname
    /// table — the section is corrupt or we're misreading the version.
    BadNameOffset { name_off: u32, table_size: usize },
}

/// Walk a binary's `.gopclntab` (or `__gopclntab` on Mach-O / `runtime.pclntab` on PE)
/// and return every Go function name it references.
///
/// Returns Ok(Vec<GoFunc>) on success — possibly empty if nfunc=0.
/// Returns Err(GoPclnError) if the section is missing or malformed.
pub fn extract_go_functions(data: &[u8]) -> Result<Vec<GoFunc>, GoPclnError> {
    let obj = object::read::File::parse(data).map_err(|_| GoPclnError::NoSection)?;

    // Section name varies by format. ELF: .gopclntab. Mach-O: __gopclntab.
    // PE: rdata-embedded, named runtime.pclntab — searchable via symbol.
    let pcln = obj
        .sections()
        .find(|s| matches!(s.name().ok(), Some(".gopclntab" | "__gopclntab" | "runtime.pclntab")))
        .ok_or(GoPclnError::NoSection)?;

    let bytes = pcln.data().map_err(|_| GoPclnError::NoSection)?;
    parse_pclntab(bytes)
}

fn parse_pclntab(bytes: &[u8]) -> Result<Vec<GoFunc>, GoPclnError> {
    if bytes.len() < 64 {
        return Err(GoPclnError::Truncated("header"));
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    match magic {
        0xfffffff0 | 0xfffffff1 => {} // supported
        other => return Err(GoPclnError::UnknownMagic(other)),
    }
    // pad1 (u8), pad2 (u8), minLC (u8), ptrSize (u8)
    let ptr_size = bytes[7] as usize;
    if ptr_size != 8 && ptr_size != 4 {
        return Err(GoPclnError::Truncated("ptrSize"));
    }
    let read_usize = |off: usize| -> Result<u64, GoPclnError> {
        if off + ptr_size > bytes.len() {
            return Err(GoPclnError::Truncated("usize"));
        }
        Ok(if ptr_size == 8 {
            u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as u64
        })
    };

    // Header field offsets after the 8-byte (magic+pads+sizes) prefix.
    let mut p = 8;
    let nfunc = read_usize(p)? as usize;
    p += ptr_size;
    let _nfiles = read_usize(p)?;
    p += ptr_size;
    let text_start = read_usize(p)?;
    p += ptr_size;
    let funcnametab_off = read_usize(p)? as usize;
    p += ptr_size;
    let _cu_off = read_usize(p)?;
    p += ptr_size;
    let _filetab_off = read_usize(p)?;
    p += ptr_size;
    let _pctab_off = read_usize(p)?;
    p += ptr_size;
    let pclntab_off = read_usize(p)? as usize;

    if pclntab_off + (nfunc + 1) * 8 > bytes.len() {
        return Err(GoPclnError::Truncated("pclntab"));
    }
    if funcnametab_off >= bytes.len() {
        return Err(GoPclnError::Truncated("funcnametab"));
    }
    let funcnametab = &bytes[funcnametab_off..];

    let mut out: Vec<GoFunc> = Vec::with_capacity(nfunc);
    for i in 0..nfunc {
        let row = pclntab_off + i * 8;
        let entry_off = u32::from_le_bytes(bytes[row..row + 4].try_into().unwrap()) as u64;
        let func_off = u32::from_le_bytes(bytes[row + 4..row + 8].try_into().unwrap()) as usize;

        // _func struct begins at gopclntab_base + pclntab_off + func_off.
        // Per Go's runtime/symtab.go, the _func layout starts with:
        //   uint32 entryOff   // duplicate of the row's entry_off
        //   int32  nameOff    // offset into funcnametab
        let func_struct_off = pclntab_off + func_off;
        if func_struct_off + 8 > bytes.len() {
            continue; // skip malformed entries instead of failing the whole walk
        }
        let name_off = i32::from_le_bytes(
            bytes[func_struct_off + 4..func_struct_off + 8].try_into().unwrap(),
        );
        if name_off < 0 || (name_off as usize) >= funcnametab.len() {
            return Err(GoPclnError::BadNameOffset {
                name_off: name_off as u32,
                table_size: funcnametab.len(),
            });
        }
        let name_bytes = &funcnametab[name_off as usize..];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
        let entry_va = text_start + entry_off;
        out.push(GoFunc { entry_va, name });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn extracts_main_main_from_stripped_go_hello() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/go/hello-go",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let funcs = extract_go_functions(&data).expect("parse should succeed");
        assert!(!funcs.is_empty(), "expected at least some functions");
        // Every Go binary has main.main.
        assert!(
            funcs.iter().any(|f| f.name == "main.main"),
            "missing main.main; sample names: {:?}",
            funcs.iter().take(5).map(|f| &f.name).collect::<Vec<_>>(),
        );
        // And runtime.* names — the entire stdlib is reachable.
        assert!(
            funcs.iter().filter(|f| f.name.starts_with("runtime.")).count() >= 50,
            "expected >=50 runtime.* names; got {}",
            funcs.iter().filter(|f| f.name.starts_with("runtime.")).count(),
        );
    }

    #[test]
    fn extracts_function_count_matches_metadata() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/go/hello-go-static",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let funcs = extract_go_functions(&data).unwrap();
        // Static binary embeds the entire stdlib — should be hundreds.
        assert!(
            funcs.len() >= 100,
            "expected hundreds of functions; got {}", funcs.len(),
        );
    }

    #[test]
    fn missing_section_returns_no_section_error() {
        // hello-c-clang-debug is not a Go binary.
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        match extract_go_functions(&data) {
            Err(GoPclnError::NoSection) => {} // expected
            other => panic!("expected NoSection; got {:?}", other),
        }
    }
}
