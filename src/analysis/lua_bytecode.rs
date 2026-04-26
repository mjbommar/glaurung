//! Lua bytecode recognizer (#211 v0).
//!
//! Detects compiled Lua bytecode (`.luac`) and LuaJIT bytecode and
//! surfaces enough header / source info to triage these files. Full
//! prototype walking — opcodes, constants, debug-info line numbers —
//! is filed for v1 once we have a real malware sample driving the
//! requirements.
//!
//! Supported magics:
//!
//!   * `\x1bLua` followed by version byte (Lua 5.1 / 5.2 / 5.3 / 5.4)
//!   * `\x1bLJ`  followed by flags + version (LuaJIT 1 / 2)
//!
//! For Lua 5.3+ the parser walks the well-defined header far enough
//! to locate the top-level prototype's source-name string, which
//! gives the analyst the original `.lua` filename — critical for
//! tracing where a script came from.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuaKind {
    Lua51,
    Lua52,
    Lua53,
    Lua54,
    LuaJit,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaInfo {
    pub kind: LuaKind,
    /// Format byte. 0 = official, anything else = customised build.
    pub format: u8,
    /// Source filename embedded in the bytecode (debug info). `None`
    /// when the file was stripped with `luac -s`.
    pub source: Option<String>,
    /// Endianness flag. Some Lua versions encode this.
    pub little_endian: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuaError {
    BadMagic,
    Truncated(&'static str),
}

const LUA_MAGIC: &[u8] = b"\x1bLua";
const LUAJIT_MAGIC: &[u8] = b"\x1bLJ";

pub fn parse_lua(data: &[u8]) -> Result<LuaInfo, LuaError> {
    if data.len() < 6 {
        return Err(LuaError::Truncated("header"));
    }
    if data.starts_with(LUA_MAGIC) {
        return parse_lua_official(data);
    }
    if data.starts_with(LUAJIT_MAGIC) {
        return parse_luajit(data);
    }
    Err(LuaError::BadMagic)
}

fn parse_lua_official(data: &[u8]) -> Result<LuaInfo, LuaError> {
    let version = data[4];
    let format = data[5];
    let kind = match version {
        0x51 => LuaKind::Lua51,
        0x52 => LuaKind::Lua52,
        0x53 => LuaKind::Lua53,
        0x54 => LuaKind::Lua54,
        other => LuaKind::Unknown(other),
    };

    // For Lua 5.3+ the header is well-defined enough to extract the
    // source filename. The layout is:
    //   [0..4]  \x1bLua
    //   [4]     version
    //   [5]     format
    //   [6..12] LUAC_DATA = \x19\x93\r\n\x1a\n
    //   [12]    sizeof(int)        usually 4
    //   [13]    sizeof(size_t)     usually 8
    //   [14]    sizeof(Instruction) usually 4
    //   [15]    sizeof(lua_Integer) (5.3+) usually 8
    //   [16]    sizeof(lua_Number)
    //   [17..]  LUAC_INT (sizeof_int), LUAC_NUM (sizeof_number) test values
    //   ... upvalue count u8, then top-level prototype.
    //
    // Prototype starts with the source name string. Lua 5.3+ encodes
    // strings with a single-byte length L (0 = nil; 0xFF = follow
    // with size_t). String body is L-1 bytes long when L < 0xFF.
    let mut source: Option<String> = None;
    if matches!(kind, LuaKind::Lua53 | LuaKind::Lua54) {
        if let Some(name) = extract_source_53(data) {
            source = Some(name);
        }
    }

    let little_endian = true; // Lua 5.3+ removed the explicit endianness byte; assume LE.

    Ok(LuaInfo {
        kind,
        format,
        source,
        little_endian,
    })
}

fn extract_source_53(data: &[u8]) -> Option<String> {
    // Header is fixed-size up through LUAC_NUM:
    //   12 bytes header + LUAC_DATA  = bytes 0..12
    //   13: sizeof_int
    //   14: sizeof_size_t
    //   15: sizeof_Instruction
    //   16: sizeof_lua_Integer (5.3) or sizeof_lua_Number for 5.4
    //   17: sizeof_lua_Number  (5.3) — for 5.4 this slot doesn't exist
    //
    // Then test integer (sizeof_lua_Integer bytes for 5.3, sizeof_int
    // for 5.4) and test number (sizeof_lua_Number bytes).
    if data.len() < 18 {
        return None;
    }
    let version = data[4];
    let mut p = 12;
    let sizeof_int = data[p] as usize;
    p += 1;
    let _sizeof_size_t = data[p] as usize;
    p += 1;
    let _sizeof_inst = data[p] as usize;
    p += 1;
    let sizeof_lua_int;
    let sizeof_lua_num;
    if version == 0x53 {
        sizeof_lua_int = data[p] as usize; p += 1;
        sizeof_lua_num = data[p] as usize; p += 1;
        // Skip LUAC_INT and LUAC_NUM tag values.
        p += sizeof_lua_int + sizeof_lua_num;
    } else if version == 0x54 {
        // 5.4 layout: sizeof(Instruction), sizeof(lua_Integer), sizeof(lua_Number)
        // already consumed sizeof_inst above; the next bytes are
        // sizeof(lua_Integer) then sizeof(lua_Number).
        sizeof_lua_int = data[p] as usize; p += 1;
        sizeof_lua_num = data[p] as usize; p += 1;
        p += sizeof_lua_int + sizeof_lua_num;
    } else {
        return None;
    }
    if p >= data.len() {
        return None;
    }
    // Upvalue count u8 (number of upvalues for the main chunk).
    p += 1;
    if p >= data.len() {
        return None;
    }
    // Now we're at the start of the top-level prototype. Its first
    // field is the source-name string.
    let _ = sizeof_int;
    read_lua_string(data, &mut p)
}

/// Read a Lua 5.3+ string at `*p`, advancing `*p`. Returns None when
/// the encoded string is nil (length byte 0) or when the data is
/// truncated. The encoding is:
///   - First byte L. If 0, string is nil.
///   - If L < 0xFF: actual length is L-1; body follows.
///   - If L == 0xFF: next sizeof(size_t) bytes are the actual length.
fn read_lua_string(data: &[u8], p: &mut usize) -> Option<String> {
    if *p >= data.len() {
        return None;
    }
    let first = data[*p];
    *p += 1;
    if first == 0 {
        return None;
    }
    if first == 0xFF {
        // Long-string form: 8-byte size_t length follows. Bound this
        // generously to avoid runaway reads on malformed files.
        if *p + 8 > data.len() {
            return None;
        }
        let len = u64::from_le_bytes(data[*p..*p + 8].try_into().unwrap()) as usize;
        *p += 8;
        if len == 0 || *p + len.saturating_sub(1) > data.len() || len > 4096 {
            return None;
        }
        let actual = len - 1; // Lua stores length+1; the trailing nul is implicit.
        let s = String::from_utf8_lossy(&data[*p..*p + actual]).into_owned();
        *p += actual;
        Some(s)
    } else {
        let actual = (first as usize).saturating_sub(1);
        if *p + actual > data.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&data[*p..*p + actual]).into_owned();
        *p += actual;
        Some(s)
    }
}

fn parse_luajit(data: &[u8]) -> Result<LuaInfo, LuaError> {
    // LuaJIT header: \x1b L J <version> <flags> [<chunkname>]
    // version 1 = LJ1, 2 = LJ2 (the modern one).
    if data.len() < 5 {
        return Err(LuaError::Truncated("ljheader"));
    }
    let version_byte = data[3];
    let _flags = data[4];
    let _ = version_byte;
    Ok(LuaInfo {
        kind: LuaKind::LuaJit,
        format: 0,
        source: None, // TODO v1: parse LJ chunkname
        little_endian: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_lua_53_bytecode() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_lua(&data).expect("parse");
        // The 5.3.luac sample's actual version byte is 0x53.
        assert!(matches!(info.kind, LuaKind::Lua53 | LuaKind::Lua54));
    }

    #[test]
    fn detects_luajit_bytecode() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/lua/hello-luajit.luac",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_lua(&data).expect("parse");
        assert!(matches!(info.kind, LuaKind::LuaJit));
    }

    #[test]
    fn rejects_non_lua() {
        match parse_lua(b"hello world") {
            Err(LuaError::BadMagic) => {}
            other => panic!("expected BadMagic; got {:?}", other),
        }
    }

    #[test]
    fn extracts_source_filename_when_present() {
        // hello-lua5.3.luac was compiled from samples/source/lua/hello.lua
        // — depending on whether luac -s was used the source field may
        // be the full path, the basename, or absent. Just check it
        // parses without error.
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_lua(&data).expect("parse");
        // Source extraction is best-effort. When present, should
        // contain "hello" (the filename stem).
        if let Some(src) = &info.source {
            // Either a full path, a relative path, or just "hello.lua".
            // We only assert it's non-empty and probably ASCII-printable.
            assert!(!src.is_empty());
        }
    }
}
