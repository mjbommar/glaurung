//! Mach-O environment analysis: rpaths, minOS target, code-sign presence.

pub struct MachoEnv {
    pub rpaths: Vec<String>,
    pub minos: Option<String>,
    pub code_signature: bool,
}

fn read_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

pub fn analyze_macho_env(data: &[u8]) -> Option<MachoEnv> {
    if data.len() < 32 {
        return None;
    }
    let magic_raw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Recognize Mach-O, not FAT
    let (is_64, le) = match (magic_le, magic_raw) {
        (0xfeedfacf, _) => (true, true),
        (0xfeedface, _) => (false, true),
        (_, 0xcffaedfe) => (true, false),
        (_, 0xcefaedfe) => (false, false),
        _ => return None,
    };
    // header fields: ncmds at +16, sizeofcmds at +20
    let ncmds = read_u32(data, 16, le).unwrap_or(0);
    let sizeofcmds = read_u32(data, 20, le).unwrap_or(0) as usize;
    let mut off: usize = if is_64 { 32 } else { 28 };
    let lc_end = off.saturating_add(sizeofcmds).min(data.len());
    let mut rpaths: Vec<String> = Vec::new();
    let mut code_signature = false;
    let mut minos: Option<String> = None;
    for _ in 0..ncmds {
        if off + 8 > lc_end {
            break;
        }
        let cmd = read_u32(data, off, le).unwrap_or(0);
        let cmdsize = read_u32(data, off + 4, le).unwrap_or(0) as usize;
        if cmdsize < 8 || off + cmdsize > lc_end {
            break;
        }
        match cmd & 0x7fff_ffff {
            0x1c /* LC_RPATH */ => {
                // path offset at +8
                let path_off = read_u32(data, off+8, le).unwrap_or(0) as usize;
                let start = off.saturating_add(path_off);
                if start < lc_end {
                    let mut i = start;
                    let end = (off + cmdsize).min(lc_end);
                    while i < end && i - start < 1024 {
                        if data[i] == 0 { break; }
                        i += 1;
                    }
                    if i <= end {
                        if let Ok(s) = std::str::from_utf8(&data[start..i]) { rpaths.push(s.to_string()); }
                    }
                }
            }
            0x1d /* LC_CODE_SIGNATURE */ => {
                code_signature = true;
            }
            0x24 /* LC_VERSION_MIN_MACOSX */ | 0x25 /* LC_VERSION_MIN_IPHONEOS */ => {
                // version at +8: X.Y.Z packed as xxxx.yy.zz (BCD-ish in 2.16.16)
                let ver = read_u32(data, off+8, le).unwrap_or(0);
                let major = (ver >> 16) & 0xffff;
                let minor = (ver >> 8) & 0xff;
                let patch = ver & 0xff;
                minos = Some(format!("{}.{}.{}", major, minor, patch));
            }
            _ => {}
        }
        off += cmdsize;
    }
    Some(MachoEnv {
        rpaths,
        minos,
        code_signature,
    })
}
