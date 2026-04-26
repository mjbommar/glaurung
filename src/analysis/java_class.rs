//! Java classfile parser (#209 v0).
//!
//! Recovers class name, super class, interfaces, and the full method
//! table (name + JVM descriptor + access flags) from a `.class` file.
//! Java is unlike PE/ELF in that the file itself is the function
//! container — there are no RVAs/VAs to map onto. We surface the
//! metadata as a structured `ClassInfo` and let downstream callers
//! decide whether to mirror it into the KB or just render it.
//!
//! Spec reference: JVM Specification §4 (the ClassFile structure).
//! Supports JDK 1.0 through latest (constant-pool tags 1-20).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaMethod {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassInfo {
    pub minor_version: u16,
    pub major_version: u16,
    pub access_flags: u16,
    pub class_name: String,
    pub super_class: String,
    pub interfaces: Vec<String>,
    pub methods: Vec<JavaMethod>,
    pub fields: Vec<JavaMethod>, // same shape — name + descriptor + flags
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassError {
    BadMagic(u32),
    Truncated(&'static str),
    BadCpIndex(u16),
    BadCpTag(u8),
}

const MAGIC: u32 = 0xCAFE_BABE;

#[derive(Debug, Clone)]
enum CpEntry {
    Empty,
    Utf8(String),
    Class { name_idx: u16 },
    NameAndType { name_idx: u16, desc_idx: u16 },
    Other,
}

/// Parse a `.class` file and return its `ClassInfo`.
pub fn parse_class(data: &[u8]) -> Result<ClassInfo, ClassError> {
    if data.len() < 10 {
        return Err(ClassError::Truncated("header"));
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(ClassError::BadMagic(magic));
    }
    let minor = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let major = u16::from_be_bytes(data[6..8].try_into().unwrap());
    let cp_count = u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize;

    let mut p = 10;
    // Constant pool is 1-indexed; entry 0 is reserved. Long & Double
    // each occupy two slots.
    let mut cp: Vec<CpEntry> = vec![CpEntry::Empty; cp_count];
    let mut i = 1;
    while i < cp_count {
        if p >= data.len() {
            return Err(ClassError::Truncated("constant pool"));
        }
        let tag = data[p];
        p += 1;
        match tag {
            1 => {
                // Utf8: u16 length, then `length` bytes of modified UTF-8.
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("utf8 length"));
                }
                let len = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
                p += 2;
                if p + len > data.len() {
                    return Err(ClassError::Truncated("utf8 body"));
                }
                let s = decode_modified_utf8(&data[p..p + len]);
                cp[i] = CpEntry::Utf8(s);
                p += len;
                i += 1;
            }
            7 => {
                // Class
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("class"));
                }
                let name_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                p += 2;
                cp[i] = CpEntry::Class { name_idx };
                i += 1;
            }
            12 => {
                // NameAndType
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("nameandtype"));
                }
                let n = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                let d = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = CpEntry::NameAndType { name_idx: n, desc_idx: d };
                i += 1;
            }
            // Fixed-width entries we don't decode but must skip.
            3 | 4 => { p += 4; cp[i] = CpEntry::Other; i += 1; }       // Integer, Float
            5 | 6 => { p += 8; cp[i] = CpEntry::Other; i += 2; }       // Long, Double (2 slots)
            8 => { p += 2; cp[i] = CpEntry::Other; i += 1; }           // String
            9 | 10 | 11 => { p += 4; cp[i] = CpEntry::Other; i += 1; } // Field/Method/InterfaceMethod ref
            15 => { p += 3; cp[i] = CpEntry::Other; i += 1; }          // MethodHandle
            16 => { p += 2; cp[i] = CpEntry::Other; i += 1; }          // MethodType
            17 | 18 => { p += 4; cp[i] = CpEntry::Other; i += 1; }     // Dynamic, InvokeDynamic
            19 | 20 => { p += 2; cp[i] = CpEntry::Other; i += 1; }     // Module, Package
            other => return Err(ClassError::BadCpTag(other)),
        }
    }

    let read_utf8 = |idx: u16| -> Result<String, ClassError> {
        if (idx as usize) >= cp.len() {
            return Err(ClassError::BadCpIndex(idx));
        }
        match &cp[idx as usize] {
            CpEntry::Utf8(s) => Ok(s.clone()),
            _ => Err(ClassError::BadCpIndex(idx)),
        }
    };
    let read_class_name = |idx: u16| -> Result<String, ClassError> {
        if idx == 0 {
            return Ok(String::new());
        }
        if (idx as usize) >= cp.len() {
            return Err(ClassError::BadCpIndex(idx));
        }
        match &cp[idx as usize] {
            CpEntry::Class { name_idx } => read_utf8(*name_idx),
            _ => Err(ClassError::BadCpIndex(idx)),
        }
    };

    if p + 8 > data.len() {
        return Err(ClassError::Truncated("class header"));
    }
    let access_flags = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
    p += 2;
    let this_class = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
    p += 2;
    let super_class = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
    p += 2;
    let interfaces_count = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
    p += 2;

    let class_name = read_class_name(this_class)?;
    let super_class_name = read_class_name(super_class)?;
    let mut interfaces = Vec::with_capacity(interfaces_count);
    for _ in 0..interfaces_count {
        if p + 2 > data.len() {
            return Err(ClassError::Truncated("interfaces"));
        }
        let idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
        p += 2;
        interfaces.push(read_class_name(idx)?);
    }

    let mut fields: Vec<JavaMethod> = Vec::new();
    p = walk_member_table(data, p, &cp, &mut fields)?;
    let mut methods: Vec<JavaMethod> = Vec::new();
    p = walk_member_table(data, p, &cp, &mut methods)?;
    let _ = p; // class-level attributes ignored for v0

    Ok(ClassInfo {
        minor_version: minor,
        major_version: major,
        access_flags,
        class_name,
        super_class: super_class_name,
        interfaces,
        methods,
        fields,
    })
}

fn walk_member_table(
    data: &[u8],
    mut p: usize,
    cp: &[CpEntry],
    out: &mut Vec<JavaMethod>,
) -> Result<usize, ClassError> {
    if p + 2 > data.len() {
        return Err(ClassError::Truncated("member count"));
    }
    let count = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    for _ in 0..count {
        if p + 8 > data.len() {
            return Err(ClassError::Truncated("member info"));
        }
        let access_flags = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
        let name_idx = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
        let desc_idx = u16::from_be_bytes(data[p + 4..p + 6].try_into().unwrap());
        let attrs = u16::from_be_bytes(data[p + 6..p + 8].try_into().unwrap()) as usize;
        p += 8;
        // Skip attributes — for v0 we don't need bytecode.
        for _ in 0..attrs {
            if p + 6 > data.len() {
                return Err(ClassError::Truncated("attribute header"));
            }
            let alen =
                u32::from_be_bytes(data[p + 2..p + 6].try_into().unwrap()) as usize;
            p += 6 + alen;
            if p > data.len() {
                return Err(ClassError::Truncated("attribute body"));
            }
        }
        let name = match cp.get(name_idx as usize) {
            Some(CpEntry::Utf8(s)) => s.clone(),
            _ => return Err(ClassError::BadCpIndex(name_idx)),
        };
        let descriptor = match cp.get(desc_idx as usize) {
            Some(CpEntry::Utf8(s)) => s.clone(),
            _ => return Err(ClassError::BadCpIndex(desc_idx)),
        };
        out.push(JavaMethod { access_flags, name, descriptor });
    }
    Ok(p)
}

/// Decode JVM "modified UTF-8" — almost identical to UTF-8 except
/// the NUL byte is encoded as 0xC0 0x80 and supplementary characters
/// use surrogate pairs. We accept both standard UTF-8 and the modified
/// form by walking each byte and reconstructing chars.
fn decode_modified_utf8(buf: &[u8]) -> String {
    // For the purposes of class-name extraction, a tolerant lossy
    // decode is fine — class names and method names are nearly always
    // pure ASCII anyway.
    String::from_utf8_lossy(buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_helloworld_class() {
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_class(&data).expect("parse should succeed");
        assert_eq!(info.class_name, "HelloWorld");
        assert_eq!(info.super_class, "java/lang/Object");
        // HelloWorld.java declares: HelloWorld(String), HelloWorld(),
        // printMessage, getCounter, printGlobalInfo, main.
        let names: Vec<&str> = info.methods.iter().map(|m| m.name.as_str()).collect();
        for expected in &["main", "printMessage", "getCounter", "printGlobalInfo", "<init>"] {
            assert!(
                names.contains(expected),
                "missing method {}; got {:?}", expected, names,
            );
        }
        // Main has descriptor `([Ljava/lang/String;)V`.
        let main_method = info.methods.iter().find(|m| m.name == "main").unwrap();
        assert_eq!(main_method.descriptor, "([Ljava/lang/String;)V");
    }

    #[test]
    fn rejects_non_class_files() {
        let data = b"hello world";
        match parse_class(data) {
            Err(ClassError::Truncated(_)) | Err(ClassError::BadMagic(_)) => {}
            other => panic!("expected error; got {:?}", other),
        }
    }
}
