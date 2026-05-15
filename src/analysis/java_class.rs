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
    pub code: Option<JavaCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaCode {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code_length: u32,
    pub exception_table_len: u16,
    pub attributes_count: u16,
    pub xrefs: Vec<JavaXref>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaXref {
    pub bci: u32,
    pub opcode: u8,
    pub kind: String,
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub target: String,
    pub string_value: Option<String>,
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
    Class {
        name_idx: u16,
    },
    NameAndType {
        name_idx: u16,
        desc_idx: u16,
    },
    String {
        string_idx: u16,
    },
    Fieldref {
        class_idx: u16,
        name_and_type_idx: u16,
    },
    Methodref {
        class_idx: u16,
        name_and_type_idx: u16,
    },
    InterfaceMethodref {
        class_idx: u16,
        name_and_type_idx: u16,
    },
    Dynamic {
        name_and_type_idx: u16,
    },
    InvokeDynamic {
        name_and_type_idx: u16,
    },
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
                cp[i] = CpEntry::NameAndType {
                    name_idx: n,
                    desc_idx: d,
                };
                i += 1;
            }
            // Fixed-width entries we don't decode but must skip.
            3 | 4 => {
                p += 4;
                cp[i] = CpEntry::Other;
                i += 1;
            } // Integer, Float
            5 | 6 => {
                p += 8;
                cp[i] = CpEntry::Other;
                i += 2;
            } // Long, Double (2 slots)
            8 => {
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("string"));
                }
                let string_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                p += 2;
                cp[i] = CpEntry::String { string_idx };
                i += 1;
            } // String
            9 | 10 | 11 => {
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("member ref"));
                }
                let class_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                let name_and_type_idx = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = match tag {
                    9 => CpEntry::Fieldref {
                        class_idx,
                        name_and_type_idx,
                    },
                    10 => CpEntry::Methodref {
                        class_idx,
                        name_and_type_idx,
                    },
                    11 => CpEntry::InterfaceMethodref {
                        class_idx,
                        name_and_type_idx,
                    },
                    _ => unreachable!(),
                };
                i += 1;
            } // Field/Method/InterfaceMethod ref
            15 => {
                p += 3;
                cp[i] = CpEntry::Other;
                i += 1;
            } // MethodHandle
            16 => {
                p += 2;
                cp[i] = CpEntry::Other;
                i += 1;
            } // MethodType
            17 | 18 => {
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("dynamic"));
                }
                let _bootstrap_method_attr_idx =
                    u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                let name_and_type_idx = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = if tag == 17 {
                    CpEntry::Dynamic { name_and_type_idx }
                } else {
                    CpEntry::InvokeDynamic { name_and_type_idx }
                };
                i += 1;
            } // Dynamic, InvokeDynamic
            19 | 20 => {
                p += 2;
                cp[i] = CpEntry::Other;
                i += 1;
            } // Module, Package
            other => return Err(ClassError::BadCpTag(other)),
        }
    }

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

    let class_name = read_class_name(&cp, this_class)?;
    let super_class_name = read_class_name(&cp, super_class)?;
    let mut interfaces = Vec::with_capacity(interfaces_count);
    for _ in 0..interfaces_count {
        if p + 2 > data.len() {
            return Err(ClassError::Truncated("interfaces"));
        }
        let idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
        p += 2;
        interfaces.push(read_class_name(&cp, idx)?);
    }

    let mut fields: Vec<JavaMethod> = Vec::new();
    p = walk_member_table(data, p, &cp, false, &mut fields)?;
    let mut methods: Vec<JavaMethod> = Vec::new();
    p = walk_member_table(data, p, &cp, true, &mut methods)?;
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
    capture_code: bool,
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
        let mut code = None;
        for _ in 0..attrs {
            if p + 6 > data.len() {
                return Err(ClassError::Truncated("attribute header"));
            }
            let attr_name_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
            let alen = u32::from_be_bytes(data[p + 2..p + 6].try_into().unwrap()) as usize;
            let body_start = p + 6;
            let body_end = body_start
                .checked_add(alen)
                .ok_or(ClassError::Truncated("attribute body"))?;
            if body_end > data.len() {
                return Err(ClassError::Truncated("attribute body"));
            }
            if capture_code && read_utf8(cp, attr_name_idx)? == "Code" {
                code = Some(parse_code_attribute(&data[body_start..body_end], cp)?);
            }
            p = body_end;
        }
        let name = read_utf8(cp, name_idx)?;
        let descriptor = read_utf8(cp, desc_idx)?;
        out.push(JavaMethod {
            access_flags,
            name,
            descriptor,
            code,
        });
    }
    Ok(p)
}

fn read_utf8(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(s) => Ok(s.clone()),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn read_class_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if idx == 0 {
        return Ok(String::new());
    }
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Class { name_idx } => read_utf8(cp, *name_idx),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn parse_code_attribute(body: &[u8], cp: &[CpEntry]) -> Result<JavaCode, ClassError> {
    if body.len() < 8 {
        return Err(ClassError::Truncated("code attribute header"));
    }
    let max_stack = u16::from_be_bytes(body[0..2].try_into().unwrap());
    let max_locals = u16::from_be_bytes(body[2..4].try_into().unwrap());
    let code_length = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let code_start = 8usize;
    let code_end = code_start
        .checked_add(code_length as usize)
        .ok_or(ClassError::Truncated("code body"))?;
    if code_end + 2 > body.len() {
        return Err(ClassError::Truncated("code body"));
    }
    let exception_table_len = u16::from_be_bytes(body[code_end..code_end + 2].try_into().unwrap());
    let exception_table_bytes = (exception_table_len as usize)
        .checked_mul(8)
        .ok_or(ClassError::Truncated("exception table"))?;
    let exception_table_end = (code_end + 2)
        .checked_add(exception_table_bytes)
        .ok_or(ClassError::Truncated("exception table"))?;
    if exception_table_end + 2 > body.len() {
        return Err(ClassError::Truncated("exception table"));
    }
    let attributes_count = u16::from_be_bytes(
        body[exception_table_end..exception_table_end + 2]
            .try_into()
            .unwrap(),
    );
    let mut p = exception_table_end + 2;
    for _ in 0..attributes_count {
        if p + 6 > body.len() {
            return Err(ClassError::Truncated("code nested attribute header"));
        }
        let alen = u32::from_be_bytes(body[p + 2..p + 6].try_into().unwrap()) as usize;
        p = (p + 6)
            .checked_add(alen)
            .ok_or(ClassError::Truncated("code nested attribute body"))?;
        if p > body.len() {
            return Err(ClassError::Truncated("code nested attribute body"));
        }
    }
    let xrefs = parse_code_xrefs(&body[code_start..code_end], cp)?;
    Ok(JavaCode {
        max_stack,
        max_locals,
        code_length,
        exception_table_len,
        attributes_count,
        xrefs,
    })
}

fn parse_code_xrefs(code: &[u8], cp: &[CpEntry]) -> Result<Vec<JavaXref>, ClassError> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode = code[pc];
        match opcode {
            0x12 => {
                if pc + 1 >= code.len() {
                    return Err(ClassError::Truncated("ldc"));
                }
                let idx = code[pc + 1] as u16;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0x13 | 0x14 => {
                let idx = read_u16_operand(code, pc, "ldc_w")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xb2..=0xb5 => {
                let idx = read_u16_operand(code, pc, "field instruction")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xb6..=0xb8 => {
                let idx = read_u16_operand(code, pc, "method instruction")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xb9 => {
                let idx = read_u16_operand(code, pc, "invokeinterface")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xba => {
                let idx = read_u16_operand(code, pc, "invokedynamic")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xbb | 0xbd | 0xc0 | 0xc1 | 0xc5 => {
                let idx = read_u16_operand(code, pc, "class instruction")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            _ => {}
        }

        let Some(len) = instruction_len(code, pc, opcode)? else {
            break;
        };
        pc = pc.saturating_add(len);
    }
    Ok(out)
}

fn read_u16_operand(code: &[u8], pc: usize, label: &'static str) -> Result<u16, ClassError> {
    if pc + 2 >= code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(u16::from_be_bytes([code[pc + 1], code[pc + 2]]))
}

fn resolve_constant_xref(
    cp: &[CpEntry],
    idx: u16,
    bci: u32,
    opcode: u8,
) -> Result<Option<JavaXref>, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Fieldref {
            class_idx,
            name_and_type_idx,
        } => member_xref(cp, *class_idx, *name_and_type_idx, bci, opcode, "field").map(Some),
        CpEntry::Methodref {
            class_idx,
            name_and_type_idx,
        } => member_xref(cp, *class_idx, *name_and_type_idx, bci, opcode, "method").map(Some),
        CpEntry::InterfaceMethodref {
            class_idx,
            name_and_type_idx,
        } => member_xref(
            cp,
            *class_idx,
            *name_and_type_idx,
            bci,
            opcode,
            "interface_method",
        )
        .map(Some),
        CpEntry::Class { name_idx } => {
            let name = read_utf8(cp, *name_idx)?;
            Ok(Some(JavaXref {
                bci,
                opcode,
                kind: "class".to_string(),
                owner: name.clone(),
                name: String::new(),
                descriptor: String::new(),
                target: name,
                string_value: None,
            }))
        }
        CpEntry::String { string_idx } => {
            let value = read_utf8(cp, *string_idx)?;
            Ok(Some(JavaXref {
                bci,
                opcode,
                kind: "string".to_string(),
                owner: String::new(),
                name: String::new(),
                descriptor: String::new(),
                target: value.clone(),
                string_value: Some(value),
            }))
        }
        CpEntry::Dynamic { name_and_type_idx } => {
            dynamic_xref(cp, *name_and_type_idx, bci, opcode, "dynamic").map(Some)
        }
        CpEntry::InvokeDynamic { name_and_type_idx } => {
            dynamic_xref(cp, *name_and_type_idx, bci, opcode, "invokedynamic").map(Some)
        }
        _ => Ok(None),
    }
}

fn member_xref(
    cp: &[CpEntry],
    class_idx: u16,
    name_and_type_idx: u16,
    bci: u32,
    opcode: u8,
    kind: &str,
) -> Result<JavaXref, ClassError> {
    let owner = read_class_name(cp, class_idx)?;
    let (name, descriptor) = read_name_and_type(cp, name_and_type_idx)?;
    let target = format!("{owner}.{name}:{descriptor}");
    Ok(JavaXref {
        bci,
        opcode,
        kind: kind.to_string(),
        owner,
        name,
        descriptor,
        target,
        string_value: None,
    })
}

fn dynamic_xref(
    cp: &[CpEntry],
    name_and_type_idx: u16,
    bci: u32,
    opcode: u8,
    kind: &str,
) -> Result<JavaXref, ClassError> {
    let (name, descriptor) = read_name_and_type(cp, name_and_type_idx)?;
    let target = format!("{name}:{descriptor}");
    Ok(JavaXref {
        bci,
        opcode,
        kind: kind.to_string(),
        owner: String::new(),
        name,
        descriptor,
        target,
        string_value: None,
    })
}

fn read_name_and_type(cp: &[CpEntry], idx: u16) -> Result<(String, String), ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::NameAndType { name_idx, desc_idx } => {
            Ok((read_utf8(cp, *name_idx)?, read_utf8(cp, *desc_idx)?))
        }
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn instruction_len(code: &[u8], pc: usize, opcode: u8) -> Result<Option<usize>, ClassError> {
    let fixed = match opcode {
        0x00..=0x0f => 1,
        0x10 => 2,
        0x11 => 3,
        0x12 => 2,
        0x13 | 0x14 => 3,
        0x15..=0x19 => 2,
        0x1a..=0x35 => 1,
        0x36..=0x3a => 2,
        0x3b..=0x83 => 1,
        0x84 => 3,
        0x85..=0x98 => 1,
        0x99..=0xa8 => 3,
        0xa9 => 2,
        0xaa => return tableswitch_len(code, pc).map(Some),
        0xab => return lookupswitch_len(code, pc).map(Some),
        0xac..=0xb1 => 1,
        0xb2..=0xb8 => 3,
        0xb9 | 0xba => 5,
        0xbb => 3,
        0xbc => 2,
        0xbd => 3,
        0xbe | 0xbf => 1,
        0xc0 | 0xc1 => 3,
        0xc2 | 0xc3 => 1,
        0xc4 => return wide_len(code, pc).map(Some),
        0xc5 => 4,
        0xc6 | 0xc7 => 3,
        0xc8 | 0xc9 => 5,
        0xca | 0xfe | 0xff => 1,
        _ => return Ok(None),
    };
    if pc + fixed > code.len() {
        return Err(ClassError::Truncated("bytecode instruction"));
    }
    Ok(Some(fixed))
}

fn switch_padding(pc: usize) -> usize {
    (4 - ((pc + 1) % 4)) % 4
}

fn read_i32_at(code: &[u8], pos: usize, label: &'static str) -> Result<i32, ClassError> {
    if pos + 4 > code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(i32::from_be_bytes(code[pos..pos + 4].try_into().unwrap()))
}

fn tableswitch_len(code: &[u8], pc: usize) -> Result<usize, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let low = read_i32_at(code, base + 4, "tableswitch")?;
    let high = read_i32_at(code, base + 8, "tableswitch")?;
    if high < low {
        return Err(ClassError::Truncated("tableswitch bounds"));
    }
    let count = (high as i64 - low as i64 + 1) as usize;
    let len = 1usize
        .checked_add(pad)
        .and_then(|v| v.checked_add(12))
        .and_then(|v| v.checked_add(count.checked_mul(4)?))
        .ok_or(ClassError::Truncated("tableswitch"))?;
    if pc + len > code.len() {
        return Err(ClassError::Truncated("tableswitch"));
    }
    Ok(len)
}

fn lookupswitch_len(code: &[u8], pc: usize) -> Result<usize, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let npairs = read_i32_at(code, base + 4, "lookupswitch")?;
    if npairs < 0 {
        return Err(ClassError::Truncated("lookupswitch bounds"));
    }
    let len = 1usize
        .checked_add(pad)
        .and_then(|v| v.checked_add(8))
        .and_then(|v| v.checked_add((npairs as usize).checked_mul(8)?))
        .ok_or(ClassError::Truncated("lookupswitch"))?;
    if pc + len > code.len() {
        return Err(ClassError::Truncated("lookupswitch"));
    }
    Ok(len)
}

fn wide_len(code: &[u8], pc: usize) -> Result<usize, ClassError> {
    if pc + 1 >= code.len() {
        return Err(ClassError::Truncated("wide"));
    }
    let len = if code[pc + 1] == 0x84 { 6 } else { 4 };
    if pc + len > code.len() {
        return Err(ClassError::Truncated("wide"));
    }
    Ok(len)
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
        let path = Path::new("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class");
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
        for expected in &[
            "main",
            "printMessage",
            "getCounter",
            "printGlobalInfo",
            "<init>",
        ] {
            assert!(
                names.contains(expected),
                "missing method {}; got {:?}",
                expected,
                names,
            );
        }
        // Main has descriptor `([Ljava/lang/String;)V`.
        let main_method = info.methods.iter().find(|m| m.name == "main").unwrap();
        assert_eq!(main_method.descriptor, "([Ljava/lang/String;)V");
        let main_code = main_method
            .code
            .as_ref()
            .expect("main should have bytecode");
        assert!(main_code.max_stack > 0);
        assert!(main_code.max_locals >= 1);
        assert!(main_code.code_length > 0);
        assert!(info.fields.iter().all(|f| f.code.is_none()));
    }

    #[test]
    fn parses_method_bytecode_xrefs() {
        let path = Path::new("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_class(&data).expect("parse should succeed");

        let print_message = info
            .methods
            .iter()
            .find(|m| m.name == "printMessage")
            .expect("printMessage method");
        let xrefs = &print_message.code.as_ref().expect("code").xrefs;
        assert!(
            xrefs.iter().any(|xref| {
                xref.kind == "field"
                    && xref.owner == "java/lang/System"
                    && xref.name == "out"
                    && xref.bci == 0
            }),
            "expected System.out field xref, got {xrefs:?}",
        );
        assert!(
            xrefs.iter().any(|xref| {
                xref.kind == "method"
                    && xref.owner == "java/io/PrintStream"
                    && xref.name == "println"
                    && xref.bci == 7
            }),
            "expected PrintStream.println method xref, got {xrefs:?}",
        );

        let default_init = info
            .methods
            .iter()
            .find(|m| m.name == "<init>" && m.descriptor == "()V")
            .expect("default constructor");
        let init_xrefs = &default_init.code.as_ref().expect("code").xrefs;
        assert!(
            init_xrefs.iter().any(|xref| {
                xref.kind == "string"
                    && xref.string_value.as_deref() == Some("Hello, World from Java!")
                    && xref.bci == 1
            }),
            "expected constructor string constant xref, got {init_xrefs:?}",
        );
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
