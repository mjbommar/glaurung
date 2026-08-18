//! Instruction and cross-reference decoding (JVM Specification 4.10, 6.5).
//!
//! [`parse_code_instructions`] walks a method's `code[]` array into
//! [`JavaInstruction`] records with rendered operands;
//! [`parse_code_xrefs`] walks the same array for the constant-pool
//! references the body makes. Opcode widths and mnemonics come from
//! `opcodes`.

use super::constant_pool::{read_class_name, read_name_and_type, read_utf8};
use super::opcodes::{instruction_len, opcode_mnemonic, read_i32_at, switch_padding};
use super::types::{ClassError, JavaInstruction, JavaXref};
use super::CpEntry;

pub(super) fn parse_code_instructions(code: &[u8]) -> Result<Vec<JavaInstruction>, ClassError> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode = code[pc];
        let Some(len) = instruction_len(code, pc, opcode)? else {
            out.push(JavaInstruction {
                bci: pc as u32,
                opcode,
                mnemonic: format!("unknown_0x{opcode:02x}"),
                operands: Vec::new(),
                length: 1,
            });
            break;
        };
        out.push(JavaInstruction {
            bci: pc as u32,
            opcode,
            mnemonic: opcode_mnemonic(opcode).to_string(),
            operands: instruction_operands(code, pc, opcode)?,
            length: len as u32,
        });
        pc = pc.saturating_add(len);
    }
    Ok(out)
}

fn instruction_operands(code: &[u8], pc: usize, opcode: u8) -> Result<Vec<String>, ClassError> {
    match opcode {
        0x10 => Ok(vec![format!("{}", code[pc + 1] as i8)]),
        0x11 => Ok(vec![format!("{}", read_i16_operand(code, pc, "sipush")?)]),
        0x12 => Ok(vec![format!("cp#{}", code[pc + 1])]),
        0x13 | 0x14 => Ok(vec![format!("cp#{}", read_u16_operand(code, pc, "ldc_w")?)]),
        0x15..=0x19 | 0x36..=0x3a | 0xa9 => Ok(vec![format!("local={}", code[pc + 1])]),
        0x84 => Ok(vec![
            format!("local={}", code[pc + 1]),
            format!("const={}", code[pc + 2] as i8),
        ]),
        0x99..=0xa8 | 0xc6 | 0xc7 => {
            let offset = read_i16_operand(code, pc, "branch")?;
            Ok(vec![format!("target={}", branch_target(pc, offset as i32))])
        }
        0xaa => tableswitch_operands(code, pc),
        0xab => lookupswitch_operands(code, pc),
        0xb2..=0xb8 | 0xbb | 0xbd | 0xc0 | 0xc1 => Ok(vec![format!(
            "cp#{}",
            read_u16_operand(code, pc, "constant-pool instruction")?
        )]),
        0xb9 => Ok(vec![
            format!("cp#{}", read_u16_operand(code, pc, "invokeinterface")?),
            format!("count={}", code[pc + 3]),
        ]),
        0xba => Ok(vec![format!(
            "cp#{}",
            read_u16_operand(code, pc, "invokedynamic")?
        )]),
        0xbc => Ok(vec![format!("atype={}", newarray_type(code[pc + 1]))]),
        0xc4 => wide_operands(code, pc),
        0xc5 => Ok(vec![
            format!("cp#{}", read_u16_operand(code, pc, "multianewarray")?),
            format!("dimensions={}", code[pc + 3]),
        ]),
        0xc8 | 0xc9 => {
            let offset = read_i32_operand(code, pc, "wide branch")?;
            Ok(vec![format!("target={}", branch_target(pc, offset))])
        }
        _ => Ok(Vec::new()),
    }
}

pub(super) fn parse_code_xrefs(code: &[u8], cp: &[CpEntry]) -> Result<Vec<JavaXref>, ClassError> {
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

fn read_i16_operand(code: &[u8], pc: usize, label: &'static str) -> Result<i16, ClassError> {
    if pc + 2 >= code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(i16::from_be_bytes([code[pc + 1], code[pc + 2]]))
}

fn read_i32_operand(code: &[u8], pc: usize, label: &'static str) -> Result<i32, ClassError> {
    if pc + 4 >= code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(i32::from_be_bytes([
        code[pc + 1],
        code[pc + 2],
        code[pc + 3],
        code[pc + 4],
    ]))
}

fn branch_target(pc: usize, offset: i32) -> i64 {
    pc as i64 + offset as i64
}

fn tableswitch_operands(code: &[u8], pc: usize) -> Result<Vec<String>, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let default = read_i32_at(code, base, "tableswitch")?;
    let low = read_i32_at(code, base + 4, "tableswitch")?;
    let high = read_i32_at(code, base + 8, "tableswitch")?;
    if high < low {
        return Err(ClassError::Truncated("tableswitch bounds"));
    }
    let cases = high as i64 - low as i64 + 1;
    Ok(vec![
        format!("default={}", branch_target(pc, default)),
        format!("low={low}"),
        format!("high={high}"),
        format!("cases={cases}"),
    ])
}

fn lookupswitch_operands(code: &[u8], pc: usize) -> Result<Vec<String>, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let default = read_i32_at(code, base, "lookupswitch")?;
    let npairs = read_i32_at(code, base + 4, "lookupswitch")?;
    if npairs < 0 {
        return Err(ClassError::Truncated("lookupswitch bounds"));
    }
    Ok(vec![
        format!("default={}", branch_target(pc, default)),
        format!("pairs={npairs}"),
    ])
}

fn newarray_type(atype: u8) -> &'static str {
    match atype {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => "unknown",
    }
}

fn wide_operands(code: &[u8], pc: usize) -> Result<Vec<String>, ClassError> {
    if pc + 1 >= code.len() {
        return Err(ClassError::Truncated("wide"));
    }
    let widened_opcode = code[pc + 1];
    if widened_opcode == 0x84 {
        if pc + 5 >= code.len() {
            return Err(ClassError::Truncated("wide iinc"));
        }
        let local = u16::from_be_bytes([code[pc + 2], code[pc + 3]]);
        let value = i16::from_be_bytes([code[pc + 4], code[pc + 5]]);
        return Ok(vec![
            "wide=iinc".to_string(),
            format!("local={local}"),
            format!("const={value}"),
        ]);
    }
    if pc + 3 >= code.len() {
        return Err(ClassError::Truncated("wide local"));
    }
    let local = u16::from_be_bytes([code[pc + 2], code[pc + 3]]);
    Ok(vec![
        format!("wide={}", opcode_mnemonic(widened_opcode)),
        format!("local={local}"),
    ])
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
        CpEntry::Dynamic {
            name_and_type_idx, ..
        } => dynamic_xref(cp, *name_and_type_idx, bci, opcode, "dynamic").map(Some),
        CpEntry::InvokeDynamic {
            name_and_type_idx, ..
        } => dynamic_xref(cp, *name_and_type_idx, bci, opcode, "invokedynamic").map(Some),
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
