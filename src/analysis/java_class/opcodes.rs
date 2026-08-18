//! The JVM opcode tables.
//!
//! Two pure lookups over the 0x00-0xff opcode space -- [`opcode_mnemonic`]
//! and [`instruction_len`] -- plus the variable-length forms
//! (`tableswitch`, `lookupswitch`, `wide`) that cannot be answered from a
//! fixed table. No state, no constant pool.

use super::types::ClassError;

pub(super) fn opcode_mnemonic(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "nop",
        0x01 => "aconst_null",
        0x02 => "iconst_m1",
        0x03 => "iconst_0",
        0x04 => "iconst_1",
        0x05 => "iconst_2",
        0x06 => "iconst_3",
        0x07 => "iconst_4",
        0x08 => "iconst_5",
        0x09 => "lconst_0",
        0x0a => "lconst_1",
        0x0b => "fconst_0",
        0x0c => "fconst_1",
        0x0d => "fconst_2",
        0x0e => "dconst_0",
        0x0f => "dconst_1",
        0x10 => "bipush",
        0x11 => "sipush",
        0x12 => "ldc",
        0x13 => "ldc_w",
        0x14 => "ldc2_w",
        0x15 => "iload",
        0x16 => "lload",
        0x17 => "fload",
        0x18 => "dload",
        0x19 => "aload",
        0x1a => "iload_0",
        0x1b => "iload_1",
        0x1c => "iload_2",
        0x1d => "iload_3",
        0x1e => "lload_0",
        0x1f => "lload_1",
        0x20 => "lload_2",
        0x21 => "lload_3",
        0x22 => "fload_0",
        0x23 => "fload_1",
        0x24 => "fload_2",
        0x25 => "fload_3",
        0x26 => "dload_0",
        0x27 => "dload_1",
        0x28 => "dload_2",
        0x29 => "dload_3",
        0x2a => "aload_0",
        0x2b => "aload_1",
        0x2c => "aload_2",
        0x2d => "aload_3",
        0x2e => "iaload",
        0x2f => "laload",
        0x30 => "faload",
        0x31 => "daload",
        0x32 => "aaload",
        0x33 => "baload",
        0x34 => "caload",
        0x35 => "saload",
        0x36 => "istore",
        0x37 => "lstore",
        0x38 => "fstore",
        0x39 => "dstore",
        0x3a => "astore",
        0x3b => "istore_0",
        0x3c => "istore_1",
        0x3d => "istore_2",
        0x3e => "istore_3",
        0x3f => "lstore_0",
        0x40 => "lstore_1",
        0x41 => "lstore_2",
        0x42 => "lstore_3",
        0x43 => "fstore_0",
        0x44 => "fstore_1",
        0x45 => "fstore_2",
        0x46 => "fstore_3",
        0x47 => "dstore_0",
        0x48 => "dstore_1",
        0x49 => "dstore_2",
        0x4a => "dstore_3",
        0x4b => "astore_0",
        0x4c => "astore_1",
        0x4d => "astore_2",
        0x4e => "astore_3",
        0x4f => "iastore",
        0x50 => "lastore",
        0x51 => "fastore",
        0x52 => "dastore",
        0x53 => "aastore",
        0x54 => "bastore",
        0x55 => "castore",
        0x56 => "sastore",
        0x57 => "pop",
        0x58 => "pop2",
        0x59 => "dup",
        0x5a => "dup_x1",
        0x5b => "dup_x2",
        0x5c => "dup2",
        0x5d => "dup2_x1",
        0x5e => "dup2_x2",
        0x5f => "swap",
        0x60 => "iadd",
        0x61 => "ladd",
        0x62 => "fadd",
        0x63 => "dadd",
        0x64 => "isub",
        0x65 => "lsub",
        0x66 => "fsub",
        0x67 => "dsub",
        0x68 => "imul",
        0x69 => "lmul",
        0x6a => "fmul",
        0x6b => "dmul",
        0x6c => "idiv",
        0x6d => "ldiv",
        0x6e => "fdiv",
        0x6f => "ddiv",
        0x70 => "irem",
        0x71 => "lrem",
        0x72 => "frem",
        0x73 => "drem",
        0x74 => "ineg",
        0x75 => "lneg",
        0x76 => "fneg",
        0x77 => "dneg",
        0x78 => "ishl",
        0x79 => "lshl",
        0x7a => "ishr",
        0x7b => "lshr",
        0x7c => "iushr",
        0x7d => "lushr",
        0x7e => "iand",
        0x7f => "land",
        0x80 => "ior",
        0x81 => "lor",
        0x82 => "ixor",
        0x83 => "lxor",
        0x84 => "iinc",
        0x85 => "i2l",
        0x86 => "i2f",
        0x87 => "i2d",
        0x88 => "l2i",
        0x89 => "l2f",
        0x8a => "l2d",
        0x8b => "f2i",
        0x8c => "f2l",
        0x8d => "f2d",
        0x8e => "d2i",
        0x8f => "d2l",
        0x90 => "d2f",
        0x91 => "i2b",
        0x92 => "i2c",
        0x93 => "i2s",
        0x94 => "lcmp",
        0x95 => "fcmpl",
        0x96 => "fcmpg",
        0x97 => "dcmpl",
        0x98 => "dcmpg",
        0x99 => "ifeq",
        0x9a => "ifne",
        0x9b => "iflt",
        0x9c => "ifge",
        0x9d => "ifgt",
        0x9e => "ifle",
        0x9f => "if_icmpeq",
        0xa0 => "if_icmpne",
        0xa1 => "if_icmplt",
        0xa2 => "if_icmpge",
        0xa3 => "if_icmpgt",
        0xa4 => "if_icmple",
        0xa5 => "if_acmpeq",
        0xa6 => "if_acmpne",
        0xa7 => "goto",
        0xa8 => "jsr",
        0xa9 => "ret",
        0xaa => "tableswitch",
        0xab => "lookupswitch",
        0xac => "ireturn",
        0xad => "lreturn",
        0xae => "freturn",
        0xaf => "dreturn",
        0xb0 => "areturn",
        0xb1 => "return",
        0xb2 => "getstatic",
        0xb3 => "putstatic",
        0xb4 => "getfield",
        0xb5 => "putfield",
        0xb6 => "invokevirtual",
        0xb7 => "invokespecial",
        0xb8 => "invokestatic",
        0xb9 => "invokeinterface",
        0xba => "invokedynamic",
        0xbb => "new",
        0xbc => "newarray",
        0xbd => "anewarray",
        0xbe => "arraylength",
        0xbf => "athrow",
        0xc0 => "checkcast",
        0xc1 => "instanceof",
        0xc2 => "monitorenter",
        0xc3 => "monitorexit",
        0xc4 => "wide",
        0xc5 => "multianewarray",
        0xc6 => "ifnull",
        0xc7 => "ifnonnull",
        0xc8 => "goto_w",
        0xc9 => "jsr_w",
        0xca => "breakpoint",
        0xfe => "impdep1",
        0xff => "impdep2",
        _ => "unknown",
    }
}

pub(super) fn instruction_len(
    code: &[u8],
    pc: usize,
    opcode: u8,
) -> Result<Option<usize>, ClassError> {
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

pub(super) fn switch_padding(pc: usize) -> usize {
    (4 - ((pc + 1) % 4)) % 4
}

pub(super) fn read_i32_at(code: &[u8], pos: usize, label: &'static str) -> Result<i32, ClassError> {
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
